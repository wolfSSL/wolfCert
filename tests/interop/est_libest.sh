#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
#
# EST interoperability against Cisco's libest (archived but still the
# reference implementation of RFC 7030).
#
# libest is not packaged on any major distro; this script looks for
# `estserver` and `estclient` in PATH. Install by:
#
#   git clone https://github.com/cisco/libest
#   cd libest && ./configure --disable-safec \
#       --with-ssl-dir=$(pkg-config --variable prefix openssl)
#   make && sudo make install

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib/common.sh"

need estserver "Install libest from https://github.com/cisco/libest"
need estclient "Install libest from https://github.com/cisco/libest"
need openssl   "Standard on most distros"

WC_CLIENT="$(wolfcert_bin wolfcert-client)"
WC_SERVER="$(wolfcert_bin wolfcert-server)"

cd "$WOLFCERT_INTEROP_WORK"
ES_PID=""; WC_PID=""
trap 'kill_if "$ES_PID"; kill_if "$WC_PID"
      echo "--- work dir: $WOLFCERT_INTEROP_WORK"' EXIT

# The example estserver issues through an OpenSSL `ca` config and state dir.
echo "[setup] bootstrap a CA with openssl for libest"
mkdir -p ca CA/estCA/private CA/estCA/newcerts
: > CA/estCA/index.txt
echo "01" > CA/estCA/serial
openssl req -x509 -new -newkey rsa:2048 -nodes \
    -keyout CA/estCA/private/cakey.pem -out CA/estCA/cacert.crt \
    -days 30 -subj "/CN=libest-interop-CA" -batch >/dev/null 2>&1
# Convenience copies the wolfcert client uses as a trust anchor.
cp CA/estCA/cacert.crt ca/ca.crt
cp CA/estCA/private/cakey.pem ca/ca.key
openssl req -new -newkey rsa:2048 -nodes \
    -keyout ca/srv.key -out ca/srv.csr \
    -subj "/CN=localhost" -batch >/dev/null 2>&1
openssl x509 -req -in ca/srv.csr -CA ca/ca.crt -CAkey ca/ca.key -CAcreateserial \
    -out ca/srv.crt -days 30 -sha256 >/dev/null 2>&1

cat > estCA.cnf <<'CNF'
[ ca ]
default_ca = CA_default
[ CA_default ]
dir            = CA/estCA
database       = $dir/index.txt
new_certs_dir  = $dir/newcerts
certificate    = $dir/cacert.crt
serial         = $dir/serial
private_key    = $dir/private/cakey.pem
default_days   = 30
default_md     = sha256
policy         = policy_any
email_in_dn    = no
name_opt       = ca_default
cert_opt       = ca_default
copy_extensions = copyall
unique_subject = no
[ policy_any ]
commonName             = supplied
organizationName       = optional
organizationalUnitName = optional
countryName            = optional
stateOrProvinceName    = optional
CNF
export EST_OPENSSL_CACONFIG="$PWD/estCA.cnf"

# D1: wolfcert-client -> libest estserver
echo "[1] wolfcert-client -> libest estserver"
EST_PORT=$(free_port)
# estserver takes /cacerts and its client-cert trust from env vars, and rejects
# a DER PKCS#7 bundle in its length-vs-strnlen check, so both are PEM.
openssl crl2pkcs7 -nocrl -certfile ca/ca.crt -out ca/cacerts.p7 \
    >/dev/null 2>&1
export EST_CACERTS_RESP="$PWD/ca/cacerts.p7"
export EST_TRUSTED_CERTS="$PWD/ca/ca.crt"
estserver -c ca/srv.crt -k ca/srv.key -r "estrealm" \
          -p "$EST_PORT" >estserver.log 2>&1 &
ES_PID=$!
wait_port 127.0.0.1 "$EST_PORT"

# srv.crt has CN=localhost, so connect by that name.
"$WC_CLIENT" enroll --proto est \
    --url   "https://localhost:$EST_PORT/.well-known/est" \
    --trust ca/ca.crt \
    --user  "estuser" --pass "estpwd" \
    --key-type ecc:256 \
    --subject "CN=libest-interop-client" \
    --out-key libest.key --out-cert libest.crt \
    >wc-client.log 2>&1 \
    || { echo "    FAIL (wolfcert-client enroll failed):"; cat wc-client.log
         tail -n 40 estserver.log; exit 1; }

openssl x509 -in libest.crt -noout -subject \
    | grep -q "CN *= *libest-interop-client"
openssl verify -CAfile ca/ca.crt libest.crt >/dev/null
echo "    PASS"
kill_if "$ES_PID"; ES_PID=""

# D2: libest estclient -> wolfcert-server (native TLS)
echo "[2] libest estclient -> wolfcert-server (HTTPS via built-in TLS)"
EST_PORT=$(free_port)

# Mint a loopback server identity for wolfcert-server's --tls-cert/--tls-key.
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
    -keyout wc-srv.key -out wc-srv.crt -subj "/CN=127.0.0.1" \
    -addext "subjectAltName=IP:127.0.0.1" >/dev/null 2>&1

"$WC_SERVER" --proto est --listen "127.0.0.1:$EST_PORT" \
             --tls-cert wc-srv.crt --tls-key wc-srv.key --est-allow-anonymous \
             >wc-server.log 2>&1 &
WC_PID=$!
wait_port 127.0.0.1 "$EST_PORT"

# -o is an output directory; the cert lands there as base64 PKCS#7.
mkdir -p d2out
estclient -e -s "127.0.0.1" -p "$EST_PORT" \
          --common-name "libest-cli-1" \
          --trustanchor wc-srv.crt \
          -o d2out >estclient.log 2>&1 \
    || { echo "    FAIL (estclient enroll failed):"; cat estclient.log; exit 1; }

# An unmatched glob fails ls under pipefail, aborting before the guard below.
cert_p7=$(ls d2out/cert-*.pkcs7 2>/dev/null | head -1 || true)
[ -n "$cert_p7" ] || { echo "    FAIL (no cert emitted)"; cat estclient.log; exit 1; }
openssl base64 -d -in "$cert_p7" -out d2out/cert.p7der
openssl pkcs7 -inform DER -in d2out/cert.p7der -print_certs -out d2out/cert.pem
openssl x509 -in d2out/cert.pem -noout -subject \
    | grep -q "CN *= *libest-cli-1"
echo "    PASS"
kill_if "$WC_PID"

echo "OK"
