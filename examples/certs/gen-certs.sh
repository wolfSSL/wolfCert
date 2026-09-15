#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Generate example PKIs for exercising the wolfcert CLI tools over TLS / mTLS.
# These are throwaway test credentials -- do NOT use them anywhere real.
#
# For each algorithm family a three-cert hierarchy is produced:
#
#     <alg>/ca-cert.pem      self-signed CA (trust anchor)
#     <alg>/ca-key.pem
#     <alg>/server-cert.pem  TLS server leaf, SAN = localhost / 127.0.0.1 /
#                            ::1 / 10.0.2.2
#     <alg>/server-key.pem
#     <alg>/client-cert.pem  mTLS client leaf
#     <alg>/client-key.pem
#
# Mapping onto the CLIs:
#   wolfcert-server --tls-cert <alg>/server-cert.pem --tls-key <alg>/server-key.pem \
#                   [--tls-client-ca <alg>/ca-cert.pem]
#   wolfcert-client ... --trust <alg>/ca-cert.pem \
#                   [--client-cert <alg>/client-cert.pem --client-key <alg>/client-key.pem]
#
# Requires OpenSSL >= 3.5 (for ML-DSA). Re-run any time to regenerate.

set -eu

cd "$(dirname "$0")"

DAYS=3650

gen_leaf() {
    dir="$1"; role="$2"; subj="$3"; ext="$4"; shift 4
    # remaining args ($@) are the openssl genpkey algorithm options

    openssl genpkey "$@" -out "$dir/$role-key.pem"
    openssl req -new -key "$dir/$role-key.pem" -subj "$subj" \
        -out "$dir/$role.csr"

    extfile="$(mktemp)"
    printf '%s\n' "$ext" > "$extfile"
    printf 'basicConstraints=critical,CA:FALSE\n'        >> "$extfile"
    printf 'subjectKeyIdentifier=hash\n'                 >> "$extfile"
    printf 'authorityKeyIdentifier=keyid,issuer\n'       >> "$extfile"

    openssl x509 -req -in "$dir/$role.csr" \
        -CA "$dir/ca-cert.pem" -CAkey "$dir/ca-key.pem" -CAcreateserial \
        -days "$DAYS" -extfile "$extfile" -out "$dir/$role-cert.pem"

    rm -f "$extfile" "$dir/$role.csr" "$dir/ca-cert.srl"
}

gen_pki() {
    dir="$1"; label="$2"; shift 2
    # remaining args ($@) are the openssl genpkey algorithm options

    rm -rf "$dir"
    mkdir -p "$dir"

    # --- self-signed CA -------------------------------------------------
    openssl genpkey "$@" -out "$dir/ca-key.pem"
    openssl req -x509 -new -key "$dir/ca-key.pem" -days "$DAYS" \
        -subj "/CN=wolfCert Example $label CA" \
        -addext "basicConstraints=critical,CA:TRUE" \
        -addext "keyUsage=critical,keyCertSign,cRLSign" \
        -addext "subjectKeyIdentifier=hash" \
        -out "$dir/ca-cert.pem"

    # --- TLS server leaf (CN + SAN so hostname verification passes) -----
    # 10.0.2.2 is the QEMU SLIRP gateway, i.e. the host as seen from a Zephyr
    # guest, so the same leaf serves the emulator tests.
    gen_leaf "$dir" server "/CN=localhost" \
"subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1,IP:10.0.2.2
extendedKeyUsage=serverAuth" "$@"

    # --- mTLS client leaf ----------------------------------------------
    gen_leaf "$dir" client "/CN=wolfCert Example Client" \
"extendedKeyUsage=clientAuth" "$@"

    echo "generated $dir/  ($label)"
}

gen_pki ecc   "ECC P-256" -algorithm EC -pkeyopt ec_paramgen_curve:P-256
gen_pki mldsa "ML-DSA-65" -algorithm ML-DSA-65
