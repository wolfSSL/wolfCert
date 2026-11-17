#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
#
# EST enrollment with keys in a TPM: examples/enroll_tpm against wolfTPM's
# fwTPM and wolfcert-server. Needs fwtpm_server in PATH (or FWTPM_SERVER) and
# a wolfCert build with examples on, found through WOLFCERT_BUILD.
#
# TPM_KEY_TYPES picks the key types (default: all the example knows).

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
. "$HERE/lib/common.sh"

FWTPM="${FWTPM_SERVER:-}"
if [ -z "$FWTPM" ]; then
    need fwtpm_server "Build wolfTPM with -DWOLFTPM_FWTPM=yes (scripts/ci/build-wolftpm.sh)"
    FWTPM="$(command -v fwtpm_server)"
fi
WC_SERVER="$(wolfcert_bin wolfcert-server)"
EXAMPLE="$WOLFCERT_BUILD/examples/example_enroll_tpm"
if [ ! -x "$EXAMPLE" ]; then
    echo "ERROR: $EXAMPLE not built; configure wolfCert with" \
         "-DWOLFCERT_ENABLE_EXAMPLES=ON and a wolfTPM with its CryptoCb" >&2
    exit 1
fi
KEY_TYPES="${TPM_KEY_TYPES:-ecc:256 ecc:384 rsa:2048 mldsa:44 mldsa:65 mldsa:87}"

cd "$WOLFCERT_INTEROP_WORK"
fw_pid=""
srv_pid=""
trap 'kill_if "$srv_pid"; kill_if "$fw_pid"; echo "--- work dir: $WOLFCERT_INTEROP_WORK"' EXIT

fails=0
checks=0
pass() { checks=$((checks + 1)); echo "ok   $1"; }
fail() {
    checks=$((checks + 1)); fails=$((fails + 1))
    echo "FAIL $1"
    [ -n "${2:-}" ] && [ -f "$2" ] && sed 's/^/     /' "$2"
    return 0
}

# The fwTPM also binds TPM_PORT + 1 for its platform port.
free_port_pair() {
    python3 -c '
import socket
while True:
    a = socket.socket(); a.bind(("127.0.0.1", 0)); p = a.getsockname()[1]
    b = socket.socket()
    try:
        b.bind(("127.0.0.1", p + 1))
    except OSError:
        a.close(); b.close(); continue
    a.close(); b.close(); print(p); break
'
}

TPM_PORT="$(free_port_pair)"
export TPM2_SWTPM_PORT="$TPM_PORT"

# start_fwtpm <nv-dir> [--clear]: without --clear a restart keeps the keys.
start_fwtpm() {
    local dir="$1"; shift
    mkdir -p "$dir"
    (cd "$dir" && exec "$FWTPM" "$@" --port "$TPM_PORT" \
        --platform-port $((TPM_PORT + 1))) >>fwtpm.log 2>&1 &
    fw_pid=$!
    wait_port 127.0.0.1 "$TPM_PORT"
}

stop_fwtpm() {
    kill_if "$fw_pid"
    fw_pid=""
}

TRUST="$REPO/examples/certs/ecc/ca-cert.pem"
mkdir -m 0700 ca

start_est() {
    "$WC_SERVER" --proto est --listen "127.0.0.1:$EST_PORT" \
        --tls-cert "$REPO/examples/certs/ecc/server-cert.pem" \
        --tls-key "$REPO/examples/certs/ecc/server-key.pem" \
        --est-allow-anonymous --ca-dir ca --tls-trust-issued \
        >>est.log 2>&1 &
    srv_pid=$!
    wait_port 127.0.0.1 "$EST_PORT"
    kill -0 "$srv_pid" 2>/dev/null || { cat est.log >&2; exit 1; }
}

# ex <log> <args...>: run the example, output to <log>; returns its status.
ex() {
    local log="$1"; shift
    "$EXAMPLE" "$@" >"$log" 2>&1
}

# The fwTPM keeps 8 persistent objects, so each key type gets its own NV.
run_type() {
    local kt="$1" t="${1/:/-}"
    local h0=0x81000100 h1=0x81000101 h2=0x81000102

    start_fwtpm "tpm-$t" --clear
    if ex "$t-enroll.log" enroll "$URL" "$TRUST" "CN=tpm-$t" "$kt" "$h0" "$t-0.crt" &&
            grep -q "BEGIN CERTIFICATE" "$t-0.crt"; then
        pass "$kt: enroll at $h0"
    else
        fail "$kt: enroll at $h0" "$t-enroll.log"
        stop_fwtpm
        return 0
    fi

    if ! ex "$t-busy.log" enroll "$URL" "$TRUST" "CN=tpm-$t" "$kt" "$h0" "$t-x.crt" &&
            grep -q "needs a free persistent handle" "$t-busy.log"; then
        pass "$kt: occupied handle refused"
    else
        fail "$kt: occupied handle refused" "$t-busy.log"
    fi

    if ! ex "$t-dead.log" enroll "https://127.0.0.1:1/.well-known/est" "$TRUST" \
            "CN=tpm-$t" "$kt" "$h2" "$t-x.crt" &&
            ex "$t-after-dead.log" enroll "$URL" "$TRUST" "CN=tpm-$t" "$kt" "$h2" \
                "$t-2.crt"; then
        pass "$kt: a failed enroll leaves the handle free"
    else
        fail "$kt: a failed enroll leaves the handle free" "$t-after-dead.log"
    fi

    # Keys and CA survive a restart of both the fwTPM and the EST server.
    stop_fwtpm
    kill_if "$srv_pid"; srv_pid=""
    start_fwtpm "tpm-$t"
    start_est

    cp "$t-0.crt" "$t-before.crt"
    if ex "$t-renew.log" reenroll "$URL" "$TRUST" "$kt" "$h0" "$t-0.crt" "$t-0.crt" &&
            ! cmp -s "$t-0.crt" "$t-before.crt" &&
            grep -q "BEGIN CERTIFICATE" "$t-0.crt" && [ ! -e "$t-0.crt.tmp" ]; then
        pass "$kt: renew in place after a restart"
    else
        fail "$kt: renew in place after a restart" "$t-renew.log"
    fi

    if ! ex "$t-ro.log" reenroll "$URL" "$TRUST" "$kt" "$h0" "$t-0.crt" notadir/x.crt "$h1" &&
            grep -q "revoke this certificate, its key is evicted" "$t-ro.log"; then
        pass "$kt: unwritable rekey shows the certificate, evicts the new key"
    else
        fail "$kt: unwritable rekey shows the certificate, evicts the new key" "$t-ro.log"
    fi

    if ex "$t-rekey.log" reenroll "$URL" "$TRUST" "$kt" "$h0" "$t-0.crt" "$t-1.crt" "$h1" &&
            grep -q "old key at TPM handle $h0 evicted" "$t-rekey.log"; then
        pass "$kt: rekey to $h1 evicts $h0"
    else
        fail "$kt: rekey to $h1 evicts $h0" "$t-rekey.log"
    fi

    if ! ex "$t-gone.log" reenroll "$URL" "$TRUST" "$kt" "$h0" "$t-0.crt" "$t-x.crt"; then
        pass "$kt: the evicted key cannot renew"
    else
        fail "$kt: the evicted key cannot renew" "$t-gone.log"
    fi

    if ex "$t-renew1.log" reenroll "$URL" "$TRUST" "$kt" "$h1" "$t-1.crt" "$t-1b.crt"; then
        pass "$kt: the rotated key renews"
    else
        fail "$kt: the rotated key renews" "$t-renew1.log"
    fi

    if ! ex "$t-down.log" reenroll "$URL" "$TRUST" "$kt" "$h1" "$t-1.crt" "$t-x.crt" \
            0x80000000 && grep -q "NEW_HANDLE must be persistent" "$t-down.log"; then
        pass "$kt: a persistent key does not rotate to a transient one"
    else
        fail "$kt: a persistent key does not rotate to a transient one" "$t-down.log"
    fi
    stop_fwtpm
}

# A transient key lives until the fwTPM restarts; it has no resource manager.
run_transient() {
    local kt="$1" t="${1/:/-}-tr" th

    start_fwtpm "tpm-$t" --clear
    if ex "$t.log" enroll "$URL" "$TRUST" "CN=tpm-$t" "$kt" 0x80000000 "$t.crt"; then
        th="$(sed -n 's/^enrolled: key in TPM handle \(0x[0-9a-f]*\),.*/\1/p' "$t.log")"
        pass "$kt: enroll under 0x80000000 (got $th)"
        if ex "$t-renew.log" reenroll "$URL" "$TRUST" "$kt" "$th" "$t.crt" "$t-2.crt"; then
            pass "$kt: another process renews the transient key"
        else
            fail "$kt: another process renews the transient key" "$t-renew.log"
        fi
    else
        fail "$kt: enroll under 0x80000000" "$t.log"
    fi
    if ! ex "$t-other.log" enroll "$URL" "$TRUST" "CN=tpm-$t" "$kt" 0x80000001 "$t-x.crt"; then
        pass "$kt: a transient handle other than 0x80000000 is refused"
    else
        fail "$kt: a transient handle other than 0x80000000 is refused" "$t-other.log"
    fi
    stop_fwtpm
}

# A write under a regular file fails even for root.
: >notadir
start_fwtpm tpm-probe --clear
# Picked while the fwTPM holds both of its ports.
EST_PORT="$(free_port)"
URL="https://127.0.0.1:$EST_PORT/.well-known/est"
stop_fwtpm
start_est

for kt in $KEY_TYPES; do
    run_type "$kt"
done
run_transient "${KEY_TYPES%% *}"

echo "$checks checks, $fails failures"
[ "$fails" -eq 0 ]
