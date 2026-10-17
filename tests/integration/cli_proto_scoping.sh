#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
#
# wolfcert-client rejects options of the other protocol and validates the SCEP
# keyword arguments. The --ca-fingerprint pinning and server argv groups start
# wolfcert-server; they fail when the build passed WOLFCERT_SERVER and the
# server cannot start, and skip otherwise.

set -u

# CMake passes the built binary as $1. Automake's test harness passes no
# arguments, so it exports WOLFCERT_CLI instead.
CLI="${1:-${WOLFCERT_CLI:-}}"
if [ -z "$CLI" ]; then
    echo "usage: cli_proto_scoping.sh /path/to/wolfcert-client" >&2
    echo "       (or set WOLFCERT_CLI)" >&2
    exit 1
fi
fails=0

# The CLI installs no static pool, so it cannot initialise on WOLFSSL_NO_MALLOC.
probe="$("$CLI" getcacerts --proto scep --url "http://127.0.0.1:1/scep" 2>&1)"
case "$probe" in
    *"wolfcert_init failed"*)
        echo "SKIP: wolfcert-client cannot initialise in this build (no allocator)"
        exit 77 ;;
esac

# expect_reject <description> <substring the message must contain> <args...>
expect_reject() {
    local what="$1"; shift
    local want="$1"; shift
    local out rc
    out="$("$CLI" "$@" 2>&1)"
    rc=$?
    if [ "$rc" -eq 0 ]; then
        echo "FAIL: $what was accepted (exit 0)"
        fails=$((fails + 1))
        return
    fi
    case "$out" in
        *"$want"*) echo "ok   $what" ;;
        *)
            echo "FAIL: $what rejected, but not for the expected reason"
            echo "      wanted substring: $want"
            echo "      got: $out"
            fails=$((fails + 1))
            ;;
    esac
}

# Repeat a string; seq(1) is not everywhere.
rep() {
    local i=0
    while [ "$i" -lt "$2" ]; do
        printf '%s' "$1"
        i=$((i + 1))
    done
}

EST_URL="https://127.0.0.1:1/.well-known/est"
SCEP_URL="http://127.0.0.1:1/scep"

# EST-only options must be refused under SCEP.
expect_reject "--user under scep"  "EST-only" \
    getcacerts --proto scep --url "$SCEP_URL" --user alice --pass hunter2
expect_reject "--pha under scep"   "EST-only" \
    getcacerts --proto scep --url "$SCEP_URL" --pha
expect_reject "--csrattrs-auto under scep" "EST-only" \
    getcacerts --proto scep --url "$SCEP_URL" --csrattrs-auto

# SCEP-only options must be refused under EST.
expect_reject "--ca-id under est"          "SCEP-only" \
    getcacerts --proto est --url "$EST_URL" --ca-id MyCA
expect_reject "--txid-mode under est"      "SCEP-only" \
    getcacerts --proto est --url "$EST_URL" --txid-mode pubkey
expect_reject "--content-cipher under est" "SCEP-only" \
    getcacerts --proto est --url "$EST_URL" --content-cipher aes256
expect_reject "--serial under est"          "SCEP-only" \
    getcacerts --proto est --url "$EST_URL" --serial 4B3A

# getcert is SCEP-only, and --serial is validated before any network access.
expect_reject "getcert under est"      "only --proto scep" \
    getcert --proto est --url "$EST_URL" --cert /dev/null --key /dev/null
expect_reject "getcert without --serial" "--serial required" \
    getcert --proto scep --url "$SCEP_URL" --cert /dev/null --key /dev/null
expect_reject "odd-length --serial"    "even number" \
    getcert --proto scep --url "$SCEP_URL" --cert /dev/null --key /dev/null \
    --serial abc
expect_reject "non-hex --serial"       "non-hex" \
    getcert --proto scep --url "$SCEP_URL" --cert /dev/null --key /dev/null \
    --serial zz
expect_reject "over-long --serial"     "20 octets" \
    getcert --proto scep --url "$SCEP_URL" --cert /dev/null --key /dev/null \
    --serial "$(rep 42 21)"

# reenroll authenticates TLS with --cert/--key, so a separate identity is refused.
expect_reject "reenroll with --client-cert" "--client-cert/--client-key are not used" \
    reenroll --proto est --url "$EST_URL" --cert /dev/null \
    --key /dev/null --client-cert /dev/null --client-key /dev/null

# reenroll refuses --subject and --san-*.
expect_reject "reenroll with --subject" "--subject/--san-* are not used" \
    reenroll --proto est --url "$EST_URL" --subject CN=x --cert /dev/null \
    --key /dev/null
for san in --san-dns --san-ip --san-uri --san-email; do
    expect_reject "reenroll with $san" "--subject/--san-* are not used" \
        reenroll --proto est --url "$EST_URL" "$san" x --cert /dev/null \
        --key /dev/null
done

# 20 octets is the RFC 5280 maximum and must get past parse_serial.
out="$("$CLI" getcert --proto scep --url "$SCEP_URL" \
        --cert /dev/null --key /dev/null --serial "$(rep 42 20)" 2>&1)"
case "$out" in
    *"20 octets"*|*non-hex*|*"even number"*)
        echo "FAIL: a 20-octet --serial was rejected by parse_serial"
        echo "      got: $out"
        fails=$((fails + 1))
        ;;
    *)  echo "ok   20-octet --serial accepted" ;;
esac

# Keyword arguments are validated rather than silently defaulted.
expect_reject "bogus --txid-mode"      "must be random or pubkey" \
    getcacerts --proto scep --url "$SCEP_URL" --txid-mode bogus
expect_reject "bogus --content-cipher" "must be auto, aes128, aes256" \
    getcacerts --proto scep --url "$SCEP_URL" --content-cipher rc4

# --challenge is not scoped, since /csrattrs can ask for a challengePassword in
# an EST CSR.
out="$("$CLI" enroll --proto est --url "$EST_URL" --subject "CN=x" \
        --challenge secret --out-key /dev/null --out-cert /dev/null 2>&1)"
case "$out" in
    *EST-only*|*SCEP-only*)
        echo "FAIL: --challenge was scoped to one protocol"
        echo "      got: $out"
        fails=$((fails + 1))
        ;;
    *)  echo "ok   --challenge accepted under est" ;;
esac

# --ca-fingerprint is SCEP-only and validated before any network access.
expect_reject "--ca-fingerprint under est" "SCEP-only" \
    getcacerts --proto est --url "$EST_URL" \
    --ca-fingerprint sha256:0000000000000000000000000000000000000000000000000000000000000000
expect_reject "odd-length --ca-fingerprint" "even number" \
    getcacerts --proto scep --url "$SCEP_URL" --ca-fingerprint abc
expect_reject "non-hex --ca-fingerprint" "non-hex" \
    getcacerts --proto scep --url "$SCEP_URL" \
    --ca-fingerprint 00000000000000000000000000000000000000000000000000000000000000zz
expect_reject "unknown --ca-fingerprint digest" "must be sha256, sha1 or sha512" \
    getcacerts --proto scep --url "$SCEP_URL" \
    --ca-fingerprint md5:00000000000000000000000000000000
expect_reject "sha256 --ca-fingerprint of the wrong length" "needs 32 bytes" \
    getcacerts --proto scep --url "$SCEP_URL" \
    --ca-fingerprint sha256:0000000000000000000000000000000000000000
expect_reject "over-long --ca-fingerprint" "longer than any supported digest" \
    getcacerts --proto scep --url "$SCEP_URL" \
    --ca-fingerprint "sha512:$(rep 0 200)"
expect_reject "--ra-fingerprint under est" "SCEP-only" \
    getcacerts --proto est --url "$EST_URL" --ra-fingerprint "sha256:$(rep 0 64)"
expect_reject "--ra-fingerprint without --ca-fingerprint" "needs --ca-fingerprint" \
    getcacerts --proto scep --url "$SCEP_URL" --ra-fingerprint "sha256:$(rep 0 64)"
expect_reject "odd-length --ra-fingerprint" "--ra-fingerprint needs an even number" \
    getcacerts --proto scep --url "$SCEP_URL" \
    --ca-fingerprint "sha256:$(rep 0 64)" --ra-fingerprint abc
expect_reject "getnextca with --ra-fingerprint" "does not apply" \
    getnextca --proto scep --url "$SCEP_URL" \
    --ca-fingerprint "sha256:$(rep 0 64)" --ra-fingerprint "sha256:$(rep 0 64)"
z="sha256:$(rep 0 64)"
expect_reject "five --ra-fingerprint values" "takes at most 4 values" \
    getcacerts --proto scep --url "$SCEP_URL" --ca-fingerprint "$z" \
    --ra-fingerprint "$z" --ra-fingerprint "$z" --ra-fingerprint "$z" \
    --ra-fingerprint "$z" --ra-fingerprint "$z"

# A named non-default digest may fail on the network or as unsupported, but
# never as a syntax error.
expect_parses() {
    local what="$1"; shift
    local out
    out="$("$CLI" getcacerts --proto scep --url "$SCEP_URL" \
            --ca-fingerprint "$1" 2>&1)"
    case "$out" in
        *"must be sha256"*|*"non-hex"*|*"even number"*|*"needs "*)
            echo "FAIL: a valid $what --ca-fingerprint was rejected as malformed"
            echo "      got: $out"
            fails=$((fails + 1))
            ;;
        *)  echo "ok   $what --ca-fingerprint parses" ;;
    esac
}
expect_parses sha512 "sha512:$(rep 0 128)"
expect_parses sha1   "sha1:$(rep 0 40)"

# A well-formed pin leaves a connection failure reported as such.
GOOD_FP="sha256:$(rep 1 64)"
out="$("$CLI" enroll --proto scep --url "$SCEP_URL" --key-type rsa:2048 \
        --subject "CN=x" --ca-fingerprint "$GOOD_FP" \
        --out-key /dev/null --out-cert /dev/null 2>&1)"
rc=$?
if [ "$rc" -eq 0 ]; then
    echo "FAIL: enroll against an unreachable port succeeded"
    fails=$((fails + 1))
else
    case "$out" in
        *"fingerprint mismatch"*)
            echo "FAIL: a connection failure was reported as a fingerprint mismatch"
            echo "      got: $out"
            fails=$((fails + 1))
            ;;
        *)  echo "ok   enroll accepts a well-formed --ca-fingerprint" ;;
    esac
fi

# Credentials on the client command line must not stay visible to ps. The client
# parks opening a --trust FIFO that nobody writes, well after option parsing.
ctmp="$(mktemp -d -t wolfcert-argv.XXXXXX)"
mkfifo "$ctmp/trust"
"$CLI" enroll --proto est --url "$EST_URL" --trust "$ctmp/trust" \
    --subject CN=argv --user argvuser --pass argv-client-pass \
    --challenge argv-client-challenge >/dev/null 2>&1 &
cargv_pid=$!
trap 'kill "$cargv_pid" 2>/dev/null; rm -rf "$ctmp"' EXIT
i=0
args=""
while [ "$i" -lt 10 ]; do
    args="$(ps -ww -o args= -p "$cargv_pid")"
    case "$args" in
        *argv-client-pass*|*argv-client-challenge*) ;;
        *--trust*) break ;;
    esac
    sleep 1
    i=$((i + 1))
done
case "$args" in
    *argv-client-pass*|*argv-client-challenge*)
        echo "FAIL: client secrets still visible in ps: $args"
        fails=$((fails + 1))
        ;;
    *--trust*)  echo "ok   client scrubs --pass and --challenge from argv" ;;
    *)
        echo "FAIL: client did not stay parked on the --trust FIFO"
        fails=$((fails + 1))
        ;;
esac
kill "$cargv_pid" 2>/dev/null
rm -rf "$ctmp"

SERVER="${WOLFCERT_SERVER:-$(dirname "$CLI")/wolfcert-server}"
server_required="${WOLFCERT_SERVER:+1}"
# Without an allocator the tools run out of memory, so a server cannot start.
case "$probe" in *"out of memory"*) server_required="" ;; esac

# skip_group <description>: a FAIL when the build provided the server.
skip_group() {
    if [ -n "$server_required" ]; then
        echo "FAIL: $1"
        fails=$((fails + 1))
    else
        echo "skip $1"
    fi
}

# wolfcert-server refuses an EST listener that could not authenticate anyone.
# Any readable file passes as --tls-cert: these checks run before it is parsed.
expect_server_reject() {
    local saved="$CLI"
    CLI="$SERVER"
    expect_reject "$@"
    CLI="$saved"
}
if [ -x "$SERVER" ]; then
    expect_server_reject "est server with no client auth" "--est-allow-anonymous" \
        --proto est --tls-cert "$0" --tls-key "$0"
    for b in ":pw" "alice:" "alice"; do
        expect_server_reject "--basic $b" "non-empty USER:PASS" \
            --proto est --tls-cert "$0" --tls-key "$0" --basic "$b"
    done
    # $0 is no PEM, so start fails in TLS setup, before anything binds.
    out="$("$SERVER" --proto est --listen 127.0.0.1:0 --tls-cert "$0" \
            --tls-key "$0" --est-allow-anonymous 2>&1)"
    case "$out" in
        *"start failed"*)
            echo "ok   --est-allow-anonymous passes the auth check" ;;
        *)
            echo "FAIL: --est-allow-anonymous did not reach server start"
            echo "      got: $out"
            fails=$((fails + 1))
            ;;
    esac
fi
if [ ! -x "$SERVER" ]; then
    skip_group "--ca-fingerprint pinning (wolfcert-server not built)"
else
    tmp="$(mktemp -d -t wolfcert-cli.XXXXXX)"
    srv_pid=""
    ra_pid=""
    argv_pid=""
    est_pid=""
    caps_pid=""
    bundle_pid=""
    started_pid=""
    trap '[ -n "$started_pid" ] && kill "$started_pid" 2>/dev/null;
          [ -n "$srv_pid" ] && kill "$srv_pid" 2>/dev/null;
          [ -n "$ra_pid" ] && kill "$ra_pid" 2>/dev/null;
          [ -n "$est_pid" ] && kill "$est_pid" 2>/dev/null;
          [ -n "$caps_pid" ] && kill "$caps_pid" 2>/dev/null;
          [ -n "$bundle_pid" ] && kill "$bundle_pid" 2>/dev/null;
          [ -n "$argv_pid" ] && kill "$argv_pid" 2>/dev/null; rm -rf "$tmp"' EXIT

    # Not every sleep(1) takes a fractional delay.
    if sleep 0.1 2>/dev/null; then
        poll_delay=0.1
        poll_tries=100
    else
        poll_delay=1
        poll_tries=10
    fi

    # start_server <log> <server args...>: start wolfcert-server on a free port
    # and set started_pid, and port from its "listening on" line.
    start_server() {
        local log="$1" i=0
        shift
        port=""
        # The child's own truncation can land after the first read below.
        : >"$log"
        "$SERVER" --listen 127.0.0.1:0 "$@" >"$log" 2>&1 &
        started_pid=$!
        while [ "$i" -lt "$poll_tries" ] &&
                kill -0 "$started_pid" 2>/dev/null; do
            port="$(sed -n 's/.* listening on [0-9.]*:\([0-9]*\)$/\1/p' "$log")"
            [ -n "$port" ] && return 0
            sleep "$poll_delay"
            i=$((i + 1))
        done
        return 1
    }

    # start_scep_server <name> <server args...>: GetCACert into $tmp/<name>-*.
    start_scep_server() {
        local name="$1"
        shift
        ready=0
        url=""
        if start_server "$tmp/$name-server.log" --proto scep "$@"; then
            url="http://127.0.0.1:$port/scep"
            if "$CLI" getcacerts --proto scep --url "$url" \
                    --out-cert "$tmp/$name-ca.pem" \
                    >"$tmp/$name-getca.log" 2>&1; then
                ready=1
                return
            fi
        fi
        kill "$started_pid" 2>/dev/null
        wait "$started_pid" 2>/dev/null
    }

    # cert_fp <log> <index>: the pin getcacerts printed for that certificate.
    cert_fp() {
        sed -n "s/.*certificate $2 is \(sha256:[0-9A-Fa-f:]*\).*/\1/p" "$1"
    }

    start_scep_server pin --scep-enable-next-ca
    srv_pid=$started_pid
    PIN_URL="$url"

    # getcacerts reports the fingerprint an operator is meant to pin.
    fp="$(cert_fp "$tmp/pin-getca.log" 0)"
    if [ "$ready" -ne 1 ]; then
        skip_group "--ca-fingerprint pinning (no test server would start)"
        cat "$tmp/pin-server.log"
    elif [ -z "$fp" ]; then
        echo "FAIL: getcacerts printed no sha256 fingerprint to pin"
        cat "$tmp/pin-getca.log"
        fails=$((fails + 1))
    else
        echo "ok   getcacerts reports a sha256 fingerprint"

        # A pinned getcacerts writes only the certificate that matched.
        if "$CLI" getcacerts --proto scep --url "$PIN_URL" \
                --ca-fingerprint "$fp" --out-cert "$tmp/pinned.pem" \
                >"$tmp/pinned.log" 2>&1 &&
                [ "$(grep -c "BEGIN CERTIFICATE" "$tmp/pinned.pem")" = "1" ]; then
            echo "ok   pinned getcacerts writes one certificate"
        else
            echo "FAIL: pinned getcacerts did not write exactly the pinned cert"
            cat "$tmp/pinned.log"
            fails=$((fails + 1))
        fi

        ZERO=sha256:0000000000000000000000000000000000000000000000000000000000000000
        expect_reject "enroll with a mismatched --ca-fingerprint" \
            "does not match --ca-fingerprint" \
            enroll --proto scep --url "$PIN_URL" --key-type rsa:2048 \
            --subject "CN=pin-test" --ca-fingerprint "$ZERO" \
            --out-key "$tmp/bad.key" --out-cert "$tmp/bad.crt"

        if "$CLI" enroll --proto scep --url "$PIN_URL" --key-type rsa:2048 \
                --subject "CN=pin-test" --ca-fingerprint "$fp" \
                --out-key "$tmp/ok.key" --out-cert "$tmp/ok.crt" \
                >"$tmp/enroll.log" 2>&1 &&
                grep -q "BEGIN CERTIFICATE" "$tmp/ok.crt"; then
            echo "ok   enroll with the pinned --ca-fingerprint"
        else
            echo "FAIL: enroll rejected the CA it was correctly pinned to"
            cat "$tmp/enroll.log"
            fails=$((fails + 1))
        fi

        if "$CLI" reenroll --proto scep --url "$PIN_URL" \
                --ca-fingerprint "$fp" --cert "$tmp/ok.crt" \
                --key "$tmp/ok.key" --out-cert "$tmp/renewed.crt" \
                >"$tmp/reenroll.log" 2>&1 &&
                grep -q "BEGIN CERTIFICATE" "$tmp/renewed.crt" &&
                ! cmp -s "$tmp/ok.crt" "$tmp/renewed.crt"; then
            echo "ok   SCEP reenroll renews the pinned enrollment"
        else
            echo "FAIL: SCEP reenroll did not renew the certificate"
            cat "$tmp/reenroll.log"
            fails=$((fails + 1))
        fi

        awk '/^-----BEGIN/ { f = 1; next } /^-----END/ { exit } f' \
            "$tmp/renewed.crt" | base64 --decode >"$tmp/renewed.der"
        if "$CLI" reenroll --proto scep --url "$PIN_URL" \
                --ca-fingerprint "$fp" --cert "$tmp/renewed.der" \
                --key "$tmp/ok.key" --out-cert "$tmp/renewed-der.crt" \
                >"$tmp/reenroll-der.log" 2>&1 &&
                grep -q "BEGIN CERTIFICATE" "$tmp/renewed-der.crt"; then
            echo "ok   SCEP reenroll takes a DER --cert"
        else
            echo "FAIL: SCEP reenroll with a DER --cert"
            cat "$tmp/reenroll-der.log"
            fails=$((fails + 1))
        fi

        { printf ' 0 s:CN=ok\n'; cat "$tmp/renewed.crt"; } \
            >"$tmp/renewed-pre.crt"
        { printf '\n '; cat "$tmp/renewed.der"; } >"$tmp/renewed-ws.der"
        { cat "$tmp/renewed.der"; printf '\n'; } >"$tmp/renewed-nl.der"
        for f in renewed-pre.crt renewed-ws.der renewed-nl.der; do
            if "$CLI" reenroll --proto scep --url "$PIN_URL" \
                    --ca-fingerprint "$fp" --cert "$tmp/$f" \
                    --key "$tmp/ok.key" --out-cert "$tmp/$f.out" \
                    >"$tmp/reenroll-$f.log" 2>&1 &&
                    grep -q "BEGIN CERTIFICATE" "$tmp/$f.out"; then
                echo "ok   SCEP reenroll takes --cert $f"
            else
                echo "FAIL: SCEP reenroll with --cert $f"
                cat "$tmp/reenroll-$f.log"
                fails=$((fails + 1))
            fi
        done

        # EST reenroll presents --cert as the TLS client certificate too, so it
        # renews against an mTLS server whose TLS identity this CA issued.
        est_ready=0
        if "$CLI" enroll --proto scep --url "$PIN_URL" --key-type rsa:2048 \
                --subject "CN=localhost" --san-ip 127.0.0.1 \
                --ca-fingerprint "$fp" --out-key "$tmp/tls.key" \
                --out-cert "$tmp/tls.crt" >"$tmp/tls-enroll.log" 2>&1; then
            start_server "$tmp/est-server.log" --proto est \
                --tls-cert "$tmp/tls.crt" --tls-key "$tmp/tls.key" \
                --tls-client-ca "$tmp/pin-ca.pem"
            est_pid=$started_pid
            est_url="https://127.0.0.1:$port/.well-known/est"
            if [ -n "$port" ] &&
                    "$CLI" getcacerts --proto est --url "$est_url" \
                        --trust "$tmp/pin-ca.pem" \
                        --client-cert "$tmp/ok.crt" \
                        --client-key "$tmp/ok.key" \
                        --out-cert "$tmp/est-ca.pem" \
                        >"$tmp/est-getca.log" 2>&1; then
                est_ready=1
            fi
        fi
        if [ "$est_ready" -ne 1 ]; then
            skip_group "EST reenroll --cert forms (no mTLS server would start)"
            cat "$tmp/tls-enroll.log" "$tmp/est-server.log" 2>/dev/null
        else
            for f in renewed.crt renewed-pre.crt renewed-ws.der renewed-nl.der; do
                if "$CLI" reenroll --proto est --url "$est_url" \
                        --trust "$tmp/pin-ca.pem" --cert "$tmp/$f" \
                        --key "$tmp/ok.key" --out-cert "$tmp/est-$f.out" \
                        >"$tmp/est-reenroll-$f.log" 2>&1 &&
                        grep -q "BEGIN CERTIFICATE" "$tmp/est-$f.out"; then
                    echo "ok   EST reenroll takes --cert $f"
                else
                    echo "FAIL: EST reenroll with --cert $f"
                    cat "$tmp/est-reenroll-$f.log"
                    fails=$((fails + 1))
                fi
            done
        fi
        kill "$est_pid" 2>/dev/null
        est_pid=""

        # getnextca resolves the current CA through the same pin.
        expect_reject "getnextca with a mismatched --ca-fingerprint" \
            "does not match --ca-fingerprint" \
            getnextca --proto scep --url "$PIN_URL" --ca-fingerprint "$ZERO" \
            --out-cert "$tmp/bad-next.pem"

        if "$CLI" getnextca --proto scep --url "$PIN_URL" \
                --ca-fingerprint "$fp" --out-cert "$tmp/next.pem" \
                >"$tmp/getnext.log" 2>&1 &&
                grep -q "BEGIN CERTIFICATE" "$tmp/next.pem"; then
            echo "ok   getnextca with the pinned --ca-fingerprint"
        else
            echo "FAIL: getnextca rejected the CA it was correctly pinned to"
            cat "$tmp/getnext.log"
            fails=$((fails + 1))
        fi
    fi

    # Against a split CA/RA server that defers issuance, the RA counts only once
    # --ra-fingerprint names it; pinning the RA alone ignores the CA.
    poll="--poll-attempts 5 --poll-interval-ms 100"
    start_scep_server ra --scep-split-ra --scep-require-approval \
        --scep-enable-next-ca --scep-enable-get-cert
    ra_pid=$started_pid
    RA_URL="$url"

    ra_fp="$(cert_fp "$tmp/ra-getca.log" 0)"
    ca_fp="$(cert_fp "$tmp/ra-getca.log" 1)"
    if [ "$ready" -ne 1 ]; then
        skip_group "split CA/RA pinning (no test server would start)"
        cat "$tmp/ra-server.log"
    elif [ -z "$ra_fp" ] || [ -z "$ca_fp" ]; then
        echo "FAIL: getcacerts did not list the RA and the CA"
        cat "$tmp/ra-getca.log"
        fails=$((fails + 1))
    else
        if "$CLI" getcacerts --proto scep --url "$RA_URL" \
                --ca-fingerprint "$ca_fp" --out-cert "$tmp/ra-pinned.pem" \
                >"$tmp/ra-pinned.log" 2>&1 &&
                grep -q "only --ra-fingerprint admits" "$tmp/ra-pinned.log" &&
                [ "$(grep -c "BEGIN CERTIFICATE" "$tmp/ra-pinned.pem")" = "1" ]; then
            echo "ok   CA-pinned getcacerts writes only the CA"
        else
            echo "FAIL: CA-pinned getcacerts did not write only the CA"
            cat "$tmp/ra-pinned.log"
            fails=$((fails + 1))
        fi

        expect_reject "enroll through the RA with only the CA pinned" \
            "only --ra-fingerprint admits" \
            enroll --proto scep --url "$RA_URL" --key-type rsa:2048 \
            --subject "CN=ra-test" --ca-fingerprint "$ca_fp" $poll \
            --out-key "$tmp/ra-ca.key" --out-cert "$tmp/ra-ca.crt"

        if "$CLI" enroll --proto scep --url "$RA_URL" --key-type rsa:2048 \
                --subject "CN=ra-test" --ca-fingerprint "$ca_fp" \
                --ra-fingerprint "$ra_fp" $poll \
                --out-key "$tmp/ra-ok.key" --out-cert "$tmp/ra-ok.crt" \
                >"$tmp/ra-enroll.log" 2>&1 &&
                grep -q "BEGIN CERTIFICATE" "$tmp/ra-ok.crt"; then
            echo "ok   enroll through the RA with the CA and RA pinned"
        else
            echo "FAIL: enroll with the CA and RA pinned"
            cat "$tmp/ra-enroll.log"
            fails=$((fails + 1))
        fi

        if "$CLI" reenroll --proto scep --url "$RA_URL" $poll \
                --ca-fingerprint "$ca_fp" --ra-fingerprint "$ra_fp" \
                --cert "$tmp/ra-ok.crt" --key "$tmp/ra-ok.key" \
                --out-cert "$tmp/ra-renewed.crt" >"$tmp/ra-reenroll.log" 2>&1 &&
                grep -q "BEGIN CERTIFICATE" "$tmp/ra-renewed.crt"; then
            echo "ok   SCEP reenroll through the RA with the CA and RA pinned"
        else
            echo "FAIL: SCEP reenroll through the RA"
            cat "$tmp/ra-reenroll.log"
            fails=$((fails + 1))
        fi

        if "$CLI" enroll --proto scep --url "$RA_URL" --key-type rsa:2048 \
                --subject "CN=ra-test" --ca-fingerprint "$ra_fp" $poll \
                --out-key "$tmp/ra-ra.key" --out-cert "$tmp/ra-ra.crt" \
                >"$tmp/ra-ra.log" 2>&1 &&
                grep -q "ignoring 1 of 2.*--ca-fingerprint does not name" \
                    "$tmp/ra-ra.log" &&
                grep -q "BEGIN CERTIFICATE" "$tmp/ra-ra.crt"; then
            echo "ok   enroll with the RA pinned ignores the CA"
        else
            echo "FAIL: enroll with the RA pinned"
            cat "$tmp/ra-ra.log"
            fails=$((fails + 1))
        fi

        if "$CLI" getcacerts --proto scep --url "$RA_URL" \
                --ca-fingerprint "$ca_fp" --ra-fingerprint "$ra_fp" \
                --ra-fingerprint "$ra_fp" \
                --out-cert "$tmp/ra-both.pem" >"$tmp/ra-both.log" 2>&1 &&
                [ "$(grep -c "BEGIN CERTIFICATE" "$tmp/ra-both.pem")" = "2" ]; then
            echo "ok   getcacerts with the CA and the RA pinned twice writes both"
        else
            echo "FAIL: getcacerts with the CA and RA pinned"
            cat "$tmp/ra-both.log"
            fails=$((fails + 1))
        fi

        if "$CLI" getcert --proto scep --url "$RA_URL" \
                --ca-fingerprint "$ca_fp" --ra-fingerprint "$ra_fp" \
                --cert "$tmp/ra-ok.crt" --key "$tmp/ra-ok.key" --serial 01 \
                --out-cert "$tmp/ra-got.crt" >"$tmp/ra-getcert.log" 2>&1 ||
                grep -q "no certificate with that serial" \
                    "$tmp/ra-getcert.log"; then
            echo "ok   getcert through the RA with the CA and RA pinned"
        else
            echo "FAIL: getcert through the RA with the CA and RA pinned"
            cat "$tmp/ra-getcert.log"
            fails=$((fails + 1))
        fi

        if "$CLI" getnextca --proto scep --url "$RA_URL" \
                --ca-fingerprint "$ca_fp" --out-cert "$tmp/ra-next.pem" \
                >"$tmp/ra-next.log" 2>&1 &&
                ! grep -q "ignoring" "$tmp/ra-next.log"; then
            echo "ok   CA-pinned getnextca leaves the RA out without a note"
        else
            echo "FAIL: CA-pinned getnextca against the split RA"
            cat "$tmp/ra-next.log"
            fails=$((fails + 1))
        fi

        expect_reject "enroll with a mismatched --ra-fingerprint" \
            "matches --ra-fingerprint" \
            enroll --proto scep --url "$RA_URL" --key-type rsa:2048 \
            --subject "CN=ra-test" --ca-fingerprint "$ca_fp" \
            --ra-fingerprint "sha256:$(rep 0 64)" \
            --out-key "$tmp/ra-bad.key" --out-cert "$tmp/ra-bad.crt"

        expect_reject "--ra-fingerprint on a certificate the pin did not sign" \
            "was not signed by the pinned CA" \
            getcacerts --proto scep --url "$RA_URL" \
            --ca-fingerprint "$ra_fp" --ra-fingerprint "$ca_fp"

        if "$CLI" getcacerts --proto scep --url "$RA_URL" \
                --ca-fingerprint "$ca_fp" --ra-fingerprint "$ca_fp" \
                --out-cert "$tmp/ra-same.pem" >"$tmp/ra-same.log" 2>&1 &&
                [ "$(grep -c "BEGIN CERTIFICATE" "$tmp/ra-same.pem")" = "1" ]; then
            echo "ok   --ra-fingerprint naming the pinned CA writes only the CA"
        else
            echo "FAIL: --ra-fingerprint naming the pinned CA"
            cat "$tmp/ra-same.log"
            fails=$((fails + 1))
        fi
    fi
    kill "$ra_pid" 2>/dev/null
    ra_pid=""

    bundle_fp() {
        cert_fp "$tmp/bundle-getca.log" "$1"
    }

    # Each layout's envelope reaches the certificate that decrypts: the RA,
    # the issuing CA under its root, or the RSA CA past an ECC leaf.
    for layout in ras chain ecc tie expired; do
        split=""
        case "$layout" in
            ras|tie|expired) split="--scep-split-ra" ;;
        esac
        start_scep_server bundle $split --scep-ca-bundle "$layout"
        bundle_pid=$started_pid
        BUNDLE_URL="$url"

        if [ "$ready" -ne 1 ]; then
            if [ "$layout" = ecc ] &&
                    grep -q "scep-ca-bundle failed (unsupported)" \
                        "$tmp/bundle-server.log"; then
                echo "skip GetCACert ecc bundle (wolfSSL lacks ECC)"
            else
                skip_group "GetCACert $layout bundle (no server would start)"
                cat "$tmp/bundle-server.log"
            fi
            continue
        fi

        if [ "$layout" = ras ]; then
            if "$CLI" enroll --proto scep --url "$BUNDLE_URL" \
                    --key-type rsa:2048 --subject "CN=bundle-open" \
                    --out-key "$tmp/bundle-open.key" \
                    --out-cert "$tmp/bundle-open.crt" \
                    >"$tmp/bundle-open.log" 2>&1; then
                echo "ok   unpinned enroll envelopes to the keyEncipherment RA"
            else
                echo "FAIL: unpinned enroll missed the keyEncipherment RA"
                cat "$tmp/bundle-open.log"
                fails=$((fails + 1))
            fi

            if [ -n "$(bundle_fp 3)" ] && "$CLI" enroll --proto scep \
                    --url "$BUNDLE_URL" --key-type rsa:2048 \
                    --subject "CN=bundle-pinned" \
                    --ca-fingerprint "$(bundle_fp 3)" \
                    --ra-fingerprint "$(bundle_fp 0)" \
                    --ra-fingerprint "$(bundle_fp 1)" \
                    --ra-fingerprint "$(bundle_fp 2)" \
                    --out-key "$tmp/bundle-pinned.key" \
                    --out-cert "$tmp/bundle-pinned.crt" \
                    >"$tmp/bundle-pinned.log" 2>&1; then
                echo "ok   enroll with every RA pinned envelopes to the" \
                     "keyEncipherment RA"
            else
                echo "FAIL: enroll with every RA pinned"
                cat "$tmp/bundle-getca.log" "$tmp/bundle-pinned.log"
                fails=$((fails + 1))
            fi

            expect_reject "enroll with only the signing-only RA pinned" \
                "no certificate --ra-fingerprint names can receive" \
                enroll --proto scep --url "$BUNDLE_URL" --key-type rsa:2048 \
                --subject "CN=bundle-signer" \
                --ca-fingerprint "$(bundle_fp 3)" \
                --ra-fingerprint "$(bundle_fp 1)" \
                --out-key "$tmp/bundle-signer.key" \
                --out-cert "$tmp/bundle-signer.crt"
        elif [ "$layout" = tie ]; then
            expect_reject "unpinned enroll with two keyEncipherment RAs" \
                "more than one served certificate could receive the request" \
                enroll --proto scep --url "$BUNDLE_URL" --key-type rsa:2048 \
                --subject "CN=bundle-tie" --out-key "$tmp/bundle-tie.key" \
                --out-cert "$tmp/bundle-tie.crt"

            if [ -n "$(bundle_fp 2)" ] && "$CLI" enroll --proto scep \
                    --url "$BUNDLE_URL" --key-type rsa:2048 \
                    --subject "CN=bundle-tie-pinned" \
                    --ca-fingerprint "$(bundle_fp 2)" \
                    --ra-fingerprint "$(bundle_fp 1)" \
                    --out-key "$tmp/bundle-tie-pinned.key" \
                    --out-cert "$tmp/bundle-tie-pinned.crt" \
                    >"$tmp/bundle-tie-pinned.log" 2>&1; then
                echo "ok   --ra-fingerprint settles a keyEncipherment tie"
            else
                echo "FAIL: enroll with one of two tied RAs pinned"
                cat "$tmp/bundle-getca.log" "$tmp/bundle-tie-pinned.log"
                fails=$((fails + 1))
            fi
        elif [ "$layout" = expired ]; then
            expect_reject "--ra-fingerprint on an expired RA" \
                "was not signed by the pinned CA or is not valid now" \
                enroll --proto scep --url "$BUNDLE_URL" --key-type rsa:2048 \
                --subject "CN=bundle-expired" \
                --ca-fingerprint "$(bundle_fp 1)" \
                --ra-fingerprint "$(bundle_fp 0)" \
                --out-key "$tmp/bundle-expired.key" \
                --out-cert "$tmp/bundle-expired.crt"
        elif [ "$layout" = ecc ]; then
            if "$CLI" enroll --proto scep --url "$BUNDLE_URL" \
                    --key-type rsa:2048 --subject "CN=bundle-ecc" \
                    --out-key "$tmp/bundle-ecc.key" \
                    --out-cert "$tmp/bundle-ecc.crt" \
                    >"$tmp/bundle-ecc.log" 2>&1; then
                echo "ok   unpinned enroll skips an ECC leaf for the RSA CA"
            else
                echo "FAIL: unpinned enroll chose the ECC leaf"
                cat "$tmp/bundle-ecc.log"
                fails=$((fails + 1))
            fi
        else
            if "$CLI" enroll --proto scep --url "$BUNDLE_URL" \
                    --key-type rsa:2048 --subject "CN=bundle-chain" \
                    --out-key "$tmp/bundle-chain.key" \
                    --out-cert "$tmp/bundle-chain.crt" \
                    >"$tmp/bundle-chain.log" 2>&1; then
                echo "ok   unpinned enroll envelopes to the issuing CA, not" \
                     "its root"
            else
                echo "FAIL: unpinned enroll chose the root"
                cat "$tmp/bundle-chain.log"
                fails=$((fails + 1))
            fi

            if [ -n "$(bundle_fp 1)" ] && "$CLI" getcacerts --proto scep \
                    --url "$BUNDLE_URL" --ca-fingerprint "$(bundle_fp 1)" \
                    --out-cert "$tmp/bundle-ca.pem" \
                    >"$tmp/bundle-ca.log" 2>&1 &&
                    grep -q "which --ca-fingerprint does not name" \
                        "$tmp/bundle-ca.log"; then
                echo "ok   a CA pin ignores a served root without naming" \
                     "--ra-fingerprint"
            else
                echo "FAIL: a CA pin with a served root"
                cat "$tmp/bundle-getca.log" "$tmp/bundle-ca.log"
                fails=$((fails + 1))
            fi
        fi
        kill "$bundle_pid" 2>/dev/null
        wait "$bundle_pid" 2>/dev/null
        bundle_pid=""
    done

    # A non-200 GetCACaps warns and carries on; a dropped one stops enroll and
    # getcert with exit 2. AES is forced; NO_DES3 builds lack the 3DES default.
    for caps in 404 close; do
        start_scep_server caps --scep-enable-get-cert \
            --scep-caps-status "$caps"
        caps_pid=$started_pid
        CAPS_URL="$url"

        if [ "$ready" -ne 1 ]; then
            skip_group "GetCACaps $caps (no test server would start)"
            cat "$tmp/caps-server.log"
            continue
        fi

        "$CLI" enroll --proto scep --url "$CAPS_URL" --key-type rsa:2048 \
            --content-cipher aes128 \
            --subject "CN=caps-test" --out-key "$tmp/caps-$caps.key" \
            --out-cert "$tmp/caps-$caps.crt" >"$tmp/caps-enroll.log" 2>&1
        rc=$?
        if [ "$caps" = 404 ]; then
            if [ "$rc" -eq 0 ] &&
                    grep -q "enroll: GetCACaps failed, assuming" \
                        "$tmp/caps-enroll.log"; then
                echo "ok   enroll warns and carries on after a GetCACaps 404"
            else
                echo "FAIL: enroll after a GetCACaps 404 (exit $rc)"
                cat "$tmp/caps-enroll.log"
                fails=$((fails + 1))
            fi
        elif [ "$rc" -eq 2 ] &&
                grep -q "enroll: GetCACaps: " "$tmp/caps-enroll.log"; then
            echo "ok   enroll stops on a dropped GetCACaps"
        else
            echo "FAIL: enroll on a dropped GetCACaps (exit $rc)"
            cat "$tmp/caps-enroll.log"
            fails=$((fails + 1))
        fi

        if [ ! -s "$tmp/caps-404.crt" ]; then
            skip_group "getcert GetCACaps $caps (no enrolled signer)"
        else
            "$CLI" getcert --proto scep --url "$CAPS_URL" \
                --content-cipher aes128 \
                --cert "$tmp/caps-404.crt" --key "$tmp/caps-404.key" \
                --serial 01 --out-cert "$tmp/caps-got.crt" \
                >"$tmp/caps-getcert.log" 2>&1
            rc=$?
            if [ "$caps" = 404 ]; then
                if grep -q "getcert: GetCACaps failed, assuming" \
                        "$tmp/caps-getcert.log" &&
                        grep -q "no certificate with that serial" \
                        "$tmp/caps-getcert.log"; then
                    echo "ok   getcert reaches GetCert after a GetCACaps 404"
                else
                    echo "FAIL: getcert after a GetCACaps 404 (exit $rc)"
                    cat "$tmp/caps-getcert.log"
                    fails=$((fails + 1))
                fi

                awk '/^-----BEGIN/ { f = 1; next } /^-----END/ { exit } f' \
                    "$tmp/caps-404.crt" | base64 --decode >"$tmp/caps-404.der"
                printf '\n' >>"$tmp/caps-404.der"
                if "$CLI" getcert --proto scep --url "$CAPS_URL" \
                        --content-cipher aes128 \
                        --cert "$tmp/caps-404.der" --key "$tmp/caps-404.key" \
                        --serial 01 --out-cert "$tmp/caps-got-der.crt" \
                        >"$tmp/caps-getcert-der.log" 2>&1 ||
                        grep -q "no certificate with that serial" \
                            "$tmp/caps-getcert-der.log"; then
                    echo "ok   getcert takes a DER --cert with a trailing newline"
                else
                    echo "FAIL: getcert with a DER --cert"
                    cat "$tmp/caps-getcert-der.log"
                    fails=$((fails + 1))
                fi

                { printf ' 0 s:CN=caps\n'; cat "$tmp/caps-404.crt"; } \
                    >"$tmp/caps-404-pre.crt"
                if "$CLI" getcert --proto scep --url "$CAPS_URL" \
                        --content-cipher aes128 \
                        --cert "$tmp/caps-404-pre.crt" \
                        --key "$tmp/caps-404.key" \
                        --serial 01 --out-cert "$tmp/caps-got-pre.crt" \
                        >"$tmp/caps-getcert-pre.log" 2>&1 ||
                        grep -q "no certificate with that serial" \
                            "$tmp/caps-getcert-pre.log"; then
                    echo "ok   getcert takes a PEM --cert behind a '0' preamble"
                else
                    echo "FAIL: getcert with a PEM --cert behind a preamble"
                    cat "$tmp/caps-getcert-pre.log"
                    fails=$((fails + 1))
                fi
            elif [ "$rc" -eq 2 ] &&
                    grep -q "getcert: GetCACaps: " "$tmp/caps-getcert.log"; then
                echo "ok   getcert stops on a dropped GetCACaps"
            else
                echo "FAIL: getcert on a dropped GetCACaps (exit $rc)"
                cat "$tmp/caps-getcert.log"
                fails=$((fails + 1))
            fi
        fi

        if [ "$caps" = 404 ] && [ -s "$tmp/caps-404.crt" ]; then
            if "$CLI" reenroll --proto scep --url "$CAPS_URL" \
                    --content-cipher aes128 \
                    --cert "$tmp/caps-404.crt" --key "$tmp/caps-404.key" \
                    --out-cert "$tmp/caps-renewed.crt" \
                    >"$tmp/caps-reenroll.log" 2>&1 &&
                    grep -q "does not advertise Renewal, sending a PKCSReq" \
                        "$tmp/caps-reenroll.log" &&
                    grep -q "BEGIN CERTIFICATE" "$tmp/caps-renewed.crt"; then
                echo "ok   reenroll sends a PKCSReq after a GetCACaps 404"
            else
                echo "FAIL: reenroll after a GetCACaps 404"
                cat "$tmp/caps-reenroll.log"
                fails=$((fails + 1))
            fi
        fi
        kill "$caps_pid" 2>/dev/null
        wait "$caps_pid" 2>/dev/null
        caps_pid=""
    done

    # A hostname --listen is refused, and the reason reaches stderr.
    "$SERVER" --proto scep --listen localhost:0 >"$tmp/listen.log" 2>&1 &
    listen_pid=$!
    i=0
    while [ "$i" -lt "$poll_tries" ] && kill -0 "$listen_pid" 2>/dev/null; do
        sleep "$poll_delay"
        i=$((i + 1))
    done
    if kill -0 "$listen_pid" 2>/dev/null; then
        kill "$listen_pid" 2>/dev/null
        echo "FAIL: --listen localhost was accepted"
        fails=$((fails + 1))
    elif grep -q "not a numeric IPv4 address" "$tmp/listen.log"; then
        echo "ok   --listen localhost names the reason it was refused"
    else
        echo "FAIL: --listen localhost refused without the reason"
        cat "$tmp/listen.log"
        fails=$((fails + 1))
    fi

    # Secrets passed on the server command line must not stay visible to ps.
    listening=0
    if start_server "$tmp/argv.log" --proto scep \
            --basic argvuser:argv-basic-secret \
            --challenge argv-challenge-secret; then
        listening=1
    fi
    argv_pid=$started_pid

    if [ "$listening" -ne 1 ]; then
        skip_group "server argv scrubbing (no test server would start)"
        cat "$tmp/argv.log"
    else
        args="$(ps -ww -o args= -p "$argv_pid")"
        case "$args" in
            *argv-basic-secret*|*argv-challenge-secret*)
                echo "FAIL: server secrets still visible in ps: $args"
                fails=$((fails + 1))
                ;;
            *--basic*)
                echo "ok   server scrubs --basic and --challenge from argv" ;;
            *)
                echo "FAIL: could not read the server argv from ps: $args"
                fails=$((fails + 1))
                ;;
        esac
    fi
    kill "$argv_pid" 2>/dev/null
    argv_pid=""
fi

if [ "$fails" -ne 0 ]; then
    echo "$fails case(s) failed"
    exit 1
fi
echo "OK"
