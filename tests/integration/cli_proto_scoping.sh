#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
#
# wolfcert-client rejects an option belonging to the other protocol, and
# validates the keyword arguments of the SCEP options, rather than accepting
# either and quietly doing nothing. Both were only ever checked by hand.
#
# Most cases here fail before any network access. The --ca-fingerprint pinning
# group is the exception: it starts wolfcert-server, and skips itself when that
# binary was not built.

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

# A wolfSSL built WOLFSSL_NO_MALLOC needs a static memory pool installed before
# anything can allocate, which the unit tests do and the CLI does not. There the
# binary cannot get past wolfcert_init, so there is nothing to assert about
# option scoping: skip rather than fail. 77 is the automake skip convention this
# repo already uses in tests/interop.
if "$CLI" getcacerts --proto scep --url "http://127.0.0.1:1/scep" 2>&1 \
        | grep -q "wolfcert_init failed"; then
    echo "SKIP: wolfcert-client cannot initialise in this build (no allocator)"
    exit 77
fi

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

# Repeat a string. seq(1) is not everywhere, and where it is missing the
# substitution collapses to an empty argument.
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

# Keyword arguments are validated rather than silently defaulted.
expect_reject "bogus --txid-mode"      "must be random or pubkey" \
    getcacerts --proto scep --url "$SCEP_URL" --txid-mode bogus
expect_reject "bogus --content-cipher" "must be auto, aes128, aes256" \
    getcacerts --proto scep --url "$SCEP_URL" --content-cipher rc4

# --challenge is deliberately NOT scoped: a challengePassword is legitimate in
# an EST CSR that /csrattrs asked for. It must get past option validation and
# fail on the network instead, which is what the unreachable port produces.
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

# --ca-fingerprint belongs to SCEP, and its argument is validated before any
# network access rather than at the point of use.
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

# A named non-default digest parses. It then fails on the unreachable port, or
# is refused by name on a wolfSSL built without that digest, but never as a
# syntax error.
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

# enroll carries a well-formed pin to the transport and reports the connection
# failure as itself. The stale-mismatch path needs more than one certificate.
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

# The pinning itself, end to end against the in-tree test server. wolfcert-server
# is built alongside wolfcert-client whenever the server is enabled; without it
# there is nothing to enroll against, so skip just this group.
SERVER="$(dirname "$CLI")/wolfcert-server"
if [ ! -x "$SERVER" ]; then
    echo "skip --ca-fingerprint pinning (wolfcert-server not built)"
else
    tmp="$(mktemp -d -t wolfcert-cli.XXXXXX)"
    srv_pid=""
    trap '[ -n "$srv_pid" ] && kill "$srv_pid" 2>/dev/null; rm -rf "$tmp"' EXIT

    # Not every sleep(1) takes a fractional delay. Poll in whole seconds where
    # it does not, keeping the same ten-second budget.
    if sleep 0.1 2>/dev/null; then
        poll_delay=0.1
        poll_tries=100
    else
        poll_delay=1
        poll_tries=10
    fi

    # A busy port is an environment problem, not a regression, so try a few and
    # poll GetCACert until the server has generated its CA and bound.
    ready=0
    for port in 18088 18188 18288 18388; do
        "$SERVER" --proto scep --listen "127.0.0.1:$port" --scep-enable-next-ca \
            >"$tmp/server.log" 2>&1 &
        srv_pid=$!
        PIN_URL="http://127.0.0.1:$port/scep"
        i=0
        while [ "$i" -lt "$poll_tries" ]; do
            if "$CLI" getcacerts --proto scep --url "$PIN_URL" \
                    --out-cert "$tmp/ca.pem" >"$tmp/getca.log" 2>&1; then
                ready=1
                break
            fi
            sleep "$poll_delay"
            i=$((i + 1))
        done
        if [ "$ready" -eq 1 ]; then
            break
        fi
        kill "$srv_pid" 2>/dev/null
    done

    # getcacerts reports the fingerprint an operator is meant to pin.
    fp="$(sed -n 's/.*\(sha256:[0-9A-Fa-f:]\{32,\}\).*/\1/p' "$tmp/getca.log" | head -1)"
    if [ "$ready" -ne 1 ]; then
        echo "skip --ca-fingerprint pinning (no test server would start)"
        cat "$tmp/server.log"
    elif [ -z "$fp" ]; then
        echo "FAIL: getcacerts printed no sha256 fingerprint to pin"
        cat "$tmp/getca.log"
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
fi

if [ "$fails" -ne 0 ]; then
    echo "$fails case(s) failed"
    exit 1
fi
echo "OK"
