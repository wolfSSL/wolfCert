#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Config-resolution gate: wolfCert's two public entry points must resolve the
# same wolfSSL feature set from the same flags.
#
#   <wolfcert/wolfcert.h>  -> memory.h -> types.h -> check_config.h
#   <wolfcert/est.h>       ->             types.h -> check_config.h
#
# Each case stages an <wolfssl/options.h> that disagrees with user_settings.h;
# docs/CI.md says why.
#
# Preprocess-only, so it wants a wolfSSL checkout for headers rather than a
# build, and finishes in seconds.
#
# Usage:
#   check-config-resolution.sh --wolfssl-src DIR [--cc CC] [CASE ...]
#
# Defaults: --cc cc (CC_BIN also overrides), every case.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"

CC_BIN="${CC_BIN:-cc}"
WOLFSSL_SRC=""
WANTED=""

while [ "$#" -gt 0 ]; do
    case "$1" in
        --wolfssl-src) WOLFSSL_SRC="$2"; shift 2 ;;
        --cc)          CC_BIN="$2";      shift 2 ;;
        -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        --*) echo "ERROR: unknown flag '$1'." >&2; exit 2 ;;
        *) WANTED="$WANTED $1"; shift ;;
    esac
done

if [ -z "$WOLFSSL_SRC" ]; then
    echo "ERROR: --wolfssl-src is required." >&2
    exit 2
fi
if [ ! -d "$WOLFSSL_SRC/wolfssl" ]; then
    echo "ERROR: '$WOLFSSL_SRC' does not look like a wolfSSL checkout." >&2
    exit 2
fi

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
mkdir -p "$STAGE/inc"

# Never a configured tree's own options.h: it describes that build, not the
# feature set each case pins here.
cp -R "$WOLFSSL_SRC/wolfssl" "$STAGE/inc/wolfssl"
rm -f "$STAGE/inc/wolfssl/options.h"

# poison satisfies nothing wolfCert requires, rich satisfies everything.
write_decoy() {
    {
        echo '#ifndef WOLFSSL_OPTIONS_H'
        echo '#define WOLFSSL_OPTIONS_H'
        echo '#define WOLFCERT_CI_DECOY_OPTIONS_H'
        if [ "$1" = "rich" ]; then
            for m in HAVE_PKCS7 WOLFSSL_CERT_GEN WOLFSSL_CERT_REQ \
                     WOLFSSL_CERT_EXT WOLFSSL_KEY_GEN WOLF_CRYPTO_CB \
                     WOLFSSL_BASE64_ENCODE WOLFSSL_ALT_NAMES \
                     WOLFSSL_CERT_NAME_ALL HAVE_SNI WOLFSSL_TLS13; do
                echo "#define $m"
            done
        fi
        echo '#endif'
    } > "$STAGE/inc/wolfssl/options.h"
}

# Preprocess one entry header into a sorted probe report.
probe() {
    local hdr="$1" out="$2" rc=0
    "$CC_BIN" -E -P "${CPP_ARGS[@]}" -D"WOLFCERT_PROBE_HEADER=<$hdr>" \
        "$HERE/config-probe.c" > "$out.raw" 2> "$out.err" || rc=$?
    grep -o 'wcprobe_[A-Za-z0-9_]*_is_[01]' "$out.raw" | sort -u > "$out.fp" || true
    echo "$rc" > "$out.rc"
}

# Compiler-independent diagnostic set: message text only.
norm_err() {
    sed -nE 's/^.*(error|fatal error): //p' "$1" | sed 's/[[:space:]]*$//' | sort -u
}

indent() { sed 's/^/        /'; }

# name : decoy : user_settings.h source : WOLFSSL_USER_SETTINGS : header forced
# ahead of wolfCert's ("-" for none) : macro appended to the staged
# user_settings.h, so it arrives from inside the file rather than the command
# line ("-" for none) : expectation
CASES="
usersettings-wins:poison:scripts/ci/freestanding-user_settings.h:on:-:-:agree-ok
optionsh-decoy:rich:scripts/ci/wolfcert-only-user_settings.h:on:-:-:agree-fail
optionsh-wins:rich:scripts/ci/wolfcert-only-user_settings.h:off:-:-:agree-ok-optionsh
wolfssl-header-first:rich:scripts/ci/wolfcert-only-user_settings.h:off:wolfssl/ssl.h:-:agree-fail-order
selector-in-user-settings:poison:scripts/ci/freestanding-user_settings.h:off:-:WOLFSSL_NO_OPTIONS_H:agree-ok
"

status=0
ran=0

for spec in $CASES; do
    name="${spec%%:*}"; rest="${spec#*:}"
    flavour="${rest%%:*}"; rest="${rest#*:}"
    us_src="${rest%%:*}"; rest="${rest#*:}"
    us_def="${rest%%:*}"; rest="${rest#*:}"
    preinc="${rest%%:*}"; rest="${rest#*:}"
    us_extra="${rest%%:*}"; expect="${rest#*:}"

    if [ -n "$WANTED" ]; then
        case " $WANTED " in *" $name "*) ;; *) continue ;; esac
    fi
    ran=$((ran + 1))

    write_decoy "$flavour"
    cp "$ROOT/$us_src" "$STAGE/inc/user_settings.h"
    if [ "$us_extra" != "-" ]; then
        echo "#define $us_extra" >> "$STAGE/inc/user_settings.h"
    fi

    CPP_ARGS=(-DWOLFCERT_USER_SETTINGS -I"$ROOT" -I"$STAGE/inc")
    if [ "$us_def" = "on" ]; then
        CPP_ARGS=(-DWOLFSSL_USER_SETTINGS "${CPP_ARGS[@]}")
    fi
    if [ "$preinc" != "-" ]; then
        CPP_ARGS+=(-include "$preinc")
    fi

    probe wolfcert/est.h      "$STAGE/est"
    probe wolfcert/wolfcert.h "$STAGE/umbrella"

    est_rc="$(cat "$STAGE/est.rc")"
    umb_rc="$(cat "$STAGE/umbrella.rc")"
    bad=0

    if [ "$est_rc" != "$umb_rc" ]; then
        echo "  FAIL  $name: the entry headers disagree on compilability"
        echo "          <wolfcert/est.h>      exit $est_rc"
        echo "          <wolfcert/wolfcert.h> exit $umb_rc"
        bad=1
    fi

    if ! diff -u "$STAGE/est.fp" "$STAGE/umbrella.fp" > "$STAGE/fp.diff"; then
        echo "  FAIL  $name: the entry headers resolved a different wolfSSL"
        echo "        feature set from identical flags (-est.h, +wolfcert.h):"
        grep '^[-+]wcprobe_' "$STAGE/fp.diff" | indent || true
        bad=1
    fi

    if ! diff -u <(norm_err "$STAGE/est.err") <(norm_err "$STAGE/umbrella.err") \
         > "$STAGE/err.diff"; then
        echo "  FAIL  $name: the entry headers produced different diagnostics"
        echo "        (-est.h, +wolfcert.h):"
        grep '^[-+][^-+]' "$STAGE/err.diff" | indent || true
        bad=1
    fi

    # Agreement alone is satisfiable by "both broken the same way", so pin the
    # expected polarity too.
    case "$expect" in
        agree-ok)
            if [ "$est_rc" != 0 ]; then
                echo "  FAIL  $name: both agree but both failed; expected both to build."
                sed 's/^/          /' "$STAGE/est.err"
                bad=1
            fi
            if grep -q 'wcprobe_WOLFCERT_CI_DECOY_OPTIONS_H_is_1' "$STAGE/est.fp"; then
                echo "  FAIL  $name: a translation unit read <wolfssl/options.h> while"
                echo "        WOLFSSL_USER_SETTINGS was defined; expected settings.h"
                echo "        to reach user_settings.h in both."
                bad=1
            fi
            ;;
        agree-ok-optionsh)
            if [ "$est_rc" != 0 ]; then
                echo "  FAIL  $name: both agree but both failed; expected both to build."
                sed 's/^/          /' "$STAGE/est.err"
                bad=1
            elif ! grep -q 'wcprobe_WOLFCERT_CI_DECOY_OPTIONS_H_is_1' "$STAGE/est.fp"; then
                echo "  FAIL  $name: no translation unit read <wolfssl/options.h> while"
                echo "        WOLFSSL_USER_SETTINGS was undefined; expected"
                echo "        WOLFSSL_USE_OPTIONS_H to carry options.h into both."
                bad=1
            fi
            ;;
        agree-fail-order)
            if [ "$est_rc" = 0 ]; then
                echo "  FAIL  $name: both agree but both built; a wolfSSL header"
                echo "        came first, so the ordering check was expected to stop them."
                bad=1
            elif ! grep -q 'included before wolfCert' "$STAGE/est.err"; then
                echo "  FAIL  $name: expected the include-order #error; got:"
                sed 's/^/          /' "$STAGE/est.err"
                bad=1
            elif grep -q 'wolfSSL is missing' "$STAGE/est.err"; then
                echo "  FAIL  $name: tier-2 errors reported alongside the ordering"
                echo "        error; they name a feature set that was never resolved."
                bad=1
            fi
            ;;
        agree-fail)
            if [ "$est_rc" = 0 ]; then
                echo "  FAIL  $name: both agree but both built; the decoy options.h was"
                echo "        expected to be ignored, leaving the tier-2 set unmet."
                bad=1
            elif ! grep -q 'missing HAVE_PKCS7' "$STAGE/est.err"; then
                echo "  FAIL  $name: expected the tier-2 HAVE_PKCS7 #error; got:"
                sed 's/^/          /' "$STAGE/est.err"
                bad=1
            fi
            ;;
    esac

    if [ "$bad" -eq 0 ]; then
        printf '  ok    %s (both exit %s)\n' "$name" "$est_rc"
    else
        status=1
    fi
done

if [ "$ran" -eq 0 ]; then
    echo "ERROR: no case matched '$WANTED'." >&2
    exit 2
fi
if [ "$status" -eq 0 ]; then
    echo "config resolution OK: $ran case(s), both entry headers agree."
fi
exit "$status"
