#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Negative-configuration gate: assert that wolfCert's configure step HARD-FAILS
# (non-zero exit) with the expected diagnostic when the underlying wolfSSL is
# built in a way wolfCert cannot support. Exercises the fail-fast guards in
# CMakeLists.txt and configure.ac, for BOTH build systems (their gate
# implementations are independent, so we check parity of the rejection too).
#
# Usage:
#   assert-configure-fails.sh [--build-system cmake|autoconf|both]
#                             [--wolfssl-base DIR] [--ref REF]
#                             [CASE ...]
#
# With no CASE names, every case runs.
#
# Each case builds a purpose-built wolfSSL (via build-wolfssl.sh, cached under
# --wolfssl-base) then runs wolfCert configure and requires: (a) non-zero exit,
# (b) the expected message. A configure that unexpectedly SUCCEEDS is a failure
# of this gate.
#
# Scope: only misconfigurations that a *buildable* wolfSSL can express are
# covered here (RSA-off-with-SCEP, PKCS7 missing). wolfSSL's own configure
# refuses to drop AES / SHA-256 / all TLS / all key algorithms, so wolfCert's
# compile-time #error guards for those (check_config.h) can't be fed by a real
# wolfSSL build and are not exercised by this script.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
BUILD_WOLFSSL="$HERE/build-wolfssl.sh"

BUILD_SYSTEM="both"
WOLFSSL_BASE="$PWD/.wolfssl-install"
REF="${WOLFSSL_REF:-master}"
CASES=()

while [ "$#" -gt 0 ]; do
    case "$1" in
        --build-system) BUILD_SYSTEM="$2"; shift 2 ;;
        --wolfssl-base) WOLFSSL_BASE="$2";  shift 2 ;;
        --ref)          REF="$2";           shift 2 ;;
        -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        --*) echo "ERROR: unknown flag '$1'." >&2; exit 2 ;;
        *) CASES+=("$1"); shift ;;
    esac
done

# ----------------------------------------------------------------------------
# Case table. Fields (":"-separated):
#   name : wolfssl-config : cmake-extra-opts : autoconf-extra-opts : grep -E pattern
# ----------------------------------------------------------------------------
CASE_TABLE=(
  "no-rsa-scep:neg-no-rsa:::SCEP is RSA-only"
  "no-pkcs7:neg-no-pkcs7:::HAVE_PKCS7|missing a required feature"
)

lookup_case() {
    local want="$1" row
    for row in "${CASE_TABLE[@]}"; do
        [ "${row%%:*}" = "$want" ] && { echo "$row"; return 0; }
    done
    return 1
}

# Default: run all cases in table order.
if [ "${#CASES[@]}" -eq 0 ]; then
    for row in "${CASE_TABLE[@]}"; do CASES+=("${row%%:*}"); done
fi

PASS=0
FAIL=0

run_cmake() {  # <wolfssl-prefix> <extra-opts> <pattern> <case>
    local prefix="$1" extra="$2" pattern="$3" name="$4"
    local bdir log rc
    bdir="$(mktemp -d)"; log="$bdir/configure.log"
    set +e
    # shellcheck disable=SC2086
    cmake -S "$REPO_ROOT" -B "$bdir" -DWITH_WOLFSSL="$prefix" $extra >"$log" 2>&1
    rc=$?
    set -e
    if [ "$rc" -eq 0 ]; then
        echo "  [cmake] FAIL: configure unexpectedly SUCCEEDED for '$name'"
        FAIL=$((FAIL+1)); rm -rf "$bdir"; return
    fi
    if grep -Eiq "$pattern" "$log"; then
        echo "  [cmake] OK: '$name' rejected (matched: $pattern)"
        PASS=$((PASS+1))
    else
        echo "  [cmake] FAIL: '$name' failed but message did not match /$pattern/"
        echo "          --- tail of configure log ---"; tail -n 15 "$log" | sed 's/^/          /'
        FAIL=$((FAIL+1))
    fi
    rm -rf "$bdir"
}

run_autoconf() {  # <wolfssl-prefix> <extra-opts> <pattern> <case>
    local prefix="$1" extra="$2" pattern="$3" name="$4"
    local bdir log rc
    # Autoconf needs a bootstrapped source tree once; build out-of-tree (VPATH).
    if [ ! -x "$REPO_ROOT/configure" ]; then
        ( cd "$REPO_ROOT" && ./autogen.sh >/dev/null 2>&1 )
    fi
    # A VPATH build refuses to run when the source tree is already configured
    # in-tree (leftover config.status). Clean it so local runs match CI's fresh
    # checkout.
    if [ -f "$REPO_ROOT/config.status" ]; then
        ( cd "$REPO_ROOT" && make distclean >/dev/null 2>&1 ) || true
        ( cd "$REPO_ROOT" && ./autogen.sh >/dev/null 2>&1 )
    fi
    bdir="$(mktemp -d)"; log="$bdir/configure.log"
    set +e
    # shellcheck disable=SC2086
    ( cd "$bdir" && PKG_CONFIG_PATH="$prefix/lib/pkgconfig:${PKG_CONFIG_PATH:-}" \
        "$REPO_ROOT/configure" --with-wolfssl="$prefix" $extra ) >"$log" 2>&1
    rc=$?
    set -e
    if [ "$rc" -eq 0 ]; then
        echo "  [autoconf] FAIL: configure unexpectedly SUCCEEDED for '$name'"
        FAIL=$((FAIL+1)); rm -rf "$bdir"; return
    fi
    if grep -Eiq "$pattern" "$log"; then
        echo "  [autoconf] OK: '$name' rejected (matched: $pattern)"
        PASS=$((PASS+1))
    else
        echo "  [autoconf] FAIL: '$name' failed but message did not match /$pattern/"
        echo "          --- tail of configure log ---"; tail -n 15 "$log" | sed 's/^/          /'
        FAIL=$((FAIL+1))
    fi
    rm -rf "$bdir"
}

for name in "${CASES[@]}"; do
    row="$(lookup_case "$name")" || { echo "ERROR: unknown case '$name'." >&2; exit 2; }
    IFS=':' read -r _n wcfg cmake_extra ac_extra pattern <<<"$row"
    echo "== case '$name' (wolfSSL: $wcfg) =="
    prefix="$WOLFSSL_BASE/$wcfg"
    "$BUILD_WOLFSSL" "$wcfg" --prefix "$prefix" --ref "$REF" >/dev/null

    case "$BUILD_SYSTEM" in
        cmake)    run_cmake    "$prefix" "$cmake_extra" "$pattern" "$name" ;;
        autoconf) run_autoconf "$prefix" "$ac_extra"    "$pattern" "$name" ;;
        both)     run_cmake    "$prefix" "$cmake_extra" "$pattern" "$name"
                  run_autoconf "$prefix" "$ac_extra"    "$pattern" "$name" ;;
        *) echo "ERROR: --build-system must be cmake|autoconf|both." >&2; exit 2 ;;
    esac
done

echo "----------------------------------------"
echo "negative-config gate: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
