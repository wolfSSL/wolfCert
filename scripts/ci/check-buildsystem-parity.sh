#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Fail on library or test source drift between CMake and autoconf, Zephyr
# module sources that differ from the client set, or a version or shared
# library version mismatch.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"

indent() {
    while IFS= read -r line; do printf '  %s\n' "$line"; done
}

# extract_lib <build-file>: sorted-unique src/*.c references.
extract_lib() {
    grep -oE 'src/[A-Za-z0-9_/]+\.c' "$1" | sort -u
}

# extract_tests_am <Makefile.am>: test sources with the tests/ prefix stripped.
extract_tests_am() {
    grep -oE 'tests/(unit|integration)/[A-Za-z0-9_]+\.c' "$1" \
        | sed 's|^tests/||' | sort -u
}

# extract_tests_cmake <tests/CMakeLists.txt>: test sources, same form.
extract_tests_cmake() {
    grep -oE '(unit|integration)/[A-Za-z0-9_]+\.c' "$1" | sort -u
}

status=0

# compare <what> <set-a> <name-a> <set-b> <name-b>: report either-side drift.
compare() {
    local what="$1" a="$2" na="$3" b="$4" nb="$5"
    local only_a only_b
    only_a="$(comm -23 <(printf '%s\n' "$a") <(printf '%s\n' "$b"))"
    only_b="$(comm -13 <(printf '%s\n' "$a") <(printf '%s\n' "$b"))"
    if [ -n "$only_a" ]; then
        echo "ERROR: $what in $na but MISSING from $nb:"
        printf '%s\n' "$only_a" | indent
        status=1
    fi
    if [ -n "$only_b" ]; then
        echo "ERROR: $what in $nb but MISSING from $na:"
        printf '%s\n' "$only_b" | indent
        status=1
    fi
}

cmake_srcs="$(extract_lib "$ROOT/CMakeLists.txt")"
am_srcs="$(extract_lib "$ROOT/Makefile.am")"
compare "library sources" \
    "$cmake_srcs" CMakeLists.txt "$am_srcs" Makefile.am

# The Zephyr module builds the client only; these are the test server's.
zephyr_omits="src/ca_issue.c
src/est/est_server.c
src/scep/scep_server.c
src/server.c"
zephyr_expected="$(comm -23 <(printf '%s\n' "$cmake_srcs") \
                            <(printf '%s\n' "$zephyr_omits" | sort))"
zephyr_srcs="$(extract_lib "$ROOT/zephyr/CMakeLists.txt")"
compare "library sources" \
    "$zephyr_expected" "CMakeLists.txt (client)" \
    "$zephyr_srcs" zephyr/CMakeLists.txt

cmake_tests="$(extract_tests_cmake "$ROOT/tests/CMakeLists.txt")"
am_tests="$(extract_tests_am "$ROOT/Makefile.am")"
compare "test sources" \
    "$cmake_tests" tests/CMakeLists.txt "$am_tests" Makefile.am

# The SBOM takes the version from AC_INIT, project() or version.h.
am_ver="$(sed -n 's/^AC_INIT(\[wolfCert\], *\[\([^]]*\)\].*/\1/p' "$ROOT/configure.ac")"
cmake_ver="$(sed -n '/^project(wolfCert/,/)/s/^ *VERSION \([0-9.]*\).*/\1/p' \
    "$ROOT/CMakeLists.txt")"
hdr_ver="$(sed -n 's/^#define WOLFCERT_VERSION_STRING "\(.*\)"/\1/p' \
    "$ROOT/wolfcert/version.h")"
if [ -z "$am_ver" ] || [ "$am_ver" != "$cmake_ver" ] || \
   [ "$am_ver" != "$hdr_ver" ]; then
    echo "ERROR: version mismatch: configure.ac '$am_ver'," \
         "CMakeLists.txt '$cmake_ver', wolfcert/version.h '$hdr_ver'"
    status=1
fi

# Libtool's -version-info C:R:A installs libwolfcert.so.<C-A>.<A>.<R>.
lt="$(sed -n 's/.*-version-info \([0-9]*:[0-9]*:[0-9]*\).*/\1/p' "$ROOT/Makefile.am")"
IFS=: read -r lt_c lt_r lt_a <<<"$lt"
lt_so=$((lt_c - lt_a))
lt_ver="$lt_so.$lt_a.$lt_r"
props="$(sed -n '/^set_target_properties(wolfcert PROPERTIES/,/)/p' \
    "$ROOT/CMakeLists.txt")"
cm_ver="$(sed -n 's/^ *VERSION *\([^ ]*\)$/\1/p' <<<"$props")"
cm_so="$(sed -n 's/^ *SOVERSION *\([^ ]*\)$/\1/p' <<<"$props")"
if [ -z "$lt" ] || [ "$cm_ver" != "$lt_ver" ] || [ "$cm_so" != "$lt_so" ]; then
    echo "ERROR: CMakeLists.txt VERSION ${cm_ver:-?} SOVERSION ${cm_so:-?} does"\
         "not match Makefile.am -version-info ${lt:-?}"
    status=1
fi

if [ "$status" -eq 0 ]; then
    echo "build-system parity OK: $(echo "$cmake_srcs" | wc -l | tr -d ' ') library"\
         "sources, $(echo "$zephyr_srcs" | wc -l | tr -d ' ') of them in the Zephyr"\
         "module, $(echo "$cmake_tests" | wc -l | tr -d ' ') test sources, the"\
         "version ($am_ver) and the library version $lt_ver match."
fi
exit "$status"
