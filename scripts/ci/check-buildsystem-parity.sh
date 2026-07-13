#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Guard the "CMake is primary, autoconf is kept at parity" invariant. A source
# added to one build system but not the other is a common and easy-to-miss
# drift; this fails CI when it happens. Two independent sets are compared:
#
#   1. Library sources (src/*.c): CMakeLists.txt vs Makefile.am.
#   2. Test sources (tests/{unit,integration}/*.c): tests/CMakeLists.txt vs
#      Makefile.am -- so `make check` and CTest register the same test set.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"

indent() {  # prefix each input line with two spaces
    while IFS= read -r line; do printf '  %s\n' "$line"; done
}

# extract_lib <build-file>: sorted-unique src/*.c references.
extract_lib() {
    grep -oE 'src/[A-Za-z0-9_/]+\.c' "$1" | sort -u
}

# extract_tests_am <Makefile.am>: sorted-unique test sources, normalized to
# the unit/*.c | integration/*.c form (the tests/ prefix is stripped).
extract_tests_am() {
    grep -oE 'tests/(unit|integration)/[A-Za-z0-9_]+\.c' "$1" \
        | sed 's|^tests/||' | sort -u
}

# extract_tests_cmake <tests/CMakeLists.txt>: same normalized form (paths are
# already relative to tests/).
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

cmake_tests="$(extract_tests_cmake "$ROOT/tests/CMakeLists.txt")"
am_tests="$(extract_tests_am "$ROOT/Makefile.am")"
compare "test sources" \
    "$cmake_tests" tests/CMakeLists.txt "$am_tests" Makefile.am

if [ "$status" -eq 0 ]; then
    echo "build-system parity OK: $(echo "$cmake_srcs" | wc -l | tr -d ' ') library"\
         "sources and $(echo "$cmake_tests" | wc -l | tr -d ' ') test sources match."
fi
exit "$status"
