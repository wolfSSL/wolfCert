#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Compile every portable wolfCert source for a bare-metal ARM target: no POSIX
# headers, no built-in transport, no POSIX store, no test server. This keeps
# src/http.c, src/csr.c and src/store.c free of syscalls, so wolfCert can run on
# a non-BSD-sockets stack through a caller-supplied WolfCertTransport.
#
# Compile-only, so it wants a wolfSSL checkout for headers rather than a build,
# and finishes in seconds. Feature set: freestanding-user_settings.h alongside.
#
# Usage:
#   compile-freestanding.sh --wolfssl-src DIR [--cc CC] [--cpu MCPU]
#
# Defaults: --cc arm-none-eabi-gcc, --cpu cortex-m4 (CC_BIN / CPU also override).

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"

CC_BIN="${CC_BIN:-arm-none-eabi-gcc}"
CPU="${CPU:-cortex-m4}"
WOLFSSL_SRC=""

while [ "$#" -gt 0 ]; do
    case "$1" in
        --wolfssl-src) WOLFSSL_SRC="$2"; shift 2 ;;
        --cc)          CC_BIN="$2";      shift 2 ;;
        --cpu)         CPU="$2";         shift 2 ;;
        -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "ERROR: unknown flag '$1'." >&2; exit 2 ;;
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
mkdir -p "$STAGE/inc" "$STAGE/obj"

# Never a configured tree's own options.h: it describes that build, not the set
# pinned here. The stub replacing it is what --enable-usersettings generates,
# which check_config.h and memory.h need to resolve <wolfssl/options.h>.
cp -R "$WOLFSSL_SRC/wolfssl" "$STAGE/inc/wolfssl"
rm -f "$STAGE/inc/wolfssl/options.h"
cat > "$STAGE/inc/wolfssl/options.h" <<'EOF'
#ifndef WOLFSSL_OPTIONS_H
#define WOLFSSL_OPTIONS_H
#include <user_settings.h>
#endif
EOF

cp "$HERE/freestanding-user_settings.h" "$STAGE/inc/user_settings.h"

# From CMakeLists.txt, so a new src/*.c joins the gate automatically. Skipped:
# the POSIX transport and the test server, both POSIX by design.
SKIP_RE='^src/(net_posix|server|ca_issue|est/est_server|scep/scep_server)\.c$'
SRCS="$(grep -oE 'src/[A-Za-z0-9_/]+\.c' "$ROOT/CMakeLists.txt" \
    | sort -u | grep -Ev "$SKIP_RE" || true)"

if [ -z "$SRCS" ]; then
    echo "ERROR: no sources extracted from CMakeLists.txt" >&2
    exit 1
fi
n_srcs="$(printf '%s\n' "$SRCS" | wc -l | tr -d ' ')"

# -Wno-error=cpp keeps wolfSSL's own #warning non-fatal; ours stay fatal.
CFLAGS=(-c -mcpu="$CPU" -mthumb -ffreestanding
        -Wall -Wextra -Werror -Wno-error=cpp
        -DWOLFSSL_USER_SETTINGS -DWOLFCERT_USER_SETTINGS
        -I"$ROOT" -I"$STAGE/inc")

echo "Compiling $n_srcs sources with $CC_BIN (-mcpu=$CPU), no POSIX:"
status=0
# Fed by here-doc rather than an array: macOS ships bash 3.2, which has no
# mapfile.
while IFS= read -r s; do
    obj="$STAGE/obj/$(echo "$s" | tr '/' '_').o"
    if "$CC_BIN" "${CFLAGS[@]}" -o "$obj" "$ROOT/$s" 2> "$STAGE/err.log"; then
        printf '  ok    %s\n' "$s"
    else
        printf '  FAIL  %s\n' "$s"
        sed 's/^/        /' "$STAGE/err.log"
        status=1
    fi
done <<EOF
$SRCS
EOF

if [ "$status" -eq 0 ]; then
    echo "freestanding compile OK: $n_srcs sources, no POSIX headers."
fi
exit "$status"
