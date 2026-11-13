#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Build and install wolfTPM with its fwTPM for the TPM interop test.
#
# Usage:
#   build-wolftpm.sh --wolfssl PREFIX [--prefix DIR] [--ref REF] [--jobs N]
#                    [--src DIR]
#
# Defaults: --ref master, --prefix $PWD/.wolftpm-install, --src
# $PWD/.wolftpm-src. Installs lib/cmake/wolftpm and bin/fwtpm_server.

set -euo pipefail

WOLFTPM_REPO="${WOLFTPM_REPO:-https://github.com/wolfSSL/wolfTPM.git}"

WOLFSSL=""
PREFIX="$PWD/.wolftpm-install"
REF="${WOLFTPM_REF:-master}"
JOBS=""
SRC="$PWD/.wolftpm-src"

while [ "$#" -gt 0 ]; do
    case "$1" in
        --wolfssl) WOLFSSL="$2"; shift 2 ;;
        --prefix)  PREFIX="$2";  shift 2 ;;
        --ref)     REF="$2";     shift 2 ;;
        --jobs)    JOBS="$2";    shift 2 ;;
        --src)     SRC="$2";     shift 2 ;;
        *) echo "ERROR: unknown argument '$1'." >&2; exit 2 ;;
    esac
done
if [ -z "$WOLFSSL" ] || [ ! -d "$WOLFSSL/include/wolfssl" ]; then
    echo "ERROR: --wolfssl must name a wolfSSL install prefix." >&2
    exit 2
fi
: "${JOBS:=$( (command -v nproc >/dev/null && nproc) || sysctl -n hw.ncpu 2>/dev/null || echo 2)}"

echo "==> Building wolfTPM $REF against $WOLFSSL"
if [ -d "$SRC/.git" ]; then
    git -C "$SRC" fetch -q origin "$REF"
    git -C "$SRC" checkout -q --detach FETCH_HEAD
else
    rm -rf "$SRC"
    # A raw SHA cannot go through --branch, so fall back to a full clone.
    git clone --depth 1 --branch "$REF" "$WOLFTPM_REPO" "$SRC" 2>/dev/null \
        || { git clone "$WOLFTPM_REPO" "$SRC" && git -C "$SRC" checkout "$REF"; }
fi
git -C "$SRC" log -1 --format='    commit: %H %s'

# v1.85 is forced on, so a wolfSSL without ML-DSA fails here, not as missing
# ML-DSA in the test.
cmake -S "$SRC" -B "$SRC/build" \
    -DWITH_WOLFSSL="$WOLFSSL" \
    -DCMAKE_INSTALL_PREFIX="$PREFIX" \
    -DCMAKE_INSTALL_RPATH="$PREFIX/lib;$WOLFSSL/lib" \
    -DWOLFTPM_FWTPM=yes -DWOLFTPM_INTERFACE=SWTPM \
    -DWOLFTPM_V185=yes -DWOLFTPM_EXAMPLES=no
cmake --build "$SRC/build" -j "$JOBS" --target wolftpm fwtpm_server
cmake --install "$SRC/build"

echo "==> Installed wolfTPM to $PREFIX"
echo "$PREFIX"
