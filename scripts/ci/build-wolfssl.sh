#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Build and install a named wolfSSL configuration for wolfCert CI (and for
# local developers who want to reproduce a CI config).
#
# This script is the single source of truth mapping a short config name to the
# exact wolfSSL ./configure flags. CI hashes `--print-flags <name>` into its
# cache key, so the cached prefix and a local build can never disagree.
#
# Usage:
#   build-wolfssl.sh <config> [--prefix DIR] [--ref REF] [--jobs N] [--src DIR]
#   build-wolfssl.sh --print-flags <config>   # emit the configure flags (for hashing)
#   build-wolfssl.sh --list                   # list known config names
#
# Defaults: --ref master, --prefix $PWD/.wolfssl-install/<config>, --jobs nproc.
#
# The build is idempotent: if <prefix>/lib/pkgconfig/wolfssl.pc already exists,
# the build is skipped (a warm CI cache short-circuits, local re-runs are fast).

set -euo pipefail

WOLFSSL_REPO="${WOLFSSL_REPO:-https://github.com/wolfSSL/wolfssl.git}"

# ----------------------------------------------------------------------------
# Config-name -> wolfSSL ./configure argument array.
#
# The canonical base (satisfies every hard wolfCert requirement plus all
# optional key algorithms) mirrors README.md / CLAUDE.md. Each variant layers
# a delta onto that base. VAR=VALUE assignments are passed to configure as
# single argv elements so embedded spaces survive word-splitting.
# ----------------------------------------------------------------------------

# wolfCert never links wolfSSL's own testsuite/benchmark, so skip building them
# -- a large CI wall-clock saving with no effect on the installed library.
_ci_flags() {
    printf '%s\n' --disable-examples --disable-crypttests
}

# Canonical "everything on" wolfSSL feature set.
_base_flags() {
    _ci_flags
    printf '%s\n' \
        --enable-pkcs7 --enable-certgen --enable-certreq --enable-certext \
        --enable-keygen --enable-ecc --enable-cryptocb --enable-base64encode \
        --enable-ed25519 --enable-ed448 --enable-mldsa \
        --enable-postauth --enable-opensslextra --enable-ip-alt-name \
        --enable-des3 --enable-sni \
        'CPPFLAGS=-DWOLFSSL_ALT_NAMES -DWOLFSSL_CERT_NAME_ALL'
}

# List of every config name this script understands (kept in sync with the
# case in resolve_flags; used by --list and to validate input).
KNOWN_CONFIGS=(
    full full-tsan
    est-only-nonrsa rsa-min ecc-only-est
    no-des3 tls13-only
    mldsa-44off mldsa-65off mldsa-87off
    static-mem no-malloc
    # Negative configs consumed by assert-configure-fails.sh: a valid wolfSSL
    # that wolfCert configure MUST reject. Only the two below are buildable --
    # wolfSSL's own configure refuses to drop AES/SHA-256/all-TLS/all-key-algs
    # (those are cascade-required), so wolfCert's compile-time #error guards for
    # them in check_config.h cannot be fed by a real wolfSSL build.
    neg-no-rsa neg-no-pkcs7
)

# Emit the configure argument list (one per line) for a config name.
resolve_flags() {
    local cfg="$1"
    case "$cfg" in
        full)
            _base_flags ;;
        full-tsan)
            # -Wno-error=tsan: wolfSSL's default GCC build turns on -Werror, and
            # GCC's -Wtsan fires on wc_port.h's C11 atomic_thread_fence() under
            # -fsanitize=thread ("not supported with -fsanitize=thread"), which
            # otherwise aborts the wolfSSL build before any test runs. Demote it
            # back to a warning. It precedes wolfSSL's trailing -Werror on the
            # command line, and an explicit -Wno-error= survives a later bare
            # -Werror, so the exemption holds.
            _base_flags
            printf '%s\n' 'CFLAGS=-fsanitize=thread -g -O1 -Wno-error=tsan' \
                          'LDFLAGS=-fsanitize=thread' ;;
        est-only-nonrsa)
            # EST-capable, RSA absent (NO_RSA). ECC + Ed + ML-DSA still present.
            # RSA is default-on in wolfSSL, so --disable-rsa is the only delta.
            _base_flags
            printf '%s\n' --disable-rsa ;;
        rsa-min)
            # Minimal single-algorithm build: RSA only, no ECC/Ed/ML-DSA.
            _ci_flags
            printf '%s\n' \
                --enable-pkcs7 --enable-certgen --enable-certreq --enable-certext \
                --enable-keygen --enable-cryptocb --enable-base64encode \
                --enable-postauth --enable-opensslextra --enable-ip-alt-name \
                --disable-ecc --disable-ed25519 --disable-ed448 --disable-dilithium \
                'CPPFLAGS=-DWOLFSSL_ALT_NAMES -DWOLFSSL_CERT_NAME_ALL' ;;
        ecc-only-est)
            # EST with ECC keys, RSA absent (so SCEP must be disabled by caller).
            _ci_flags
            printf '%s\n' \
                --enable-pkcs7 --enable-certgen --enable-certreq --enable-certext \
                --enable-keygen --enable-ecc --enable-cryptocb --enable-base64encode \
                --enable-postauth --enable-opensslextra --enable-ip-alt-name \
                --disable-rsa --disable-ed25519 --disable-ed448 --disable-dilithium \
                'CPPFLAGS=-DWOLFSSL_ALT_NAMES -DWOLFSSL_CERT_NAME_ALL' ;;
        no-des3)
            # SCEP content encryption falls to AES-only (no 3DES fallback path).
            _base_flags
            printf '%s\n' --disable-des3 ;;
        tls13-only)
            # WOLFSSL_NO_TLS12 -> the TLS floor becomes 1.3; keeps PHA meaningful.
            _base_flags
            printf '%s\n' --disable-tlsv12 ;;
        mldsa-44off)
            _base_flags
            printf '%s\n' 'CPPFLAGS=-DWOLFSSL_ALT_NAMES -DWOLFSSL_CERT_NAME_ALL -DWOLFSSL_NO_ML_DSA_44' ;;
        mldsa-65off)
            _base_flags
            printf '%s\n' 'CPPFLAGS=-DWOLFSSL_ALT_NAMES -DWOLFSSL_CERT_NAME_ALL -DWOLFSSL_NO_ML_DSA_65' ;;
        mldsa-87off)
            _base_flags
            printf '%s\n' 'CPPFLAGS=-DWOLFSSL_ALT_NAMES -DWOLFSSL_CERT_NAME_ALL -DWOLFSSL_NO_ML_DSA_87' ;;
        static-mem)
            # Static memory pools + single-threaded (constrained-target shape).
            _base_flags
            printf '%s\n' --enable-staticmemory --enable-singlethreaded ;;
        no-malloc)
            # WOLFSSL_NO_MALLOC: no dynamic allocator at all, so pair it with
            # static-memory pools (the only allocation source). Tests load a
            # pool and register it as wolfCert's default heap. SCEP server needs
            # MAX_SIGNED_ATTRIBS_SZ>=9 to carry the full RFC 8894 signed-
            # attribute set without heap growth.
            _base_flags
            printf '%s\n' --enable-staticmemory \
                'CPPFLAGS=-DWOLFSSL_ALT_NAMES -DWOLFSSL_CERT_NAME_ALL -DWOLFSSL_NO_MALLOC -DMAX_SIGNED_ATTRIBS_SZ=9' ;;

        # -------- negative configs (a buildable wolfSSL wolfCert MUST reject) --
        neg-no-rsa)
            # NO_RSA with SCEP still requested -> "SCEP is RSA-only".
            _base_flags
            printf '%s\n' --disable-rsa ;;
        neg-no-pkcs7)
            # Missing a tier-1 symbol (HAVE_PKCS7) -> "built without HAVE_PKCS7".
            _ci_flags
            printf '%s\n' \
                --enable-certgen --enable-certreq --enable-certext \
                --enable-keygen --enable-ecc --enable-cryptocb --enable-base64encode \
                --enable-opensslextra --enable-ip-alt-name \
                'CPPFLAGS=-DWOLFSSL_ALT_NAMES -DWOLFSSL_CERT_NAME_ALL' ;;
        *)
            echo "ERROR: unknown wolfSSL config '$cfg'." >&2
            echo "       Known: ${KNOWN_CONFIGS[*]}" >&2
            exit 2 ;;
    esac
}

# ----------------------------------------------------------------------------
# Argument parsing
# ----------------------------------------------------------------------------
if [ "$#" -eq 0 ]; then
    echo "ERROR: no config given. Try --list." >&2
    exit 2
fi

case "$1" in
    --list)
        printf '%s\n' "${KNOWN_CONFIGS[@]}"
        exit 0 ;;
    --print-flags)
        [ "$#" -ge 2 ] || { echo "ERROR: --print-flags needs a config name." >&2; exit 2; }
        resolve_flags "$2"
        exit 0 ;;
esac

CONFIG="$1"; shift
PREFIX=""
REF="${WOLFSSL_REF:-master}"
JOBS=""
SRC=""

while [ "$#" -gt 0 ]; do
    case "$1" in
        --prefix) PREFIX="$2"; shift 2 ;;
        --ref)    REF="$2";    shift 2 ;;
        --jobs)   JOBS="$2";   shift 2 ;;
        --src)    SRC="$2";    shift 2 ;;
        *) echo "ERROR: unknown argument '$1'." >&2; exit 2 ;;
    esac
done

# Validate config early (resolve_flags exits 2 on unknown). Read into the
# array with a while-read loop rather than `mapfile`: mapfile is bash 4+, but
# this script runs under the macOS runners' /bin/bash 3.2 on a cache miss.
CONFIGURE_FLAGS=()
while IFS= read -r _flag; do
    CONFIGURE_FLAGS+=("$_flag")
done < <(resolve_flags "$CONFIG")

: "${PREFIX:=$PWD/.wolfssl-install/$CONFIG}"
: "${JOBS:=$( (command -v nproc >/dev/null && nproc) || sysctl -n hw.ncpu 2>/dev/null || echo 2)}"
: "${SRC:=$PWD/.wolfssl-src/$CONFIG}"

# Idempotent short-circuit: a warm cache already has the install tree.
if [ -f "$PREFIX/lib/pkgconfig/wolfssl.pc" ]; then
    echo "wolfSSL '$CONFIG' already installed at $PREFIX (skipping build)."
    echo "$PREFIX"
    exit 0
fi

echo "==> Building wolfSSL config '$CONFIG'"
echo "    ref:    $REF"
echo "    prefix: $PREFIX"
echo "    flags:  ${CONFIGURE_FLAGS[*]}"

# Clone (shallow) at the requested ref if we don't have the source yet.
if [ ! -d "$SRC/.git" ]; then
    rm -rf "$SRC"
    # Fast path: a branch/tag ref clones directly (shallow). Fallback: $REF is
    # a raw SHA, which --branch can't take, so do a full clone and check the
    # commit out explicitly -- otherwise we'd silently build the default branch.
    git clone --depth 1 --branch "$REF" "$WOLFSSL_REPO" "$SRC" 2>/dev/null \
        || { git clone "$WOLFSSL_REPO" "$SRC" \
                && git -C "$SRC" checkout "$REF"; }
    if [ ! -e "$SRC/configure" ] && [ ! -f "$SRC/configure.ac" ]; then
        echo "ERROR: wolfSSL checkout looks empty at $SRC" >&2
        exit 1
    fi
fi

cd "$SRC"
if [ ! -x ./configure ]; then
    ./autogen.sh
fi

./configure --prefix="$PREFIX" "${CONFIGURE_FLAGS[@]}"
make "-j${JOBS}"
make install

echo "==> Installed wolfSSL '$CONFIG' to $PREFIX"
echo "$PREFIX"
