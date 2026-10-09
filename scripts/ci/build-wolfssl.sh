#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Build and install a named wolfSSL configuration for wolfCert CI. CI hashes
# `--print-flags <name>` into its cache key.
#
# Usage:
#   build-wolfssl.sh <config> [--prefix DIR] [--ref REF] [--jobs N] [--src DIR]
#   build-wolfssl.sh --print-flags <config>   # emit the configure flags (for hashing)
#   build-wolfssl.sh --list                   # list known config names
#
# Defaults: --ref master, --prefix $PWD/.wolfssl-install/<config>, --jobs nproc.
# Skipped when <prefix>/lib/pkgconfig/wolfssl.pc already exists.

set -euo pipefail

WOLFSSL_REPO="${WOLFSSL_REPO:-https://github.com/wolfSSL/wolfssl.git}"

# wolfCert never uses wolfSSL's own examples or crypt tests.
_ci_flags() {
    printf '%s\n' --disable-examples --disable-crypttests
}

# Canonical "everything on" wolfSSL feature set, as in AGENTS.md.
_base_flags() {
    _ci_flags
    printf '%s\n' \
        --enable-pkcs7 --enable-certgen --enable-certreq --enable-certext \
        --enable-keygen --enable-ecc --enable-cryptocb --enable-base64encode \
        --enable-ed25519 --enable-ed448 --enable-mldsa \
        --enable-postauth --enable-ip-alt-name \
        --enable-des3 --enable-sni \
        'CPPFLAGS=-DWOLFSSL_ALT_NAMES -DWOLFSSL_CERT_NAME_ALL -DKEEP_PEER_CERT -DWOLFSSL_HAVE_TLS_UNIQUE -DWOLFSSL_PUBLIC_ASN'
}

# Must match the cases in resolve_flags.
KNOWN_CONFIGS=(
    full full-tsan full-opensslextra full-all
    est-only-nonrsa rsa-min ecc-only-est
    no-des3 tls13-only
    mldsa-44off mldsa-65off mldsa-87off
    static-mem no-malloc
    # Negative configs for assert-configure-fails.sh.
    neg-no-rsa neg-no-pkcs7 neg-no-public-asn neg-no-aes128
)

# Emit the configure argument list (one per line) for a config name.
resolve_flags() {
    local cfg="$1"
    case "$cfg" in
        full)
            _base_flags ;;
        full-tsan)
            # GCC's -Wtsan fires on wc_port.h's atomic_thread_fence() and
            # wolfSSL builds with -Werror; -Wno-error=tsan survives that.
            _base_flags
            printf '%s\n' 'CFLAGS=-fsanitize=thread -g -O1 -Wno-error=tsan' \
                          'LDFLAGS=-fsanitize=thread' ;;
        full-opensslextra)
            # The canonical line before OPENSSL_EXTRA was dropped, unchanged.
            _ci_flags
            printf '%s\n' \
                --enable-pkcs7 --enable-certgen --enable-certreq --enable-certext \
                --enable-keygen --enable-ecc --enable-cryptocb --enable-base64encode \
                --enable-ed25519 --enable-ed448 --enable-mldsa \
                --enable-postauth --enable-opensslextra --enable-ip-alt-name \
                --enable-des3 --enable-sni \
                'CPPFLAGS=-DWOLFSSL_ALT_NAMES -DWOLFSSL_CERT_NAME_ALL' ;;
        full-all)
            # OPENSSL_ALL and its compatible defaults, e.g. grouped messages.
            _base_flags
            printf '%s\n' --enable-all ;;
        est-only-nonrsa)
            # RSA absent; ECC, Ed and ML-DSA still present.
            _base_flags
            printf '%s\n' --disable-rsa ;;
        rsa-min)
            # Minimal single-algorithm build: RSA only, no ECC/Ed/ML-DSA.
            _ci_flags
            printf '%s\n' \
                --enable-pkcs7 --enable-certgen --enable-certreq --enable-certext \
                --enable-keygen --enable-cryptocb --enable-base64encode \
                --enable-postauth --enable-ip-alt-name \
                --disable-ecc --disable-ed25519 --disable-ed448 --disable-dilithium \
                'CPPFLAGS=-DWOLFSSL_ALT_NAMES -DWOLFSSL_CERT_NAME_ALL -DKEEP_PEER_CERT -DWOLFSSL_HAVE_TLS_UNIQUE -DWOLFSSL_PUBLIC_ASN' ;;
        ecc-only-est)
            # EST with ECC keys, RSA absent (so SCEP must be disabled by caller).
            _ci_flags
            printf '%s\n' \
                --enable-pkcs7 --enable-certgen --enable-certreq --enable-certext \
                --enable-keygen --enable-ecc --enable-cryptocb --enable-base64encode \
                --enable-postauth --enable-ip-alt-name \
                --disable-rsa --disable-ed25519 --disable-ed448 --disable-dilithium \
                'CPPFLAGS=-DWOLFSSL_ALT_NAMES -DWOLFSSL_CERT_NAME_ALL -DKEEP_PEER_CERT -DWOLFSSL_HAVE_TLS_UNIQUE -DWOLFSSL_PUBLIC_ASN' ;;
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
            printf '%s\n' 'CPPFLAGS=-DWOLFSSL_ALT_NAMES -DWOLFSSL_CERT_NAME_ALL -DKEEP_PEER_CERT -DWOLFSSL_HAVE_TLS_UNIQUE -DWOLFSSL_PUBLIC_ASN -DWOLFSSL_NO_ML_DSA_44' ;;
        mldsa-65off)
            _base_flags
            printf '%s\n' 'CPPFLAGS=-DWOLFSSL_ALT_NAMES -DWOLFSSL_CERT_NAME_ALL -DKEEP_PEER_CERT -DWOLFSSL_HAVE_TLS_UNIQUE -DWOLFSSL_PUBLIC_ASN -DWOLFSSL_NO_ML_DSA_65' ;;
        mldsa-87off)
            _base_flags
            printf '%s\n' 'CPPFLAGS=-DWOLFSSL_ALT_NAMES -DWOLFSSL_CERT_NAME_ALL -DKEEP_PEER_CERT -DWOLFSSL_HAVE_TLS_UNIQUE -DWOLFSSL_PUBLIC_ASN -DWOLFSSL_NO_ML_DSA_87' ;;
        static-mem)
            # Static memory pools + single-threaded (constrained-target shape).
            _base_flags
            printf '%s\n' --enable-staticmemory --enable-singlethreaded ;;
        no-malloc)
            # Static pools are the only allocator. The SCEP server needs
            # MAX_SIGNED_ATTRIBS_SZ>=9 for the RFC 8894 signed attributes.
            _base_flags
            printf '%s\n' --enable-staticmemory \
                'CPPFLAGS=-DWOLFSSL_ALT_NAMES -DWOLFSSL_CERT_NAME_ALL -DKEEP_PEER_CERT -DWOLFSSL_HAVE_TLS_UNIQUE -DWOLFSSL_PUBLIC_ASN -DWOLFSSL_NO_MALLOC -DMAX_SIGNED_ATTRIBS_SZ=9' ;;

        # Negative configs: buildable wolfSSL builds that wolfCert rejects
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
                --enable-ip-alt-name \
                'CPPFLAGS=-DWOLFSSL_ALT_NAMES -DWOLFSSL_CERT_NAME_ALL -DKEEP_PEER_CERT -DWOLFSSL_HAVE_TLS_UNIQUE -DWOLFSSL_PUBLIC_ASN' ;;
        neg-no-public-asn)
            # No ASN-export macro -> "does not export its ASN helpers".
            _base_flags
            printf '%s\n' 'CPPFLAGS=-DWOLFSSL_ALT_NAMES -DWOLFSSL_CERT_NAME_ALL -DKEEP_PEER_CERT -DWOLFSSL_HAVE_TLS_UNIQUE' ;;
        neg-no-aes128)
            # NO_AES_128 with SCEP still requested -> "requires AES-128-CBC".
            _base_flags
            printf '%s\n' 'CPPFLAGS=-DWOLFSSL_ALT_NAMES -DWOLFSSL_CERT_NAME_ALL -DKEEP_PEER_CERT -DWOLFSSL_HAVE_TLS_UNIQUE -DWOLFSSL_PUBLIC_ASN -DNO_AES_128' ;;
        *)
            echo "ERROR: unknown wolfSSL config '$cfg'." >&2
            echo "       Known: ${KNOWN_CONFIGS[*]}" >&2
            exit 2 ;;
    esac
}

# Argument parsing
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

# One flag per line keeps the spaces inside CPPFLAGS. No mapfile: macOS
# runners run this under /bin/bash 3.2 on a cache miss.
_flags=$(resolve_flags "$CONFIG") || exit 2
CONFIGURE_FLAGS=()
while IFS= read -r _flag; do
    CONFIGURE_FLAGS+=("$_flag")
done <<< "$_flags"

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
    # A raw SHA cannot go through --branch, so fall back to a full clone.
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
