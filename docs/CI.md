# Continuous Integration

wolfCert's CI runs on GitHub Actions. Every job builds (or restores from cache)
a wolfSSL configuration, builds wolfCert to match, and runs the tests. wolfSSL
is tracked at `master` and built from source; the install *prefix* is cached so
a run with an unchanged wolfSSL commit + configure-flag set skips the wolfSSL
build entirely.

## Workflows

| Workflow | Trigger | What it does |
|----------|---------|--------------|
| `pr.yml` | PR + push | Merge gate: CMake (`-Werror`) + autoconf + ASan/UBSan on the canonical config, plus per-PR feature/config gating — EST-only, SCEP-only, server-off, the key-alg variants (NO_RSA, ECC-only, RSA-only, no-3DES), TLS 1.3-only, the three ML-DSA per-level builds, the static-memory and no-malloc constrained builds, the header-only (`WOLFCERT_USER_SETTINGS`) build, a macOS build, and the two cheapest configure-must-fail assertions. |
| `lint.yml` | PR + push | GPL license-header check and CMake↔autoconf parity of both the library and test source lists (`scripts/ci/check-buildsystem-parity.sh`). No wolfSSL build — fails in seconds. |
| `nightly.yml` | schedule + dispatch | Re-runs the wolfSSL-variant build matrix against fresh wolfSSL `master`, the macOS extras, and the full negative-config set. Also **reseeds the wolfSSL prefix caches** so the next day's PRs restore instead of build. The feature/config gating itself now runs per-PR (see `pr.yml`). |
| `sanitizers.yml` | schedule + dispatch | ASan+UBSan over the full test suite, ThreadSanitizer over the threaded integration roundtrips (against a TSAN-instrumented wolfSSL), and valgrind over a representative subset. |
| `interop.yml` | schedule + dispatch | Third-party EST/SCEP interop (openssl, micromdm/scep, globalsign/est, cisco/libest, smallstep/step-ca). Best-effort: a dependency that fails to install makes its script exit 77, which is treated as a neutral skip; a real interop regression fails. |

## wolfSSL configurations

`scripts/ci/build-wolfssl.sh` is the single source of truth mapping a short
config name to the exact wolfSSL `./configure` flags. CI hashes
`--print-flags <name>` into the cache key, so a cached prefix and a local build
can never disagree.

```sh
scripts/ci/build-wolfssl.sh --list                 # every known config name
scripts/ci/build-wolfssl.sh --print-flags full     # the flags for a config
scripts/ci/build-wolfssl.sh full --prefix /tmp/ws  # build + install to /tmp/ws
```

Config names include `full` (all algorithms), `full-tsan`, `est-only-nonrsa`
(NO_RSA), `rsa-min`, `ecc-only-est`, `no-des3`, `tls13-only`,
`mldsa-{44,65,87}off`, `static-mem`, `no-malloc`, and the `neg-*` configs used
by the negative-config gate.

## Reproducing a CI job locally

```sh
# 1. Build the wolfSSL config the job uses.
scripts/ci/build-wolfssl.sh full --prefix /tmp/wolfssl

# 2. Build wolfCert against it and run the tests (CMake).
cmake -S . -B build -DWITH_WOLFSSL=/tmp/wolfssl -DWOLFCERT_ENABLE_TESTS=ON
cmake --build build -j
ctest --test-dir build --output-on-failure

# autoconf equivalent
./autogen.sh
PKG_CONFIG_PATH=/tmp/wolfssl/lib/pkgconfig ./configure \
    --with-wolfssl=/tmp/wolfssl --enable-tests
make -j && make check
```

The negative-config gate asserts wolfCert's configure hard-fails on an
unsupportable wolfSSL. It covers the cases a *buildable* wolfSSL can express
(`no-rsa-scep`, `no-pkcs7`); wolfSSL itself refuses to drop AES / SHA-256 / all
TLS / all key algorithms, so wolfCert's compile-time `#error` guards for those
(`wolfcert/check_config.h`) are validated at compile time, not by this gate.

```sh
scripts/ci/assert-configure-fails.sh              # all cases, both build systems
scripts/ci/assert-configure-fails.sh no-rsa-scep  # a single case
```
