# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

wolfCert is a C library for client-side certificate lifecycle management
built on top of wolfSSL. It implements EST (RFC 7030) and SCEP (RFC 8894)
for certificate enrollment over HTTP/S. Current version is v0.1.0
(`wolfcert/version.h`). License is GPL-3.0-or-later.

## Build

CMake is the primary build system; autoconf is kept at parity.

```sh
# Dev build: everything enabled, tests + examples on
cmake -S . -B build \
    -DWOLFCERT_ENABLE_TESTS=ON \
    -DWOLFCERT_ENABLE_EXAMPLES=ON
cmake --build build -j

# Autoconf equivalent
./autogen.sh
./configure --enable-tests --enable-examples
make -j
```

wolfCert targets **wolfSSL >= 5.9.2**. The build **hard-fails** at
configure time if the installed wolfSSL lacks any of `HAVE_PKCS7`,
`WOLFSSL_CERT_GEN`, `WOLFSSL_CERT_REQ`, `WOLFSSL_CERT_EXT`,
`WOLFSSL_KEY_GEN`, `WOLF_CRYPTO_CB`, `WOLFSSL_BASE64_ENCODE`,
`OPENSSL_EXTRA`, `WOLFSSL_ALT_NAMES`, or `WOLFSSL_CERT_NAME_ALL`, or if
it was built with `NO_AES` / `NO_SHA256`, or if it provides neither
TLS 1.2 nor TLS 1.3.

**Key algorithms are gated** by `WOLFCERT_HAVE_<ALG>` (RSA, ECC,
ED25519, ED448, MLDSA). RSA, ECC, Ed25519, Ed448 and ML-DSA are each
*optional* (absent => warning, that key type returns
`WOLFCERT_ERR_UNSUPPORTED`), with two constraints: at least one key
algorithm must be present, and **SCEP requires RSA** (RFC 8894 is
RSA-only) so a `NO_RSA` wolfSSL hard-fails unless SCEP is disabled. SCEP
content encryption defaults to AES-128-CBC (the RFC 8894 `AES` capability); when
a legacy peer does not advertise `AES` the client falls back to
triple DES-CBC, which needs a wolfSSL built with 3DES support. A wolfSSL
built `NO_DES3` still interoperates with any AES-advertising peer, but the
client rejects a non-AES peer with `WOLFCERT_ERR_UNSUPPORTED`. A caller can
override this per-connection via `WolfCertServerCfg.proto_opts.scep.content_cipher`
(e.g. force AES-256-CBC for a peer that requires it). TLS:
the HTTPS transport pins its floor to TLS 1.2, or TLS 1.3 when wolfSSL
is built `WOLFSSL_NO_TLS12`.

All of these resolved feature flags are written into a **generated
`wolfcert/options.h`** (from `wolfcert/options.h.in`, by both CMake's
`configure_file` and autoconf's `config.status`, like
`wolfssl/options.h`) which `wolfcert/types.h` includes -- the sources no
longer receive `WOLFCERT_HAVE_*` via `-D`. Alternatively, define
**`WOLFCERT_USER_SETTINGS`** and supply a `user_settings.h` on the include
path (the wolfSSL `WOLFSSL_USER_SETTINGS` analogue, for header-only builds with
no configure step); `types.h` then includes it instead of `options.h`. Either
way `wolfcert/check_config.h` validates the resolved feature set at compile
time. See `docs/EMBEDDED.md` and `examples/user_settings.h.example`. Canonical
wolfSSL configure:

```sh
./configure --enable-pkcs7 --enable-certgen --enable-certreq \
    --enable-certext --enable-keygen --enable-ecc --enable-cryptocb \
    --enable-base64encode --enable-ed25519 --enable-ed448 \
    --enable-mldsa --enable-postauth --enable-opensslextra \
    --enable-ip-alt-name --enable-des3 --enable-sni \
    CPPFLAGS="-DWOLFSSL_ALT_NAMES -DWOLFSSL_CERT_NAME_ALL"
```

CMake options live at the top of `CMakeLists.txt`; the matching autoconf
flags are in `configure.ac`. The SCEP server emits the full RFC 8894
signed-attribute set (including `recipientNonce`) on any malloc-enabled
wolfSSL — its PKCS#7 encoder grows the signed-attribute array on the heap
past the inline `MAX_SIGNED_ATTRIBS_SZ`. Only a `WOLFSSL_NO_MALLOC` build
needs wolfSSL rebuilt with `-DMAX_SIGNED_ATTRIBS_SZ>=9` to carry it.

## Test

```sh
ctest --test-dir build --output-on-failure          # everything
ctest --test-dir build -R est_pha_roundtrip         # single test by name
ctest --test-dir build -R roundtrip --output-on-failure   # regex
```

Unit tests live in `tests/unit/`; end-to-end flows in
`tests/integration/` drive the in-tree test server via
`WOLFCERT_ENABLE_SERVER=ON`. Third-party interop scripts under
`tests/interop/` are hand-run and not part of `ctest`.

## Run the CLIs

After a build with `-DWOLFCERT_ENABLE_CLI=ON` (the default):

```sh
build/wolfcert-server --proto est  --listen 127.0.0.1:8443
build/wolfcert-client enroll --proto est \
    --url http://127.0.0.1:8443/.well-known/est \
    --key-type ecc:256 --subject "CN=dev" \
    --out-key dev.key --out-cert dev.crt
```

See `README.md` for TLS / mTLS / PHA / SCEP pending-queue variants.

## Architecture at a glance

The authoritative internal-architecture document is **`docs/ARCHITECTURE.md`** -
it covers module decomposition, data structures, subsystems, protocol
layers, end-to-end request walkthroughs with ASCII sequence diagrams, the
MCU / CryptoCb integration guide, and conventions. Read it before making
non-trivial changes.

Minimal orientation:

- **Public API** lives in `wolfcert/`; `wolfcert.h` is the
  umbrella header. Public headers never include internal headers.
- **Four layers**: application -> `wolfcert/*.h` -> protocol
  (`src/est/`, `src/scep/`) -> subsystems (`src/keygen.c`, `src/csr.c`,
  `src/http.c`, `src/store.c`, `src/pkcs7_util.c`, `src/server.c`) ->
  wolfSSL. Protocol modules depend on subsystem modules, never the
  reverse.
- **Three vtables** carry all the pluggability: `WolfCertKeyAlg`
  (algorithm dispatch in `src/key_algs.c`), `WolfCertStoreOps`
  (storage backends in `src/store.c`), `WolfCertServerOps` (test-server
  protocol dispatch in `src/internal.h`, factories in
  `src/est/est_server.c` and `src/scep/scep_server.c`).
- **Adding a key algorithm** = one `WolfCertKeyAlg` struct literal in
  `src/key_algs.c` plus (if applicable) a `WOLFCERT_HAVE_<ALG>` compile
  guard. No edits to `keygen.c`, `csr.c`, or `ca_issue.c`.

## Non-obvious conventions

- **Every allocation takes a heap hint.** Use
  `WOLFCERT_XMALLOC` / `XFREE` / `XREALLOC` macros from
  `wolfcert/memory.h`. The hint rides through to wolfSSL so
  static-memory pools are honoured. Every public API accepts - directly
  or via a config struct - an optional `heap` field; fall back to
  `wolfcert_default_heap()` when it's NULL.
- **CryptoCb devId, never direct registration.** wolfCert never calls
  `wolfCrypt_CryptoCb_RegisterDevice`. The application registers its
  backend and passes the resulting `dev_id` via `WolfCertKeyCfg.dev_id`;
  wolfCert threads it into every `wc_*_init_ex` call.
- **Error codes are small and closed.** See `wolfcert/errors.h`.
  Extended per-thread diagnostics live behind
  `wolfcert_last_error_message()` / `wolfcert_last_wolfssl_err()`. Use
  the `WOLFCERT_ERR(rc, module, fmt, ...)` and
  `WOLFCERT_ERR_WC(wc_rc, module, fmt, ...)` macros from
  `src/internal.h` at every error site; `wolfcert_strerror` must cover
  every code.
- **Naming.** Public and internal functions both use the `wolfcert_*`
  prefix; public types are `WolfCert*` and macros / enums `WOLFCERT_*`.
  The public/private boundary is enforced by visibility, not by name:
  the library builds with hidden default visibility, public prototypes
  in `wolfcert/*.h` are decorated `WOLFCERT_API`, and internal helpers
  declared in `src/internal.h` stay hidden. Internal symbols that
  in-tree tests need to link against are tagged `WOLFCERT_TEST_VIS`,
  which becomes a default-visibility export only when
  `WOLFCERT_BUILD_TESTING` is defined.
- **License header.** Every `.c` / `.h` source file opens with the full
  GPL copyright block (`Copyright (C) 2026 wolfSSL Inc. ...`) - copy it
  verbatim from any existing source file. The
  `SPDX-License-Identifier: GPL-3.0-or-later` one-liner is used *only* on
  build files (`CMakeLists.txt`, `configure.ac`, `Makefile.am`), never on
  C sources. Include order within a `.c`/`.h`: the module's own headers
  (`<wolfcert/*.h>` and `"internal.h"`) -> wolfSSL (`<wolfssl/...>`) ->
  system headers.
- **Session vs one-shot APIs.** The non-blocking session variants
  (`wolfcert_http_session_request_nb`, `wolfcert_est_session_*_nb`,
  `wolfcert_scep_session_*_nb`) are the only non-blocking entry points;
  one-shot `wolfcert_http_request` / `wolfcert_est_*` / `wolfcert_scep_*`
  calls are blocking by design. DNS + initial TCP connect remain
  synchronous even in non-blocking mode. The SCEP session (unlike EST)
  does not require TLS, since SCEP authenticates at the pkiMessage layer.
- **SCEP is RSA-only** (per RFC 8894). The SCEP entry points reject
  non-RSA keys with `WOLFCERT_ERR_UNSUPPORTED`. EST is the right
  protocol for Ed25519 / Ed448 / ML-DSA.

## Pointers to the rest of the docs

- `README.md` - user-facing quick start.
- `docs/ARCHITECTURE.md` - design overview, protocol flows, and the
  MCU / CryptoCb integration guide (start here for non-trivial changes).
- `docs/EMBEDDED.md` - RAM-sizing knobs for constrained targets
  (`Cert`/`CertName` shrinking, tunable HTTP stack buffers).
- `docs/MIGRATING-FROM-WOLFSCEP.md` - call mapping and behavioural
  differences for an existing wolfSCEP integration, including which
  messageType a renewal should carry.
- `wolfcert/*.h` - authoritative API reference (inline
  comments document every field and function contract).
