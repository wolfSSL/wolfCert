# Sizing wolfCert for embedded targets

wolfCert is designed to run on memory-constrained MCUs, but a few of the
data structures it borrows from wolfSSL are large under wolfSSL's default
desktop configuration. This document collects the knobs that control
wolfCert's RAM footprint - both the wolfSSL build-time settings that
dominate, and wolfCert's own tunables.

For the complementary topics - heap hints, static-memory pools, CryptoCb
offload - see [`ARCHITECTURE.md` section 4 (MCU / CryptoCb integration
guide)](ARCHITECTURE.md#4-mcu--cryptocb-integration-guide).

## Configuring wolfCert without its build system (`user_settings.h`)

By default wolfCert's feature set lives in a generated `wolfcert/options.h`,
produced when you run wolfCert's CMake or autoconf step. MCU toolchains that
drive their own build (and never run that step) can instead supply the config
as a header, exactly like wolfSSL's `WOLFSSL_USER_SETTINGS` / `user_settings.h`:

1. Copy [`examples/user_settings.h.example`](../examples/user_settings.h.example)
   to `user_settings.h` somewhere on your include path and edit which
   `WOLFCERT_HAVE_*` macros are defined.
2. Compile wolfCert (and your application) with `-DWOLFCERT_USER_SETTINGS`.
   `wolfcert/types.h` then pulls your `user_settings.h` in place of the
   generated `options.h`.

The macro set is small and closed - three protocol switches
(`WOLFCERT_HAVE_EST` / `_SCEP` / `_SERVER`) and five key algorithms
(`WOLFCERT_HAVE_RSA` / `_ECC` / `_ED25519` / `_ED448` / `_MLDSA`). **Enable a
feature by defining its macro; disable it by leaving the line commented out -
never `#define ... 0`, because the code tests presence with `#ifdef`.**

`wolfcert/check_config.h` (included automatically by `types.h`) validates the
result at compile time, so a contradictory or incomplete config fails with a
clear `#error` rather than a confusing downstream error. It enforces the same
rules the configure step does: at least one key algorithm, SCEP requires RSA
(RFC 8894), and the wolfSSL feature set wolfCert depends on (PKCS#7, cert
gen/req/ext, key gen, CryptoCb, base64 encode, OpenSSL-extra, alt names,
`WOLFSSL_CERT_NAME_ALL`, AES, SHA-256, and TLS 1.2 or 1.3). The header you copy
documents the matching wolfSSL configure flags. If wolfSSL itself is configured
through *its own* `user_settings.h` (so `<wolfssl/options.h>` does not reflect
its real feature set), define `WOLFCERT_NO_WOLFSSL_FEATURE_CHECK` to skip just
the wolfSSL half of the validation.

When you build wolfCert's own tree this way, the `WOLFCERT_ENABLE_EST` /
`_SCEP` / `_SERVER` options (CMake `-DWOLFCERT_USER_SETTINGS=ON
-DWOLFCERT_USER_SETTINGS_DIR=<dir>`, or autoconf
`--enable-user-settings --with-user-settings=<dir>`) still select which source
files compile - keep them in sync with the macros in your header. External
build systems just compile the file set they want directly.

### Sharing the file name with wolfSSL

The header is called `user_settings.h` on purpose: it is the same basename
wolfSSL looks for under `WOLFSSL_USER_SETTINGS`. That is deliberate and safe,
because the macro namespaces are disjoint - wolfCert reads only
`WOLFCERT_HAVE_*`, wolfSSL reads `HAVE_*` / `NO_*` / `WOLFSSL_*`. **The clean
pattern is therefore a single `user_settings.h` that carries both libraries'
config**, with `-DWOLFSSL_USER_SETTINGS -DWOLFCERT_USER_SETTINGS` so both read
it.

The one thing to know: both `<wolfssl/wolfcrypt/settings.h>` and
`<wolfcert/types.h>` reach the file via a *quoted* `#include "user_settings.h"`,
which searches the including header's own directory first and then the shared
`-I` path. So if you keep **two separate files both named `user_settings.h`**
on the include path, the first one found wins for *both* includes. Prefer one
combined file; if you must keep them apart, make sure wolfCert's directory is
the one its include resolves to. Either way a wrong pick fails loudly at compile
time - `check_config.h` will report a missing key algorithm rather than
miscompile.

## Where the memory goes

| Consumer | Where it lives | Default size | Dominated by |
|----------|----------------|--------------|--------------|
| wolfSSL `Cert` (CSR / cert build) | **heap** (`wc_CertNew`) | ~20+ KB | `altNames[16384]` |
| wolfSSL `DecodedCert` (cert parse) | **stack**, transient | several KB | parse scratch |
| HTTP request handling | **stack** (EST + client); **heap** (SCEP server) | 2-3 KB stack | request read buffer |

The good news: wolfCert never stack-allocates a `Cert`. Every CSR/cert
build path (`src/csr.c`, `src/ca_issue.c`, `src/scep/scep_msg.c`) obtains
it from `wc_CertNew(heap)`, so its weight lands on your heap or static-
memory pool, not the call stack. The bad news: at wolfSSL defaults a single
`Cert` is ~20 KB, almost all of it the `altNames` array.

## 1. The big one: wolfSSL `Cert` / `CertName`

`Cert` embeds two `CertName` structures (issuer + subject), two raw copies
of them, and an alternate-names buffer. Two wolfSSL build-time macros set
the bulk of the size (defaults from `wolfssl/wolfcrypt/asn_public.h`):

| Macro | Default | Effect |
|-------|---------|--------|
| `WC_CTC_MAX_ALT_SIZE` | `16384` | size of `Cert.altNames[]` - the encoded SAN extension. **Single largest contributor.** |
| `WC_CTC_NAME_SIZE` | `64` | size of every `CertName` string field (CN, O, OU, ...). `CertName` carries ~19 such fields under the `WOLFSSL_CERT_NAME_ALL` + `WOLFSSL_CERT_EXT` config wolfCert requires, ×2 for issuer+subject, plus raw copies. |

These are **wolfSSL** settings, not wolfCert ones - set them when you build
wolfSSL (via `user_settings.h` or `CPPFLAGS`), and wolfCert picks up
whatever wolfSSL provides. For example, to drop a `Cert` from ~20 KB to
~3 KB:

```c
/* user_settings.h, when building wolfSSL */
#define WC_CTC_MAX_ALT_SIZE 1024   /* was 16384 */
#define WC_CTC_NAME_SIZE    32     /* was 64    */
```

Trade-offs:
- `WC_CTC_MAX_ALT_SIZE` bounds the **total encoded size of all SANs** on a
  certificate. 1024 bytes still holds a handful of DNS / IP / URI names;
  size it to your longest realistic SAN set.
- `WC_CTC_NAME_SIZE` bounds the length of each subject/issuer RDN value
  (CN, O, ...). wolfCert truncates over-long values to fit
  (`copy_name()` in `src/csr.c`), so shrinking this silently caps how long
  a CN you can request.
- Disabling `WOLFSSL_CERT_NAME_ALL` and/or `WOLFSSL_CERT_EXT` in wolfSSL
  removes the less-common `CertName` fields entirely - but wolfCert's
  build requires both (see `CLAUDE.md` / `CMakeLists.txt`), so prefer
  shrinking `WC_CTC_NAME_SIZE` over dropping these.

## 2. wolfCert HTTP stack buffers

The in-tree test server and HTTP client size a few request-handling
buffers with `#ifndef`-guarded macros in `src/internal.h`; override via `-D`
or your `user_settings`-style config header. The EST server and the client
place these on the stack; the SCEP server, whose GET `PKIOperation` read
buffer is by far the largest, allocates it on the **heap** (freed as soon as
the request completes) so it never counts against the stack budget.

| Macro | Default | Buffer |
|-------|---------|--------|
| `WOLFCERT_HTTP_REQ_BUF_SZ` | `2048` | server request-header read buffer. The SCEP server adds `WOLFCERT_HTTP_QUERY_SZ` to it (so a base64 GET `PKIOperation` fits) and allocates the result on the heap; the EST server keeps its `2048`-byte buffer on the stack (`est_server.c`, `scep_server.c`) |
| `WOLFCERT_HTTP_PATH_SZ` | `512` | EST server request `path` field (the SCEP server points `path`/`query` into its heap read buffer instead) |
| `WOLFCERT_HTTP_QUERY_SZ` | `8192` | sized to hold a base64 GET `PKIOperation` message; on the SCEP server it extends the heap read buffer (`REQ_BUF_SZ + QUERY_SZ`) that `query` points into |
| `WOLFCERT_HTTP_AUTH_BUF_SZ` | `512` | client Basic-auth header line (`http.c`) |
| `WOLFCERT_HTTP_MAX_PATH_LEN` | `8192` | client-side ceiling on a request URL's path+query (`http.c`) |
| `WOLFCERT_SCEP_MAX_GET_URL` | `8192` | client cap on a GET `PKIOperation` URL; a larger message is refused with `WOLFCERT_ERR_UNSUPPORTED` so the caller POSTs (`internal.h`) |

Shrinking `WOLFCERT_HTTP_REQ_BUF_SZ` lowers the largest request header
block the server accepts; `WOLFCERT_HTTP_PATH_SZ` / `WOLFCERT_HTTP_QUERY_SZ`
lower the longest request path / query; `WOLFCERT_HTTP_AUTH_BUF_SZ` lowers the
longest Basic-auth credential the client can send. A POST-only SCEP deployment
can trim `WOLFCERT_HTTP_QUERY_SZ` (and, on the client, `WOLFCERT_SCEP_MAX_GET_URL`
and `WOLFCERT_HTTP_MAX_PATH_LEN`) back down. Example:

```c
#define WOLFCERT_HTTP_REQ_BUF_SZ 768
#define WOLFCERT_HTTP_PATH_SZ    128
#define WOLFCERT_HTTP_QUERY_SZ   256
#define WOLFCERT_HTTP_AUTH_BUF_SZ 128
```

Two related buffers are intentionally **not** exposed as knobs:
- the ≤256-byte response-builder buffers (`hdr[256]`, `body[192]`, ...) -
  too small to matter for a stack budget;
- the SCEP `scratch[1024]` in `src/scep/scep_msg.c`, whose size is tied to
  PKCS#7 signed-attribute encoding; shrinking it risks breaking SCEP
  signing rather than saving meaningful RAM.

## 3. SCEP pkiMessage encode buffer

Encoding a SCEP SignedData pkiMessage allocates a one-shot heap buffer
sized `envelope + signer-cert + WOLFCERT_SCEP_PKI_SLACK`. The slack bounds
everything else in the message (signed attributes, signature, ASN.1
framing); see the `WOLFCERT_SCEP_PKI_SLACK` comment in `src/internal.h`.

| Macro | Default | Bounds |
|-------|---------|--------|
| `WOLFCERT_SCEP_PKI_SLACK` | `8192` | signed-attribute set + signature + SignerInfo/ASN.1 framing on top of the envelope and signer cert |

A PENDING/FAILURE CertRep has no envelope, so its buffer is just
`signer-cert + WOLFCERT_SCEP_PKI_SLACK`. Override via `-D` or your
`user_settings`-style config header; ~4 KiB is the realistic floor for an
RSA-2048 signer (drop further only if you also bound the signer cert and
RSA key size). Example:

```c
#define WOLFCERT_SCEP_PKI_SLACK (6 * 1024)
```

On the decode side, `wolfcert_scep_self_signed_rsa` (the CSR) and
`wolfcert_scep_deenvelop` (the enveloped CertRep) each allocate a one-shot
buffer sized `body + 4 KiB`. `WOLFCERT_SCEP_MAX_MSG_SZ` caps the accepted
`body` so a malformed or hostile length cannot drive a huge allocation; an
over-large body is rejected with `WOLFCERT_ERR_BAD_ARG` before any `malloc`.

| Macro | Default | Bounds |
|-------|---------|--------|
| `WOLFCERT_SCEP_MAX_MSG_SZ` | `65536` | largest CSR / enveloped CertRep accepted by the SCEP PKCS#7 helpers |

In the normal client/server flow these bodies already arrive bounded by the
HTTP body cap (`WOLFCERT_HTTP_DEFAULT_MAX_BODY`, also 64 KiB), so this is a
last-resort limit for direct callers. Real CSRs are `< 4 KiB` and a typical
RSA cert chain is `< 16 KiB`, so this can be trimmed well below the default on
constrained targets. Example:

```c
#define WOLFCERT_SCEP_MAX_MSG_SZ (16 * 1024)
```

## 4. Heap / static-memory pools

Every wolfCert allocation carries a `heap` hint that threads through to
wolfSSL's `XMALLOC`. Build wolfSSL with `WOLFSSL_STATIC_MEMORY` and pass a
pool hint to bound total heap use; this is the primary mechanism for
keeping the large heap-allocated `Cert` off a general-purpose allocator.
See [`ARCHITECTURE.md` section 4.1](ARCHITECTURE.md#41-heap-hints--static-memory-pools)
for the three levels of hint granularity.

## 5. Threading

If your target is single-threaded, build wolfSSL with `SINGLE_THREADED`.
wolfCert holds no locks of its own (init/cleanup delegate refcounting to
`wolfSSL_Init`/`wolfSSL_Cleanup`), so there is nothing extra to configure.

## 6. Algorithms & protocols

Strip unused key algorithms and protocols at configure time so their code
and tables drop out entirely - see the `WOLFCERT_HAVE_*` /
`WOLFCERT_ENABLE_*` options in `CMakeLists.txt` / `configure.ac` and the
gating discussion in `CLAUDE.md`. SCEP is RSA-only; if you only need EST
with ECC or a PQC algorithm, disabling SCEP avoids pulling in RSA.

## 7. Targets without BSD sockets or a filesystem

Two platform pieces can be compiled out entirely, so a target that has
neither a socket API nor a filesystem links neither.

| Macro | Off means | Build flags |
|---|---|---|
| `WOLFCERT_HAVE_BUILTIN_TRANSPORT` | `src/net_posix.c` is not compiled | `-DWOLFCERT_ENABLE_BUILTIN_TRANSPORT=OFF` / `--disable-builtin-transport` |
| `WOLFCERT_HAVE_POSIX_STORE` | the POSIX file store backend is stubbed out | `-DWOLFCERT_ENABLE_POSIX_STORE=OFF` / `--disable-posix-store` |

With the transport off, every config must carry a `WolfCertTransport`;
leaving it NULL is `WOLFCERT_ERR_BAD_ARG`. Writing one is a small glue file
in your own tree - `connect` / `read` / `write` / `disconnect` over your
stack, no TLS code - described in
[`ARCHITECTURE.md` section 4.6](ARCHITECTURE.md#46-pluggable-transport).
With the store off, `wolfcert_store_posix_open()` returns NULL and the
in-memory backend or your own `WolfCertStoreOps` carries persistence.

The CLI tools and the built-in test server both need real sockets, so both
build systems reject enabling them alongside `--disable-builtin-transport`.

A wolfSSL built with `WOLFSSL_USER_IO` works: wolfCert installs its own CBIO
callbacks on every session, so wolfSSL's own socket I/O is never needed.

**wolfCert requires `HAVE_SNI`**, which a cross-compiled wolfSSL often lacks;
`check_config.h` fails the build with a message pointing at `--enable-sni`.

If your device only reaches endpoints that serve a single certificate, or
addresses them by IP, define `WOLFCERT_NO_SNI` to build without it. Do not
take that opt-out for a hosted EST service: the server would return its
default certificate and `verify_server` would reject the handshake with
`WOLFCERT_ERR_TLS`.

## A worked "small footprint" wolfSSL config

```c
/* user_settings.h fragment for a constrained wolfCert target */
#define WC_CTC_MAX_ALT_SIZE 1024
#define WC_CTC_NAME_SIZE    32
#define WOLFSSL_STATIC_MEMORY
#define SINGLE_THREADED
```

```c
/* wolfCert side (compiler -D or your config header) */
#define WOLFCERT_HTTP_REQ_BUF_SZ  768
#define WOLFCERT_HTTP_PATH_SZ     128
#define WOLFCERT_HTTP_AUTH_BUF_SZ 128
#define WOLFCERT_SCEP_PKI_SLACK   (6 * 1024)
```

This drops the per-`Cert` heap cost by ~17 KB and the HTTP request stack
footprint by ~2 KB, while still supporting realistic device-certificate
subjects and SAN sets. Validate against your own longest expected subject
DN and SAN list before committing to the smaller sizes.
