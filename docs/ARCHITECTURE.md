# wolfCert design overview

This document gives an integrator's view of how wolfCert is put together:
the design goals it's built around, how the layers fit, how the EST and SCEP
flows work, and how to bring it up on a constrained or offload-friendly
target. It's aimed at people integrating wolfCert into an application or
device — for a quick start see [`README.md`](../README.md); for the exact
function contracts see the inline comments in the public headers under
`wolfcert/`.

## Contents

1. [Design goals](#1-design-goals)
2. [Layers](#2-layers)
3. [Protocols: EST and SCEP](#3-protocols-est-and-scep)
4. [MCU / CryptoCb integration guide](#4-mcu--cryptocb-integration-guide)
5. [Extension points](#5-extension-points)
6. [Build & feature gating](#6-build--feature-gating)
7. [Further reading](#7-further-reading)

## 1. Design goals

wolfCert is a C library for **client-side certificate lifecycle management**
on top of wolfSSL. An application — typically an embedded device, a gateway,
or an on-prem service — uses it to retrieve a CA's trust chain, generate a
private key (in software or behind a CryptoCb-registered accelerator), build a
PKCS#10 CSR, submit it via **EST** (RFC 7030) or **SCEP** (RFC 8894), and
persist the issued certificate.

A few constraints shape the whole library:

1. **Only wolfSSL for crypto and transport.** Every hash, cipher, signature,
   RNG, and TLS operation goes through wolfSSL. There is no other
   cryptographic dependency, and the build hard-fails at configure time if the
   local wolfSSL lacks a required feature.
2. **A heap hint on every path.** Allocations go through the
   `WOLFCERT_XMALLOC` / `WOLFCERT_XFREE` / `WOLFCERT_XREALLOC` macros, which
   expand to wolfSSL's `XMALLOC` family and therefore honour
   `WOLFSSL_STATIC_MEMORY`. Every public API that allocates takes — directly
   or via a config struct — an opaque `heap` hint that rides all the way down
   to wolfSSL. Output buffers remember the heap they came from, so their
   `_free` functions need no heap argument.
3. **Backend-agnostic offload via CryptoCb devId.** wolfCert never registers a
   CryptoCb itself. The application registers its own (TPM, HSM, PKCS#11,
   custom) and passes the resulting `devId` through `WolfCertKeyCfg.dev_id`;
   wolfCert threads that into every wolfSSL crypto call on the key.
4. **Pluggable storage and protocol handling via vtables** (see
   [section 5](#5-extension-points)).
5. **Event-loop-friendly I/O.** The keep-alive HTTP and EST session APIs
   support a non-blocking mode that surfaces `WOLFCERT_ERR_WANT_READ` /
   `WOLFCERT_ERR_WANT_WRITE` so callers can drive the flow from their own
   `poll`/`epoll`/`kqueue` loop. Blocking transports are the default.
6. **Compile-time feature gating.** EST, SCEP, the test server, the optional
   key types, and a handful of wolfSSL-tuning opt-ins are all togglable;
   disabled subsystems disappear from the link entirely.
7. **Minimal, explicit error reporting.** Every function returns a small
   negative `WOLFCERT_ERR_*` code; extended diagnostics (module, underlying
   wolfSSL error, message) are recorded in thread-local state and retrieved
   via `wolfcert_last_error_message()` / `wolfcert_last_wolfssl_err()`.

### What wolfCert is not

Deliberately out of scope: full CMP or CMC, CRL/OCSP revocation checking, a
long-running renewal daemon, EST `/serverkeygen`, TLS-PSK / EAP, SCEP non-RSA
keys (the RFC mandates RSA), and Windows host support. The in-tree test server
is intentionally minimal — it exists so the library and CLIs can be exercised
end-to-end without an external PKI, and is not hardened for production.

## 2. Layers

wolfCert is organised in four layers, top to bottom:

```
 +----------------------------------------------------------------------+
 |                         application / CLI                            |
 |  (wolfcert-client, wolfcert-server, examples/enroll_*.c, host app)   |
 +----------------------------------------------------------------------+
                                   |
 +----------------------------------------------------------------------+
 |                       public API headers (wolfcert/*.h)              |
 |  wolfcert.h (umbrella)  client.h  est.h  scep.h  http.h             |
 |  keygen.h  csr.h  store.h  server.h  memory.h  errors.h  status.h    |
 +----------------------------------------------------------------------+
                                   |
 +----------------------------------------------------------------------+
 |                         protocol layer                               |
 |  src/est/*   src/scep/*   src/client.c (protocol-agnostic)           |
 +----------------------------------------------------------------------+
                                   |
 +----------------------------------------------------------------------+
 |                        subsystem layer                               |
 |  keygen / key_algs   csr   http (TLS + keep-alive + async)           |
 |  store   pkcs7_util   server + ca_issue   memory / errors / logging  |
 +----------------------------------------------------------------------+
                                   |
 +----------------------------------------------------------------------+
 |                              wolfSSL                                 |
 |  TLS   PKCS#7   crypto (RSA/ECC/Ed25519/Ed448/ML-DSA)   ASN.1        |
 |  cert gen   RNG   XMALLOC (static-memory aware)   CryptoCb (devId)   |
 +----------------------------------------------------------------------+
```

The layering rules that matter to an integrator:

- **`<wolfcert/wolfcert.h>` is the single entry point.** It conditionally
  pulls the protocol headers based on what was compiled in, so an application
  can include it without caring whether EST or SCEP is present.
- **`wolfcert_client_*` is the high-level orchestrator.**
  `wolfcert_client_enroll` / `_reenroll` route to EST or SCEP based on
  `WolfCertServerCfg.protocol`. Callers that want finer control reach directly
  into the `wolfcert_est_*` / `wolfcert_scep_*` primitives.
- **Protocol modules depend on subsystems, never the reverse**, and the test
  server lives below the public API — an embedder can hand it an
  already-accepted socket via `wolfcert_server_serve_fd()` instead of using
  its accept loop.
- **`WolfCertServerCfg` carries the shared transport settings plus one
  protocol-specific arm.** A connection is either EST or SCEP, so the
  per-protocol knobs live in the `proto_opts` union (`WolfCertEstServerOpts` /
  `WolfCertScepServerOpts`) selected by `protocol`; the arm that does not match
  is never read. Both arms are zero-init-safe, so leaving the union untouched
  keeps the default behavior. Because `protocol` is the discriminator, every
  `wolfcert_est_*` and `wolfcert_scep_*` entry point validates it up front and
  returns `WOLFCERT_ERR_BAD_ARG` on a mismatch, so a config built for one
  protocol can never be reinterpreted through the other's arm.

## 3. Protocols: EST and SCEP

### EST (RFC 7030)

EST is a REST-shaped enrollment protocol over HTTPS. wolfCert implements the
four endpoints a typical device needs:

| Endpoint | Entry point | Notes |
|---|---|---|
| `GET  /cacerts`        | `wolfcert_est_get_cacerts`     | CA chain as degenerate PKCS#7; decoded to PEM for you. |
| `GET  /csrattrs`       | `wolfcert_est_get_csr_attrs`   | Raw body (empty on HTTP 204); decode with `wolfcert_est_parse_csr_attrs`. |
| `POST /simpleenroll`   | `wolfcert_est_simple_enroll`   | Body is base64-wrapped CSR DER; 200 returns the issued cert as PKCS#7. |
| `POST /simplereenroll` | `wolfcert_est_simple_reenroll` | Same, with the cert being renewed used as the implicit client identity. |

A typical flow is: `wolfcert_key_generate` → `wolfcert_csr_build` →
`wolfcert_est_simple_enroll` → persist the returned PEM. The keep-alive
`WolfCertEstSession` carries several requests on one TLS connection, and is
what enables the post-handshake-auth bootstrap below.

**Authentication shapes.** EST supports three, all through the same
`WolfCertServerCfg`:

1. **HTTP Basic over TLS** — set `proto_opts.est.username` / `.password`. Sent
   on the one-shot calls and on every request a keep-alive session issues.
   EST-only: SCEP authenticates inside the pkiMessage, so the fields live in
   the EST arm of the union and no SCEP entry point reads them.
2. **mTLS up front** — set `client_cert` / `client_key`; they're presented
   during the handshake.
3. **TLS 1.3 post-handshake auth** — set `client_cert` / `client_key` *and*
   `proto_opts.est.allow_post_handshake_auth = 1`, and use the session API. The first request
   (`/cacerts`) rides an anonymous handshake; the server triggers a
   mid-session `CertificateRequest` when the client first hits a protected
   endpoint, and wolfSSL answers from the pre-loaded identity with no further
   caller involvement. Requires a wolfSSL built with
   `WOLFSSL_POST_HANDSHAKE_AUTH`.

**Manual approval.** A server may park an enrollment with `202 Accepted` +
`Retry-After` (RFC 7030 §4.2.3), symmetrical to SCEP's PENDING. The
`wolfcert_est_simple_enroll_ex` / `_simple_reenroll_ex` variants surface this
as a `WolfCertEstResult` with `UNSET` / `SUCCESS` / `FAILURE` / `PENDING`
status and a `retry_after_sec` hint; the simple-result calls flatten PENDING to
`WOLFCERT_ERR_PENDING`.

**`/csrattrs` key-policy pinning.** `wolfcert_est_parse_csr_attrs` decodes the
RFC 7030 §4.5.2 response into both a raw per-item OID/values list and
structured hints (challenge-password / extension-request flags, preferred
signature hash, preferred key algorithm + size). `wolfcert_csr_attrs_apply`
overlays those hints onto a caller-supplied `WolfCertKeyCfg` / `WolfCertCertMeta`
*one-way* — each field is filled only when the caller left it at its
zero-value default, so an explicit choice always wins. With
`WolfCertServerCfg.proto_opts.est.auto_csrattrs = 1`, `wolfcert_client_enroll` runs
fetch+parse+apply before keygen, so a caller can hand in an empty
`WolfCertKeyCfg{0}` and let the server pin the algorithm.

### SCEP (RFC 8894)

SCEP carries CMS / PKCS#7 pkiMessages over HTTP. Every message is a SignedData
whose payload is an EnvelopedData, built on wolfSSL's `wc_PKCS7` API.

| Operation | Message type | Entry point |
|---|---|---|
| `GetCACaps`      | plain text | `wolfcert_scep_get_ca_caps` |
| `GetCACert`      | cert body  | `wolfcert_scep_get_ca_cert` |
| `GetNextCACert`  | cert body  | `wolfcert_scep_get_next_ca_cert` |
| `PKCSReq`        | 19         | `wolfcert_scep_pkcs_req_ex` (+ simple `_pkcs_req`) |
| `RenewalReq`     | 17         | `wolfcert_scep_renewal_req_ex` (+ simple `_renewal_req`) |
| `GetCertInitial` | 20         | `wolfcert_scep_get_cert_initial` |

Each round trip envelopes the payload to the RA/CA cert's public key, signs it
(for `PKCSReq` with a transient self-signed cert whose key matches the one
being enrolled), sends it, and parses the response. The pkiMessage is POSTed by
default; when the passed `caps` shows the CA does **not** advertise
`POSTPKIOperation`, the client falls back to the RFC 8894 section 4.1 HTTP GET
form, carrying the message base64-encoded and percent-escaped in the `message`
query parameter (refusing, with `WOLFCERT_ERR_UNSUPPORTED`, to build a URL
longer than `WOLFCERT_SCEP_MAX_GET_URL`). The in-tree test server accepts both.
The server's `pkiStatus` maps to a `WolfCertScepResult.status` of `SUCCESS`
(cert in `cert_pem`), `PENDING` (poll with `GetCertInitial`, quoting the
returned transaction ID), or `FAILURE`.

Moving an existing wolfSCEP integration across is covered separately in
[`MIGRATING-FROM-WOLFSCEP.md`](MIGRATING-FROM-WOLFSCEP.md).

**SCEP is RSA-only.** The entry points reject non-RSA keys with
`WOLFCERT_ERR_UNSUPPORTED` — this is a protocol constraint, not a wolfCert
limitation. Use EST for Ed25519 / Ed448 / ML-DSA.

**Trust bootstrap.** A `GetCACert` response is only trustworthy once its
fingerprint has been checked against a value obtained out of band.
`wolfcert_scep_verify_ca_fingerprint` hashes the DER CA certificate (SHA-256,
or SHA-1 / SHA-512, with `WOLFCERT_SCEP_FP_AUTO` selecting the algorithm from
the fingerprint length) and constant-time-compares it, returning
`WOLFCERT_ERR_AUTH` on mismatch. Verify the bundle this way before using it as
the `ca_bundle` trust set for enrollment.

**Keep-alive / async sessions.** Alongside the one-shot calls, PKCSReq,
RenewalReq and GetCertInitial have session variants
(`wolfcert_scep_session_pkcs_req_ex`/`_nb`, etc.) that reuse one connection,
built on the same non-blocking HTTP session as EST (see the session section
below). Fetch caps + the CA cert with the one-shot getters first, then open a
session with `wolfcert_scep_session_open` (blocking) or
`wolfcert_scep_session_open_async` (event-loop). Each round trip is
prepared (envelope + sign), sent, and its CertRep parsed as one logical step;
in async mode only the HTTP transport is pumped through `WANT_READ`/`WANT_WRITE`
while the crypto stays synchronous.

**Client options** (`WolfCertServerCfg.proto_opts.scep`, a `WolfCertScepServerOpts`; all zero-init to the default behavior):
- `ca_id` — CA identifier sent as `message=<id>` on GetCACaps / GetCACert
  to select a specific CA on a multi-CA responder; omitted when NULL.
- `txid_mode` — `WOLFCERT_SCEP_TXID_RANDOM` (default) or `..._PUBKEY_HASH`,
  which derives the transactionID as the SHA-256 of the signer
  public key (RFC 8894 §3.2.1) so retries of the same key reuse one
  ID. Matches wolfSCEP's derivation.
- `content_cipher` — `WOLFCERT_SCEP_CIPHER_AUTO` (default: the caps-driven
  AES-128-CBC / 3DES choice) or an explicit `AES128` / `AES256` / `DES3`.
  There is no GetCACaps token for AES-256, so forcing it is a deliberate choice
  for a peer that requires it (e.g. a wolfSCEP deployment); the envelope is
  self-describing, so any AES-capable recipient decrypts it by OID.

**Signed attributes.** The CertRep carries the full RFC 8894 §3.1
signed-attribute set (including `recipientNonce`) — up to 9 entries alongside
the CMS auto-defaults. wolfSSL's PKCS#7 encoder grows its signed-attribute
array on the heap past the inline `MAX_SIGNED_ATTRIBS_SZ` (default 7), so this
encodes fine on any malloc-enabled build. Only a `WOLFSSL_NO_MALLOC` build with
the default inline cap can't fit it, and there wolfCert drops
`recipientNonce`/`failInfo` unless wolfSSL is rebuilt with
`-DMAX_SIGNED_ATTRIBS_SZ>=9`. The client requires the `recipientNonce`
(RFC 8894 §3.2.1.2) and rejects a CertRep that omits it, so a
`WOLFSSL_NO_MALLOC` server that drops it will not interoperate with a wolfCert
client until wolfSSL is rebuilt with that cap raised. Raise
`-DMAX_SIGNED_ATTRIBS_SZ>=9` on both peers of a `WOLFSSL_NO_MALLOC` deployment.

## 4. MCU / CryptoCb integration guide

An end-to-end recipe for bringing wolfCert up on a memory-constrained,
offload-friendly target. For the RAM-sizing knobs specifically — shrinking the
large wolfSSL `Cert`/`CertName` structures and wolfCert's HTTP stack buffers —
see [`EMBEDDED.md`](EMBEDDED.md).

### 4.1 Heap hints & static-memory pools

Every wolfCert allocation takes a `heap` hint that it forwards unchanged to
wolfSSL. When wolfSSL is built with `WOLFSSL_STATIC_MEMORY`, its `XMALLOC`
uses the hint to pick a bucket in the static pool — the primary mechanism for
bounding wolfCert's heap footprint. Three levels of granularity:

1. **Process-wide default** — `wolfcert_init(my_static_heap_hint)` at startup;
   `wolfcert_set_default_heap(hint)` updates it at runtime.
2. **Per-call override** — `WolfCertKeyCfg.heap`, `WolfCertServerCfg.heap`,
   `WolfCertHttpSessionCfg.heap`, and `WolfCertServerCfgSrv.heap` are each
   honoured for every allocation that services that request.
3. **Compile-time custom allocator** — define `WOLFCERT_CUSTOM_ALLOC` and
   supply your own `WOLFCERT_XMALLOC` / `XFREE` / `XREALLOC` macros, for when
   wolfSSL's `XMALLOC` isn't the right backing store.

The peak allocation points are the TLS handshake (scales with trust-chain
depth and cipher suite), PKCS#7 signing/parsing (a SCEP pkiMessage + envelope
+ signer cert easily exceeds 4–8 KiB), and RSA key generation. Always set
`max_response_bytes` explicitly on MCUs — the 64 KiB default is sized for
hosts.

### 4.2 CryptoCb offload (TPM / HSM / PKCS#11 / custom)

wolfCert uses wolfSSL's CryptoCb `devId` as an opaque token. The application
registers the backend; wolfCert threads the devId through every crypto call:

```c
/* Application startup: register the CryptoCb with wolfSSL. */
wolfCrypt_CryptoCb_RegisterDevice(MY_DEVID, my_callback, my_ctx);

/* Generate a key that lives behind the CryptoCb. */
WolfCertKeyCfg cfg = {
    .type      = WOLFCERT_KEY_ECC,
    .param     = 256,
    .dev_id    = MY_DEVID,
    .key_label = "tpm:/handles/0x01800001",  /* optional */
};
WolfCertKey* key;
wolfcert_key_generate(&cfg, &key);
```

From there, every wolfSSL crypto call on the key — CSR signing, TLS handshake
client-auth, SCEP pkiMessage signing — routes through `my_callback`. Pass
`WOLFCERT_DEVID_SOFTWARE` (`-1`) to force software operation. CryptoCb-resident
keys typically can't be exported in PEM, so `wolfcert_key_to_pem` will fail;
persist the key by its `key_label` instead and resolve it against your backend
on the next boot. See `examples/enroll_cryptocb.c` for a full example.

### 4.3 Non-blocking I/O in a caller-owned event loop

The session API flips to non-blocking mode with a single flag:

```c
WolfCertServerCfg srv = { /* ... as normal ... */ };
WolfCertEstSession* s;
wolfcert_est_session_open_async(&srv, &s);   /* NON-BLOCKING session */

int fd = wolfcert_est_session_fd(s);

WolfCertBuffer ca;
for (;;) {
    int rc = wolfcert_est_session_get_cacerts_nb(s, &ca);
    if (rc == WOLFCERT_OK) break;
    if (rc == WOLFCERT_ERR_WANT_READ)  { poll_fd_readable(fd);  continue; }
    if (rc == WOLFCERT_ERR_WANT_WRITE) { poll_fd_writable(fd);  continue; }
    wolfcert_est_session_close(s);   /* permanent failure */
    return rc;
}
```

Key points:

- **Only the session API is non-blocking.** One-shot `wolfcert_http_request` /
  `wolfcert_est_*` / `wolfcert_scep_*` calls are blocking by design. Both EST
  (`wolfcert_est_session_*_nb`) and SCEP (`wolfcert_scep_session_*_nb`) offer
  non-blocking session variants; the SCEP session additionally does not require
  TLS, since SCEP authenticates at the pkiMessage layer.
- **DNS and the initial TCP connect stay synchronous.** Only socket operations
  *after* the session is open are non-blocking; if you can't afford a blocking
  connect, resolve and connect the socket yourself.
- **The descriptor comes from the built-in transport.** `*_session_fd()`
  returns `-1` on a caller-supplied `WolfCertTransport`, which has no
  descriptor to hand out; drive the loop from whatever readiness signal your
  stack offers instead. See [section 4.6](#46-pluggable-transport).
- **Re-invoke with identical arguments after a WANT-\*.** The session remembers
  its in-flight state; don't mutate the request/response between calls.
- **One in-flight request per session** — pipelining is not supported.

### 4.4 Pluggable storage for flash / NVM

Populate a `WolfCertStoreOps` with your backend and hand it to the store
helpers:

```c
WolfCertStoreOps flash_ops = {
    .read   = flash_read,
    .write  = flash_write,
    .remove = flash_remove,
    .heap   = my_heap,
    .ctx    = &my_flash_state,
};
wolfcert_store_write_cert(&flash_ops, "device.crt", cert.data, cert.len);
```

Keys are opaque strings — map them to flash slots, handles, or paths however
your storage layer prefers. `sensitive = 1` on a write tells you the blob is
private-key material; enforce whatever access-control or encryption policy the
device needs. `wolfcert_store_write_key` / `_read_key` round-trip a
`WolfCertKey` via PEM and always mark the write sensitive.

### 4.5 Logging & errors on targets without stdio

The library is silent by default. Install a sink once at startup:

```c
static void my_log(WolfCertLogLevel lvl, const char* mod,
                   const char* msg, void* ctx)
{
    /* route to RTT, UART, an RTOS log bus, ... */
}
wolfcert_set_log_cb(my_log, NULL);
wolfcert_set_log_level(WOLFCERT_LOG_INFO);   /* default is WARN */
```

Extended error state is thread-local. On metal without TLS support, define
`WOLFCERT_NO_THREAD_LOCAL` and it degrades to a global. After any failing call:

```c
int rc = wolfcert_est_simple_enroll(&srv, csr, csr_len, &cert);
if (rc != WOLFCERT_OK) {
    LOG("wolfCert: %s (ssl=%d): %s",
        wolfcert_strerror(rc),
        wolfcert_last_wolfssl_err(),
        wolfcert_last_error_message());
}
```

The message string is valid until the next wolfCert call on the same thread.

### 4.6 Pluggable transport

wolfCert owns no socket. Every byte on the wire - TLS records and plain HTTP
alike - moves through a `WolfCertTransport`, so a target with no BSD sockets
needs one small glue file in *its own* tree and no change to wolfCert:

```c
typedef struct WolfCertTransport {
    int  (*connect)(void* ctx, const char* host, int port,
                    int timeout_ms, void** conn);
    int  (*read)(void* ctx, void* conn, uint8_t* buf, size_t len,
                 int timeout_ms);
    int  (*write)(void* ctx, void* conn, const uint8_t* buf, size_t len,
                  int timeout_ms);
    int  (*disconnect)(void* ctx, void* conn);
    void* ctx;
} WolfCertTransport;
```

Set it on `WolfCertServerCfg.transport` (or `WolfCertHttpRequest` /
`WolfCertHttpSessionCfg`). Leaving it `NULL` selects the built-in POSIX
instance in `src/net_posix.c`, which is an ordinary implementation of this
same vtable rather than a privileged path.

The contract:

- **The handle is opaque.** `connect` writes it to `*conn`; wolfCert never
  dereferences, compares or NULL-tests it, so `0` is a perfectly valid handle
  (a wolfIP descriptor starts there). It is passed back verbatim.
- **`read` / `write` return a positive byte count**, or a negative
  `WOLFCERT_ERR_*`. Never `0`: an orderly peer close is
  `WOLFCERT_ERR_CONN_CLOSED`, which is what terminates a response body that
  has neither `Content-Length` nor chunking.
- **`connect`'s `timeout_ms` is the caller's**, passed through from
  `WolfCertServerCfg.timeout_ms` / `WolfCertHttpRequest.timeout_ms`. A value
  above zero bounds the whole connect attempt. Zero or less imposes no limit
  of wolfCert's, leaving the stack's own default.
- **`read` / `write`'s `timeout_ms` carries the blocking mode**, and means
  something different from `connect`'s. wolfCert passes only two values.
  `0` asks the call never to block: return `WOLFCERT_ERR_WANT_READ` or
  `WOLFCERT_ERR_WANT_WRITE` rather than wait. `-1` asks it to block until
  bytes move. If your stack has its own receive or send timeout, implement
  `-1` with a call that lets it apply, rather than an unbounded wait around a
  non-blocking transfer: the second shape silently discards whatever the
  application configured.
- **`disconnect` runs exactly once per successful `connect`**, on every error
  path included. A failed `connect` is never paired with one.
- **`ctx` is transport-wide** (the stack instance, say), distinct from the
  per-connection handle. The transport struct must outlive its connections.
- **All four callbacks are required.** An incomplete vtable is rejected with
  `WOLFCERT_ERR_BAD_ARG` before anything is dialled.

TLS needs no extra work from the transport. wolfCert registers its own
wolfSSL CBIO pair against the open connection, so records flow through the
same `read`/`write` as plain HTTP:

```
wolfSSL_read/write -> wolfcert_cbio_recv/send -> t->read / t->write -> your stack
```

`WolfCertServerCfg.connect_cb` is the deprecated predecessor: it yields a
socket descriptor rather than an opaque handle, which is exactly what a
non-socket stack cannot supply. It still works, adapted internally onto the
POSIX byte path, but setting both it and `transport` is `WOLFCERT_ERR_BAD_ARG`.

Building with `WOLFCERT_ENABLE_BUILTIN_TRANSPORT=OFF` (CMake) or
`--disable-builtin-transport` (autoconf) drops `src/net_posix.c` from the
library entirely, so a target with no sockets links no socket code. A config
that then leaves `transport` NULL fails with `WOLFCERT_ERR_BAD_ARG`.

### 4.7 Putting it together

```c
/* 1. Startup */
wolfCrypt_CryptoCb_RegisterDevice(MY_DEVID, my_callback, my_ctx);
wolfcert_init(my_static_heap_hint);
wolfcert_set_log_cb(my_log, NULL);

/* 2. Key generation (stays in hardware) */
WolfCertKey* key;
WolfCertKeyCfg kcfg = { .type = WOLFCERT_KEY_ECC, .param = 256,
                        .dev_id = MY_DEVID };
wolfcert_key_generate(&kcfg, &key);

/* 3. CSR build */
WolfCertBuffer csr;
WolfCertCertMeta meta = { .subject_dn = "CN=device-123,O=Acme",
                          .san_dns = (const char*[]){ "device-123.local" },
                          .san_dns_len = 1 };
wolfcert_csr_build(key, &meta, &csr);

/* 4. Non-blocking enrollment over HTTPS with factory mTLS */
WolfCertServerCfg srv = {
    .protocol           = WOLFCERT_PROTO_EST,
    .server_url         = "https://ca.example/.well-known/est",
    .trust_anchors      = bootstrap_ca_pem,
    .trust_anchors_len  = bootstrap_ca_len,
    .verify_server      = 1,
    .client_cert        = factory_cert, .client_cert_len = factory_cert_len,
    .client_key         = factory_key,  .client_key_len  = factory_key_len,
    .max_response_bytes = 8 * 1024,   /* tighten for MCU */
    .proto_opts.est     = { .allow_post_handshake_auth = 1 },
};
WolfCertEstSession* s;
wolfcert_est_session_open_async(&srv, &s);
run_nb_loop(s);                              /* pattern from section 4.3 */
wolfcert_est_session_close(s);

/* 5. Persist to flash through our storage backend */
wolfcert_store_write_cert(&flash_ops, "device.crt", cert.data, cert.len);
/* key stays behind the CryptoCb; persist its label instead */

/* 6. Shutdown */
wolfcert_key_free(key);
wolfcert_buffer_free(&csr);
wolfcert_buffer_free(&cert);
wolfcert_cleanup();
```

## 5. Extension points

Four small vtables carry all of wolfCert's pluggability. Each is a "fill in a
struct, no library changes" extension:

- **`WolfCertKeyAlg`** (`src/key_algs.c`) — algorithm dispatch. Adding a key
  algorithm is one struct literal pairing the `WolfCertKeyType` with its
  wolfSSL constants and `alloc_init` / `make` / `priv_decode` / `priv_to_der`
  / `free_` callbacks, plus an optional `WOLFCERT_HAVE_<ALG>` compile guard. No
  edits to `keygen.c`, `csr.c`, or `ca_issue.c`.
- **`WolfCertStoreOps`** (`wolfcert/store.h`) — storage backend. Supply
  `read` / `write` / `remove` callbacks and a private `ctx`; keys are opaque
  strings. Shipped backends: POSIX files (atomic write, 0600 key mode) and
  in-memory. See [section 4.4](#44-pluggable-storage-for-flash--nvm).
- **`WolfCertTransport`** (`wolfcert/types.h`) — the bytes on the wire. Supply
  `connect` / `read` / `write` / `disconnect` and a private `ctx` to run
  wolfCert on a non-BSD-sockets stack; TLS rides the same callbacks through an
  internal CBIO bridge. The built-in POSIX transport is one instance of it.
  See [section 4.6](#46-pluggable-transport).
- **`WolfCertServerOps`** (`src/internal.h`) — test-server protocol dispatch.
  The EST and SCEP handlers are exposed through
  `wolfcert_est_server_ops()` / `wolfcert_scep_server_ops()` factories; a third
  protocol would be a factory plus a handful of handler functions.

For caller-supplied certificate fields that the subject-DN string and SAN
arrays can't express, use the `WolfCertCertMeta::customize` callback — it hands
you the wolfSSL `Cert*` to mutate before signing, rather than requiring a
library change.

## 6. Build & feature gating

wolfCert builds with **CMake** (primary) and **autoconf/automake** (parity),
producing the same `libwolfcert`. The full build recipe, the wolfSSL version
requirement, and the canonical wolfSSL configure line live in
[`README.md`](../README.md#building). This section covers the gating that
matters when trimming a build.

**Toggles** (CMake `-DWOLFCERT_ENABLE_*=ON/OFF`, autoconf `--enable/--disable-*`):
`EST`, `SCEP`, `SERVER` (the test server + local CA), `CLI`, `TESTS`,
`EXAMPLES`, `BUILD_SHARED`. A disabled subsystem's sources drop
out of the link entirely. The resolved flags are written into a generated
`wolfcert/options.h`, which the public headers key off so an application can
include `<wolfcert/wolfcert.h>` without knowing what was compiled in.
`wolfcert/types.h` is the single entry point: it includes that generated
`options.h`, or - when `WOLFCERT_USER_SETTINGS` is defined - a user-supplied
`user_settings.h` (the wolfSSL `WOLFSSL_USER_SETTINGS` analogue, for header-only
builds with no configure step), then unconditionally includes
`wolfcert/check_config.h`, which re-checks the resolved feature set as compile-
time `#error`s. See [`EMBEDDED.md`](EMBEDDED.md#configuring-wolfcert-without-its-build-system-user_settingsh).

**Required wolfSSL features** (build hard-fails with a "rebuild wolfSSL with
--enable-X" diagnostic if missing): `HAVE_PKCS7`, `WOLFSSL_CERT_GEN`,
`WOLFSSL_CERT_REQ`, `WOLFSSL_CERT_EXT`, `WOLFSSL_KEY_GEN`, `WOLF_CRYPTO_CB`,
`WOLFSSL_BASE64_ENCODE`, `OPENSSL_EXTRA`, `WOLFSSL_ALT_NAMES`,
`WOLFSSL_CERT_NAME_ALL`. A `NO_RSA` build hard-fails unless SCEP is disabled.

**Optional wolfSSL features** (absent → a warning; that key type returns
`WOLFCERT_ERR_UNSUPPORTED` at runtime): the key algorithms — RSA (`NO_RSA`
absent), ECC (`HAVE_ECC`), `HAVE_ED25519`, `HAVE_ED448`, and
`WOLFSSL_HAVE_MLDSA` (FIPS 204 ML-DSA-44/65/87) — plus
`WOLFSSL_POST_HANDSHAKE_AUTH` (probed at runtime for the PHA opt-in). At least
one key algorithm must be present.

## 7. Further reading

- [`README.md`](../README.md) — quick start, CLI examples, build instructions,
  and third-party interop status.
- [`EMBEDDED.md`](EMBEDDED.md) — RAM-sizing knobs for constrained targets.
- `wolfcert/*.h` — the authoritative API reference; every function and struct
  field carries an inline contract / ownership note.
- `examples/enroll_est.c`, `examples/enroll_scep.c`,
  `examples/enroll_cryptocb.c` — runnable minimal integrations.
