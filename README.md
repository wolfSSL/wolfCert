# wolfCert

`wolfCert` is a C library for client-side **certificate lifecycle
management**, built on top of [wolfSSL](https://www.wolfssl.com/). It lets an
application or device:

- retrieve CA (trust chain) certificates from a PKI,
- enroll for a new end-entity certificate,
- re-enroll an existing certificate for a new validity period,
- generate the associated private key on the device (software or offloaded),
- build the CSR, submit it, and persist the issued certificate.

Two enrollment protocols are supported, both over HTTP(S):

- **EST** (RFC 7030) — all key types
- **SCEP** (RFC 8894) — RSA only, per the spec

Keys can be generated and used as software keys or via any backend registered
with wolfSSL's **CryptoCb** interface — the same mechanism wolfSSL uses to
offload to HSMs, TPMs, PKCS#11 tokens, or secure elements. wolfCert stays
backend-agnostic: the application registers a CryptoCb and passes the
resulting `devId` through the wolfCert API (see `examples/enroll_cryptocb.c`).

Certificate metadata is supplied by the caller. The subject-DN string parser
understands `CN`, `O`, `OU`, `C`, `ST`, `L`, `SN`, `GN`, `emailAddress`,
`serialNumber`, `UID`, `postalCode`, and `businessCategory`; SANs cover
`dNSName`, `iPAddress`, `URI`, and `rfc822Name`. Anything the string/struct
can't express is reachable via the `WolfCertCertMeta::customize` callback,
which hands you a `wolfSSL_Cert*` to mutate before signing.

## Building

wolfCert supports both **CMake** and **autoconf**, matching the conventions of
sibling wolfSSL projects.

### CMake

```sh
cmake -S . -B build \
    -DWOLFCERT_ENABLE_EST=ON \
    -DWOLFCERT_ENABLE_SCEP=ON \
    -DWOLFCERT_ENABLE_SERVER=ON \
    -DWOLFCERT_ENABLE_CLI=ON \
    -DWOLFCERT_ENABLE_TESTS=ON
cmake --build build -j
ctest --test-dir build --output-on-failure
```

### Autoconf

```sh
./autogen.sh
./configure --enable-est --enable-scep --enable-server --enable-cli
make -j
```

### wolfSSL prerequisite

wolfCert targets **wolfSSL >= 5.9.2** and must find it via `pkg-config`
(`wolfssl`). The configure-time probe hard-fails with a specific "rebuild
wolfSSL with --enable-X" diagnostic if a required wolfSSL feature is missing.
A canonical wolfSSL configure line that satisfies every requirement, plus the
optional key types wolfCert picks up when available:

```sh
./configure \
    --enable-pkcs7 --enable-certgen --enable-certreq --enable-certext \
    --enable-keygen --enable-ecc --enable-cryptocb --enable-base64encode \
    --enable-ed25519 --enable-ed448 --enable-mldsa \
    --enable-postauth --enable-opensslextra --enable-ip-alt-name \
    --enable-des3 \
    CPPFLAGS="-DWOLFSSL_ALT_NAMES -DWOLFSSL_CERT_NAME_ALL"
```

### Header-based configuration (no build system)

Embedded toolchains that drive their own build can skip wolfCert's configure
step and supply the feature set as a header, like wolfSSL's `user_settings.h`:
build with `-DWOLFCERT_USER_SETTINGS` and put a `user_settings.h`
(copied from [`examples/user_settings.h.example`](examples/user_settings.h.example))
on the include path. See [`docs/EMBEDDED.md`](docs/EMBEDDED.md#configuring-wolfcert-without-its-build-system-user_settingsh).

## Quick start

Start the bundled test server (issues from an auto-generated local CA):

```sh
./wolfcert-server --proto est  --listen 127.0.0.1:8443
./wolfcert-server --proto scep --listen 127.0.0.1:8088
```

Enroll a certificate from the CLI:

```sh
# EST
./wolfcert-client enroll --proto est \
    --url http://127.0.0.1:8443/.well-known/est \
    --key-type ecc:256 --subject "CN=device-1,O=Acme" \
    --san-dns device-1.local --out-key dev.key --out-cert dev.crt

# SCEP (RSA only)
./wolfcert-client enroll --proto scep --url http://127.0.0.1:8088/scep \
    --key-type rsa:2048 --subject "CN=device-2" \
    --out-key dev.key --out-cert dev.crt
```

The CLI also covers TLS / mutual TLS (`--trust`, `--client-cert`,
`--client-key`), TLS 1.3 post-handshake auth (`--pha`), SCEP polling
(`--poll-attempts`, `--poll-interval-ms`), `getnextca`, and `/csrattrs`
key-policy pinning (`--csrattrs-auto`). The SCEP-specific knobs are
`--ca-id` (select one CA on a multi-CA responder), `--txid-mode` (`random`
or `pubkey`, the RFC 8894 §3.2.1 public-key derivation) and
`--content-cipher` (`auto`, `aes128`, `aes256`, `des3` - force one for a
peer that requires it, since no GetCACaps keyword advertises AES-256).
Options that belong to one protocol are rejected under the other rather
than silently ignored. Run `wolfcert-client --help` and
`wolfcert-server --help` for the full set.

EST mandates authenticating the server (RFC 7030), so an EST enroll needs
`--trust PEMFILE` (or a caller-supplied trust anchor). Without it the client
refuses rather than hand its credentials and CSR to an unverified server.

To call the library directly, see `examples/enroll_est.c`,
`examples/enroll_scep.c`, and `examples/enroll_cryptocb.c`.

### Integrating with a wolfSSL static-memory pool

Every wolfCert allocation carries a heap hint that threads through to wolfSSL,
so a static-memory pool is honoured end to end:

```c
/* Application startup. The heap hint flows to every wolfCert allocation
 * and, in turn, to every wolfSSL call wolfCert makes. */
wolfcert_init(my_static_heap_hint);

/* Per-object override (here: force a specific pool for a device key): */
WolfCertKeyCfg cfg = { .type = WOLFCERT_KEY_ECC, .param = 256,
                       .dev_id = WOLFCERT_DEVID_SOFTWARE,
                       .heap = slow_path_pool };
wolfcert_key_generate(&cfg, &key);
```

All `WolfCertBuffer` outputs remember which heap they came from, so the same
`wolfcert_buffer_free()` works for every combination.

## Capabilities & limitations

- **Key algorithms:** RSA-2048/3072/4096, ECC P-256/P-384/P-521, Ed25519,
  Ed448, and ML-DSA-44/65/87 (the last three conditional on the wolfSSL
  build). Keys run in software or through any wolfSSL CryptoCb backend.
- **SCEP is RSA-only** (per RFC 8894); use EST for the other key types.
- **EST endpoints:** `/cacerts`, `/simpleenroll`, `/simplereenroll`,
  `/csrattrs`.
- **SCEP operations:** `GetCACaps`, `GetCACert`, `GetNextCACert`, `PKCSReq`,
  `RenewalReq`, plus `pkiStatus=PENDING` + `GetCertInitial` polling.
- **Transport:** HTTP/1.1 over wolfSSL TLS 1.3/1.2 (trust anchors, SNI,
  mutual TLS), keep-alive sessions, TLS 1.3 post-handshake auth, and an
  optional non-blocking mode for `poll`/`epoll`/`kqueue` event loops. Every
  byte goes through the `WolfCertTransport` vtable, TLS records included, so
  a non-BSD-sockets stack (FreeRTOS+TCP, NetX, lwIP, wolfIP) needs one small
  glue file and no wolfCert change; the POSIX transport is the default
  instance and can be compiled out.
- **Storage:** file-based cert/key store with atomic writes and 0600 key-file
  mode; pluggable via the `WolfCertStoreOps` vtable.
- **Test servers + CLIs** for Linux/macOS (`wolfcert-server`,
  `wolfcert-client`). The servers are for development and interop testing,
  not production CA use.

## Interoperability

Beyond its own client↔server test suite, wolfCert is checked by hand against
third-party EST and SCEP implementations using the scripts under
`tests/interop/`. EST interop passes — Cisco libest, globalsign/est, and
OpenSSL `cms`/`pkcs7` cross-verification of wolfCert's PKCS#7 output. A few
caveats apply to SCEP and to some servers:

- On wolfSSL ≥ 5.9, micromdm's `scepserver` (signs its CertRep with SHA-1)
  and Smallstep step-ca's SCEP (EnvelopedData key-wrap algorithm) are
  rejected by wolfSSL's stricter PKCS#7 verification.
- step-ca's EST endpoints are only in the commercial build, not open-source.
- When serving strict third-party SCEP *clients*, wolfCert's CertRep carries
  the full RFC 8894 signed-attribute set including `recipientNonce`. This
  works on any malloc-enabled wolfSSL (its PKCS#7 encoder grows the
  signed-attribute array on the heap); only a `WOLFSSL_NO_MALLOC` build needs
  wolfSSL rebuilt with `-DMAX_SIGNED_ATTRIBS_SZ>=9` to fit it.

## Documentation

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — design overview, protocol
  flows, and the MCU / CryptoCb integration guide.
- [`docs/EMBEDDED.md`](docs/EMBEDDED.md) — tuning wolfCert's RAM footprint for
  constrained targets.
- [`docs/CI.md`](docs/CI.md) — the GitHub Actions pipeline, the shared
  `scripts/ci/build-wolfssl.sh` helper, and how to reproduce a CI config
  locally.
- [`docs/MIGRATING-FROM-WOLFSCEP.md`](docs/MIGRATING-FROM-WOLFSCEP.md) — moving an
  existing wolfSCEP integration to wolfCert: call mapping, the behavioural
  differences, and a worked enrollment.

## License

wolfCert is dual-licensed, like the rest of the wolfSSL product line:

- **Open source:** the **GNU General Public License v3.0 or later** — see
  [LICENSE](./LICENSE).
- **Commercial:** for users who cannot use wolfCert under the GPL, a
  commercial license is available. Contact wolfSSL at
  [licensing@wolfssl.com](mailto:licensing@wolfssl.com) or +1 425 245-8247,
  or visit [www.wolfssl.com](https://www.wolfssl.com).
