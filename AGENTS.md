# wolfCert Integration Guide for Agents

wolfCert is a C library for client-side certificate lifecycle management on
top of wolfSSL: fetch the CA chain, generate a key, build a CSR, enroll and
re-enroll, persist the result. It speaks EST (RFC 7030) and SCEP (RFC 8894)
over HTTP/S and targets everything from Linux hosts to RTOS and bare-metal
devices. Current version is v0.1.0 (`wolfcert/version.h`). Dual licensed:
GPL-3.0-or-later or a commercial license from wolfSSL Inc.

This file is for agents helping users *integrate wolfCert into their own
projects*. If `AGENTS.local.md` or `CLAUDE.local.md` exists in the repository
root, read it before starting work. Those files are gitignored, carry
maintainer- and machine-specific instructions, and take precedence over this
file. Changes to wolfCert itself follow `CONTRIBUTING.md`.

## Choose an integration path

| Situation | Path |
|---|---|
| CMake-based project | CMake: `find_package(wolfCert)` after install, or `add_subdirectory()`; link `wolfCert::wolfcert` |
| Unix-like host or cross-compile with autotools | Autoconf (`./configure`), consume via `pkg-config wolfcert` |
| IDE, RTOS or bare-metal build with no configure step | `user_settings.h` + `-DWOLFCERT_USER_SETTINGS` (`docs/EMBEDDED.md`) |
| Zephyr | `zephyr/` module (`module.yml`, Kconfig), see `zephyr/README.md` |
| Moving off wolfSCEP | `docs/MIGRATING-FROM-WOLFSCEP.md` |

## wolfSSL comes first

Most integration failures are a wolfSSL built without what wolfCert needs.
wolfCert requires **wolfSSL >= 5.9.4** and **hard-fails at configure time**
if the wolfSSL it finds lacks any of `HAVE_PKCS7`, `WOLFSSL_CERT_GEN`,
`WOLFSSL_CERT_REQ`, `WOLFSSL_CERT_EXT`, `WOLFSSL_KEY_GEN`, `WOLF_CRYPTO_CB`,
`WOLFSSL_BASE64_ENCODE`, `WOLFSSL_ALT_NAMES` or `WOLFSSL_CERT_NAME_ALL`, was
built with `NO_AES` / `NO_SHA256`, or provides neither TLS 1.2 nor TLS 1.3.

- **SCEP** additionally needs RSA and AES-128-CBC encrypt and decrypt
  (`NO_RSA`, `NO_AES_128`, `NO_AES_CBC` or `NO_AES_DECRYPT` hard-fail unless
  SCEP is disabled), since RFC 8894 is RSA-only and makes AES-128-CBC
  mandatory.
- **Shared libwolfssl** must export the `WOLFSSL_ASN_API` helpers wolfCert
  calls, which needs one of `WOLFSSL_PUBLIC_ASN` (the lean choice),
  `OPENSSL_EXTRA`, `OPENSSL_EXTRA_X509_SMALL` or `WOLFSSL_TEST_CERT`. A static
  libwolfssl links them regardless. The OpenSSL compatibility layer itself is
  not required.
- **ML-DSA** additionally needs `WOLFSSL_MLDSA_CHECK_KEY`, which
  `--enable-mldsa` gives by default; it is lost with
  `WOLFSSL_DILITHIUM_NO_CHECK_KEY` or `WOLFSSL_MLDSA_VERIFY_ONLY`.

The canonical wolfSSL configure line satisfies every requirement and enables
every optional key type:

```sh
./configure --enable-pkcs7 --enable-certgen --enable-certreq \
    --enable-certext --enable-keygen --enable-ecc --enable-cryptocb \
    --enable-base64encode --enable-ed25519 --enable-ed448 \
    --enable-mldsa --enable-postauth --enable-ip-alt-name \
    --enable-des3 --enable-sni \
    CPPFLAGS="-DWOLFSSL_ALT_NAMES -DWOLFSSL_CERT_NAME_ALL \
              -DKEEP_PEER_CERT -DWOLFSSL_PUBLIC_ASN \
              -DWOLFSSL_HAVE_TLS_UNIQUE"
```

`KEEP_PEER_CERT` and `WOLFSSL_HAVE_TLS_UNIQUE` are needed only by the test
server (post-handshake auth and `/simplereenroll`), and `--enable-des3` only
to talk to SCEP peers that still use DES, such as micromdm. A device-side
client can leave all three out.

## Build and install

```sh
# CMake (primary)
cmake -S . -B build -DWITH_WOLFSSL=/path/to/wolfssl/prefix
cmake --build build -j
cmake --install build

# Autoconf (kept at parity)
./autogen.sh                        # git checkouts only
./configure --with-wolfssl=/path/to/wolfssl/prefix
make -j && make install
```

Without an explicit path, CMake looks for wolfSSL's CMake package and then
`pkg-config`; autoconf uses `pkg-config`. The
install provides the library, the public headers, a generated
`wolfcert/options.h`, `wolfcert.pc`, the CMake package files and the
`wolfcert-client` / `wolfcert-server` CLIs.

| CMake | Autoconf | Default | Effect |
|---|---|---|---|
| `WOLFCERT_ENABLE_EST` | `--enable-est` | on | EST client |
| `WOLFCERT_ENABLE_SCEP` | `--enable-scep` | on | SCEP client; pulls in RSA |
| `WOLFCERT_ENABLE_SERVER` | `--enable-server` | on | Minimal EST/SCEP test server |
| `WOLFCERT_ENABLE_CLI` | `--enable-cli` | on | `wolfcert-client`, `wolfcert-server` |
| `WOLFCERT_ENABLE_BUILTIN_TRANSPORT` | `--enable-builtin-transport` | on | POSIX socket transport; turn off on targets with no sockets |
| `WOLFCERT_ENABLE_POSIX_STORE` | `--enable-posix-store` | on | File-based cert/key store |
| `WOLFCERT_BUILD_SHARED` | (libtool `--enable-shared`) | on | Shared vs static library |
| `WOLFCERT_USER_SETTINGS` | `--enable-user-settings` | off | Read features from `user_settings.h` instead of the generated `options.h` |

A device build usually turns off the server and CLI, and the built-in
transport and POSIX store where the target has no sockets or filesystem.

## Configuration model

wolfCert records its resolved features (`WOLFCERT_HAVE_EST`,
`WOLFCERT_HAVE_SCEP`, `WOLFCERT_HAVE_<ALG>` for RSA, ECC, ED25519, ED448 and
MLDSA, ...) in a generated `wolfcert/options.h`, the way wolfSSL does with
`wolfssl/options.h`. `wolfcert/types.h` includes it, so applications only
include `<wolfcert/wolfcert.h>`, which pulls in the EST and SCEP headers that
were compiled in.

- **Key algorithms follow wolfSSL.** Each one wolfSSL lacks is dropped with a
  warning and returns `WOLFCERT_ERR_UNSUPPORTED` at run time. At least one
  must remain.
- **No build system:** define `WOLFCERT_USER_SETTINGS` for the library and
  the application, and supply a `user_settings.h` started from
  `examples/user_settings.h.example`. `docs/EMBEDDED.md` explains the file
  and how to share the name with wolfSSL's own `user_settings.h`.
- `wolfcert/check_config.h` validates the resolved feature set at compile
  time, so a broken combination fails the build with a specific `#error`.

## EST or SCEP

| | EST (RFC 7030) | SCEP (RFC 8894) |
|---|---|---|
| Transport | HTTPS, server authentication mandatory | HTTP or HTTPS (HTTPS needs `verify_server`); security is in the PKCS#7 messages |
| Client authentication | mTLS (e.g. factory cert), HTTP Basic, TLS 1.3 post-handshake auth | `challengePassword` |
| Key types | RSA, ECC P-256/384/521, Ed25519, Ed448, ML-DSA-44/65/87 | RSA only |
| Typical peers | IoT and industrial PKI, Cisco libest, GlobalSign | MDM and network gear, micromdm, step-ca |
| High-level API | `wolfcert_client_*` | `wolfcert_scep_*` |

Pick EST unless the CA only speaks SCEP.

## Minimal enrollment flow

EST through the high-level client, with a TLS trust anchor for the server:

```c
#include <wolfcert/wolfcert.h>

wolfcert_init(NULL);                    /* NULL: system allocator */
WolfCertClient* client = NULL;
wolfcert_client_new(&client);

WolfCertServerCfg srv = {
    .protocol          = WOLFCERT_PROTO_EST,
    .server_url        = "https://ca.example/.well-known/est",
    .trust_anchors     = ca_pem,        /* PEM or DER */
    .trust_anchors_len = ca_pem_len,
    .verify_server     = 1,
};
WolfCertKeyCfg   kcfg = { .type = WOLFCERT_KEY_ECC, .param = 256,
                          .dev_id = WOLFCERT_DEVID_SOFTWARE };
WolfCertCertMeta meta = { .subject_dn = "CN=device-0001" };
WolfCertKey*     key  = NULL;
WolfCertBuffer   cert = { 0 };

int rc = wolfcert_client_enroll(client, &srv, &kcfg, &meta, &key, &cert);
if (rc != WOLFCERT_OK)
    printf("%s: %s\n", wolfcert_strerror(rc), wolfcert_last_error_message());

wolfcert_buffer_free(&cert);
wolfcert_key_free(key);
wolfcert_client_free(client);
wolfcert_cleanup();
```

- **SCEP:** `wolfcert_scep_get_ca_cert`, check it against an out-of-band
  fingerprint with `wolfcert_scep_verify_ca_fingerprint`, then
  `wolfcert_scep_get_ca_caps` and `wolfcert_scep_pkcs_req` with an RSA key.
  Set `meta.challenge_password` if the CA requires one.
  `examples/enroll_scep.c` is the full flow.
- **Step by step:** `wolfcert_key_generate`, `wolfcert_csr_build`, then
  `wolfcert_est_simple_enroll` (`examples/enroll_est.c`).
- **Pending approval:** the `_ex` variants report a status of PENDING; poll
  again later (EST: re-POST after `retry_after_sec`; SCEP:
  `wolfcert_scep_get_cert_initial`). The plain variants return
  `WOLFCERT_ERR_PENDING`.
- **Renewal:** `wolfcert_client_reenroll` (EST, authenticates with the
  certificate being renewed) or `wolfcert_scep_renewal_req`.
- **Hardware keys:** `examples/enroll_cryptocb.c`.

## Where to look

| Path | Contents |
|---|---|
| `wolfcert/wolfcert.h` | Umbrella header, `wolfcert_init` / `wolfcert_cleanup` |
| `wolfcert/client.h` | High-level `wolfcert_client_*` API |
| `wolfcert/est.h`, `wolfcert/scep.h` | Protocol one-shots, `_ex` PENDING variants, sessions, non-blocking `_nb` sessions |
| `wolfcert/types.h` | `WolfCertServerCfg`, `WolfCertKeyCfg`, `WolfCertCertMeta`, `WolfCertTransport`, `wolfcert_buffer_free` |
| `wolfcert/keygen.h`, `wolfcert/csr.h` | Key generation, import / export, CSR building |
| `wolfcert/store.h` | `WolfCertStoreOps` storage vtable, POSIX and in-memory backends |
| `wolfcert/errors.h`, `wolfcert/status.h`, `wolfcert/log.h` | Error codes, last-error detail, log callback |
| `wolfcert/memory.h` | Default heap hint, allocation macros |
| `examples/` | `enroll_est.c`, `enroll_scep.c`, `enroll_cryptocb.c`, `user_settings.h.example` |
| `examples/certs/` | Test credentials; never ship them |
| `zephyr/samples/wolfcert_est_client/` | EST client on Zephyr (qemu_x86, FRDM-MCXN947) |
| `src/` | Implementation; `src/internal.h` is not for applications |

The headers are the API reference: each public function and field states its
contract, alone or in a group comment.

## Porting hooks

| Need | Hook | Where |
|---|---|---|
| Static memory / custom heap | `wolfcert_init(heap)` sets the default heap hint; per-call `heap` fields override it, and the hint reaches every wolfSSL call | `wolfcert/memory.h`, README "Integrating with a wolfSSL static-memory pool" |
| Network stack without BSD sockets (lwIP, NetX, FreeRTOS+TCP, wolfIP) | Fill `WolfCertServerCfg.transport` (`WolfCertTransport`); TLS records go through it too | `wolfcert/types.h`, `docs/EMBEDDED.md` section 7 |
| Persistence in flash / NVM | Implement `WolfCertStoreOps` (`read` / `write` / `remove`) | `wolfcert/store.h` |
| Keys in a TPM, HSM, PKCS#11 token or secure element | Register a backend with `wc_CryptoCb_RegisterDevice`, pass its id as `WolfCertKeyCfg.dev_id` | `docs/ARCHITECTURE.md` section 4.2, `examples/enroll_cryptocb.c` |
| Event loop / no blocking | `wolfcert_est_session_open_async` / `wolfcert_scep_session_open_async`, then the `_nb` calls until they stop returning `WOLFCERT_ERR_WANT_READ` / `_WANT_WRITE`; `*_session_fd` gives the descriptor to poll | `wolfcert/est.h`, `wolfcert/scep.h` |
| Logging | `wolfcert_set_log_cb` (e.g. to a UART) | `wolfcert/log.h` |
| RAM budget | `max_response_bytes`, HTTP stack buffers, wolfSSL `Cert` / `CertName` sizing | `docs/EMBEDDED.md` |

## Verifying an integration

- The test server and CLI make a loopback peer for any client code:

  ```sh
  wolfcert-server --proto est --listen 127.0.0.1:8443 \
      --tls-cert server.crt --tls-key server.key --est-allow-anonymous
  wolfcert-client enroll --proto est \
      --url https://127.0.0.1:8443/.well-known/est --trust server.crt \
      --key-type ecc:256 --subject "CN=dev" \
      --out-key dev.key --out-cert dev.crt
  ```

  README "Quick start" has the SCEP and CA-pinning variants; `--help` on
  either tool lists the client authentication and approval options.
- `wolfcert-client` also covers `getcacerts`, `reenroll` (EST) and
  `getnextca` / `getcert` (SCEP), which is handy for checking a production CA
  before writing code against it.
- On Zephyr, the EST client sample runs against a host `wolfcert-server`;
  `zephyr/README.md` has the steps and the stack sizing.

## Gotchas

- **Set `verify_server` to 1.** A zero-initialized config leaves it at 0,
  which every EST call and SCEP over `https://` refuse with
  `WOLFCERT_ERR_TLS`. Plain-HTTP SCEP ignores it and relies on the CA
  fingerprint check instead.
- **The `wolfcert_client_*` calls are EST-only except `get_ca`.** For SCEP
  they return `WOLFCERT_ERR_UNSUPPORTED`; use `wolfcert_scep_*`.
- **SCEP rejects non-RSA keys** with `WOLFCERT_ERR_UNSUPPORTED`, and an ECC
  RA/CA certificate as well. Use EST for ECC, EdDSA or ML-DSA device keys.
- **Set `protocol` on every config**, not only for the `wolfcert_client_*`
  calls: every `wolfcert_est_*` / `wolfcert_scep_*` entry point returns
  `WOLFCERT_ERR_BAD_ARG` on a mismatch.
- **`max_response_bytes` defaults to 64 KiB**, sized for hosts. Set it on an
  MCU.
- **The HTTPS transport needs TLS 1.2 or newer**, or TLS 1.3 when wolfSSL
  is built with `WOLFSSL_NO_TLS12`. A server limited to older versions
  fails the handshake.
- **Non-blocking mode still blocks for DNS and the initial TCP connect.**
- **The test server is for development and interop only**, not a production
  CA.
- **SCEP over plain HTTP is downgradable:** an attacker who strips `AES` from
  GetCACaps forces 3DES. Pin the CA fingerprint and force AES with
  `proto_opts.scep.content_cipher` where the network is untrusted.
- **Error detail:** `wolfcert_strerror(rc)` names the code;
  `wolfcert_last_error_message()` and `wolfcert_last_wolfssl_err()` give the
  detail behind it, per thread when wolfSSL's `THREAD_LS_T` is thread-local
  (`HAVE_THREAD_LS`, outside FreeRTOS and Zephyr).

## Further documentation

- `README.md`: quick start, capabilities and limitations, interoperability.
- `docs/ARCHITECTURE.md`: design, protocol flows with sequence diagrams, and
  the MCU / CryptoCb integration guide (section 4).
- `docs/EMBEDDED.md`: RAM sizing, `user_settings.h` builds, targets without
  sockets or a filesystem, Zephyr.
- `docs/INTEROP.md`: tested third-party EST and SCEP peers.
- `docs/MIGRATING-FROM-WOLFSCEP.md`: call mapping from wolfSCEP.
- Support and commercial licensing: support@wolfssl.com,
  licensing@wolfssl.com.
