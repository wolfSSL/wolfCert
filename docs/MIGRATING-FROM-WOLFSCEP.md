# Migrating from wolfSCEP to wolfCert

wolfCert is the successor to wolfSCEP for SCEP client work. It speaks the same protocol (RFC 8894) against the same servers, and as of the wolfSCEP-compatibility work it also matches wolfSCEP on the three behaviours that are not in the RFC: the CA identifier sent on `GetCACaps` and `GetCACert`, the transactionID derived from the enrollee public key, and an explicitly chosen content-encryption cipher.

This document is for someone with a working wolfSCEP integration who wants to move it. It assumes you know your own call sites; it does not assume you know wolfCert. For the design behind wolfCert, read `ARCHITECTURE.md` after this.

## At a glance

| | wolfSCEP | wolfCert |
|---|---|---|
| Build | autotools, separate library | CMake (primary) or autotools |
| wolfSSL prerequisite | `--enable-scep` | a feature set checked at configure time, see below |
| Protocols | SCEP | SCEP and EST (RFC 7030) |
| Transport | yours: socket, HTTP framing, TLS | wolfCert's: HTTP and TLS included |
| Shape | request and response primitives | one call per PKI operation |
| Key algorithms | RSA (SCEP is RSA-only) | RSA for SCEP; also ECC, Ed25519, Ed448 and ML-DSA over EST |

## The change that matters

wolfSCEP is HTTP transport. It frames the request for each SCEP operation, moves the bytes, reads the reply and hands you the body. It does not build or parse a single pkiMessage: there is no `wc_PKCS7_EncodeSignedData` or `wc_PKCS7_DecodeSignedData` call anywhere in it. Your application does that work, which is why a wolfSCEP integration always carries a slab of `wc_PKCS7_*` code that builds the EnvelopedData, wraps it in SignedData, and sets the `transactionID`, `senderNonce` and `messageType` signed attributes by hand.

So on top of wolfSCEP you also own: the socket (`wolfSCEP_set_fd()`, or `WS_CallbackIORecv` and `WS_CallbackIOSend` that you pump yourself), the host, port and user agent (`wolfSCEP_set_httpField()`), the CGI path (`wolfSCEP_set_cgi()`), the wolfSSL `SSL*` for HTTPS, the whole request pkiMessage handed over as a bundle, the CertRep parse, the CA fingerprint check, and the polling loop.

wolfCert takes a URL and returns a certificate. HTTP, TLS, the CMS round trip and the response checks are inside the library.

The practical consequence is that a migration deletes code rather than translating it, and the largest part of what goes is the cryptographic message layer, not the plumbing. The `wc_PKCS7_*` request builder, the signed-attribute handling, the CertRep parse and de-envelope, the fingerprint helper, the socket setup, the TLS wiring, the response buffer sizing and the polling loop all go. What remains is a config struct and one call per operation.

If you must keep your own transport, for example on an RTOS with a proprietary stack, set `WolfCertServerCfg.connect_cb`. wolfCert then asks you for a connected socket and still does the HTTP and TLS on top of it.

## Call mapping

| wolfSCEP | wolfCert |
|---|---|
| `wolfSCEP_CTX_new` / `wolfSCEP_new` / `_free` | none needed; `WolfCertServerCfg` is a plain value you fill in |
| `wolfSCEP_set_fd`, `wolfSCEP_SetIORecv`, `wolfSCEP_SetIOSend`, `wolfSCEP_SetIOReadCtx` | handled internally; `srv.connect_cb` if you need your own transport |
| `wolfSCEP_set_httpField(name, host, port)`, `wolfSCEP_set_cgi` | all part of `srv.server_url` |
| `wolfSCEP_set_getCaId` | `srv.proto_opts.scep.ca_id` |
| `wolfSCEP_set_bundle` (the pkiMessage your application built) | nothing to pass: wolfCert builds the pkiMessage. You supply `csr_der`, `ra_cert` and `ca_bundle` and it does the rest |
| `wolfSCEP_request(WS_REQUEST_CACAPS)` then `wolfSCEP_response` | `wolfcert_scep_get_ca_caps` |
| `wolfSCEP_request(WS_REQUEST_CA)` then `wolfSCEP_response` | `wolfcert_scep_get_ca_cert` or `wolfcert_scep_get_ca_cert_enc` |
| `wolfSCEP_request(WS_REQUEST_ENROLL)` then `wolfSCEP_response` | `wolfcert_scep_pkcs_req` or `wolfcert_scep_pkcs_req_ex` |
| `WS_POST_FLAG` | automatic: POST by default, with the RFC 8894 section 4.1 GET fallback when `GetCACaps` does not advertise `POSTPKIOperation` |
| `wolfSCEP_reply_status` (the HTTP status code) | checked internally; a non-200 surfaces as `WOLFCERT_ERR_HTTP` |
| your own pkiStatus parse against `WS_PKI_SUCCESS` / `WS_PKI_FAILURE` / `WS_PKI_PENDING` | `WolfCertScepResult.status`, `WOLFCERT_SCEP_STATUS_SUCCESS` / `_FAILURE` / `_PENDING` |
| `wolfSCEP_reply_error`, `wolfSCEP_get_error` | `wolfcert_strerror` and `wolfcert_last_error_message` |
| `wolfSCEP_Debugging_ON` / `_OFF` | `wolfcert_set_log_cb` and `wolfcert_set_log_level` |
| your own CA fingerprint check | `wolfcert_scep_verify_ca_fingerprint`, or `wolfcert-client --ca-fingerprint` from the CLI |
| no equivalent | `wolfcert_scep_renewal_req` (either messageType, see below), `wolfcert_scep_get_cert_initial`, `wolfcert_scep_get_next_ca_cert`, the keep-alive and async session API, and all of EST |

`WS_REQUEST_CERT` and `WS_REQUEST_CRL` need no entry. Both fall through to the default case of `wolfSCEP_request()` and return `WS_BAD_ARGUMENT`, so no working integration can be using them.

## A worked enrollment

The wolfSCEP shape, elided to its skeleton:

```c
ctx  = wolfSCEP_CTX_new(NULL);
scep = wolfSCEP_new(ctx);

wolfSCEP_set_cgi(scep, "/certsrv/mscep/mscep.dll");
wolfSCEP_set_getCaId(scep, caId, caIdSz);
wolfSCEP_set_httpField(scep, agent, agentSz, host, hostSz, port);

/* your socket, and for HTTPS your SSL object as the IO context */
sfd = connect_to_server(host, port);
wolfSCEP_set_fd(scep, sfd);

wolfSCEP_request(scep, WS_REQUEST_CA, 0);
wolfSCEP_response(scep, answer, &answerSz, 0);
/* your own fingerprint check over the returned CA certificate */
/* your own CSR build */
wolfSCEP_set_bundle(scep, request, reqSz);
wolfSCEP_request(scep, WS_REQUEST_ENROLL, 0);
wolfSCEP_response(scep, answer, &answerSz, 0);
if (wolfSCEP_reply_status(scep) == WS_PKI_SUCCESS) { /* ... */ }
```

The same enrollment in wolfCert, which is `examples/enroll_scep.c` with the fingerprint check added:

```c
WolfCertServerCfg srv = {
    .protocol   = WOLFCERT_PROTO_SCEP,
    .server_url = "http://ca.example/certsrv/mscep/mscep.dll",
    .proto_opts.scep = { .ca_id = "CAIdentifier" },
};

/* 1) GetCACert, then pin it against a fingerprint you hold out of band. */
WolfCertBuffer ca_der = { 0 };
wolfcert_scep_get_ca_cert_enc(&srv, WOLFCERT_ENCODING_DER, &ca_der);
if (wolfcert_scep_verify_ca_fingerprint(ca_der.data, ca_der.len,
                                        expected_fp, sizeof(expected_fp),
                                        WOLFCERT_SCEP_FP_SHA256) != WOLFCERT_OK)
    return -1;

/* 2) Capabilities drive the hash, the content cipher and POST versus GET. */
WolfCertScepCaps caps = { 0 };
wolfcert_scep_get_ca_caps(&srv, &caps);

/* 3) Key and CSR. */
WolfCertKeyCfg kcfg = { .type = WOLFCERT_KEY_RSA, .param = 2048,
                        .dev_id = WOLFCERT_DEVID_SOFTWARE };
WolfCertKey* key = NULL;
wolfcert_key_generate(&kcfg, &key);

WolfCertCertMeta meta = { .subject_dn = "CN=device-1",
                          .challenge_password = challenge };
WolfCertBuffer csr = { 0 };
wolfcert_csr_build(key, &meta, &csr);

/* 4) PKCSReq. One call: envelope, sign, POST, verify, de-envelope. */
WolfCertScepResult res = { 0 };
int rc = wolfcert_scep_pkcs_req_ex(&srv, &caps,
                                   ca_der.data, ca_der.len,   /* envelope target */
                                   ca_der.data, ca_der.len,   /* trusted bundle  */
                                   key, csr.data, csr.len, &res);
```

`res.status` is then `SUCCESS` with the certificate in `res.cert_pem`, `PENDING` with the transactionID in `res.transaction_id` to poll with `wolfcert_scep_get_cert_initial`, or `FAILURE` with `res.fail_info` carrying the RFC 8894 failInfo.

In a split CA and RA deployment, pass the whole `GetCACert` bundle as `ca_bundle` and the RA encryption certificate as `ra_cert`; they are separate arguments because the response signer and the envelope recipient are not the same certificate.

For a quick check against a server before touching code, the CLI covers the same ground:

```sh
wolfcert-client enroll --proto scep --url http://ca.example/certsrv/mscep/mscep.dll \
    --ca-id CAIdentifier --challenge "$OTP" \
    --key-type rsa:2048 --subject "CN=device-1" \
    --out-key dev.key --out-cert dev.crt
```

## Differences that will bite

**An MD5 CA fingerprint has to be re-pinned.** This is the one item that can block a migration outright, so check it first. `wolfcert_scep_verify_ca_fingerprint` supports SHA-256, SHA-1 and SHA-512, and `WOLFCERT_SCEP_FP_AUTO` picks the digest from the length: 20, 32 or 64 bytes. MD5 is deliberately not offered, so a 16-byte fingerprint returns `WOLFCERT_ERR_BAD_ARG` no matter which algorithm you name. Length-based selection is a legacy convenience anyway: pass `WOLFCERT_SCEP_FP_SHA256` explicitly when you know the digest, since a 20-byte value silently selects SHA-1, whose collision resistance is broken.

**The CA identifier is no longer sent by default.** wolfSCEP always sends one and defaults it to the literal string `CAIdentifier`. wolfCert omits the `message=` parameter entirely unless you set `proto_opts.scep.ca_id`. If your server expects the parameter, or expects that particular default, set it explicitly. A single-CA responder that ignores the parameter needs nothing.

**The CGI path moves into the URL.** wolfSCEP defaults to `/cgi-bin/pkiclient.exe` on port 11111 and takes the path through `wolfSCEP_set_cgi()`. In wolfCert the path, host and port are simply the `server_url` you pass.

**The transactionID default differs.** wolfCert generates a fresh random transactionID per request. wolfSCEP derives it from the enrollee public key, which means repeated enrollments of one key share an ID and a CA can recognise the retry. To keep that, set:

```c
srv.proto_opts.scep.txid_mode = WOLFCERT_SCEP_TXID_PUBKEY_HASH;
```

That produces the SHA-256 of the signing certificate's public key, upper-case hex encoded, 64 characters, per RFC 8894 section 3.2.1. It hashes the `subjectPublicKey` BIT STRING contents, not the enclosing `SubjectPublicKeyInfo` with its AlgorithmIdentifier, which is the same input a wolfSCEP-based peer feeds in through `PKCS7.publicKey`, so the two derive the same value. On a renewal the signer is the certificate being replaced, so the ID follows the old key.

**Content encryption is negotiated, not fixed.** By default wolfCert uses AES-128-CBC when the CA advertises the `AES` capability and triple DES otherwise. No `GetCACaps` keyword advertises AES-256, so a server that requires it can only be reached by asking:

```c
srv.proto_opts.scep.content_cipher = WOLFCERT_SCEP_CIPHER_AES256;
```

A wolfSSL built `NO_DES3` cannot produce the triple DES fallback and will report `WOLFCERT_ERR_UNSUPPORTED` against a CA that advertises no AES.

**Fingerprint verification is now the library's job.** Delete your helper and call `wolfcert_scep_verify_ca_fingerprint`, which hashes the DER certificate and compares in constant time.

**Error codes are a different, smaller set.** wolfSCEP's `WS_*` codes map onto `wolfcert/errors.h`: `WS_BAD_ARGUMENT` to `WOLFCERT_ERR_BAD_ARG`, `WS_MEMORY_E` to `WOLFCERT_ERR_MEMORY`, `WS_PARSE_E` to `WOLFCERT_ERR_PARSE`, the `WS_CBIO_ERR_*` family to `WOLFCERT_ERR_IO` and, in non-blocking mode only, to `WOLFCERT_ERR_WANT_READ` and `WOLFCERT_ERR_WANT_WRITE`. There is no per-call error string; use `wolfcert_strerror` for the code and `wolfcert_last_error_message` for the per-thread detail.

**TLS is optional for SCEP and mandatory for EST.** SCEP authenticates inside the pkiMessage, so a plaintext `http://` endpoint is accepted. An `https://` endpoint requires `srv.verify_server`: every SCEP entry point, one-shot and session alike, refuses to run unverified rather than completing a silent anonymous handshake, because `verify_server` is the only peer-verification switch in the transport.

## Renewals: which messageType your CA expects

Two things travel together in an enrollment request, the `messageType` signed attribute and the certificate that signs the pkiMessage, and the signer is how the CA decides who is asking.

RFC 8894 pairs them. An initial enrollment is messageType 19 (`PKCSReq`) signed by a throwaway self-signed certificate whose key is the one being enrolled, so the signature proves possession of the new private key and the challengePassword in the CSR carries the authorization. A renewal is messageType 17 (`RenewalReq`) signed by the certificate being replaced, which the CA recognises as its own issuance.

CAs that predate `RenewalReq` expect a renewal as messageType 19 signed by the old certificate instead. wolfCert covers both, since the signer is the same either way and only the attribute differs:

```c
srv.proto_opts.scep.renewal_msg_type = WOLFCERT_SCEP_RENEWAL_MSG_PKCS_REQ;
```

The default, `WOLFCERT_SCEP_RENEWAL_MSG_RENEWAL_REQ`, sends 17. The option is read by `wolfcert_scep_renewal_req_ex` and by the session renewals; initial enrollment is always messageType 19 with the self-signed signer and is unaffected.

To decide which your CA wants, read `WolfCertScepCaps.renewal`, which `wolfcert_scep_get_ca_caps` fills from the GetCACaps `Renewal` keyword. A CA that advertises it accepts `RenewalReq`, so the default is right. If it does not advertise `Renewal` and your existing integration renews successfully anyway, you are relying on the older shape and want `PKCS_REQ`. wolfCert does not test the field for you.

## Building against wolfCert

wolfSSL no longer needs `--enable-scep`. wolfCert checks its own requirements at configure time and fails loudly if any are missing. The canonical wolfSSL build is in `README.md`; `--enable-des3` matters only for CAs that advertise no AES.

```sh
cmake -S . -B build
cmake --build build -j
sudo cmake --install build
```

Autotools is kept at parity (`./autogen.sh && ./configure && make`). For a target with no configure step, define `WOLFCERT_USER_SETTINGS` and supply a `user_settings.h`; see `EMBEDDED.md` and `examples/user_settings.h.example`.

Link against `libwolfcert` and include `<wolfcert/wolfcert.h>`, which pulls in the protocol headers that were compiled in.

## What you get on top

- **EST (RFC 7030)** for the same lifecycle over TLS, with ECC, Ed25519, Ed448 and ML-DSA keys, none of which SCEP permits.
- **Keep-alive and non-blocking sessions**, so several operations share one connection and an event loop can drive them through `WOLFCERT_ERR_WANT_READ` and `WOLFCERT_ERR_WANT_WRITE`.
- **CryptoCb offload.** Register your TPM, HSM or PKCS#11 backend with wolfSSL and pass the resulting `dev_id` in `WolfCertKeyCfg`; the private key never has to be in memory.
- **Pluggable storage** through `WolfCertStoreOps` for flash and NVM targets.
- **Static memory.** Every allocation carries a heap hint, so wolfCert runs on a wolfSSL built `WOLFSSL_NO_MALLOC` with a static pool.
- **A tested interop matrix**, described in `INTEROP.md`.

## Checklist

1. Obtain a SHA-256 fingerprint for your CA out of band, and confirm it is not MD5.
2. Fold host, port and CGI path into one `server_url`.
3. Set `protocol` to `WOLFCERT_PROTO_SCEP`. It selects the `proto_opts` arm, so the `wolfcert_scep_*` calls reject a config that leaves it unset with `WOLFCERT_ERR_BAD_ARG`.
4. Set `proto_opts.scep.ca_id` if your server expects the `message=` parameter.
5. Set `txid_mode` to `WOLFCERT_SCEP_TXID_PUBKEY_HASH` if your CA deduplicates retries by transactionID.
6. Set `content_cipher` if your CA requires AES-256.
7. Delete the socket, HTTP, TLS wiring and response buffer management.
8. Replace your fingerprint helper with `wolfcert_scep_verify_ca_fingerprint`.
9. Replace the request and response pairs with the matching `wolfcert_scep_*` call.
10. Handle `PENDING` through `wolfcert_scep_get_cert_initial` rather than your own retry loop.
11. Set `renewal_msg_type` if your CA predates `RenewalReq`; check `WolfCertScepCaps.renewal` to find out.
12. Map your error handling onto `wolfcert/errors.h`.
