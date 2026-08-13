/*
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of wolfCert.
 *
 * wolfCert is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfCert is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with wolfCert.  If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * Internal definitions shared across wolfCert source files. Not installed;
 * not part of the public API.
 */

#ifndef WOLFCERT_INTERNAL_H
#define WOLFCERT_INTERNAL_H

#include <wolfcert/types.h>
#include <wolfcert/keygen.h>
#include <wolfcert/server.h>
#include <wolfcert/memory.h>
#include <wolfcert/log.h>
#include <wolfcert/status.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
/* wolfssl/wolfcrypt/random.h declares a `pid_t` member under HAVE_GETPID
 * (e.g. static-memory builds). Pull in its POSIX declaration first so that
 * header compiles; harmless on configs that don't reference it. */
#if defined(HAVE_GETPID) && !defined(WOLFSSL_NO_GETPID)
    #include <sys/types.h>
#endif
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/wc_port.h>
#include <wolfssl/ssl.h>

/* ---- tunable HTTP request-buffer sizes ---------------------------------- *
 * These bound the HTTP request-handling buffers of the test server and client.
 * The EST server and the client keep them on the stack; the SCEP server
 * heap-allocates its (larger) read buffer, so shrinking these lowers its heap
 * churn rather than its stack. Override them (compiler -D or user_settings) on
 * constrained targets; see docs/EMBEDDED.md. Shrinking lowers the largest
 * request header block / path / Basic-auth credential accepted. */
#ifndef WOLFCERT_HTTP_REQ_BUF_SZ
#define WOLFCERT_HTTP_REQ_BUF_SZ 2048   /* server request header read buffer */
#endif
#ifndef WOLFCERT_HTTP_PATH_SZ
#define WOLFCERT_HTTP_PATH_SZ    512    /* EST server request path field      */
#endif
/* The query size is separate from the path: an RFC 8894 GET PKIOperation
 * carries the whole pkiMessage in the `message=` query parameter. What lands in
 * this buffer is the percent-encoded base64 (up to ~3x the raw bytes for a
 * fully-escaped payload), not the raw base64 - so the effective on-wire bound
 * is the client's WOLFCERT_SCEP_MAX_GET_URL cap, which shares this 8 KiB
 * default. The SCEP server adds this to REQ_BUF_SZ for its heap read buffer
 * (query points into it); trim it on a POST-only deployment to reclaim that
 * buffer. */
#ifndef WOLFCERT_HTTP_QUERY_SZ
#define WOLFCERT_HTTP_QUERY_SZ   8192   /* percent-encoded SCEP GET pkiMessage  */
#endif
#ifndef WOLFCERT_HTTP_AUTH_BUF_SZ
#define WOLFCERT_HTTP_AUTH_BUF_SZ 512   /* client Basic-auth header line      */
#endif

/* Heap headroom added on top of (envelope + signer cert) when encoding a SCEP
 * SignedData pkiMessage. wolfSSL's PKCS#7 encoder mutates internal state per
 * call, so it is given a single right-sized one-shot buffer rather than
 * size-then-encode retried. This slack bounds everything else in the message:
 * the signed-attribute set (~2 KiB), the RSA signature (<=1 KiB at RSA-8192),
 * and the SignerInfo identifier plus ASN.1 framing (~1 KiB). 8 KiB is a safe
 * default; override (compiler -D or user_settings) to trim it on constrained
 * targets, see docs/EMBEDDED.md. */
#ifndef WOLFCERT_SCEP_PKI_SLACK
#define WOLFCERT_SCEP_PKI_SLACK   (8 * 1024)
#endif

/* Upper bound on a SCEP message body handed to the PKCS#7 helpers: the CSR in
 * wolfcert_scep_self_signed_rsa and the enveloped CertRep in
 * wolfcert_scep_deenvelop, each of which drives a `len + 4096` one-shot
 * allocation. In the client/server flow these already arrive bounded by the
 * HTTP body cap (WOLFCERT_HTTP_DEFAULT_MAX_BODY, also 64 KiB), so this is the
 * helpers' own last-resort limit that keeps a direct caller from driving a
 * huge speculative malloc. The default matches the HTTP cap so it never
 * rejects a body the transport would have accepted; override (compiler -D or
 * user_settings) to trim it on constrained targets, see docs/EMBEDDED.md. */
#ifndef WOLFCERT_SCEP_MAX_MSG_SZ
#define WOLFCERT_SCEP_MAX_MSG_SZ  (64 * 1024)
#endif

/* Upper bound on the length of a base64/percent-encoded PKIOperation GET URL.
 * RFC 8894 section 4.1 lets a client fall back to HTTP GET when the CA does not
 * advertise POSTPKIOperation, carrying the pkiMessage in the `message` query
 * parameter. GET has no standard length limit but servers commonly cap request
 * lines around 8 KiB, so refuse to build a longer URL and surface a clear
 * error instead (a large message needs a POSTPKIOperation-capable CA). Override
 * with a compiler -D or user_settings if a deployment allows longer GETs. */
#ifndef WOLFCERT_SCEP_MAX_GET_URL
#define WOLFCERT_SCEP_MAX_GET_URL (8 * 1024)
#endif
/* A GET URL the client builds (bounded by WOLFCERT_SCEP_MAX_GET_URL) must also
 * fit the SCEP server's query buffer, or the server would truncate it. These
 * share the same 8 KiB default; guard the relationship so a lone -D override of
 * one fails fast at compile time rather than at runtime. The matching check
 * against the client's own URL parser (WOLFCERT_HTTP_MAX_PATH_LEN) lives in
 * http.c, where that limit is defined. */
#if WOLFCERT_SCEP_MAX_GET_URL > WOLFCERT_HTTP_QUERY_SZ
#error "WOLFCERT_SCEP_MAX_GET_URL exceeds WOLFCERT_HTTP_QUERY_SZ; raise WOLFCERT_HTTP_QUERY_SZ so the SCEP server can receive the largest GET the client will build."
#endif

/* ---- key ---------------------------------------------------------------- */

struct WolfCertKey {
    WolfCertKeyType type;
    int             dev_id;
    int             curve_id;     /* ECC only */
    int             rsa_bits;     /* RSA only */
    char*           label;
    void*           heap;
    /* Backing wolfSSL key struct (RsaKey* / ecc_key* / ed25519_key* / ...).
     * Allocated + freed by the algorithm's dispatch entry. */
    void*           impl;
};

/* ---- shared CA state (test servers) ------------------------------------ */

typedef struct {
    WolfCertKeyType type;
    /* Backing wolfSSL key struct (RsaKey* / ecc_key* / ...); owner. */
    void*    impl;
    uint8_t* cert_der;
    size_t   cert_der_len;
    uint8_t* key_der;
    size_t   key_der_len;
    void*    heap;
} WolfCertCa;

int  wolfcert_ca_generate(WolfCertCa* ca, WolfCertKeyType type, int param, void* heap);
int  wolfcert_ca_load(WolfCertCa* ca, WolfCertStoreOps* store, void* heap);
int  wolfcert_ca_save(const WolfCertCa* ca, WolfCertStoreOps* store);
void wolfcert_ca_free(WolfCertCa* ca);
int  wolfcert_ca_issue (WolfCertCa* ca, const uint8_t* csr_der, size_t csr_len,
                        uint8_t** out_cert, size_t* out_len);

/* ---- server vtable ------------------------------------------------------ */

typedef struct {
    int  (*start)(const WolfCertServerCfgSrv* cfg, WolfCertServer* base);
    int  (*serve_fd)(WolfCertServer* srv, int fd);
    void (*free_priv)(WolfCertServer* srv);
} WolfCertServerOps;

struct WolfCertServer {
    WolfCertServerCfgSrv    cfg;
    char*                   cfg_bind_host;
    char*                   cfg_challenge;
    char*                   cfg_basic_user;
    char*                   cfg_basic_pass;
    /* Owned copy of WolfCertServerCfgSrv.csr_attributes_der; the
     * handler serves these bytes on GET /.well-known/est/csrattrs. */
    uint8_t*                cfg_csr_attrs;
    size_t                  cfg_csr_attrs_len;
    WolfCertCa              ca;
    int                     listen_fd;
    /* Shutdown flag. Set by wolfcert_server_stop() -- which may run on a
     * different thread than the accept loop (test harness) or from a signal
     * handler (wolfcert-server CLI) -- and polled by wolfcert_server_run().
     * wolfSSL_Atomic_Int gives the cross-thread access a happens-before edge
     * (and async-signal-safe store); it degrades to volatile int on targets
     * that wolfSSL builds WOLFSSL_NO_ATOMICS. */
    wolfSSL_Atomic_Int      stopping;
    const WolfCertServerOps* ops;
    void*                   priv;        /* protocol-specific state */
    /* TLS terminator. `tls_ctx` is created in wolfcert_server_start() when
     * the caller provides a server cert+key; `tls_current` holds the
     * per-accept WOLFSSL while the protocol handler is running, so the
     * send/recv helpers below can transparently dispatch to wolfSSL_read /
     * wolfSSL_write. The accept loop owns the SSL lifetime. */
    WOLFSSL_CTX*            tls_ctx;
    WOLFSSL*                tls_current;
    /* Per-request keep-alive signalling. Reset to 1 at the top of every
     * serve_fd call; protocol handlers flip it to 0 when the client
     * asked for Connection: close (or when the handler decides to tear
     * down the connection for any reason). The accept loop inspects
     * this after serve_fd and breaks out of the keep-alive loop when
     * it's zero. */
    int                     keep_alive;
    void*                   heap;
};

/* Transparent read/write for protocol handlers: dispatch to wolfSSL_read /
 * wolfSSL_write when the accepted connection is TLS-wrapped, else raw
 * recv()/send(). Both return a negative value on error, matching the
 * recv()/send() conventions the handlers already branch on. */
ssize_t wolfcert_io_recv(WolfCertServer* srv, int fd, void* buf, size_t len);
ssize_t wolfcert_io_send(WolfCertServer* srv, int fd, const void* buf, size_t len);

/* Factories supplied by est/est_server.c and scep/scep_server.c. */
WOLFCERT_API const WolfCertServerOps* wolfcert_est_server_ops(void);
WOLFCERT_API const WolfCertServerOps* wolfcert_scep_server_ops(void);

#if defined(WOLFCERT_BUILD_TESTING)
/* Test-only fault injection for a started SCEP server: make it emit a CertRep
 * without a recipientNonce, sign the CertRep with a throwaway key instead of
 * the CA key, and/or force the CertRep senderNonce RNG draw to fail. Used to
 * drive the client-side rejection and server error paths. Call after
 * wolfcert_server_start and before the client request. */
WOLFCERT_TEST_VIS void wolfcert_scep_server_set_faults(WolfCertServer* s,
    int omit_recipient_nonce, int sign_with_wrong_key, int rng_fail);
#endif

/* ---- error reporting --------------------------------------------------- */

int  wolfcert_map_wc_err(int wc_rc);
int  wolfcert_set_error(int wolfcert_rc, int wolfssl_rc,
                        const char* module, const char* fmt, ...);

#define WOLFCERT_ERR(rc, module, ...) \
    wolfcert_set_error((rc), 0, (module), __VA_ARGS__)
#define WOLFCERT_ERR_WC(wc_rc, module, ...) \
    wolfcert_set_error(wolfcert_map_wc_err(wc_rc), (wc_rc), (module), __VA_ARGS__)

/* ---- logging ---------------------------------------------------------- */

void wolfcert_logv(WolfCertLogLevel lvl, const char* module, const char* fmt, ...);

#define WOLFCERT_LOG_ERR(mod,  ...) wolfcert_logv(WOLFCERT_LOG_ERROR, (mod), __VA_ARGS__)
#define WOLFCERT_LOG_WARN_(mod, ...) wolfcert_logv(WOLFCERT_LOG_WARN,  (mod), __VA_ARGS__)
#define WOLFCERT_LOG_INFO_(mod, ...) wolfcert_logv(WOLFCERT_LOG_INFO,  (mod), __VA_ARGS__)
#define WOLFCERT_LOG_DBG(mod,  ...) wolfcert_logv(WOLFCERT_LOG_DEBUG, (mod), __VA_ARGS__)

/* Default key type for callers that don't specify one (e.g. the test CA):
 * the first key algorithm compiled in. At least one is guaranteed present. */
#if defined(WOLFCERT_HAVE_RSA)
#define WOLFCERT_DEFAULT_KEY_TYPE WOLFCERT_KEY_RSA
#elif defined(WOLFCERT_HAVE_ECC)
#define WOLFCERT_DEFAULT_KEY_TYPE WOLFCERT_KEY_ECC
#elif defined(WOLFCERT_HAVE_ED25519)
#define WOLFCERT_DEFAULT_KEY_TYPE WOLFCERT_KEY_ED25519
#elif defined(WOLFCERT_HAVE_ED448)
#define WOLFCERT_DEFAULT_KEY_TYPE WOLFCERT_KEY_ED448
#elif defined(WOLFCERT_HAVE_MLDSA)
#define WOLFCERT_DEFAULT_KEY_TYPE WOLFCERT_KEY_MLDSA44
#else
#error "wolfCert needs at least one key algorithm (RSA/ECC/Ed25519/Ed448/ML-DSA)"
#endif

/* ---- shared utilities -------------------------------------------------- */

int  wolfcert_rng_new(WC_RNG* rng);
#ifdef WOLFCERT_HAVE_ECC
int  wolfcert_ecc_curve_from_param(int param, int* out_curve_id, int* out_key_size);
#endif

/* WolfCertServerCfg.protocol is the discriminator for the proto_opts union, so
 * a protocol-specific entry point must confirm it before reading its arm: the
 * other arm's members overlay incompatible types and would be reinterpreted.
 * Every EST and SCEP entry point that takes a WolfCertServerCfg calls this. */
int wolfcert_cfg_require_proto(const WolfCertServerCfg* srv,
                               WolfCertProtocol want, const char* module);

typedef struct {
    char* scheme;
    char* host;
    int   port;
    char* path;
    int   tls;
    void* heap;
} WolfCertUrl;

WOLFCERT_TEST_VIS int  wolfcert_http_url_parse(const char* url, WolfCertUrl* out, void* heap);
WOLFCERT_TEST_VIS void wolfcert_http_url_free (WolfCertUrl* u);
WOLFCERT_TEST_VIS int  wolfcert_http_url_origin(const WolfCertUrl* u, void* heap,
                                                char** out_origin);

/* Base64 helpers. `_encode` is single-line (no newlines) - the right
 * default for HTTP header values and for wolfCert's own server-side
 * decode path. `_encode_mime` wraps the output at 64 chars per
 * RFC 4648 section 3.1; use it for HTTP-body payloads when the peer is strict
 * about MIME-style line breaks (e.g. libest's estserver
 * `/simpleenroll` body parser uses OpenSSL's `BIO_f_base64`, which
 * rejects unwrapped input). `_decode` accepts both forms. */
WOLFCERT_TEST_VIS int wolfcert_base64_encode(const uint8_t* in, size_t in_len,
                                             WolfCertBuffer* out, void* heap);
WOLFCERT_TEST_VIS int wolfcert_base64_encode_mime(const uint8_t* in, size_t in_len,
                                                  WolfCertBuffer* out, void* heap);
WOLFCERT_TEST_VIS int wolfcert_base64_decode(const uint8_t* in, size_t in_len,
                                             WolfCertBuffer* out, void* heap);

/* Hex-encode `in_len` bytes into `out`, which must hold at least 2 * in_len
 * characters. `upper` selects upper-case digits. No NUL terminator is written,
 * so the same helper serves both string building (caller terminates) and
 * fixed-length wire fields such as the SCEP transactionID. */
WOLFCERT_TEST_VIS void wolfcert_hex_encode(const uint8_t* in, size_t in_len,
                                           int upper, char* out);

/* Parse an IPv4/IPv6 literal into 4 or 16 network-order bytes. Rejects zone
 * IDs, prefix lengths and leading zeros, so the accepted set is portable. */
WOLFCERT_TEST_VIS int wolfcert_parse_ip(const char* s, uint8_t out[16],
                                        size_t* out_len);

/* Built-in POSIX transport, and the adapter used when a config still sets the
 * deprecated connect_cb. Both are fd-backed, which session_fd() relies on. */
extern const WolfCertTransport wolfcert_posix_transport;
extern const WolfCertTransport wolfcert_legacy_transport;
int  wolfcert_transport_is_fd_backed(const WolfCertTransport* t);

int  wolfcert_pem_cert_to_der(const uint8_t* pem, size_t pem_len,
                              WolfCertBuffer* out_der, void* heap);

/* Heuristically classify a buffer as DER vs PEM. DER (ASN.1) starts with a
 * SEQUENCE tag (0x30) once any leading whitespace is skipped; PEM starts with
 * the "-----BEGIN" armor. Returns 1 if the buffer looks like DER, else 0. */
WOLFCERT_TEST_VIS int wolfcert_buffer_is_der(const uint8_t* buf, size_t len);

/* Degenerate (certs-only) PKCS#7 helpers. */
WOLFCERT_TEST_VIS int wolfcert_pkcs7_certs_to_pem(const uint8_t* p7_der, size_t p7_der_len,
                                                  WolfCertBuffer* out_pem, void* heap);
WOLFCERT_TEST_VIS int wolfcert_pkcs7_certs_to_der(const uint8_t* p7_der, size_t p7_der_len,
                                                  WolfCertBuffer* out_der, void* heap);

/* Encoding-aware CA retrieval. The public wolfcert_est_get_cacerts wraps this
 * with WOLFCERT_ENCODING_PEM; wolfcert_client_get_ca forwards the caller's
 * chosen encoding. (wolfcert_scep_get_ca_cert_enc is public, in scep.h.) */
WOLFCERT_TEST_VIS int wolfcert_est_get_cacerts_enc(const WolfCertServerCfg* srv,
                                                   WolfCertEncoding enc,
                                                   WolfCertBuffer* out_ca);
WOLFCERT_TEST_VIS int wolfcert_pkcs7_build_certs_only(const uint8_t* const* certs_der,
                                                      const size_t* certs_len, size_t count,
                                                      WolfCertBuffer* out_der, void* heap);

/* Render a DER OID (the subidentifier bytes) as a dotted-decimal string into
 * `out`, always NUL-terminating when out_cap > 0. Follows snprintf return
 * semantics: the count is what would have been written and may exceed out_cap
 * on truncation, so it is not a safe string length. */
WOLFCERT_TEST_VIS size_t wolfcert_oid_to_dotted(const uint8_t* oid, size_t oid_len,
                                                char* out, size_t out_cap);

/* SCEP pkiMessage helpers. */
typedef struct {
    const uint8_t* transaction_id;
    size_t transaction_id_len;
    const uint8_t* sender_nonce;
    size_t sender_nonce_len;
    const char*    message_type;
    const char*    pki_status;
    const uint8_t* recipient_nonce;
    size_t recipient_nonce_len;
    /* Optional RFC 8894 section 3.2.1.3 failInfo attribute. Emitted only when
     * pki_status indicates failure ("2"); printable-string decimal. */
    const char*    fail_info;
} WolfCertScepAttrs;

/* Build a DER-encoded IssuerAndSubject SEQUENCE (RFC 8894 section 3.3.2) from
 * the raw Name bytes of the RA/CA cert (-> issuer) and a CSR (-> subject).
 * Used as the enveloped content of a GetCertInitial pkiMessage. */
int wolfcert_scep_issuer_and_subject(const uint8_t* issuer_cert_der, size_t issuer_cert_len,
                                     const uint8_t* csr_der,         size_t csr_len,
                                     WolfCertBuffer* out_der, void* heap);

WOLFCERT_TEST_VIS int wolfcert_scep_envelop(const uint8_t* ra_cert_der,
    size_t ra_cert_len, const uint8_t* payload, size_t payload_len, int enc_oid,
    WolfCertBuffer* out_der, void* heap);

/* Build the RFC 8894 section 4.1 GET PKIOperation URL:
 *   base?operation=PKIOperation&message=<url-encoded base64 pki_msg>
 * Returns WOLFCERT_ERR_UNSUPPORTED when the encoded URL would exceed
 * WOLFCERT_SCEP_MAX_GET_URL. Exposed for white-box testing. */
WOLFCERT_TEST_VIS int wolfcert_scep_build_pki_get_url(const char* base,
    const uint8_t* pki_msg, size_t pki_len, void* heap, char** out_url);

/* Build the URL for any SCEP operation whose only parameter is the CA
 * identifier: base?operation=<op>[&message=<ca_id>]. That covers GetCACaps,
 * GetCACert and GetNextCACert; `op` is copied verbatim. The CA identifier is
 * appended (URL-encoded) only when ca_id is non-NULL and non-empty. Returns a
 * heap-allocated URL owned by the caller, or NULL. */
WOLFCERT_TEST_VIS char* wolfcert_scep_build_getca_url(const char* base,
    const char* op, const char* ca_id, void* heap);
int wolfcert_scep_deenvelop(const uint8_t* recipient_cert_der, size_t recipient_cert_len,
                            const uint8_t* recipient_key_der,  size_t recipient_key_len,
                            const uint8_t* env_der, size_t env_len,
                            WolfCertBuffer* out_plain, void* heap);
#ifdef WOLFCERT_HAVE_RSA
WOLFCERT_TEST_VIS int wolfcert_scep_self_signed_rsa(RsaKey* key,
    const uint8_t* csr_der, size_t csr_len, uint8_t** out_der, size_t* out_len, void* heap);
#endif
WOLFCERT_TEST_VIS int wolfcert_scep_build_pki_message(const uint8_t* envelope_der,
    size_t envelope_len, const uint8_t* signer_cert_der, size_t signer_cert_len,
    const uint8_t* signer_key_der, size_t signer_key_len, int hash_oid,
    const WolfCertScepAttrs* attrs, WolfCertBuffer* out_der, void* heap);
WOLFCERT_TEST_VIS int wolfcert_scep_parse_pki_message(const uint8_t* pki_der,
    size_t pki_len, WolfCertBuffer* out_envelope, uint8_t** out_transaction_id,
    size_t* out_tid_len, uint8_t** out_sender_nonce,   size_t* out_snonce_len,
    uint8_t** out_recipient_nonce,size_t* out_rnonce_len, char** out_message_type,
    char** out_pki_status, uint8_t** out_signer_cert, size_t* out_signer_cert_len,
    char** out_fail_info, void* heap);

/* Build the GetNextCACert response (RFC 8894 section 4.6.1): wrap the next CA
 * certificate in a degenerate certs-only SignedData and sign that with the
 * current CA key, so the client can bind the rollover certificate to trust it
 * already holds. */
WOLFCERT_TEST_VIS int wolfcert_scep_build_next_ca_response(
    const uint8_t* next_ca_cert, size_t next_ca_cert_len,
    const uint8_t* ca_cert, size_t ca_cert_len,
    const uint8_t* ca_key, size_t ca_key_len,
    WolfCertBuffer* out_der, void* heap);

/* Extract the SubjectPublicKeyInfo bytes from a DER certificate or CSR.
 * Result is heap-allocated; caller frees with WOLFCERT_XFREE(..., heap). */
int wolfcert_extract_spki(const uint8_t* der, size_t len, int is_csr,
                          uint8_t** out_spki, size_t* out_len, void* heap);

/* RFC 8894: a CertRep must be signed by the CA or its RA. Confirm the response
 * signer certificate shares a public key with some certificate in the trusted
 * GetCACert bundle (one or more concatenated DER certs). Returns WOLFCERT_OK on
 * match, WOLFCERT_ERR_AUTH otherwise. */
WOLFCERT_TEST_VIS int wolfcert_scep_verify_rep_signer(
    const uint8_t* signer_cert, size_t signer_cert_len,
    const uint8_t* ca_bundle, size_t ca_bundle_len, void* heap);

/* RFC 8894: an enrollment response must be a CertRep (messageType "3") whose
 * transactionID echoes the one the client sent. Returns WOLFCERT_OK when both
 * hold, WOLFCERT_ERR_PROTOCOL otherwise. */
WOLFCERT_TEST_VIS int wolfcert_scep_check_cert_rep(const char* msg_type,
    const uint8_t* rx_tid, size_t rx_tid_len,
    const uint8_t* sent_tid, size_t sent_tid_len);

/* Validate a GetNextCACert response (RFC 8894 section 4.6.1): verify it is a
 * SignedData, bind its signer to a certificate in the trusted current-CA
 * bundle (current_ca_der is one or more concatenated DER certs; required), and
 * extract the enclosed rollover certificate(s) as PEM. Rejects an unsigned
 * response or one not signed by a cert in the bundle. */
WOLFCERT_TEST_VIS int wolfcert_scep_verify_next_ca_response(
    const uint8_t* resp_der, size_t resp_len,
    const uint8_t* current_ca_der, size_t current_ca_len,
    WolfCertBuffer* out_pem, void* heap);

#endif /* WOLFCERT_INTERNAL_H */
