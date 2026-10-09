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

/* wolfSSL's random.h uses pid_t under HAVE_GETPID without declaring it. */
#if defined(HAVE_GETPID) && !defined(WOLFSSL_NO_GETPID)
    #include <sys/types.h>
#endif
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/wc_port.h>
#include <wolfssl/ssl.h>

#ifndef WOLFCERT_HTTP_REQ_BUF_SZ
#define WOLFCERT_HTTP_REQ_BUF_SZ 2048   /* server request header read buffer */
#endif
#ifndef WOLFCERT_HTTP_PATH_SZ
#define WOLFCERT_HTTP_PATH_SZ    512    /* EST server request path field      */
#endif
#ifndef WOLFCERT_HTTP_QUERY_SZ
#define WOLFCERT_HTTP_QUERY_SZ   8192   /* percent-encoded SCEP GET pkiMessage  */
#endif
#ifndef WOLFCERT_HTTP_AUTH_BUF_SZ
#define WOLFCERT_HTTP_AUTH_BUF_SZ 512   /* client Basic-auth header line      */
#endif

#ifndef WOLFCERT_HTTP_HEADER_BUDGET
#define WOLFCERT_HTTP_HEADER_BUDGET 8192 /* client response header allowance   */
#endif

/* SCEP pkiMessage encode buffer headroom over envelope + signer cert. */
#ifndef WOLFCERT_SCEP_PKI_SLACK
#define WOLFCERT_SCEP_PKI_SLACK   (8 * 1024)
#endif

/* Largest SCEP message body the PKCS#7 helpers accept. Keep it >= the HTTP
 * body cap: WOLFCERT_HTTP_DEFAULT_MAX_BODY or a caller's max_response_bytes. */
#ifndef WOLFCERT_SCEP_MAX_MSG_SZ
#define WOLFCERT_SCEP_MAX_MSG_SZ  (64 * 1024)
#endif

/* Longest SCEP GET PKIOperation URL the client builds. */
#ifndef WOLFCERT_SCEP_MAX_GET_URL
#define WOLFCERT_SCEP_MAX_GET_URL (8 * 1024)
#endif
#if WOLFCERT_SCEP_MAX_GET_URL > WOLFCERT_HTTP_QUERY_SZ
#error "WOLFCERT_SCEP_MAX_GET_URL exceeds WOLFCERT_HTTP_QUERY_SZ; raise WOLFCERT_HTTP_QUERY_SZ so the SCEP server can receive the largest GET the client will build."
#endif

struct WolfCertKey {
    WolfCertKeyType type;
    int             dev_id;
    int             curve_id;     /* ECC only */
    int             rsa_bits;     /* RSA only */
    char*           label;
    void*           heap;
    void*           impl;         /* RsaKey* / ecc_key* / ... */
};

typedef struct {
    WolfCertKeyType type;
    void*    impl;
    uint8_t* cert_der;
    size_t   cert_der_len;
    uint8_t* key_der;
    size_t   key_der_len;
    void*    heap;
} WolfCertCa;

int  wolfcert_ca_generate(WolfCertCa* ca, WolfCertKeyType type, int param, void* heap);
WOLFCERT_TEST_VIS int  wolfcert_ca_load(WolfCertCa* ca, WolfCertStoreOps* store,
                                        void* heap);
int  wolfcert_ca_save(const WolfCertCa* ca, WolfCertStoreOps* store);
WOLFCERT_TEST_VIS void wolfcert_ca_free(WolfCertCa* ca);
/* wolfcert_buffer_free() after wiping: for a buffer that held key material. */
void wolfcert_buffer_free_secure(WolfCertBuffer* buf);

/* Rebuild an issued certificate's subject from a decoded CSR. */
WOLFCERT_TEST_VIS int  wolfcert_copy_csr_subject(const DecodedCert* dc, Cert* nc);
int  wolfcert_csr_verify(const uint8_t* csr_der, size_t csr_len, void* heap);
WOLFCERT_TEST_VIS int  wolfcert_ca_issue(WolfCertCa* ca, const uint8_t* csr_der,
                                         size_t csr_len, uint8_t** out_cert,
                                         size_t* out_len);

typedef struct {
    int  (*start)(const WolfCertServerCfgSrv* cfg, WolfCertServer* base);
    int  (*serve_fd)(WolfCertServer* srv, int fd);
    void (*free_priv)(WolfCertServer* srv);
} WolfCertServerOps;

struct WolfCertServer {
    WolfCertServerCfgSrv    cfg;
    char*                   cfg_challenge;
    char*                   cfg_basic_user;
    char*                   cfg_basic_pass;
    uint8_t*                cfg_csr_attrs;
    size_t                  cfg_csr_attrs_len;
    WolfCertCa              ca;
    int                     listen_fd;
    /* Set by wolfcert_server_stop() from another thread or a signal handler. */
    wolfSSL_Atomic_Int      stopping;
    const WolfCertServerOps* ops;
    void*                   priv;        /* protocol-specific state */
    WOLFSSL_CTX*            tls_ctx;
    WOLFSSL*                tls_current; /* owned by the accept loop */
    int                     keep_alive;  /* handlers clear it to close */
    /* Set when the accept loop armed SO_RCVTIMEO/SO_SNDTIMEO; would-block
     * retries in wolfcert_io_{recv,send} are allowed only then. */
    int                     poll_timeouts_armed;
    void*                   heap;
    int64_t                 deadline_ms; /* 0 when none is armed */
};

/* wolfSSL_read/write on a TLS connection, else recv()/send(). */
ssize_t wolfcert_io_recv(WolfCertServer* srv, int fd, void* buf, size_t len);
ssize_t wolfcert_io_send(WolfCertServer* srv, int fd, const void* buf, size_t len);

/* Best-effort SO_NOSIGPIPE; a no-op where unsupported or fd is not a socket. */
WOLFCERT_TEST_VIS void wolfcert_sock_nosigpipe(int fd);

int64_t wolfcert_mono_ms(void);

WOLFCERT_API const WolfCertServerOps* wolfcert_est_server_ops(void);
WOLFCERT_API const WolfCertServerOps* wolfcert_scep_server_ops(void);

#if defined(WOLFCERT_BUILD_TESTING)
/* GetCert faults: answer with the CA cert, or drop the signer cert. */
WOLFCERT_TEST_VIS void wolfcert_scep_server_set_getcert_fault(WolfCertServer* s,
                                                              int wrong_cert,
                                                              int no_signer);

/* CertRep faults: no recipientNonce, wrong signer key, senderNonce RNG fail. */
WOLFCERT_TEST_VIS void wolfcert_scep_server_set_faults(WolfCertServer* s,
    int omit_recipient_nonce, int sign_with_wrong_key, int rng_fail);

/* Out of memory: 1 fails wolfcert_ca_issue, 2 the reply after issuing, 3 the
 * signer/CSR key match; 0 clears it. */
WOLFCERT_TEST_VIS void wolfcert_scep_server_set_oom_fault(WolfCertServer* s,
                                                          int when);
#endif

int  wolfcert_map_wc_err(int wc_rc);
int  wolfcert_set_error(int wolfcert_rc, int wolfssl_rc,
                        const char* module, const char* fmt, ...);

#define WOLFCERT_ERR(rc, module, ...) \
    wolfcert_set_error((rc), 0, (module), __VA_ARGS__)
#define WOLFCERT_ERR_WC(wc_rc, module, ...) \
    wolfcert_set_error(wolfcert_map_wc_err(wc_rc), (wc_rc), (module), __VA_ARGS__)

void wolfcert_logv(WolfCertLogLevel lvl, const char* module, const char* fmt, ...);

#define WOLFCERT_LOG_ERR(mod,  ...) wolfcert_logv(WOLFCERT_LOG_ERROR, (mod), __VA_ARGS__)
#define WOLFCERT_LOG_WARN_(mod, ...) wolfcert_logv(WOLFCERT_LOG_WARN,  (mod), __VA_ARGS__)
#define WOLFCERT_LOG_INFO_(mod, ...) wolfcert_logv(WOLFCERT_LOG_INFO,  (mod), __VA_ARGS__)
#define WOLFCERT_LOG_DBG(mod,  ...) wolfcert_logv(WOLFCERT_LOG_DEBUG, (mod), __VA_ARGS__)

/* First compiled-in key algorithm, for callers that do not pick one. */
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

int  wolfcert_rng_new(WC_RNG* rng);
#ifdef WOLFCERT_HAVE_ECC
int  wolfcert_ecc_curve_from_param(int param, int* out_curve_id, int* out_key_size);
#endif

/* Returns WOLFCERT_ERR_BAD_ARG unless srv->protocol is want. */
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

/* strncasecmp() with ASCII-only case folding */
int wolfcert_ascii_ncasecmp(const char* a, const char* b, size_t n);
/* 1 when the header line's field name is `name`, followed directly by ':'. */
int wolfcert_http_hdr_is(const char* line, size_t llen, const char* name);

/* `_encode` emits one line; `_encode_mime` wraps at 64 columns, which libest's
 * BIO_f_base64 body parser requires. `_decode` accepts both. */
WOLFCERT_TEST_VIS int wolfcert_base64_encode(const uint8_t* in, size_t in_len,
                                             WolfCertBuffer* out, void* heap);
WOLFCERT_TEST_VIS int wolfcert_base64_encode_mime(const uint8_t* in, size_t in_len,
                                                  WolfCertBuffer* out, void* heap);
WOLFCERT_TEST_VIS int wolfcert_base64_decode(const uint8_t* in, size_t in_len,
                                             WolfCertBuffer* out, void* heap);

/* Writes 2 * in_len hex digits to `out` with no NUL terminator. */
WOLFCERT_TEST_VIS void wolfcert_hex_encode(const uint8_t* in, size_t in_len,
                                           int upper, char* out);

/* IPv4/IPv6 literal to 4 or 16 network-order bytes; rejects zone IDs, prefix
 * lengths and leading zeros. */
WOLFCERT_TEST_VIS int wolfcert_parse_ip(const char* s, uint8_t out[16],
                                        size_t* out_len);

WOLFCERT_TEST_VIS extern const WolfCertTransport wolfcert_posix_transport;
/* Descriptor of a wolfcert_posix_transport connection, else -1. */
int  wolfcert_transport_fd(const WolfCertTransport* t, void* conn);

int  wolfcert_pem_cert_to_der(const uint8_t* pem, size_t pem_len,
                              WolfCertBuffer* out_der, void* heap);

/* 1 when meta sets a Subject or SAN. */
int wolfcert_csr_meta_sets_identity(const WolfCertCertMeta* meta);

/* GeneralNames of the subjectAltName in dc, or *san NULL when there is
 * none. Returns WOLFCERT_OK or WOLFCERT_ERR_PARSE. */
WOLFCERT_TEST_VIS int wolfcert_find_san(const DecodedCert* dc,
                                        const byte** san, word32* san_len);

/* wolfcert_csr_build() for a renewal: with renew_cert (PEM or DER) set, the
 * CSR carries that certificate's Subject and SAN, and meta may not set them. */
WOLFCERT_TEST_VIS int wolfcert_csr_build_ex(const WolfCertKey* key,
                                            const WolfCertCertMeta* meta,
                                            const uint8_t* renew_cert,
                                            size_t renew_cert_len,
                                            WolfCertBuffer* out_der);

/* 1 if the buffer starts with a SEQUENCE tag after whitespace, else 0. */
WOLFCERT_TEST_VIS int wolfcert_buffer_is_der(const uint8_t* buf, size_t len);

/* Degenerate (certs-only) PKCS#7 helpers. */
WOLFCERT_TEST_VIS int wolfcert_pkcs7_certs_to_pem(const uint8_t* p7_der, size_t p7_der_len,
                                                  WolfCertBuffer* out_pem, void* heap);
WOLFCERT_TEST_VIS int wolfcert_pkcs7_certs_to_der(const uint8_t* p7_der, size_t p7_der_len,
                                                  WolfCertBuffer* out_der, void* heap);

WOLFCERT_TEST_VIS int wolfcert_est_get_cacerts_enc(const WolfCertServerCfg* srv,
                                                   WolfCertEncoding enc,
                                                   WolfCertBuffer* out_ca);
WOLFCERT_TEST_VIS int wolfcert_pkcs7_build_certs_only(const uint8_t* const* certs_der,
                                                      const size_t* certs_len, size_t count,
                                                      WolfCertBuffer* out_der, void* heap);

/* DER OID to dotted decimal, NUL-terminated when out_cap > 0. Arcs that do
 * not fit are dropped; the return value can exceed out_cap. */
WOLFCERT_TEST_VIS size_t wolfcert_oid_to_dotted(const uint8_t* oid, size_t oid_len,
                                                char* out, size_t out_cap);

#define SCEP_NONCE_SZ 16

typedef struct {
    const uint8_t* transaction_id;
    size_t transaction_id_len;
    const uint8_t* sender_nonce;
    size_t sender_nonce_len;
    const char*    message_type;
    const char*    pki_status;
    const uint8_t* recipient_nonce;
    size_t recipient_nonce_len;
    /* RFC 8894 section 3.2.1.4 failInfo, set only when pki_status is "2". */
    const char*    fail_info;
} WolfCertScepAttrs;

/* GetCertInitial IssuerAndSubject (RFC 8894 section 3.3.3). An RA target names
 * its issuer, assumed to be the CA issuing the requested cert. */
WOLFCERT_TEST_VIS int wolfcert_scep_issuer_and_subject(
                                     const uint8_t* ra_cert_der, size_t ra_cert_len,
                                     const uint8_t* csr_der,     size_t csr_len,
                                     WolfCertBuffer* out_der, void* heap);

/* GetCert IssuerAndSerialNumber (RFC 8894 section 3.3.4). */
WOLFCERT_TEST_VIS int wolfcert_scep_issuer_and_serial(
                                     const uint8_t* ra_cert_der, size_t ra_cert_len,
                                     const uint8_t* serial, size_t serial_len,
                                     WolfCertBuffer* out_der, void* heap);

/* Strip leading zero bytes, keeping at least one, so a DER sign pad matches
 * wolfSSL's stripped DecodedCert.serial. */
WOLFCERT_TEST_VIS void wolfcert_scep_int_magnitude(const uint8_t** v, size_t* vl);

/* Split an IssuerAndSerialNumber into the issuer Name's contents and the serial
 * magnitude; both point into `der`. */
WOLFCERT_TEST_VIS int wolfcert_scep_parse_issuer_and_serial(
                                     const uint8_t* der, size_t der_len,
                                     const uint8_t** out_issuer,
                                     size_t* out_issuer_len,
                                     const uint8_t** out_serial,
                                     size_t* out_serial_len);

/* 1 if a certificate in `pem` has `issuer` and `serial`, 0 if not, or
 * WOLFCERT_ERR_MEMORY. Unparseable entries are skipped. */
WOLFCERT_TEST_VIS int wolfcert_scep_pem_has_cert(const uint8_t* pem, size_t pem_len,
                                     const uint8_t* issuer, size_t issuer_len,
                                     const uint8_t* serial, size_t serial_len,
                                     void* heap);

/* 1 if `name` is the Name the CA in `cert_der` issues under. */
WOLFCERT_TEST_VIS int wolfcert_scep_issuer_name_matches(
                                     const uint8_t* cert_der, size_t cert_len,
                                     const uint8_t* name, size_t name_len,
                                     void* heap);

WOLFCERT_TEST_VIS int wolfcert_scep_envelop(const uint8_t* ra_cert_der,
    size_t ra_cert_len, const uint8_t* payload, size_t payload_len, int enc_oid,
    WolfCertBuffer* out_der, void* heap);

/* RFC 8894 section 4.1 GET PKIOperation URL; WOLFCERT_ERR_UNSUPPORTED past
 * WOLFCERT_SCEP_MAX_GET_URL. */
WOLFCERT_TEST_VIS int wolfcert_scep_build_pki_get_url(const char* base,
    const uint8_t* pki_msg, size_t pki_len, void* heap, char** out_url);

/* base?operation=<op>[&message=<ca_id>], heap-allocated, or NULL. */
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

/* GetNextCACert response (RFC 8894 section 4.7.1), signed by the current CA. */
WOLFCERT_TEST_VIS int wolfcert_scep_build_next_ca_response(
    const uint8_t* next_ca_cert, size_t next_ca_cert_len,
    const uint8_t* ca_cert, size_t ca_cert_len,
    const uint8_t* ca_key, size_t ca_key_len,
    WolfCertBuffer* out_der, void* heap);

/* SubjectPublicKeyInfo of a DER cert or CSR; free with WOLFCERT_XFREE. */
int wolfcert_extract_spki(const uint8_t* der, size_t len, int is_csr,
                          uint8_t** out_spki, size_t* out_len, void* heap);

/* 1 if every byte is in the X.680 PrintableString repertoire, else 0. */
int wolfcert_is_printable_string(const uint8_t* s, size_t len);

/* WOLFCERT_OK if the signer shares a public key with a cert in the DER
 * GetCACert bundle, WOLFCERT_ERR_MEMORY, or WOLFCERT_ERR_AUTH. */
WOLFCERT_TEST_VIS int wolfcert_scep_verify_rep_signer(
    const uint8_t* signer_cert, size_t signer_cert_len,
    const uint8_t* ca_bundle, size_t ca_bundle_len, void* heap);

/* WOLFCERT_OK for a CertRep echoing sent_tid, else WOLFCERT_ERR_PROTOCOL. */
WOLFCERT_TEST_VIS int wolfcert_scep_check_cert_rep(const char* msg_type,
    const uint8_t* rx_tid, size_t rx_tid_len,
    const uint8_t* sent_tid, size_t sent_tid_len);

/* Verify a GetNextCACert response is signed by a cert in current_ca_der and
 * return the rollover certificates as PEM. */
WOLFCERT_TEST_VIS int wolfcert_scep_verify_next_ca_response(
    const uint8_t* resp_der, size_t resp_len,
    const uint8_t* current_ca_der, size_t current_ca_len,
    WolfCertBuffer* out_pem, void* heap);

#endif /* WOLFCERT_INTERNAL_H */
