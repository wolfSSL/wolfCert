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

#ifndef WOLFCERT_EST_H
#define WOLFCERT_EST_H

#include <wolfcert/types.h>
#include <wolfcert/keygen.h>

#ifdef __cplusplus
extern "C" {
#endif

/* GET /.well-known/est/cacerts - returns the CA chain as PEM for
 * WOLFCERT_ENCODING_PEM, or as concatenated DER for WOLFCERT_ENCODING_DER.
 * A 401 or 403 returns WOLFCERT_ERR_AUTH, any other non-200 _HTTP. */
WOLFCERT_API int wolfcert_est_get_cacerts(const WolfCertServerCfg* srv,
                                          WolfCertEncoding enc,
                                          WolfCertBuffer* out_ca);

/* GET /.well-known/est/csrattrs - returns the CsrAttrs DER for
 * wolfcert_est_parse_csr_attrs, empty (NULL, 0) on 204, 404, 405, 501 or a
 * 200 whose body is empty or decodes to nothing. A 401 or 403 returns
 * WOLFCERT_ERR_AUTH, others _HTTP. */
WOLFCERT_API int wolfcert_est_get_csr_attrs(const WolfCertServerCfg* srv,
                                            WolfCertBuffer* out_attrs_der);

/* Decoded CsrAttrs (RFC 7030 section 4.5.2). A bare OID asks for an attribute
 * of that type; an Attribute also dictates its values. */
typedef enum {
    WOLFCERT_CSRATTR_BARE_OID  = 0,
    WOLFCERT_CSRATTR_ATTRIBUTE = 1
} WolfCertCsrAttrKind;

typedef struct {
    WolfCertCsrAttrKind kind;
    /* OID content without tag and length; points into _backing. */
    const uint8_t*      oid;
    size_t              oid_len;
    /* Concatenated AttributeValue TLVs; NULL and 0 for a bare OID. */
    const uint8_t*      values_der;
    size_t              values_len;
} WolfCertCsrAttrItem;

typedef struct {
    WolfCertCsrAttrItem* items;
    size_t               count;

    /* Hints from recognised OIDs; 0 means no hint. */
    int require_challenge_password;  /* PKCS#9 challengePassword */
    int require_extension_request;   /* PKCS#9 extensionRequest */
    /* 256, 384 or 512 when the server pins a signatureAlgorithm. */
    int preferred_hash;
    /* A WolfCertKeyType. */
    int preferred_key_type;
    /* RSA modulus size; 0 = any. */
    int preferred_rsa_bits;
    /* ECC curve size (256/384/521); 0 = any. */
    int preferred_ecc_curve_bits;

    /* Owns the DER the items point into; freed by wolfcert_csr_attrs_free. */
    uint8_t* _backing;
    size_t   _backing_len;
    void*    heap;
} WolfCertCsrAttrs;

WOLFCERT_API int  wolfcert_est_parse_csr_attrs(const uint8_t* der, size_t der_len,
                                               WolfCertCsrAttrs* out);
WOLFCERT_API void wolfcert_csr_attrs_free(WolfCertCsrAttrs* attrs);

/* When key_cfg->type is zero, take the hinted type and, for RSA/ECC with a
 * zero param, the hinted size (else 2048 bits / P-256). A zero
 * meta->preferred_hash takes the hinted hash. Either pointer may be NULL to
 * skip it. Returns WOLFCERT_ERR_UNSUPPORTED when the resulting type is
 * Ed25519, Ed448 or ML-DSA and not in this build. */
WOLFCERT_API int wolfcert_csr_attrs_apply(const WolfCertCsrAttrs* attrs,
                                          WolfCertKeyCfg* key_cfg,
                                          WolfCertCertMeta* meta);

/* Returns the item in attrs->items matching the raw OID body (no tag), or
 * NULL. */
WOLFCERT_API const WolfCertCsrAttrItem*
    wolfcert_csr_attrs_find(const WolfCertCsrAttrs* attrs,
                            const uint8_t* oid_body, size_t oid_len);

/* Encode items as CsrAttrs DER, the inverse of wolfcert_est_parse_csr_attrs.
 * An ATTRIBUTE item's values_der holds its concatenated value TLVs; zero
 * items give an empty SEQUENCE. */
WOLFCERT_API int wolfcert_csr_attrs_build(const WolfCertCsrAttrItem* items,
                                          size_t count,
                                          WolfCertBuffer* out_der);

/* Outcome of the enroll calls (RFC 7030 section 4.2), matching the
 * WolfCertScepStatus values:
 *   SUCCESS - returns WOLFCERT_OK; cert_pem holds the issued cert.
 *   PENDING - returns WOLFCERT_OK; cert_pem is empty and the caller re-POSTs
 *             the identical request after retry_after_sec (section 4.2.3).
 *   FAILURE - a reply came back but cannot be used: an HTTP error status
 *             (WOLFCERT_ERR_AUTH for 401/403, else WOLFCERT_ERR_HTTP) or a
 *             body that is empty or does not parse.
 *   UNSET   - no reply was received; the int return code says why. */
typedef enum {
    WOLFCERT_EST_STATUS_UNSET   = 0,
    WOLFCERT_EST_STATUS_SUCCESS = 1,
    WOLFCERT_EST_STATUS_FAILURE = 2,
    WOLFCERT_EST_STATUS_PENDING = 3
} WolfCertEstStatus;

typedef struct {
    WolfCertEstStatus status;
    /* Populated and owned iff status == SUCCESS. */
    WolfCertBuffer    cert_pem;
    /* Seconds to wait before re-POSTing when PENDING; 0 if the server sent
     * no usable Retry-After. */
    int               retry_after_sec;
    void*             heap;
} WolfCertEstResult;

/* Every wolfcert_est_* call taking a WolfCertEstResult* initializes a
 * non-NULL *out first, so freeing it after any outcome is safe. A populated
 * result must be freed before it is passed again, except a session's
 * in-flight result, which every resume passes back unfreed. */
WOLFCERT_API void wolfcert_est_result_free(WolfCertEstResult* r);

/* POST /.well-known/est/simpleenroll. */
WOLFCERT_API int wolfcert_est_simple_enroll(const WolfCertServerCfg* srv,
                                            const uint8_t* csr_der, size_t csr_der_len,
                                            WolfCertEstResult* out);

/* POST /.well-known/est/simplereenroll. Uses the caller's current cert/key
 * as the TLS client credential. */
WOLFCERT_API int wolfcert_est_simple_reenroll(const WolfCertServerCfg* srv,
                                              const uint8_t* current_cert, size_t current_cert_len,
                                              const WolfCertKey* current_key,
                                              const uint8_t* csr_der, size_t csr_der_len,
                                              WolfCertEstResult* out);

/* Keep-alive EST session carrying several requests over one TLS connection.
 * Each call on it is blocking or _nb, and the style may change between
 * requests. An _nb call returning WOLFCERT_ERR_WANT_READ / _WANT_WRITE is
 * repeated with the same arguments when the session fd is ready. While a
 * request is in flight, a call for another operation, output or encoding, and
 * any blocking call, returns WOLFCERT_ERR_BAD_ARG and leaves it intact. Open
 * checks the config and connects synchronously; it does not verify the server:
 * the first request runs the TLS handshake. Open returns
 * WOLFCERT_ERR_TLS_UNTRUSTED if a trust anchor is not valid at the device time.
 * Requests return WOLFCERT_ERR_TLS_UNTRUSTED if the server certificate fails
 * verification, WOLFCERT_ERR_TLS_PEER_REJECTED if the server refuses the client
 * certificate in TLS 1.3, WOLFCERT_ERR_MEMORY if wolfSSL runs out of memory,
 * and WOLFCERT_ERR_TLS or WOLFCERT_ERR_IO for any other TLS failure. HTTP Basic
 * credentials are copied at open and sent on every request. With
 * proto_opts.est.allow_post_handshake_auth set, the server can request the
 * preloaded client cert via TLS 1.3 post-handshake auth (RFC 8446 section
 * 4.6.2); open then fails with WOLFCERT_ERR_UNSUPPORTED if wolfSSL lacks
 * WOLFSSL_POST_HANDSHAKE_AUTH. */
typedef struct WolfCertEstSession WolfCertEstSession;

WOLFCERT_API int wolfcert_est_session_open(const WolfCertServerCfg* srv,
                                           WolfCertEstSession** out);

WOLFCERT_API int wolfcert_est_session_get_cacerts(WolfCertEstSession* s,
                                                  WolfCertEncoding enc,
                                                  WolfCertBuffer* out_ca);

WOLFCERT_API int wolfcert_est_session_get_csr_attrs(WolfCertEstSession* s,
                                                    WolfCertBuffer* out_attrs_der);

WOLFCERT_API int wolfcert_est_session_simple_enroll(WolfCertEstSession* s,
                                                    const uint8_t* csr_der,
                                                    size_t csr_der_len,
                                                    WolfCertEstResult* out);

/* The session's TLS client credential, srv->client_cert and client_key at
 * open, is the cert being renewed; WOLFCERT_ERR_BAD_ARG without one. */
WOLFCERT_API int wolfcert_est_session_simple_reenroll(WolfCertEstSession* s,
                                                      const uint8_t* csr_der,
                                                      size_t csr_der_len,
                                                      WolfCertEstResult* out);

WOLFCERT_API void wolfcert_est_session_close(WolfCertEstSession* s);

/* Socket fd of the backing HTTP session - hand to poll/epoll/kqueue;
 * -1 when a caller-supplied WolfCertTransport backs it (no descriptor). */
WOLFCERT_API int wolfcert_est_session_fd(const WolfCertEstSession* s);

WOLFCERT_API int wolfcert_est_session_get_cacerts_nb(WolfCertEstSession* s,
                                                     WolfCertEncoding enc,
                                                     WolfCertBuffer* out_ca);

WOLFCERT_API int wolfcert_est_session_get_csr_attrs_nb(WolfCertEstSession* s,
                                                       WolfCertBuffer* out_attrs_der);

WOLFCERT_API int wolfcert_est_session_simple_enroll_nb(WolfCertEstSession* s,
                                                       const uint8_t* csr_der,
                                                       size_t csr_der_len,
                                                       WolfCertEstResult* out);

WOLFCERT_API int wolfcert_est_session_simple_reenroll_nb(WolfCertEstSession* s,
                                                         const uint8_t* csr_der,
                                                         size_t csr_der_len,
                                                         WolfCertEstResult* out);

#ifdef __cplusplus
}
#endif

#endif /* WOLFCERT_EST_H */
