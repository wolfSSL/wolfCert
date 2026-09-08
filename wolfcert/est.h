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

/* GET /.well-known/est/cacerts - returns the CA chain as PEM. */
WOLFCERT_API int wolfcert_est_get_cacerts(const WolfCertServerCfg* srv,
                                          WolfCertBuffer* out_ca_pem);

/* GET /.well-known/est/csrattrs - raw server response body is returned
 * in `out_attrs_der` (may be empty; len==0 and data==NULL means the
 * server returned 204 No Content). Callers typically hand the bytes
 * through to WolfCertCertMeta::csr_attributes_der when building the CSR. */
WOLFCERT_API int wolfcert_est_get_csr_attrs(const WolfCertServerCfg* srv,
                                            WolfCertBuffer* out_attrs_der);

/* ---- CsrAttrs structured decode (RFC 7030 section 4.5.2) ------------------------
 *
 *   CsrAttrs ::= SEQUENCE SIZE (0..MAX) OF AttrOrOID
 *   AttrOrOID ::= CHOICE { oid OBJECT IDENTIFIER, attribute Attribute }
 *   Attribute ::= SEQUENCE { type OID, values SET OF AttributeValue }
 *
 * A bare OID tells the client "include an attribute of this type in
 * the CSR"; an Attribute (OID + values) is a stronger directive - the
 * server is dictating the exact value(s) the client must use (e.g.
 * the signature algorithm OID it expects). The parser walks the
 * top-level SEQUENCE and fills the `items` list plus a handful of
 * structured hint fields for the attributes wolfCert recognizes. */
typedef enum {
    WOLFCERT_CSRATTR_BARE_OID  = 0,
    WOLFCERT_CSRATTR_ATTRIBUTE = 1
} WolfCertCsrAttrKind;

typedef struct {
    WolfCertCsrAttrKind kind;
    /* Raw OID body (i.e. content of the OBJECT IDENTIFIER, not its
     * outer tag/length). Stable pointer into the parsed buffer. */
    const uint8_t*      oid;
    size_t              oid_len;
    /* Only for kind == WOLFCERT_CSRATTR_ATTRIBUTE: the concatenated
     * TLVs inside the `SET OF AttributeValue`. NULL + 0 for bare
     * OIDs. */
    const uint8_t*      values_der;
    size_t              values_len;
} WolfCertCsrAttrItem;

typedef struct {
    WolfCertCsrAttrItem* items;
    size_t               count;

    /* Structured hints derived from recognised OIDs. Callers can use
     * these directly or walk `items` for protocol-specific handling. */
    int require_challenge_password;  /* PKCS#9 challengePassword */
    int require_extension_request;   /* PKCS#9 extensionRequest */
    /* Preferred signature hash, populated when the server pins a
     * signatureAlgorithm OID. 0 if no hint.
     *   256 -> SHA-256, 384 -> SHA-384, 512 -> SHA-512. */
    int preferred_hash;
    /* Preferred key algorithm, encoded as WolfCertKeyType. 0 if no hint. */
    int preferred_key_type;
    /* When preferred_key_type indicates RSA: pinned modulus size; 0 = any. */
    int preferred_rsa_bits;
    /* When preferred_key_type indicates ECC: pinned curve size (256/384/521);
     * 0 = any. */
    int preferred_ecc_curve_bits;

    /* Backing buffer; owns the DER copy that `oid` / `values_der`
     * point into. Managed by wolfcert_csr_attrs_free. */
    uint8_t* _backing;
    size_t   _backing_len;
    void*    heap;
} WolfCertCsrAttrs;

WOLFCERT_API int  wolfcert_est_parse_csr_attrs(const uint8_t* der, size_t der_len,
                                               WolfCertCsrAttrs* out);
WOLFCERT_API void wolfcert_csr_attrs_free(WolfCertCsrAttrs* attrs);

/* Overlay the parsed structured hints onto a caller-supplied
 * WolfCertKeyCfg / WolfCertCertMeta, filling fields the caller left at
 * their zero-value defaults while preserving any value the caller set
 * explicitly (explicit wins). Specifically:
 *
 *   key_cfg->type   <- attrs->preferred_key_type   (when type  == 0)
 *   key_cfg->param  <- RSA bits or ECC curve size  (when param == 0
 *                     and the new `type` is RSA / ECC; ignored for
 *                     Ed25519 / Ed448 / ML-DSA which have no `param`)
 *   meta->preferred_hash <- attrs->preferred_hash  (when zero)
 *
 * `require_challenge_password` / `require_extension_request` are
 * informational on the client: this function doesn't synthesise a
 * challengePassword or SANs that the caller didn't supply - it only
 * fills in key-algorithm / hash choices the server pinned.
 *
 * Returns WOLFCERT_ERR_UNSUPPORTED if the resulting `key_cfg->type`
 * names a key algorithm (Ed25519 / Ed448 / ML-DSA) that the current
 * wolfCert + wolfSSL build does not have. Either `key_cfg` or `meta`
 * may be NULL to skip that half of the overlay. */
WOLFCERT_API int wolfcert_csr_attrs_apply(const WolfCertCsrAttrs* attrs,
                                          WolfCertKeyCfg* key_cfg,
                                          WolfCertCertMeta* meta);

/* Lookup helper. Returns a pointer into `attrs->items` or NULL if the
 * OID is not present. `oid_body` is the raw OID content (no tag). */
WOLFCERT_API const WolfCertCsrAttrItem*
    wolfcert_csr_attrs_find(const WolfCertCsrAttrs* attrs,
                            const uint8_t* oid_body, size_t oid_len);

/* Serialise a list of items back into CsrAttrs DER. The inverse of
 * wolfcert_est_parse_csr_attrs. Items of kind WOLFCERT_CSRATTR_BARE_OID
 * contribute a bare `OBJECT IDENTIFIER` choice; items of kind
 * WOLFCERT_CSRATTR_ATTRIBUTE contribute a SEQUENCE { OID, SET OF
 * AttributeValue } where `values_der` is the caller-supplied
 * concatenated TLVs of the values (one or more; e.g. an OID naming a
 * curve). Passing a zero-length items array produces an empty outer
 * SEQUENCE (valid CsrAttrs, same shape as what the server would emit
 * in place of a 204 No Content). */
WOLFCERT_API int wolfcert_csr_attrs_build(const WolfCertCsrAttrItem* items,
                                          size_t count,
                                          WolfCertBuffer* out_der);

/* ---- EST enrollment result (RFC 7030 section 4.2) -----------------------------
 *
 * RFC 7030 section 4.2.3 lets a server respond to /simpleenroll (or
 * /simplereenroll) with `202 Accepted` + `Retry-After: <delta>` when the
 * request has been accepted but the certificate is not yet ready -
 * typically because the deployment requires manual approval. This is the
 * EST analogue of SCEP's `pkiStatus=PENDING`. The client is expected to
 * wait at least `retry_after_sec` seconds and then re-POST the identical
 * request (same CSR, same URL, same credentials).
 *
 * The richer `_ex` entry points below surface this explicitly:
 *   status == SUCCESS   -> `cert_pem` holds the issued cert (PEM).
 *   status == PENDING   -> `cert_pem` is empty; `retry_after_sec` carries
 *                         the server's hint (0 when the server did not
 *                         send Retry-After, or sent it in the HTTP-date
 *                         form which wolfCert does not yet parse).
 *   status == FAILURE   -> a 4xx/5xx came back (auth / parse / policy).
 *   status == UNSET     -> the call didn't reach a server round-trip;
 *                         inspect the int return code.
 *
 * `WolfCertEstStatus`'s values mirror `WolfCertScepStatus` on purpose so
 * callers that want a single "status -> action" switch across protocols
 * can write it once. UNSET is the zero value so a zero-initialised
 * result never looks like a success. */
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
    /* Server's suggested wait before the client should re-POST. Only
     * meaningful when status == PENDING. 0 when the server did not send
     * `Retry-After`; callers may apply their own backoff policy in that
     * case. */
    int               retry_after_sec;
    void*             heap;
} WolfCertEstResult;

WOLFCERT_API void wolfcert_est_result_free(WolfCertEstResult* r);

/* POST /.well-known/est/simpleenroll.
 *
 * Simple-result form: a 202-Accepted (pending) response is surfaced as
 * `WOLFCERT_ERR_PENDING`; the richer `_ex` form below exposes the
 * Retry-After hint so callers can drive a poll loop. */
WOLFCERT_API int wolfcert_est_simple_enroll(const WolfCertServerCfg* srv,
                                            const uint8_t* csr_der, size_t csr_der_len,
                                            WolfCertBuffer* out_cert_pem);

/* Richer-shape `/simpleenroll` that distinguishes SUCCESS / PENDING /
 * FAILURE in `out->status` and carries the server's `Retry-After` hint
 * when present. Returns `WOLFCERT_OK` for every successful HTTP
 * round-trip; negative return codes are reserved for transport / parse
 * failures. On PENDING the caller waits `out->retry_after_sec` (or its
 * own floor) and re-invokes `wolfcert_est_simple_enroll_ex` with the
 * same arguments. */
WOLFCERT_API int wolfcert_est_simple_enroll_ex(const WolfCertServerCfg* srv,
                                               const uint8_t* csr_der, size_t csr_der_len,
                                               WolfCertEstResult* out);

/* POST /.well-known/est/simplereenroll. Uses the caller's current cert/key
 * as the TLS client credential.
 *
 * Simple-result form: 202-Accepted (pending) surfaces as
 * `WOLFCERT_ERR_PENDING`; use the `_ex` form for Retry-After access. */
WOLFCERT_API int wolfcert_est_simple_reenroll(const WolfCertServerCfg* srv,
                                              const uint8_t* current_cert, size_t current_cert_len,
                                              const WolfCertKey* current_key,
                                              const uint8_t* csr_der, size_t csr_der_len,
                                              WolfCertBuffer* out_cert_pem);

/* Richer-shape `/simplereenroll`. Semantics match
 * `wolfcert_est_simple_enroll_ex`. */
WOLFCERT_API int wolfcert_est_simple_reenroll_ex(const WolfCertServerCfg* srv,
                                                 const uint8_t* current_cert, size_t current_cert_len,
                                                 const WolfCertKey* current_key,
                                                 const uint8_t* csr_der, size_t csr_der_len,
                                                 WolfCertEstResult* out);

/* ---- keep-alive EST session --------------------------------------------
 *
 * A single TCP+TLS connection that carries multiple EST requests. The
 * canonical deployment shape is:
 *
 *   1. Open the session with a client cert/key (factory identity),
 *      WolfCertServerCfg.verify_server on, and
 *      WolfCertServerCfg.proto_opts.est.allow_post_handshake_auth = 1.
 *   2. Call wolfcert_est_session_get_cacerts - goes out on an anonymous
 *      TLS connection (server doesn't ask for the identity yet).
 *   3. Call wolfcert_est_session_simple_enroll - server requests the
 *      client cert via TLS 1.3 post-handshake auth (RFC 8446 section 4.6.2);
 *      wolfSSL answers from the pre-loaded identity without further
 *      caller involvement.
 *
 * HTTP Basic (RFC 7030 section 3.2.3) works just as well as a client
 * certificate here: proto_opts.est.username / .password are copied at
 * session open and replayed on every request the session issues, blocking
 * and async alike.
 *
 * On a build where wolfSSL lacks WOLFSSL_POST_HANDSHAKE_AUTH the
 * session_open call fails with WOLFCERT_ERR_UNSUPPORTED when the caller
 * asked for PHA. */
typedef struct WolfCertEstSession WolfCertEstSession;

WOLFCERT_API int wolfcert_est_session_open(const WolfCertServerCfg* srv,
                                           WolfCertEstSession** out);

WOLFCERT_API int wolfcert_est_session_get_cacerts(WolfCertEstSession* s,
                                                  WolfCertBuffer* out_ca_pem);

WOLFCERT_API int wolfcert_est_session_simple_enroll(WolfCertEstSession* s,
                                                    const uint8_t* csr_der, size_t csr_der_len,
                                                    WolfCertBuffer* out_cert_pem);

WOLFCERT_API void wolfcert_est_session_close(WolfCertEstSession* s);

/* Socket fd of the backing HTTP session - hand to poll/epoll/kqueue;
 * -1 when a caller-supplied WolfCertTransport backs it (no descriptor). */
WOLFCERT_API int wolfcert_est_session_fd(const WolfCertEstSession* s);

/* Async variants. The session must have been opened via a
 * WolfCertServerCfg built from a WolfCertHttpSessionCfg with
 * nonblocking=1; at that API level, pass
 * srv->proto_opts.est.allow_post_handshake_auth and/or other options plus
 * the new wolfcert_est_session_open_async().
 *
 * Each call drives the HTTP session state machine forward and returns
 *   WOLFCERT_OK              - `out_*` populated.
 *   WOLFCERT_ERR_WANT_READ   - wait for readable, then call again
 *                              with the same arguments.
 *   WOLFCERT_ERR_WANT_WRITE  - wait for writable, then call again.
 *   other negative values    - permanent failure.
 */
WOLFCERT_API int wolfcert_est_session_open_async(const WolfCertServerCfg* srv,
                                                 WolfCertEstSession** out);

WOLFCERT_API int wolfcert_est_session_get_cacerts_nb(WolfCertEstSession* s,
                                                     WolfCertBuffer* out_ca_pem);

WOLFCERT_API int wolfcert_est_session_simple_enroll_nb(WolfCertEstSession* s,
                                                       const uint8_t* csr_der,
                                                       size_t csr_der_len,
                                                       WolfCertBuffer* out_cert_pem);

#ifdef __cplusplus
}
#endif

#endif /* WOLFCERT_EST_H */
