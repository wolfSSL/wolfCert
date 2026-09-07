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

#ifndef WOLFCERT_SCEP_H
#define WOLFCERT_SCEP_H

#include <wolfcert/types.h>
#include <wolfcert/keygen.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Low-level SCEP (RFC 8894) client primitives. SCEP messages are PKCS#7
 * structures; wolfCert builds them using wolfSSL's wc_PKCS7 API. */

typedef struct {
    int post_pki_operation;      /* GetCACaps: POSTPKIOperation */
    int renewal;                 /* GetCACaps: Renewal */
    int sha256;                  /* GetCACaps: SHA-256 */
    int sha384;                  /* GetCACaps: SHA-384 */
    int sha512;                  /* GetCACaps: SHA-512 */
    int aes;                     /* GetCACaps: AES */
    int scep_standard;           /* GetCACaps: SCEPStandard */
    int get_next_ca_cert;        /* GetCACaps: GetNextCACert */
} WolfCertScepCaps;

WOLFCERT_API int wolfcert_scep_get_ca_caps(const WolfCertServerCfg* srv,
                                           WolfCertScepCaps* out_caps);

WOLFCERT_API int wolfcert_scep_get_ca_cert(const WolfCertServerCfg* srv,
                                           WolfCertBuffer* out_ca_pem);

/* Like wolfcert_scep_get_ca_cert but returns the CA/RA certificate(s) in the
 * requested encoding. WOLFCERT_ENCODING_DER yields the whole GetCACert bundle
 * as concatenated DER, suitable as the ca_bundle trust set for the enroll and
 * GetNextCACert calls. */
WOLFCERT_API int wolfcert_scep_get_ca_cert_enc(const WolfCertServerCfg* srv,
                                               WolfCertEncoding enc,
                                               WolfCertBuffer* out_ca);

/* Digest algorithm for wolfcert_scep_verify_ca_fingerprint. AUTO selects the
 * algorithm from the expected fingerprint length (20 => SHA-1, 32 => SHA-256,
 * 64 => SHA-512). SHA-256 is always available; SHA-1 and SHA-512 depend on the
 * wolfSSL build and yield WOLFCERT_ERR_UNSUPPORTED when absent. MD5 is
 * intentionally not offered.
 *
 * AUTO is a legacy convenience for fingerprints of unknown provenance: a
 * 20-byte value selects SHA-1, whose collision resistance is broken, so an
 * attacker who controls the out-of-band fingerprint source could bind a forged
 * CA certificate to it. When the fingerprint's origin and digest are known,
 * pass WOLFCERT_SCEP_FP_SHA256 (or SHA-512) explicitly instead of relying on
 * AUTO. */
typedef enum {
    WOLFCERT_SCEP_FP_AUTO   = 0,
    WOLFCERT_SCEP_FP_SHA256 = 1,
    WOLFCERT_SCEP_FP_SHA1   = 2,
    WOLFCERT_SCEP_FP_SHA512 = 3
} WolfCertScepFpAlg;

/* Verify that a CA/RA certificate matches a fingerprint obtained out of band,
 * the standard SCEP trust-bootstrap check on a GetCACert response before it is
 * used as a trust anchor. The fingerprint is a hash over the whole DER-encoded
 * certificate `ca_der` (pass one certificate, e.g. the leaf of a GetCACert
 * bundle), compared in constant time against `expected`.
 *
 * Returns WOLFCERT_OK on match, WOLFCERT_ERR_AUTH on mismatch,
 * WOLFCERT_ERR_BAD_ARG on NULL/zero inputs or an `expected_len` that does not
 * match the chosen algorithm (or any known length under AUTO), and
 * WOLFCERT_ERR_UNSUPPORTED when the requested digest is not compiled into
 * wolfSSL. */
WOLFCERT_API int wolfcert_scep_verify_ca_fingerprint(const uint8_t* ca_der,
                                                     size_t ca_der_len,
                                                     const uint8_t* expected,
                                                     size_t expected_len,
                                                     WolfCertScepFpAlg alg);

/* RFC 8894 section 3.2.1.3 pkiStatus values returned by the server in a CertRep
 * pkiMessage. PENDING means the enrollment was accepted but is waiting
 * for manual approval; the caller re-queries later via
 * wolfcert_scep_get_cert_initial using the returned transactionID.
 *
 * UNSET is the zero value so a caller who does `WolfCertScepResult r =
 * {0};` doesn't get something that looks like SUCCESS before the
 * library has populated anything. The SUCCESS / FAILURE / PENDING
 * values are wolfCert-internal and need not match RFC 8894's wire
 * encoding (which uses "0" / "2" / "3" printable strings); the library
 * maps between the two in do_scep_round_trip. */
typedef enum {
    WOLFCERT_SCEP_STATUS_UNSET   = 0,
    WOLFCERT_SCEP_STATUS_SUCCESS = 1,
    WOLFCERT_SCEP_STATUS_FAILURE = 2,
    WOLFCERT_SCEP_STATUS_PENDING = 3
} WolfCertScepStatus;

typedef struct {
    WolfCertScepStatus status;
    /* cert_pem is owned and populated iff status == SUCCESS. */
    WolfCertBuffer     cert_pem;
    /* transaction_id (binary) is owned and populated whenever the server
     * returns a CertRep; callers echo it back via get_cert_initial. */
    uint8_t*           transaction_id;
    size_t             transaction_id_len;
    /* RFC 8894 section 3.2.1.4 failInfo; meaningful only when status==FAILURE.
     * 0=badAlg, 1=badMessageCheck, 2=badRequest, 3=badTime, 4=badCertId.
     * -1 if the server did not include the attribute. */
    int                fail_info;
    void*              heap;
} WolfCertScepResult;

WOLFCERT_API void wolfcert_scep_result_free(WolfCertScepResult* r);

/* PKCSReq: enroll a new certificate. The RFC 8894 section 2.9 challengePassword
 * travels inside the CSR as its PKCS#9 attribute - set
 * WolfCertCertMeta.challenge_password before wolfcert_csr_build. SCEP sends no
 * HTTP-layer credentials.
 *
 * `ra_cert` is the DER cert the request is enveloped to (the CA/RA encryption
 * cert). `ca_bundle` is the trusted GetCACert response (one or more
 * concatenated DER certs) the CertRep signer is checked against; in a split
 * CA/RA deployment the response signer differs from `ra_cert`, so pass the
 * whole bundle. For a single-cert CA, pass `ra_cert` as the bundle (the
 * wolfcert_scep_pkcs_req wrapper does this).
 *
 * Returns WOLFCERT_OK on any successful server round-trip; inspect
 * out->status to distinguish SUCCESS / PENDING / FAILURE. Transport-level
 * errors (TLS, HTTP, parse) surface as negative wolfCert error codes. */
WOLFCERT_API int wolfcert_scep_pkcs_req_ex(const WolfCertServerCfg* srv,
                                           const WolfCertScepCaps* caps,
                                           const uint8_t* ra_cert, size_t ra_cert_len,
                                           const uint8_t* ca_bundle, size_t ca_bundle_len,
                                           const WolfCertKey* new_key,
                                           const uint8_t* csr_der, size_t csr_der_len,
                                           WolfCertScepResult* out);

/* PKCSReq, simple-result form. Returns WOLFCERT_ERR_PENDING when the server
 * replies pkiStatus=3 and WOLFCERT_ERR_PROTOCOL on pkiStatus=2. For the richer
 * shape (transactionID etc.) use wolfcert_scep_pkcs_req_ex. */
WOLFCERT_API int wolfcert_scep_pkcs_req(const WolfCertServerCfg* srv,
                                        const WolfCertScepCaps* caps,
                                        const uint8_t* ra_cert, size_t ra_cert_len,
                                        const WolfCertKey* new_key,
                                        const uint8_t* csr_der, size_t csr_der_len,
                                        WolfCertBuffer* out_cert_pem);

/* RenewalReq: re-enroll using an existing cert/key to sign the pkiMessage.
 * `ra_cert` is the envelope target; `ca_bundle` is the trusted GetCACert bundle
 * the response signer is checked against (see wolfcert_scep_pkcs_req_ex).
 *
 * The renewed key pair is conveyed entirely inside `csr_der`: the CSR carries
 * the new public key and `current_key` signs the enclosing pkiMessage. There
 * is deliberately no separate new-key argument. */
WOLFCERT_API int wolfcert_scep_renewal_req_ex(const WolfCertServerCfg* srv,
                                              const WolfCertScepCaps* caps,
                                              const uint8_t* ra_cert, size_t ra_cert_len,
                                              const uint8_t* ca_bundle, size_t ca_bundle_len,
                                              const uint8_t* current_cert, size_t current_cert_len,
                                              const WolfCertKey* current_key,
                                              const uint8_t* csr_der, size_t csr_der_len,
                                              WolfCertScepResult* out);

WOLFCERT_API int wolfcert_scep_renewal_req(const WolfCertServerCfg* srv,
                                           const WolfCertScepCaps* caps,
                                           const uint8_t* ra_cert, size_t ra_cert_len,
                                           const uint8_t* current_cert, size_t current_cert_len,
                                           const WolfCertKey* current_key,
                                           const uint8_t* csr_der, size_t csr_der_len,
                                           WolfCertBuffer* out_cert_pem);

/* GetCertInitial (RFC 8894 section 3.3.2, messageType 20): poll for a
 * previously-submitted PKCSReq/RenewalReq that returned PENDING.
 *
 * For a pending PKCSReq, pass signer_cert=NULL; the function will
 * generate the same transient self-signed cert that pkcs_req_ex uses,
 * since its public key already matches signer_key. For a pending
 * RenewalReq, pass the cert being renewed as signer_cert.
 *
 * `transaction_id` must be the value returned by the prior request. It is
 * carried verbatim and the client imposes no length of its own, so whatever
 * the server chose is echoed back to it unchanged.
 * `ra_cert` is the envelope target; `ca_bundle` is the trusted GetCACert bundle
 * the response signer is checked against (see wolfcert_scep_pkcs_req_ex). */
WOLFCERT_API int wolfcert_scep_get_cert_initial(const WolfCertServerCfg* srv,
                                                const WolfCertScepCaps*  caps,
                                                const uint8_t* ra_cert, size_t ra_cert_len,
                                                const uint8_t* ca_bundle, size_t ca_bundle_len,
                                                const uint8_t* signer_cert, size_t signer_cert_len,
                                                const WolfCertKey* signer_key,
                                                const uint8_t* csr_der, size_t csr_der_len,
                                                const uint8_t* transaction_id,
                                                size_t transaction_id_len,
                                                WolfCertScepResult* out);

/* GetNextCACert (RFC 8894 section 4.6.1): retrieve the roll-over CA cert ahead
 * of the current CA's expiry, so the device can install the new trust
 * anchor before the old one stops being honored. Returns
 * WOLFCERT_ERR_NOT_FOUND when the server has no roll-over configured
 * (HTTP 404).
 *
 * The response is a CMS SignedData signed by the current CA. current_ca_der is
 * the current CA certificate(s) in DER (one or more concatenated DER certs,
 * e.g. the whole GetCACert bundle, previously fetched and verified out of band)
 * and is required: the roll-over message is rejected unless its SignedData
 * signer shares a public key with one of them, so a substituted roll-over CA
 * over an untrusted transport is refused. */
WOLFCERT_API int wolfcert_scep_get_next_ca_cert(const WolfCertServerCfg* srv,
                                                const uint8_t* current_ca_der,
                                                size_t current_ca_len,
                                                WolfCertBuffer* out_next_ca_pem);

/* ---- keep-alive / async SCEP session -----------------------------------
 *
 * A single TCP (optionally TLS) connection that carries several SCEP
 * PKIOperation round trips, mirroring the EST session API. SCEP authenticates
 * at the pkiMessage layer, so - unlike EST - the session does NOT require TLS:
 * a plaintext http:// endpoint is accepted.
 *
 * Fetch the CA capabilities and RA/CA certificate first with the one-shot
 * wolfcert_scep_get_ca_caps / wolfcert_scep_get_ca_cert, then drive the
 * enrolling round trips over the session. Open with wolfcert_scep_session_open
 * for a blocking connection, or wolfcert_scep_session_open_async for a
 * non-blocking one whose *_nb calls return WOLFCERT_ERR_WANT_READ /
 * WOLFCERT_ERR_WANT_WRITE (wait for readiness, then call again
 * with the same arguments - and in particular the same WolfCertScepResult* out
 * pointer, which the session captures on the first call; a later poll that
 * passes a different out is rejected with WOLFCERT_ERR_BAD_ARG). DNS + the
 * initial TCP connect inside session_open stay synchronous even in async mode.
 *
 * The blocking *_ex calls run to completion in one call and must be paired with
 * wolfcert_scep_session_open; the *_nb calls require wolfcert_scep_session_open_async.
 * A mismatched pairing is rejected with WOLFCERT_ERR_BAD_ARG.
 *
 * Transport auth: a plaintext http:// session is accepted, but an https://
 * session requires srv->verify_server (an unverified TLS handshake is refused).
 * The enrollment is authenticated at the pkiMessage layer (the CMS signature
 * bound to the CA/RA bundle, plus the PKCS#9 challengePassword) and via
 * optional mTLS. No SCEP entry point sends HTTP Basic credentials - RFC 8894
 * defines no HTTP-layer authentication - which is why WolfCertServerCfg keeps
 * username / password in the EST arm of proto_opts. */
typedef struct WolfCertScepSession WolfCertScepSession;

/* NOTE (transport, differs from the EST session): a plaintext http:// URL is
 * accepted with no error - SCEP does not require TLS. An https:// URL still
 * requires srv->verify_server (an unverified TLS handshake is refused). The EST
 * session, by contrast, rejects plaintext outright. A zero-initialized
 * WolfCertServerCfg pointed at an http:// endpoint therefore opens fine here. */
WOLFCERT_API int  wolfcert_scep_session_open(const WolfCertServerCfg* srv,
                                             WolfCertScepSession** out);
WOLFCERT_API int  wolfcert_scep_session_open_async(const WolfCertServerCfg* srv,
                                                   WolfCertScepSession** out);
WOLFCERT_API void wolfcert_scep_session_close(WolfCertScepSession* s);

/* Socket fd of the backing HTTP session - hand to poll/epoll/kqueue;
 * -1 when a caller-supplied WolfCertTransport backs it (no descriptor). */
WOLFCERT_API int  wolfcert_scep_session_fd(const WolfCertScepSession* s);

/* PKCSReq over the session. See wolfcert_scep_pkcs_req_ex for the argument
 * contract; the result shape (status / cert_pem / transaction_id / fail_info)
 * is identical. */
WOLFCERT_API int wolfcert_scep_session_pkcs_req_ex(WolfCertScepSession* s,
    const WolfCertScepCaps* caps,
    const uint8_t* ra_cert, size_t ra_cert_len,
    const uint8_t* ca_bundle, size_t ca_bundle_len,
    const WolfCertKey* new_key, const uint8_t* csr_der, size_t csr_der_len,
    WolfCertScepResult* out);
WOLFCERT_API int wolfcert_scep_session_pkcs_req_nb(WolfCertScepSession* s,
    const WolfCertScepCaps* caps,
    const uint8_t* ra_cert, size_t ra_cert_len,
    const uint8_t* ca_bundle, size_t ca_bundle_len,
    const WolfCertKey* new_key, const uint8_t* csr_der, size_t csr_der_len,
    WolfCertScepResult* out);

/* RenewalReq over the session. The renewed public key is carried in `csr_der`
 * and `current_key` signs the pkiMessage (see wolfcert_scep_renewal_req_ex). */
WOLFCERT_API int wolfcert_scep_session_renewal_req_ex(WolfCertScepSession* s,
    const WolfCertScepCaps* caps,
    const uint8_t* ra_cert, size_t ra_cert_len,
    const uint8_t* ca_bundle, size_t ca_bundle_len,
    const uint8_t* current_cert, size_t current_cert_len,
    const WolfCertKey* current_key, const uint8_t* csr_der, size_t csr_der_len,
    WolfCertScepResult* out);
WOLFCERT_API int wolfcert_scep_session_renewal_req_nb(WolfCertScepSession* s,
    const WolfCertScepCaps* caps,
    const uint8_t* ra_cert, size_t ra_cert_len,
    const uint8_t* ca_bundle, size_t ca_bundle_len,
    const uint8_t* current_cert, size_t current_cert_len,
    const WolfCertKey* current_key, const uint8_t* csr_der, size_t csr_der_len,
    WolfCertScepResult* out);

/* GetCertInitial (poll a PENDING enrollment) over the session. See
 * wolfcert_scep_get_cert_initial for the argument contract; pass the
 * transactionID the prior request returned. */
WOLFCERT_API int wolfcert_scep_session_get_cert_initial_ex(WolfCertScepSession* s,
    const WolfCertScepCaps* caps,
    const uint8_t* ra_cert, size_t ra_cert_len,
    const uint8_t* ca_bundle, size_t ca_bundle_len,
    const uint8_t* signer_cert, size_t signer_cert_len,
    const WolfCertKey* signer_key,
    const uint8_t* csr_der, size_t csr_der_len,
    const uint8_t* transaction_id, size_t transaction_id_len,
    WolfCertScepResult* out);
WOLFCERT_API int wolfcert_scep_session_get_cert_initial_nb(WolfCertScepSession* s,
    const WolfCertScepCaps* caps,
    const uint8_t* ra_cert, size_t ra_cert_len,
    const uint8_t* ca_bundle, size_t ca_bundle_len,
    const uint8_t* signer_cert, size_t signer_cert_len,
    const WolfCertKey* signer_key,
    const uint8_t* csr_der, size_t csr_der_len,
    const uint8_t* transaction_id, size_t transaction_id_len,
    WolfCertScepResult* out);

#ifdef __cplusplus
}
#endif

#endif /* WOLFCERT_SCEP_H */
