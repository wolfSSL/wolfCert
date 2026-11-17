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

/* SCEP (RFC 8894) client primitives. */

typedef struct {
    int post_pki_operation;      /* GetCACaps: POSTPKIOperation */
    int renewal;                 /* GetCACaps: Renewal */
    int sha256;                  /* GetCACaps: SHA-256 */
    int sha384;                  /* GetCACaps: SHA-384 */
    int sha512;                  /* GetCACaps: SHA-512 */
    int aes;                     /* GetCACaps: AES */
    int scep_standard;           /* GetCACaps: SCEPStandard; also sets
                                  * post_pki_operation, sha256 and aes */
    int get_next_ca_cert;        /* GetCACaps: GetNextCACert */
} WolfCertScepCaps;

/* GET ?operation=GetCACaps. A non-200 reply returns WOLFCERT_ERR_HTTP with
 * out_caps all zero. */
WOLFCERT_API int wolfcert_scep_get_ca_caps(const WolfCertServerCfg* srv,
                                           WolfCertScepCaps* out_caps);

/* GET ?operation=GetCACert - returns the CA cert(s) as PEM for
 * WOLFCERT_ENCODING_PEM, or for WOLFCERT_ENCODING_DER the whole bundle as
 * concatenated DER, usable as ca_bundle for the enroll and GetNextCACert
 * calls. An application/x-x509-ca-ra-cert response or a signedData body under
 * any Content-Type is read as a bundle; any other reply that is not a
 * certificate returns WOLFCERT_ERR_PARSE. */
WOLFCERT_API int wolfcert_scep_get_ca_cert(const WolfCertServerCfg* srv,
                                           WolfCertEncoding enc,
                                           WolfCertBuffer* out_ca);

/* Digest for wolfcert_scep_verify_ca_fingerprint. AUTO picks it from the
 * fingerprint length (20 SHA-1, 32 SHA-256, 64 SHA-512), so a 20-byte value
 * selects the collision-broken SHA-1; an explicit SHA256 or SHA512 avoids that
 * when the digest is known. SHA-1 and SHA-512 return WOLFCERT_ERR_UNSUPPORTED
 * when wolfSSL lacks them. */
typedef enum {
    WOLFCERT_SCEP_FP_AUTO   = 0,
    WOLFCERT_SCEP_FP_SHA256 = 1,
    WOLFCERT_SCEP_FP_SHA1   = 2,
    WOLFCERT_SCEP_FP_SHA512 = 3
} WolfCertScepFpAlg;

/* Compare the hash of one DER CA/RA certificate (e.g. the GetCACert leaf) in
 * constant time against a fingerprint obtained out of band. Returns
 * WOLFCERT_OK on match, WOLFCERT_ERR_AUTH on mismatch, WOLFCERT_ERR_BAD_ARG for
 * empty input or an expected_len that does not match the algorithm, and
 * WOLFCERT_ERR_UNSUPPORTED when the digest is not in wolfSSL. */
WOLFCERT_API int wolfcert_scep_verify_ca_fingerprint(const uint8_t* ca_der,
                                                     size_t ca_der_len,
                                                     const uint8_t* expected,
                                                     size_t expected_len,
                                                     WolfCertScepFpAlg alg);

/* The certificate in a GetCACert bundle (concatenated DER, as from
 * wolfcert_scep_get_ca_cert in DER) to envelope requests to; *cert points into
 * bundle, and heap NULL = default. Nothing here is verified, so bundle should
 * hold only certificates the caller trusts, such as a pinned CA and the RAs
 * it issued. A non-CA RSA certificate is preferred:
 * keyEncipherment without digitalSignature, keyEncipherment, no keyUsage,
 * then dataEncipherment alone. Failing that, the RSA CA that issued no other
 * CA in the bundle, a subordinate CA ahead of a self-issued one and
 * keyEncipherment breaking a tie; certificates for one key count once. Returns WOLFCERT_ERR_PROTOCOL when certificates for different
 * keys tie, WOLFCERT_ERR_UNSUPPORTED when none qualifies,
 * WOLFCERT_ERR_BAD_ARG past MAX_PKCS7_CERTS certificates and
 * WOLFCERT_ERR_PARSE when bundle does not start with a DER SEQUENCE. A
 * SEQUENCE that is not a certificate is skipped, and bytes after the last
 * SEQUENCE are ignored. */
WOLFCERT_API int wolfcert_scep_select_ra_cert(const uint8_t* bundle,
                                              size_t bundle_len,
                                              const uint8_t** cert,
                                              size_t* cert_len, void* heap);

/* CertRep pkiStatus (RFC 8894 section 3.2.1.3). UNSET takes the zero value,
 * so SUCCESS is 1 where the wire encoding is "0". PENDING awaits manual
 * approval and is polled with wolfcert_scep_get_cert_initial using the
 * returned transactionID. */
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
    /* transaction_id (PrintableString) is owned and populated whenever the
     * server returns a CertRep; callers echo it back via get_cert_initial. */
    uint8_t*           transaction_id;
    size_t             transaction_id_len;
    /* RFC 8894 section 3.2.1.4 failInfo when status == FAILURE: 0=badAlg,
     * 1=badMessageCheck, 2=badRequest, 3=badTime, 4=badCertId; else -1. */
    int                fail_info;
    void*              heap;
} WolfCertScepResult;

/* Every wolfcert_scep_* call taking a WolfCertScepResult* initializes a
 * non-NULL *out first, so freeing it after any outcome is safe. A populated
 * result must be freed before it is passed again, except a session's
 * in-flight result, which every resume passes back unfreed. */
WOLFCERT_API void wolfcert_scep_result_free(WolfCertScepResult* r);

/* PKCSReq. The challengePassword travels in the CSR, from
 * meta.challenge_password at wolfcert_csr_build; SCEP sends no HTTP
 * credentials. caps is the GetCACaps reply; NULL sends a POST with SHA-256 and
 * 3DES where proto_opts.scep leaves the hash and cipher on AUTO, and returns
 * WOLFCERT_ERR_UNSUPPORTED if wolfSSL lacks 3DES. ra_cert is the DER cert the
 * request is enveloped to; ca_bundle is the trusted GetCACert bundle the
 * CertRep signer is checked against, which for a single-cert CA is ra_cert
 * itself. Returns WOLFCERT_OK once a CertRep verifies, with SUCCESS /
 * PENDING / FAILURE in out->status; TLS, HTTP and parse failures return their
 * error code. */
WOLFCERT_API int wolfcert_scep_pkcs_req(const WolfCertServerCfg* srv,
                                        const WolfCertScepCaps* caps,
                                        const uint8_t* ra_cert, size_t ra_cert_len,
                                        const uint8_t* ca_bundle, size_t ca_bundle_len,
                                        const WolfCertKey* new_key,
                                        const uint8_t* csr_der, size_t csr_der_len,
                                        WolfCertScepResult* out);

/* RenewalReq: current_key signs the pkiMessage and csr_der carries the new
 * public key. caps, ra_cert and ca_bundle are as for wolfcert_scep_pkcs_req. */
WOLFCERT_API int wolfcert_scep_renewal_req(const WolfCertServerCfg* srv,
                                           const WolfCertScepCaps* caps,
                                           const uint8_t* ra_cert, size_t ra_cert_len,
                                           const uint8_t* ca_bundle, size_t ca_bundle_len,
                                           const uint8_t* current_cert, size_t current_cert_len,
                                           const WolfCertKey* current_key,
                                           const uint8_t* csr_der, size_t csr_der_len,
                                           WolfCertScepResult* out);

/* GetCertInitial (RFC 8894 section 3.3.3): poll a PKCSReq or RenewalReq that
 * returned PENDING. signer_cert is NULL for a PKCSReq (the transient
 * self-signed cert is rebuilt from signer_key), or the cert being renewed for
 * a RenewalReq.
 * transaction_id is the prior request's, echoed verbatim; a value outside
 * PrintableString returns WOLFCERT_ERR_BAD_ARG. caps, ra_cert and ca_bundle
 * are as for wolfcert_scep_pkcs_req. */
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

/* GetCert (RFC 8894 section 3.3.4): fetch an issued certificate by serial,
 * e.g. to recover a lost local copy. GetCert is optional, so a CA may answer
 * FAILURE/badCertId or not at all. signer_cert / signer_key sign the
 * pkiMessage, with no self-signed fallback. serial is the INTEGER content
 * (DecodedCert.serial / serialSz). caps, ra_cert and ca_bundle are as for
 * wolfcert_scep_pkcs_req. On a hit out->status is SUCCESS; a verified reply
 * without the requested issuer and serial returns WOLFCERT_ERR_PROTOCOL with
 * out->status UNSET, and running out of memory searching it returns
 * WOLFCERT_ERR_MEMORY. */
WOLFCERT_API int wolfcert_scep_get_cert(const WolfCertServerCfg* srv,
                                        const WolfCertScepCaps* caps,
                                        const uint8_t* ra_cert, size_t ra_cert_len,
                                        const uint8_t* ca_bundle, size_t ca_bundle_len,
                                        const uint8_t* signer_cert, size_t signer_cert_len,
                                        const WolfCertKey* signer_key,
                                        const uint8_t* serial, size_t serial_len,
                                        WolfCertScepResult* out);

/* GetNextCACert (RFC 8894 section 4.7): fetch the roll-over CA cert, as PEM or
 * concatenated DER per enc. Returns WOLFCERT_ERR_NOT_FOUND on HTTP 404 (no
 * roll-over). current_ca_der is required: the current, verified CA cert(s) as
 * concatenated DER. The reply is rejected unless its signer shares a public
 * key with one of them. */
WOLFCERT_API int wolfcert_scep_get_next_ca_cert(const WolfCertServerCfg* srv,
                                                WolfCertEncoding enc,
                                                const uint8_t* current_ca_der,
                                                size_t current_ca_len,
                                                WolfCertBuffer* out_next_ca);

/* Keep-alive SCEP session carrying several requests over one connection.
 * Plain http:// is accepted and https:// needs srv->verify_server. Each call
 * on it is blocking or _nb, and the style may change between requests. Open
 * checks the config, copies proto_opts.scep and connects synchronously; over
 * https:// it does not verify the server: the first request runs the TLS
 * handshake and returns WOLFCERT_ERR_TLS if it fails, or WOLFCERT_ERR_MEMORY
 * if wolfSSL runs out of memory. An _nb call returning WOLFCERT_ERR_WANT_READ
 * / _WANT_WRITE is repeated with the same arguments when the session fd is
 * ready. While a request is in flight, a call for another operation, output
 * or encoding, and any blocking call, returns WOLFCERT_ERR_BAD_ARG and leaves
 * it intact. */
typedef struct WolfCertScepSession WolfCertScepSession;

WOLFCERT_API int  wolfcert_scep_session_open(const WolfCertServerCfg* srv,
                                             WolfCertScepSession** out);
WOLFCERT_API void wolfcert_scep_session_close(WolfCertScepSession* s);

/* Socket fd of the backing HTTP session - hand to poll/epoll/kqueue;
 * -1 when a caller-supplied WolfCertTransport backs it (no descriptor). */
WOLFCERT_API int  wolfcert_scep_session_fd(const WolfCertScepSession* s);

WOLFCERT_API int wolfcert_scep_session_get_ca_caps(WolfCertScepSession* s,
                                                   WolfCertScepCaps* out_caps);
WOLFCERT_API int wolfcert_scep_session_get_ca_caps_nb(WolfCertScepSession* s,
                                                      WolfCertScepCaps* out_caps);
WOLFCERT_API int wolfcert_scep_session_get_ca_cert(WolfCertScepSession* s,
                                                   WolfCertEncoding enc,
                                                   WolfCertBuffer* out_ca);
WOLFCERT_API int wolfcert_scep_session_get_ca_cert_nb(WolfCertScepSession* s,
                                                      WolfCertEncoding enc,
                                                      WolfCertBuffer* out_ca);
WOLFCERT_API int wolfcert_scep_session_get_next_ca_cert(WolfCertScepSession* s,
                                                        WolfCertEncoding enc,
                                                        const uint8_t* current_ca_der,
                                                        size_t current_ca_len,
                                                        WolfCertBuffer* out_next_ca);
WOLFCERT_API int wolfcert_scep_session_get_next_ca_cert_nb(WolfCertScepSession* s,
                                                           WolfCertEncoding enc,
                                                           const uint8_t* current_ca_der,
                                                           size_t current_ca_len,
                                                           WolfCertBuffer* out_next_ca);

WOLFCERT_API int wolfcert_scep_session_pkcs_req(WolfCertScepSession* s,
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

WOLFCERT_API int wolfcert_scep_session_renewal_req(WolfCertScepSession* s,
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

WOLFCERT_API int wolfcert_scep_session_get_cert_initial(WolfCertScepSession* s,
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

WOLFCERT_API int wolfcert_scep_session_get_cert(WolfCertScepSession* s,
                                                const WolfCertScepCaps* caps,
                                                const uint8_t* ra_cert, size_t ra_cert_len,
                                                const uint8_t* ca_bundle, size_t ca_bundle_len,
                                                const uint8_t* signer_cert, size_t signer_cert_len,
                                                const WolfCertKey* signer_key,
                                                const uint8_t* serial, size_t serial_len,
                                                WolfCertScepResult* out);
WOLFCERT_API int wolfcert_scep_session_get_cert_nb(WolfCertScepSession* s,
                                                   const WolfCertScepCaps* caps,
                                                   const uint8_t* ra_cert, size_t ra_cert_len,
                                                   const uint8_t* ca_bundle, size_t ca_bundle_len,
                                                   const uint8_t* signer_cert, size_t signer_cert_len,
                                                   const WolfCertKey* signer_key,
                                                   const uint8_t* serial, size_t serial_len,
                                                   WolfCertScepResult* out);

#ifdef __cplusplus
}
#endif

#endif /* WOLFCERT_SCEP_H */
