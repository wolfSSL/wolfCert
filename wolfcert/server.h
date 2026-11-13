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

#ifndef WOLFCERT_SERVER_H
#define WOLFCERT_SERVER_H

#include <wolfcert/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Minimal EST/SCEP test servers for development and interop; not hardened
 * for production use. */

typedef struct WolfCertServer WolfCertServer;

typedef struct {
    WolfCertProtocol protocol;
    const char*      bind_host;          /* numeric IPv4, NULL = all
                                          * interfaces */
    uint16_t         bind_port;
    const char*      challenge_password; /* SCEP challengePassword to accept; NULL disables */
    const char*      http_basic_user;    /* EST HTTP Basic credentials to accept; NULL disables */
    const char*      http_basic_pass;    /* must be non-empty when http_basic_user is set */

    /* Key for each CA the server generates: at start without ca_cert, and for
     * GetNextCACert. NULL/zero values fall back to library defaults. */
    WolfCertKeyType  ca_key_type;        /* WOLFCERT_KEY_RSA default */
    int              ca_key_param;       /* 2048 default for RSA, 256 for ECC */

    /* TLS identity, required for EST (wolfcert_server_start() returns
     * WOLFCERT_ERR_TLS without it) and optional for SCEP. tls_client_ca_pem
     * enables mutual TLS; EST /simplereenroll needs it (else 403) and a
     * wolfSSL built with KEEP_PEER_CERT (else 500). All three PEM buffers
     * are copied by wolfcert_server_start(). */
    const uint8_t*   tls_cert_pem;
    size_t           tls_cert_pem_len;
    const uint8_t*   tls_key_pem;
    size_t           tls_key_pem_len;
    const uint8_t*   tls_client_ca_pem;  /* optional mutual-TLS client CA */
    size_t           tls_client_ca_pem_len;

    /* SCEP manual approval: PKCSReq/RenewalReq answer PENDING, or FAILURE
     * for a bad CSR signature. The first GetCertInitial that quotes the
     * transactionID and is signed with the parked request's signer key
     * approves it. */
    int              scep_require_approval;

    /* SCEP CA roll-over: advertise GetNextCACert and answer it with a second
     * CA generated on demand. The current CA is not replaced. */
    int              scep_enable_next_ca;

    /* SCEP GetCert (RFC 8894 section 3.3.4), answered badRequest while clear.
     * When set, any client that can sign a pkiMessage can fetch the 16 most
     * recently issued certificates by serial; older ones answer badCertId. */
    int              scep_enable_get_cert;

    /* EST manual approval (RFC 7030 section 4.2.3): the first POST of a CSR
     * gets 202 Accepted with Retry-After: est_retry_after_sec (1 when 0), and
     * the next POST of the same CSR is issued. A CSR that fails to decode or
     * verify gets 400 and is never parked. */
    int              est_require_approval;
    int              est_retry_after_sec;

    /* TLS 1.3 post-handshake auth (RFC 8446 section 4.6.2) for EST enrollment,
     * checked against `tls_client_ca_pem`, which it requires. Other protocols
     * reject it with WOLFCERT_ERR_BAD_ARG. wolfcert_server_start() returns
     * WOLFCERT_ERR_UNSUPPORTED without KEEP_PEER_CERT and
     * WOLFSSL_HAVE_TLS_UNIQUE; see docs/ARCHITECTURE.md. */
    int              tls_post_handshake_auth;

    /* DER CsrAttrs (RFC 7030 section 4.5.2) served at /csrattrs; NULL or 0
     * answers 204 No Content. Copied by wolfcert_server_start(). */
    const uint8_t*   csr_attributes_der;
    size_t           csr_attributes_len;

    /* Answer 400 to an EST enroll CSR lacking an attribute named by a bare
     * OID in csr_attributes_der; Attribute items are ignored. */
    int              est_require_csr_attributes;

    /* Heap hint for server-internal allocations. */
    void*            heap;

    /* Lets EST start with neither Basic nor tls_client_ca_pem. */
    int              est_allow_anonymous_enroll;

    /* SCEP split CA/RA: the CA issues a new RA certificate at every start to
     * decrypt and sign SCEP messages; wolfcert_server_get_ca() omits it. */
    int              scep_split_ra;

    /* CA to issue from: one certificate and its key, PEM or DER, copied at
     * start. Both NULL generates a CA; one alone is WOLFCERT_ERR_BAD_ARG. */
    const uint8_t*   ca_cert;
    size_t           ca_cert_len;
    const uint8_t*   ca_key;
    size_t           ca_key_len;
} WolfCertServerCfgSrv;

WOLFCERT_API int  wolfcert_server_start(const WolfCertServerCfgSrv* cfg, WolfCertServer** out);
/* Blocking accept loop. Closes a connection that does not finish its TLS
 * handshake or its next request within WOLFCERT_SERVER_REQUEST_TIMEOUT_MS. */
WOLFCERT_API int  wolfcert_server_run(WolfCertServer* srv);
WOLFCERT_API int  wolfcert_server_stop(WolfCertServer* srv);
WOLFCERT_API void wolfcert_server_free(WolfCertServer* srv);

/* Returns the port the server is bound to. Useful after binding on port 0. */
WOLFCERT_API uint16_t wolfcert_server_port(const WolfCertServer* srv);

/* Copies out the CA the server issues from, e.g. to keep a generated one.
 * out_key may be NULL; free the key with wolfcert_buffer_free_secure(). */
WOLFCERT_API int wolfcert_server_get_ca(const WolfCertServer* srv,
                                        WolfCertEncoding enc,
                                        WolfCertBuffer* out_cert,
                                        WolfCertBuffer* out_key);

/* Service exactly one request on an already-accepted connection; the caller
 * closes fd. WOLFCERT_SERVER_REQUEST_TIMEOUT_MS does not apply. The fd carries
 * no TLS, so EST enrollment on it needs http_basic_user or
 * est_allow_anonymous_enroll. */
WOLFCERT_API int wolfcert_server_serve_fd(WolfCertServer* srv, int fd);

#ifdef __cplusplus
}
#endif

#endif /* WOLFCERT_SERVER_H */
