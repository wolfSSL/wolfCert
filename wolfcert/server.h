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
#include <wolfcert/store.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Minimal EST/SCEP test servers. Not hardened for production use - they
 * exist so the library and CLIs can be exercised end-to-end without an
 * external PKI. */

typedef struct WolfCertServer WolfCertServer;

typedef struct {
    WolfCertProtocol protocol;
    const char*      bind_host;          /* e.g. "0.0.0.0"; ignored when
                                          * serve_fd() is used directly */
    uint16_t         bind_port;
    WolfCertStoreOps* ca_store;          /* optional: persist the local CA
                                            across runs; NULL = regen on
                                            each start */
    const char*      challenge_password; /* SCEP challengePassword to accept; NULL disables */
    const char*      http_basic_user;    /* EST HTTP Basic credentials to accept; NULL disables */
    const char*      http_basic_pass;

    /* CA configuration. NULL/zero values fall back to library defaults. */
    WolfCertKeyType  ca_key_type;        /* WOLFCERT_KEY_RSA default */
    int              ca_key_param;       /* 2048 default for RSA, 256 for ECC */

    /* TLS identity. If tls_cert_pem + tls_key_pem are set, the server
     * terminates TLS on every accepted connection before dispatching to
     * the protocol handler. tls_client_ca_pem, when set, enables mutual
     * TLS (WOLFSSL_VERIFY_PEER) against the supplied client-CA bundle.
     *
     * Mandatory for WOLFCERT_PROTO_EST (RFC 7030 has no plaintext mode):
     * wolfcert_server_start() returns WOLFCERT_ERR_TLS without them.
     * Optional for WOLFCERT_PROTO_SCEP, which authenticates at the
     * pkiMessage layer and may be served over cleartext HTTP.
     *
     * All three point at caller-owned PEM bytes; wolfCert copies what it
     * needs during wolfcert_server_start() and does not retain the
     * pointers. */
    const uint8_t*   tls_cert_pem;
    size_t           tls_cert_pem_len;
    const uint8_t*   tls_key_pem;
    size_t           tls_key_pem_len;
    const uint8_t*   tls_client_ca_pem;  /* optional mutual-TLS client CA */
    size_t           tls_client_ca_pem_len;

    /* SCEP manual-approval mode. When set, PKCSReq/RenewalReq return
     * pkiStatus=PENDING instead of issuing immediately; the client must
     * poll with GetCertInitial. The test server's built-in policy auto-
     * approves a pending request on the first poll that quotes its
     * transactionID, which is enough to exercise the pending -> issued
     * transition end-to-end without an admin UI. */
    int              scep_require_approval;

    /* SCEP CA roll-over. When set, the server advertises GetNextCACert
     * in GetCACaps and answers the operation by generating a second CA
     * keypair on demand (cached for the process lifetime). The current
     * CA is not replaced - rollover is the caller's decision. */
    int              scep_enable_next_ca;

    /* EST manual-approval mode (RFC 7030 section 4.2.3). When set, the first
     * /simpleenroll or /simplereenroll POST for a given CSR returns
     * `202 Accepted` with a `Retry-After: <est_retry_after_sec>` header;
     * the next POST with the same CSR body issues the certificate
     * normally. Server-side state is keyed on the SHA-256 of the CSR
     * body so the client must re-POST an identical request - which is
     * what `wolfcert_est_simple_enroll_ex` does when a caller loops on
     * the PENDING status.
     *
     * `est_retry_after_sec` is the value emitted in the `Retry-After`
     * header; defaults to 1 when zero. This is a test-server
     * convenience - a production RA has a richer approval workflow. */
    int              est_require_approval;
    int              est_retry_after_sec;

    /* TLS 1.3 post-handshake authentication (RFC 8446 section 4.6.2). When set
     * AND the server has TLS enabled, the CTX opts into PHA and the
     * initial handshake stays anonymous - protected endpoints
     * (currently EST /simpleenroll and /simplereenroll) ask for a
     * client certificate mid-connection by calling
     * wolfSSL_request_certificate() on first hit. `tls_client_ca_pem`
     * becomes the trust anchor the server uses to verify the
     * certificate the client sends back.
     *
     * Implied side effects: WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT is NOT
     * set on the CTX (the initial handshake has no client cert), and
     * the accept loop keeps the TLS connection open across requests
     * so the anon /cacerts -> authenticated /simpleenroll pattern
     * lands on one connection. */
    int              tls_post_handshake_auth;

    /* EST /csrattrs body. When set, the EST server returns this
     * DER-encoded CsrAttrs blob (RFC 7030 section 4.5.2) as the body of
     * GET /.well-known/est/csrattrs (base64-encoded on the wire).
     * When NULL / zero, the server answers 204 No Content and the
     * client's wolfcert_est_get_csr_attrs returns success with an
     * empty buffer. wolfCert copies the bytes during
     * wolfcert_server_start(), so the caller's buffer can be freed
     * right after. Assemble via wolfcert_csr_attrs_build or hand-
     * roll the DER; either way the client can decode with
     * wolfcert_est_parse_csr_attrs. */
    const uint8_t*   csr_attributes_der;
    size_t           csr_attributes_len;

    /* When set, the EST server parses every incoming /simpleenroll +
     * /simplereenroll CSR and rejects (with HTTP 400) those that do
     * not carry every bare-OID Attribute advertised in
     * `csr_attributes_der`. Currently presence-only enforcement;
     * attribute values are not compared. No-op when
     * csr_attributes_der is empty (nothing to enforce).
     *
     * Test-server convenience for exercising the client-side
     * `srv->proto_opts.est.auto_csrattrs` round-trip end to end;
     * real deployments wire this policy into a proper RA. */
    int              est_require_csr_attributes;

    /* Heap hint for server-internal allocations. */
    void*            heap;
} WolfCertServerCfgSrv;

WOLFCERT_API int  wolfcert_server_start(const WolfCertServerCfgSrv* cfg, WolfCertServer** out);
WOLFCERT_API int  wolfcert_server_run(WolfCertServer* srv);  /* blocking accept loop */
WOLFCERT_API int  wolfcert_server_stop(WolfCertServer* srv);
WOLFCERT_API void wolfcert_server_free(WolfCertServer* srv);

/* Returns the port the server is bound to. Useful after binding on port 0. */
WOLFCERT_API uint16_t wolfcert_server_port(const WolfCertServer* srv);

/* Embed wolfCert's protocol handling in an existing event loop: hand the
 * library an already-accepted connection; it services exactly one request
 * and returns, leaving the caller to close the fd. */
WOLFCERT_API int wolfcert_server_serve_fd(WolfCertServer* srv, int fd);

#ifdef __cplusplus
}
#endif

#endif /* WOLFCERT_SERVER_H */
