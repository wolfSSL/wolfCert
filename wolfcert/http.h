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

#ifndef WOLFCERT_HTTP_H
#define WOLFCERT_HTTP_H

#include <wolfcert/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Minimal HTTP/1.1 client used by the EST and SCEP modules. TLS, when
 * requested by the URL scheme, is layered on top of wolfSSL with the
 * caller-supplied trust anchors. */

/* Built-in WolfCertConnectFn: blocking getaddrinfo + socket + connect over
 * POSIX/BSD sockets. Exported so applications can wrap or chain it. */
#ifdef WOLFCERT_HAVE_BUILTIN_TRANSPORT
WOLFCERT_API int wolfcert_posix_connect(const char* host, int port,
                                        int timeout_ms, void* ctx);
#endif

typedef struct {
    const char* method;            /* "GET" or "POST" */
    const char* url;               /* full URL; scheme http or https */
    const char* content_type;
    const char* content_transfer_encoding;
    const char* accept;
    const char* basic_user;        /* optional HTTP Basic auth */
    const char* basic_pass;
    const uint8_t* body;
    size_t         body_len;

    /* Optional TLS client auth (used by EST simplereenroll).
     * client_cert / client_key / trust_anchors may be PEM or DER. */
    const uint8_t* client_cert;
    size_t         client_cert_len;
    const uint8_t* client_key;
    size_t         client_key_len;

    const uint8_t* trust_anchors;
    size_t         trust_anchors_len;
    int            verify_server;
    int            timeout_ms;

    /* Hard cap on the response body. 0 -> 64 KiB default. A caller
     * embedding wolfCert in an MCU almost always sets this explicitly. */
    size_t         max_response_bytes;

    WolfCertConnectFn connect_cb;
    void*          connect_ctx;

    void*          heap;           /* NULL -> default */

    const WolfCertTransport* transport;
} WolfCertHttpRequest;

typedef struct {
    int       status_code;
    char*     content_type;
    uint8_t*  body;
    size_t    body_len;
    /* `Retry-After` header parsed as delta-seconds (RFC 7231 section 7.1.3).
     * Populated for any response that carries the header; 0 means the
     * header was absent or wasn't in the delta-seconds form. The HTTP
     * date form is not supported. */
    int       retry_after_sec;
    void*     heap;
} WolfCertHttpResponse;

WOLFCERT_API int wolfcert_http_request(const WolfCertHttpRequest* req,
                                       WolfCertHttpResponse* resp);
WOLFCERT_API void wolfcert_http_response_free(WolfCertHttpResponse* resp);

/* ---- keep-alive HTTP sessions ------------------------------------------
 *
 * One TCP+TLS connection, many requests. Used by the EST session layer so
 * that an anonymous `/cacerts` and an mTLS-authenticated `/simpleenroll`
 * can ride the same TLS connection. When `allow_post_handshake_auth` is
 * non-zero the underlying TLS 1.3 context opts into RFC 8446 section 4.6.2
 * post-handshake authentication - the initial handshake stays anonymous
 * and the server asks for a certificate mid-session when a protected
 * resource is first hit. The client cert + key are loaded on the WOLFSSL
 * object up front so wolfSSL can answer that prompt without any further
 * caller involvement. */
typedef struct WolfCertHttpSession WolfCertHttpSession;

typedef struct {
    const char*    base_url;          /* e.g. https://ca.example */
    const uint8_t* trust_anchors;
    size_t         trust_anchors_len;
    int            verify_server;
    int            timeout_ms;
    size_t         max_response_bytes;

    /* TLS client identity. When set it's loaded on the WOLFSSL before
     * the initial handshake, so it's usable both for up-front mTLS and
     * for answering a later TLS 1.3 post-handshake CertificateRequest. */
    const uint8_t* client_cert;
    size_t         client_cert_len;
    const uint8_t* client_key;
    size_t         client_key_len;

    /* TLS 1.3 post-handshake authentication opt-in. */
    int            allow_post_handshake_auth;

    /* Non-blocking session I/O: wolfcert_http_session_request_nb returns
     * WOLFCERT_ERR_WANT_READ / WOLFCERT_ERR_WANT_WRITE instead of blocking,
     * and the TLS handshake is driven incrementally. Poll
     * wolfcert_http_session_fd(), or your transport's own readiness signal.
     * DNS and the initial connect stay synchronous. */
    int            nonblocking;

    WolfCertConnectFn connect_cb;
    void*          connect_ctx;

    void*          heap;

    const WolfCertTransport* transport;
} WolfCertHttpSessionCfg;

WOLFCERT_API int  wolfcert_http_session_open (const WolfCertHttpSessionCfg* cfg,
                                              WolfCertHttpSession** out);

/* Issue one HTTP request on the already-open connection. `req->url` must
 * match the session's scheme + host + port; the path component is what
 * actually drives the request. TLS / trust-anchor fields on `req` are
 * ignored - they're fixed at session open. */
WOLFCERT_API int  wolfcert_http_session_request(WolfCertHttpSession* s,
                                                const WolfCertHttpRequest* req,
                                                WolfCertHttpResponse* resp);

WOLFCERT_API void wolfcert_http_session_close(WolfCertHttpSession* s);

/* Socket descriptor of the open session, for event loops: poll POLLIN /
 * POLLOUT per the last WOLFCERT_ERR_WANT_READ / _WANT_WRITE returned;
 * undefined after wolfcert_http_session_close. A caller-supplied
 * WolfCertTransport has no descriptor to offer, so it returns -1. */
WOLFCERT_API int wolfcert_http_session_fd(const WolfCertHttpSession* s);

/* Non-blocking variant of wolfcert_http_session_request. Must be used
 * against a session opened with WolfCertHttpSessionCfg.nonblocking = 1.
 *
 * Returns:
 *   WOLFCERT_OK             - `resp` populated; re-usable for next call.
 *   WOLFCERT_ERR_WANT_READ  - block on fd readable, then call again
 *                             with the same arguments.
 *   WOLFCERT_ERR_WANT_WRITE - block on fd writable, then call again.
 *   other negative values   - permanent failure; close the session.
 *
 * Sessions remember their in-flight state across calls. The caller
 * must NOT mutate `req` or `resp` between WANT_* returns and the final
 * OK/error return. */
WOLFCERT_API int wolfcert_http_session_request_nb(WolfCertHttpSession* s,
                                                  const WolfCertHttpRequest* req,
                                                  WolfCertHttpResponse* resp);

#ifdef __cplusplus
}
#endif

#endif /* WOLFCERT_HTTP_H */
