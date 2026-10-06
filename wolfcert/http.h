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

/* Minimal HTTP/1.1 client used by EST and SCEP; https URLs run over wolfSSL
 * with the request's trust anchors. */

/* Blocking getaddrinfo + socket + connect over POSIX/BSD sockets, returning
 * a connected fd or -1. Exported so a custom transport's connect can open its
 * TCP leg with it. */
#ifdef WOLFCERT_HAVE_BUILTIN_TRANSPORT
WOLFCERT_API int wolfcert_posix_connect(const char* host, int port,
                                        int timeout_ms, void* ctx);
#endif

typedef struct {
    const char* method;            /* "GET", "HEAD" or "POST" */
    const char* url;               /* full URL; scheme http or https */
    const char* content_type;
    const char* content_transfer_encoding;
    const char* accept;
    const char* basic_user;        /* optional HTTP Basic auth */
    const char* basic_pass;
    const uint8_t* body;
    size_t         body_len;

    /* Optional TLS client cert and key, PEM or DER. */
    const uint8_t* client_cert;
    size_t         client_cert_len;
    const uint8_t* client_key;
    size_t         client_key_len;

    const uint8_t* trust_anchors;   /* PEM or DER */
    size_t         trust_anchors_len;
    int            verify_server;
    int            timeout_ms;

    /* Hard cap on the response body; 0 -> 64 KiB. */
    size_t         max_response_bytes;

    void*          heap;           /* NULL -> default */

    WolfCertTransport transport;

    /* As in WolfCertServerCfg. */
    WolfCertClientKeySrc client_key_src;
    int                  client_key_dev_id;
} WolfCertHttpRequest;

typedef struct {
    int       status_code;
    char*     content_type;
    /* May be NULL when body_len is 0; check body_len, not body. */
    uint8_t*  body;
    size_t    body_len;
    /* `Retry-After` in seconds, capped at 86400 (RFC 9110 10.2.3); 0 if absent,
     * malformed, past, or a date under NO_ASN_TIME or an unset clock. */
    int       retry_after_sec;
    void*     heap;
} WolfCertHttpResponse;

WOLFCERT_API int wolfcert_http_request(const WolfCertHttpRequest* req,
                                       WolfCertHttpResponse* resp);
WOLFCERT_API void wolfcert_http_response_free(WolfCertHttpResponse* resp);

/* Keep-alive HTTP session: one TCP+TLS connection carrying many requests. */
typedef struct WolfCertHttpSession WolfCertHttpSession;

typedef struct {
    /* Server to connect to, e.g. https://ca.example; a path is ignored. */
    const char*    base_url;
    const uint8_t* trust_anchors;
    size_t         trust_anchors_len;
    int            verify_server;
    int            timeout_ms;
    size_t         max_response_bytes;

    /* TLS client identity, loaded before the handshake; it serves both mTLS
     * and a later post-handshake CertificateRequest. */
    const uint8_t* client_cert;
    size_t         client_cert_len;
    const uint8_t* client_key;
    size_t         client_key_len;

    /* TLS 1.3 post-handshake auth opt-in (RFC 8446 section 4.6.2). */
    int            allow_post_handshake_auth;

    void*          heap;

    WolfCertTransport transport;

    /* As in WolfCertServerCfg. */
    WolfCertClientKeySrc client_key_src;
    int                  client_key_dev_id;
} WolfCertHttpSessionCfg;

/* Connects without verifying the server; the first request runs the TLS
 * handshake and returns WOLFCERT_ERR_TLS if it fails, or WOLFCERT_ERR_MEMORY
 * if wolfSSL runs out of memory. */
WOLFCERT_API int  wolfcert_http_session_open (const WolfCertHttpSessionCfg* cfg,
                                              WolfCertHttpSession** out);

/* req->url must match the session's scheme, host and port; req's TLS fields
 * are ignored. After a failed exchange, a body ending at the close or extra
 * bytes after a reply, requests get WOLFCERT_ERR_CONN_CLOSED. */
WOLFCERT_API int  wolfcert_http_session_request(WolfCertHttpSession* s,
                                                const WolfCertHttpRequest* req,
                                                WolfCertHttpResponse* resp);

WOLFCERT_API void wolfcert_http_session_close(WolfCertHttpSession* s);

/* Socket descriptor to poll for the last WOLFCERT_ERR_WANT_*; the built-in
 * transport owns all I/O on it. -1 under any other transport; undefined after
 * close. */
WOLFCERT_API int wolfcert_http_session_fd(const WolfCertHttpSession* s);

/* wolfcert_http_session_request without waiting, on any session. WANT_READ /
 * WANT_WRITE: repeat with the same req and resp once the fd is ready, keeping
 * req->body valid and unchanged; other calls get WOLFCERT_ERR_BAD_ARG. */
WOLFCERT_API int wolfcert_http_session_request_nb(WolfCertHttpSession* s,
                                                  const WolfCertHttpRequest* req,
                                                  WolfCertHttpResponse* resp);

#ifdef __cplusplus
}
#endif

#endif /* WOLFCERT_HTTP_H */
