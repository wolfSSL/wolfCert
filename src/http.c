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

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include <wolfcert/http.h>
#include <wolfcert/errors.h>
#include <wolfcert/version.h>
#include "internal.h"

#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/coding.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define WOLFCERT_HTTP_MAX_HOST_LEN 256
/* Large enough to carry an RFC 8894 GET PKIOperation whose base64 pkiMessage
 * rides in the query string (bounded by WOLFCERT_SCEP_MAX_GET_URL). The parsed
 * path is heap-allocated and the request head buffer is sized to it, so this is
 * only a sanity ceiling. */
#ifndef WOLFCERT_HTTP_MAX_PATH_LEN
#define WOLFCERT_HTTP_MAX_PATH_LEN 8192
#endif
/* The SCEP GET fallback builds a URL up to WOLFCERT_SCEP_MAX_GET_URL and then
 * parses its own request through wolfcert_http_url_parse, which rejects a
 * path+query longer than this. Guard the relationship so an inconsistent -D
 * override fails fast instead of the client rejecting a URL it just built. */
#if WOLFCERT_SCEP_MAX_GET_URL > WOLFCERT_HTTP_MAX_PATH_LEN
#error "WOLFCERT_SCEP_MAX_GET_URL exceeds WOLFCERT_HTTP_MAX_PATH_LEN; raise WOLFCERT_HTTP_MAX_PATH_LEN so the client accepts the largest GET URL it will build."
#endif
#define WOLFCERT_HTTP_DEFAULT_MAX_BODY  (64 * 1024)
#define WOLFCERT_HTTP_READ_CHUNK   2048

/* ---- URL parsing -------------------------------------------------------- */

WOLFCERT_TEST_VIS void wolfcert_http_url_free(WolfCertUrl* u)
{
    if (u == NULL)
        return;

    WOLFCERT_XFREE(u->scheme, u->heap);
    WOLFCERT_XFREE(u->host,   u->heap);
    WOLFCERT_XFREE(u->path,   u->heap);

    u->scheme = u->host = u->path = NULL;
}

/* Build the "scheme://host[:port]" origin for a parsed URL into a freshly
 * allocated buffer (owned by the caller, free with WOLFCERT_XFREE). The default
 * port (443 for TLS, 80 otherwise) is omitted. Shared by the EST and SCEP
 * session opens so the two origin builders cannot drift. */
WOLFCERT_TEST_VIS int wolfcert_http_url_origin(const WolfCertUrl* u, void* heap,
                                               char** out_origin)
{
    size_t origin_len;
    char*  origin;

    if (u == NULL || u->scheme == NULL || u->host == NULL || out_origin == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    /* scheme + "://" (3) + host + the optional ":65535" and NUL; 16 leaves the
     * port suffix room to spare rather than sizing it to the digit. */
    origin_len = strlen(u->scheme) + 3 + strlen(u->host) + 16;
    origin = (char*)WOLFCERT_XMALLOC(origin_len, heap);
    if (origin == NULL)
        return WOLFCERT_ERR_MEMORY;

    if ((u->tls && u->port == 443) || (!u->tls && u->port == 80))
        snprintf(origin, origin_len, "%s://%s", u->scheme, u->host);
    else
        snprintf(origin, origin_len, "%s://%s:%d", u->scheme, u->host, u->port);

    *out_origin = origin;
    return WOLFCERT_OK;
}

static char* dup_range(const char* s, const char* e, void* heap)
{
    size_t n = (size_t)(e - s);

    char* r = (char*)WOLFCERT_XMALLOC(n + 1, heap);
    if (r == NULL)
        return NULL;

    memcpy(r, s, n);
    r[n] = '\0';
    return r;
}

WOLFCERT_TEST_VIS int wolfcert_http_url_parse(const char* url, WolfCertUrl* out,
                                              void* heap)
{
    memset(out, 0, sizeof(*out));
    out->heap = heap;
    if (url == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    /* TLS is the secure default: a URL without an explicit scheme is treated
     * as https. An explicit "http://" still opts out into plaintext (SCEP, and
     * EST against a local/test server, legitimately run over plain HTTP). */
    const char* sep = strstr(url, "://");
    const char* host_start;
    if (sep == NULL) {
        out->scheme = wolfcert_strdup("https", heap);
        if (out->scheme == NULL)
            return WOLFCERT_ERR_MEMORY;

        out->tls = 1;
        out->port = 443;
        host_start = url;
    }
    else {
        size_t scheme_len = (size_t)(sep - url);
        if (scheme_len > 16)
            return WOLFCERT_ERR_PARSE;

        out->scheme = dup_range(url, sep, heap);
        if (out->scheme == NULL)
            return WOLFCERT_ERR_MEMORY;

        if (strcasecmp(out->scheme, "https") == 0) {
            out->tls = 1;
            out->port = 443;
        }
        else if (strcasecmp(out->scheme, "http")  == 0) {
            out->tls = 0;
            out->port = 80;
        }
        else {
            wolfcert_http_url_free(out);
            return WOLFCERT_ERR_UNSUPPORTED;
        }

        host_start = sep + 3;
    }

    const char* host_end;
    if (*host_start == '[') {
        const char* close = strchr(host_start, ']');

        if (close == NULL) {
            wolfcert_http_url_free(out);
            return WOLFCERT_ERR_PARSE;
        }

        if ((size_t)(close - host_start - 1) > WOLFCERT_HTTP_MAX_HOST_LEN) {
            wolfcert_http_url_free(out);
            return WOLFCERT_ERR_PARSE;
        }

        out->host = dup_range(host_start + 1, close, heap);
        host_end = close + 1;
    }
    else {
        host_end = host_start;
        while (*host_end && *host_end != ':' && *host_end != '/') {
            ++host_end;
        }

        if ((size_t)(host_end - host_start) > WOLFCERT_HTTP_MAX_HOST_LEN) {
            wolfcert_http_url_free(out);
            return WOLFCERT_ERR_PARSE;
        }

        out->host = dup_range(host_start, host_end, heap);
    }

    if (out->host == NULL) {
        wolfcert_http_url_free(out);
        return WOLFCERT_ERR_MEMORY;
    }

    if (*host_end == ':') {
        char* end;
        long p = strtol(host_end + 1, &end, 10);
        if (p <= 0 || p > 65535) {
            wolfcert_http_url_free(out);
            return WOLFCERT_ERR_PARSE;
        }

        out->port = (int)p;
        host_end = end;
    }

    size_t plen = *host_end ? strlen(host_end) : 1;
    if (plen > WOLFCERT_HTTP_MAX_PATH_LEN) {
        wolfcert_http_url_free(out);
        return WOLFCERT_ERR_PARSE;
    }

    out->path = (*host_end == '\0') ? wolfcert_strdup("/", heap)
                                    : wolfcert_strdup(host_end, heap);
    if (out->path == NULL) {
        wolfcert_http_url_free(out);
        return WOLFCERT_ERR_MEMORY;
    }

    return WOLFCERT_OK;
}

/* ---- base64 auth header ------------------------------------------------- */

static int basic_auth_header(const char* user, const char* pass,
                             char* out, size_t out_cap, void* heap)
{
    if (user == NULL)
        return 0;

    size_t ulen = strlen(user);
    size_t plen = pass ? strlen(pass) : 0;
    size_t total = ulen + 1 + plen;
    uint8_t* raw = (uint8_t*)WOLFCERT_XMALLOC(total, heap);
    if (raw == NULL)
        return WOLFCERT_ERR_MEMORY;

    memcpy(raw, user, ulen);
    raw[ulen] = ':';
    if (plen > 0)
        memcpy(raw + ulen + 1, pass, plen);

    word32 enc_cap = (word32)(((total + 2) / 3) * 4 + 4);
    uint8_t* enc = (uint8_t*)WOLFCERT_XMALLOC(enc_cap, heap);
    if (enc == NULL) {
        wc_ForceZero(raw, (word32)total);
        WOLFCERT_XFREE(raw, heap);
        return WOLFCERT_ERR_MEMORY;
    }

    word32 enc_len = enc_cap;
    int rc = Base64_Encode_NoNl(raw, (word32)total, enc, &enc_len);

    /* `raw` is the credential in the clear and `enc` is base64, which is
     * encoding rather than protection - neither has any reason to sit in freed
     * heap after the header is built. */
    wc_ForceZero(raw, (word32)total);
    WOLFCERT_XFREE(raw, heap);
    if (rc != 0) {
        wc_ForceZero(enc, enc_cap);
        WOLFCERT_XFREE(enc, heap);
        return WOLFCERT_ERR_CRYPTO;
    }

    int n = snprintf(out, out_cap, "Authorization: Basic %.*s\r\n",
                     (int)enc_len, (char*)enc);

    wc_ForceZero(enc, enc_cap);
    WOLFCERT_XFREE(enc, heap);
    if (n < 0 || (size_t)n >= out_cap) {
        /* snprintf wrote into the caller's buffer before this check, so the
         * error path still has a truncated credential to clear. */
        wc_ForceZero(out, (word32)out_cap);
        return WOLFCERT_ERR_MEMORY;
    }

    return n;
}

/* ---- TCP + TLS I/O ------------------------------------------------------ */

/* Open a TCP connection via the caller-supplied transport, falling back to
 * the built-in POSIX connect when none was given. Returns a connected fd or
 * a negative value on failure. */
static int dial(const char* host, int port, int timeout_ms,
                WolfCertConnectFn connect_cb, void* connect_ctx)
{
    WolfCertConnectFn fn = connect_cb ? connect_cb : wolfcert_posix_connect;

    return fn(host, port, timeout_ms, connect_ctx);
}

typedef struct {
    int       fd;
    WOLFSSL*  ssl;
} WolfCertConn;

/* Per-request state for the async state machine. `sm_state` picks up
 * where the previous tick left off. Buffers are owned by the session
 * across WANT_READ/WRITE returns. */
typedef enum {
    SM_IDLE         = 0,
    SM_HANDSHAKE    = 1,  /* TLS handshake not yet complete */
    SM_WRITE_HEAD   = 2,
    SM_WRITE_BODY   = 3,
    SM_READ_HEAD    = 4,
    SM_READ_BODY_CL = 5,  /* Content-Length known */
    SM_READ_BODY_EOF= 6,  /* read until close */
    SM_DONE         = 7
} SmState;

struct WolfCertHttpSession {
    WolfCertConn  conn;
    WOLFSSL_CTX*  ctx;
    WolfCertUrl   base;
    /* Bytes read past the end of the previous response's body; we carry
     * them into the next request's parser. In practice HTTP/1.1 rarely
     * pipelines responses, but we handle the case. */
    uint8_t*      residual;
    size_t        residual_len;
    size_t        max_body;
    void*         heap;
    int           closed;

    /* ---- async ---------------------------------------------------- */
    int           nonblocking;
    SmState       sm_state;
    /* Outgoing head buffer (prebuilt once per request, then streamed). */
    char*         sm_head;
    size_t        sm_head_len;
    size_t        sm_head_off;
    /* Borrowed body pointer from the caller; valid only until SM_DONE. */
    const uint8_t* sm_body;
    size_t         sm_body_len;
    size_t         sm_body_off;
    /* Response accumulator across ticks. */
    uint8_t*      sm_rx;
    size_t        sm_rx_len;
    size_t        sm_rx_cap;
    size_t        sm_hdr_end;
    long          sm_content_length;  /* -1 if unknown */
    char*         sm_content_type;     /* taken from headers */
    int           sm_status;
    int           sm_retry_after_sec;   /* delta-seconds; 0 if absent */
    WolfCertHttpResponse* sm_resp;     /* caller's resp; written to on DONE */
};

static int conn_write(WolfCertConn* c, const void* buf, size_t len)
{
    const uint8_t* p = (const uint8_t*)buf;
    size_t n = 0;

    while (n < len) {
        int w;
        if (c->ssl) {
            w = wolfSSL_write(c->ssl, p + n, (int)(len - n));
        }
        else {
            ssize_t rc;
            do {
                rc = send(c->fd, p + n, len - n, 0);
            }
            while (rc < 0 && errno == EINTR);
            w = (int)rc;
        }

        if (w <= 0)
            return WOLFCERT_ERR_IO;

        n += (size_t)w;
    }

    return WOLFCERT_OK;
}

static int conn_read(WolfCertConn* c, void* buf, size_t len)
{
    if (c->ssl)
        return wolfSSL_read(c->ssl, buf, (int)len);

    ssize_t rc;
    do {
        rc = recv(c->fd, buf, len, 0);
    }
    while (rc < 0 && errno == EINTR);

    return (int)rc;
}

/* ---- response parsing --------------------------------------------------- */

typedef struct {
    uint8_t* buf;
    size_t   len;
    size_t   cap;
    size_t   max;
    void*    heap;
} DynBuf;

static int dyn_append(DynBuf* d, const void* data, size_t len)
{
    if (len > d->max - d->len)
        return WOLFCERT_ERR_PROTOCOL;

    if (d->len + len > d->cap) {
        size_t nc = d->cap ? d->cap : 1024;

        while (nc < d->len + len)
            nc *= 2;

        if (nc > d->max)
            nc = d->max;

        uint8_t* nb = (uint8_t*)WOLFCERT_XREALLOC(d->buf, nc, d->heap);
        if (nb == NULL)
            return WOLFCERT_ERR_MEMORY;

        d->buf = nb;
        d->cap = nc;
    }

    memcpy(d->buf + d->len, data, len);
    d->len += len;

    return WOLFCERT_OK;
}

static char* find_header(const char* headers, const char* name, void* heap)
{
    size_t nlen = strlen(name);
    const char* p = headers;

    while (*p) {
        if (strncasecmp(p, name, nlen) == 0 && p[nlen] == ':') {
            const char* v = p + nlen + 1;
            while (*v == ' ' || *v == '\t') {
                ++v;
            }

            const char* e = strstr(v, "\r\n");
            if (e == NULL)
                return NULL;

            size_t n = (size_t)(e - v);
            char* s = (char*)WOLFCERT_XMALLOC(n + 1, heap);
            if (s == NULL)
                return NULL;

            memcpy(s, v, n);
            s[n] = '\0';

            return s;
        }

        const char* nl = strstr(p, "\r\n");
        if (nl == NULL)
            break;

        p = nl + 2;
    }
    return NULL;
}

static int parse_status_line(const char* line, int* out_status)
{
    if (strncmp(line, "HTTP/", 5) != 0)
        return WOLFCERT_ERR_PROTOCOL;

    const char* sp = strchr(line, ' ');
    if (sp == NULL)
        return WOLFCERT_ERR_PROTOCOL;

    char* end = NULL;
    long v = strtol(sp + 1, &end, 10);
    if (v < 100 || v > 999)
        return WOLFCERT_ERR_PROTOCOL;

    *out_status = (int)v;

    return WOLFCERT_OK;
}

static int read_headers(WolfCertConn* c, DynBuf* rx)
{
    uint8_t tmp[WOLFCERT_HTTP_READ_CHUNK];

    while (1) {
        const char* hay = (const char*)rx->buf;
        size_t hay_len = rx->len;
        for (size_t i = 0; i + 3 < hay_len; ++i) {
            if (hay[i] == '\r' && hay[i+1] == '\n' &&
                hay[i+2] == '\r' && hay[i+3] == '\n') {
                return (int)(i + 4);
            }
        }

        int r = conn_read(c, tmp, sizeof(tmp));
        if (r <= 0)
            return WOLFCERT_ERR_IO;

        int rc = dyn_append(rx, tmp, (size_t)r);
        if (rc != WOLFCERT_OK)
            return rc;
    }
}

static int decode_chunked(const uint8_t* in, size_t in_len,
                          uint8_t** out, size_t* out_len,
                          size_t max_bytes, void* heap)
{
    DynBuf body = { .heap = heap, .max = max_bytes };
    size_t p = 0;

    while (p < in_len) {
        size_t start = p;
        while (p < in_len && in[p] != '\r')
            ++p;

        if (p + 1 >= in_len || in[p+1] != '\n') {
            WOLFCERT_XFREE(body.buf, heap);
            return WOLFCERT_ERR_PROTOCOL;
        }

        char hex[17] = { 0 };
        size_t hex_len = p - start;
        if (hex_len == 0 || hex_len > 16) {
            WOLFCERT_XFREE(body.buf, heap);
            return WOLFCERT_ERR_PROTOCOL;
        }

        memcpy(hex, in + start, hex_len);
        char* semi = strchr(hex, ';');
        if (semi)
            *semi = '\0';

        size_t clen = (size_t)strtoul(hex, NULL, 16);
        p += 2;
        if (clen == 0) {
            *out = body.buf;
            *out_len = body.len;
            return WOLFCERT_OK;
        }

        if (clen > max_bytes || p + 2 > in_len || clen > in_len - p - 2) {
            WOLFCERT_XFREE(body.buf, heap);
            return WOLFCERT_ERR_PROTOCOL;
        }

        int rc = dyn_append(&body, in + p, clen);
        if (rc != WOLFCERT_OK) {
            WOLFCERT_XFREE(body.buf, heap);
            return rc;
        }

        p += clen;
        if (in[p] != '\r' || in[p+1] != '\n') {
            WOLFCERT_XFREE(body.buf, heap);
            return WOLFCERT_ERR_PROTOCOL;
        }

        p += 2;
    }

    WOLFCERT_XFREE(body.buf, heap);

    return WOLFCERT_ERR_PROTOCOL;
}

static int read_body(WolfCertConn* c, DynBuf* rx, size_t body_start,
                     const char* headers,
                     uint8_t** out, size_t* out_len,
                     size_t max_bytes, void* heap)
{
    char* te = find_header(headers, "Transfer-Encoding", heap);
    char* cl = find_header(headers, "Content-Length",    heap);

    int chunked = (te != NULL && strcasecmp(te, "chunked") == 0);
    long length = -1;
    if (cl != NULL)
        length = strtol(cl, NULL, 10);

    WOLFCERT_XFREE(te, heap);
    WOLFCERT_XFREE(cl, heap);

    if (length >= 0 && (size_t)length > max_bytes)
        return WOLFCERT_ERR_PROTOCOL;

    if (chunked) {
        while (1) {
            if (rx->len >= body_start + 5) {
                for (size_t i = body_start; i + 4 < rx->len; ++i) {
                    if (rx->buf[i] == '0' && rx->buf[i+1] == '\r' &&
                        rx->buf[i+2] == '\n' && rx->buf[i+3] == '\r' &&
                        rx->buf[i+4] == '\n') {
                        /* Break out of the while loop */
                        goto done_chunks;
                    }
                }
            }

            uint8_t tmp[WOLFCERT_HTTP_READ_CHUNK];
            int r = conn_read(c, tmp, sizeof(tmp));
            if (r <= 0)
                return WOLFCERT_ERR_IO;

            int rc = dyn_append(rx, tmp, (size_t)r);
            if (rc != WOLFCERT_OK)
                return rc;
        }

done_chunks:
        return decode_chunked(rx->buf + body_start, rx->len - body_start,
                              out, out_len, max_bytes, heap);
    }

    if (length >= 0) {
        while (rx->len < body_start + (size_t)length) {
            uint8_t tmp[WOLFCERT_HTTP_READ_CHUNK];

            int r = conn_read(c, tmp, sizeof(tmp));
            if (r <= 0)
                return WOLFCERT_ERR_IO;

            int rc = dyn_append(rx, tmp, (size_t)r);
            if (rc != WOLFCERT_OK)
                return rc;
        }

        size_t n = (size_t)length;
        uint8_t* b = (uint8_t*)WOLFCERT_XMALLOC(n, heap);
        if (b == NULL)
            return WOLFCERT_ERR_MEMORY;

        memcpy(b, rx->buf + body_start, n);
        *out = b;
        *out_len = n;

        return WOLFCERT_OK;
    }

    /* read until close */
    while (1) {
        uint8_t tmp[WOLFCERT_HTTP_READ_CHUNK];

        int r = conn_read(c, tmp, sizeof(tmp));
        if (r < 0)
            return WOLFCERT_ERR_IO;

        if (r == 0)
            break;

        int rc = dyn_append(rx, tmp, (size_t)r);
        if (rc != WOLFCERT_OK)
            return rc;
    }

    size_t n = rx->len - body_start;
    uint8_t* b = (uint8_t*)WOLFCERT_XMALLOC(n ? n : 1, heap);
    if (b == NULL)
        return WOLFCERT_ERR_MEMORY;

    if (n > 0)
        memcpy(b, rx->buf + body_start, n);

    *out = b;
    *out_len = n;

    return WOLFCERT_OK;
}

/* ---- TLS setup ---------------------------------------------------------- */

typedef struct {
    const uint8_t* trust_anchors;
    size_t         trust_anchors_len;
    int            verify_server;
    const uint8_t* client_cert;
    size_t         client_cert_len;
    const uint8_t* client_key;
    size_t         client_key_len;
    int            allow_post_handshake_auth;
} TlsDials;

/* Pick the wolfSSL file type for a credential buffer that may be PEM or DER. */
static int buf_filetype(const uint8_t* buf, size_t len)
{
    return wolfcert_buffer_is_der(buf, len) ? WOLFSSL_FILETYPE_ASN1
                                            : WOLFSSL_FILETYPE_PEM;
}

static int setup_tls_ex(WolfCertConn* c, const TlsDials* dials,
                        const char* sni_host, WOLFSSL_CTX** out_ctx)
{
    /* Flex method: negotiates the highest mutually-supported TLS version,
     * which on any modern peer will be TLS 1.3. We pin the *minimum* at
     * TLS 1.2 so legacy-only servers still interoperate but SSL3/TLS1.0/
     * TLS1.1 are refused outright. When wolfSSL is built without TLS 1.2
     * (WOLFSSL_NO_TLS12), the floor is TLS 1.3. */
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(wolfTLS_client_method());
    if (ctx == NULL)
        return WOLFCERT_ERR_TLS;

#ifdef WOLFSSL_NO_TLS12
    (void)wolfSSL_CTX_SetMinVersion(ctx, WOLFSSL_TLSV1_3);
#else
    (void)wolfSSL_CTX_SetMinVersion(ctx, WOLFSSL_TLSV1_2);
#endif

#ifdef WOLFSSL_POST_HANDSHAKE_AUTH
    if (dials->allow_post_handshake_auth) {
        /* Enabling PHA on the CTX lets the handshake negotiate the
         * post_handshake_auth extension (RFC 8446 section 4.6.2). Without it a
         * mid-session CertificateRequest is rejected. */
        (void)wolfSSL_CTX_set_post_handshake_auth(ctx, 1);
    }
#else
    if (dials->allow_post_handshake_auth) {
        wolfSSL_CTX_free(ctx);
        return WOLFCERT_ERR(WOLFCERT_ERR_UNSUPPORTED, "http",
            "wolfSSL was built without WOLFSSL_POST_HANDSHAKE_AUTH; "
            "rebuild with --enable-postauth to enable TLS 1.3 PHA");
    }
#endif

    if (dials->trust_anchors != NULL && dials->trust_anchors_len > 0) {
        int rc = wolfSSL_CTX_load_verify_buffer(ctx, dials->trust_anchors,
                    (long)dials->trust_anchors_len,
                    buf_filetype(dials->trust_anchors, dials->trust_anchors_len));

        if (rc != WOLFSSL_SUCCESS) {
            wolfSSL_CTX_free(ctx);
            return WOLFCERT_ERR_TLS;
        }
    }

    wolfSSL_CTX_set_verify(ctx,
        dials->verify_server ? WOLFSSL_VERIFY_PEER : WOLFSSL_VERIFY_NONE, NULL);

    WOLFSSL* ssl = wolfSSL_new(ctx);
    if (ssl == NULL) {
        wolfSSL_CTX_free(ctx);
        return WOLFCERT_ERR_TLS;
    }

    if (dials->client_cert != NULL && dials->client_key != NULL) {
        /* Load the client identity even when the initial handshake is
         * anonymous, so that a later TLS 1.3 CertificateRequest (PHA)
         * can be answered without further caller involvement. */
        int rc = 0;
        rc = wolfSSL_use_certificate_buffer(ssl, dials->client_cert,
                (long)dials->client_cert_len,
                buf_filetype(dials->client_cert, dials->client_cert_len));
        if (rc != WOLFSSL_SUCCESS) {
            wolfSSL_free(ssl);
            wolfSSL_CTX_free(ctx);
            return WOLFCERT_ERR_TLS;
        }

        rc = wolfSSL_use_PrivateKey_buffer(ssl, dials->client_key,
                (long)dials->client_key_len,
                buf_filetype(dials->client_key, dials->client_key_len));
        if (rc != WOLFSSL_SUCCESS) {
            wolfSSL_free(ssl);
            wolfSSL_CTX_free(ctx);
            return WOLFCERT_ERR_TLS;
        }
    }

    if (sni_host != NULL) {
        wolfSSL_UseSNI(ssl, 0, sni_host, (word16)strlen(sni_host));

        if (dials->verify_server) {
            /* RFC 6125: a literal IP address matches only iPAddress SAN
             * entries, not DNS SAN entries. wolfSSL >= 5.9 enforces this
             * split - `wolfSSL_check_domain_name` only walks DNS SANs
             * and the CN, so an IP in SNI won't match an iPAddress SAN.
             * Detect a numeric host with inet_pton and route it through
             * the IP-specific checker. */
            struct in_addr  v4;
            struct in6_addr v6;
            if (inet_pton(AF_INET,  sni_host, &v4) == 1 ||
                inet_pton(AF_INET6, sni_host, &v6) == 1) {
                wolfSSL_check_ip_address(ssl, sni_host);
            } else {
                wolfSSL_check_domain_name(ssl, sni_host);
            }
        }
    }

    if (wolfSSL_set_fd(ssl, c->fd) != WOLFSSL_SUCCESS) {
        wolfSSL_free(ssl);
        wolfSSL_CTX_free(ctx);
        return WOLFCERT_ERR_TLS;
    }

    c->ssl = ssl;
    *out_ctx = ctx;

    return WOLFCERT_OK;
}

/* Blocking variant: perform the handshake right here. */
static int do_tls_handshake_blocking(WolfCertConn* c)
{
    int r = wolfSSL_connect(c->ssl);

    if (r != WOLFSSL_SUCCESS) {
        int e = wolfSSL_get_error(c->ssl, r);
        char buf[80];
        wolfSSL_ERR_error_string((unsigned long)e, buf);

        return WOLFCERT_ERR_WC(e, "http",
            "TLS handshake failed: wolfSSL_connect=%d err=%d (%s)", r, e, buf);
    }

    return WOLFCERT_OK;
}

/* Non-blocking TLS handshake step. Returns WOLFCERT_OK when the
 * handshake is complete, WOLFCERT_ERR_WANT_READ / _WANT_WRITE while
 * it's still in progress, WOLFCERT_ERR_TLS on failure. */
static int do_tls_handshake_step(WolfCertConn* c)
{
    int r = wolfSSL_connect(c->ssl);
    if (r == WOLFSSL_SUCCESS)
        return WOLFCERT_OK;

    int e = wolfSSL_get_error(c->ssl, r);
    if (e == WOLFSSL_ERROR_WANT_READ)
        return WOLFCERT_ERR_WANT_READ;
    else if (e == WOLFSSL_ERROR_WANT_WRITE)
        return WOLFCERT_ERR_WANT_WRITE;

    return WOLFCERT_ERR_TLS;
}

static int setup_tls(WolfCertConn* c, const WolfCertHttpRequest* req,
                     const char* sni_host, WOLFSSL_CTX** out_ctx)
{
    TlsDials dials = {
        .trust_anchors     = req->trust_anchors,
        .trust_anchors_len = req->trust_anchors_len,
        .verify_server     = req->verify_server,
        .client_cert       = req->client_cert,
        .client_cert_len   = req->client_cert_len,
        .client_key        = req->client_key,
        .client_key_len    = req->client_key_len,
    };

    return setup_tls_ex(c, &dials, sni_host, out_ctx);
}

/* ---- request / response primitives (shared by one-shot + session) ------ */

/* Write one complete HTTP/1.1 request (headers + optional body). The
 * `keep_alive` flag flips between `Connection: keep-alive` (session
 * mode) and `Connection: close` (one-shot mode). */
static int http_write_request(WolfCertConn* c, const WolfCertUrl* u,
                              const WolfCertHttpRequest* req,
                              int keep_alive, void* heap)
{
    char auth[WOLFCERT_HTTP_AUTH_BUF_SZ] = { 0 };

    if (req->basic_user != NULL) {
        int n = basic_auth_header(req->basic_user, req->basic_pass,
                                  auth, sizeof(auth), heap);
        if (n < 0) {
            wc_ForceZero(auth, (word32)sizeof(auth));
            return n;
        }
    }

    char port_frag[16] = { 0 };
    if ((u->tls && u->port != 443) || (!u->tls && u->port != 80)) {
        snprintf(port_frag, sizeof(port_frag), ":%d", u->port);
    }

    size_t head_cap = 1024 + (req->content_type ? strlen(req->content_type) : 0)
                           + (req->content_transfer_encoding ?
                              strlen(req->content_transfer_encoding) : 0)
                           + (req->accept ? strlen(req->accept) : 0)
                           + strlen(u->host) + strlen(u->path) + strlen(auth);
    char* head = (char*)WOLFCERT_XMALLOC(head_cap, heap);
    if (head == NULL) {
        wc_ForceZero(auth, (word32)sizeof(auth));
        return WOLFCERT_ERR_MEMORY;
    }

    int hn = snprintf(head, head_cap,
        "%s %s HTTP/1.1\r\n"
        "Host: %s%s\r\n"
        "User-Agent: wolfCert/%s\r\n"
        "Connection: %s\r\n"
        "%s%s%s"
        "%s%s%s"
        "%s%s%s"
        "Content-Length: %zu\r\n"
        "%s"
        "\r\n",
        req->method, u->path,
        u->host, port_frag,
        WOLFCERT_VERSION_STRING,
        keep_alive ? "keep-alive" : "close",
        req->accept ? "Accept: " : "",
        req->accept ? req->accept : "",
        req->accept ? "\r\n" : "",
        req->content_type ? "Content-Type: " : "",
        req->content_type ? req->content_type : "",
        req->content_type ? "\r\n" : "",
        req->content_transfer_encoding ? "Content-Transfer-Encoding: " : "",
        req->content_transfer_encoding ? req->content_transfer_encoding : "",
        req->content_transfer_encoding ? "\r\n" : "",
        req->body_len,
        auth);

    /* The Authorization line has been copied into `head`; drop this copy. */
    wc_ForceZero(auth, (word32)sizeof(auth));

    if (hn < 0 || (size_t)hn >= head_cap) {
        /* A truncated head can still carry part of the Authorization line. */
        wc_ForceZero(head, (word32)head_cap);
        WOLFCERT_XFREE(head, heap);
        return WOLFCERT_ERR_MEMORY;
    }

    int rc = conn_write(c, head, (size_t)hn);

    wc_ForceZero(head, (word32)hn);
    WOLFCERT_XFREE(head, heap);
    if (rc != WOLFCERT_OK)
        return rc;

    if (req->body_len > 0)
        rc = conn_write(c, req->body, req->body_len);

    return rc;
}

/* Read headers + body into the caller's WolfCertHttpResponse. The
 * blocking path does not try to carry pipelined bytes forward across
 * requests - HTTP/1.1 pipelining is effectively dead on the wire, and
 * the async state machine has its own per-request residual tracking
 * that doesn't depend on this helper. */
static int http_read_response(WolfCertConn* c,
                              size_t max_body,
                              WolfCertHttpResponse* resp,
                              void* heap)
{
    DynBuf rx = { .heap = heap, .max = max_body + 8192 };
    int hdr_end = read_headers(c, &rx);
    if (hdr_end < 0) {
        WOLFCERT_XFREE(rx.buf, heap);
        return hdr_end;
    }

    char* headers_nt = (char*)WOLFCERT_XMALLOC((size_t)hdr_end + 1, heap);
    if (headers_nt == NULL) {
        WOLFCERT_XFREE(rx.buf, heap);
        return WOLFCERT_ERR_MEMORY;
    }

    memcpy(headers_nt, rx.buf, (size_t)hdr_end);
    headers_nt[hdr_end] = '\0';

    int status = 0;
    int rc = parse_status_line(headers_nt, &status);
    if (rc != WOLFCERT_OK) {
        WOLFCERT_XFREE(headers_nt, heap);
        WOLFCERT_XFREE(rx.buf, heap);
        return rc;
    }

    char* ct = find_header(headers_nt, "Content-Type", heap);
    /* RFC 7231 section 7.1.3: `Retry-After` carries either delta-seconds or an
     * HTTP-date. wolfCert parses delta-seconds only; a non-digit first
     * character (i.e. the HTTP-date form) leaves retry_after_sec at 0. */
    char* ra = find_header(headers_nt, "Retry-After", heap);
    int   retry_after = 0;

    if (ra != NULL) {
        const char* p = ra;
        while (*p == ' ' || *p == '\t')
            ++p;

        if (*p >= '0' && *p <= '9') {
            long v = strtol(p, NULL, 10);
            if (v > 0 && v <= 86400)
                retry_after = (int)v;
        }
        WOLFCERT_XFREE(ra, heap);
    }
    rc = read_body(c, &rx, (size_t)hdr_end, headers_nt,
                   &resp->body, &resp->body_len, max_body, heap);

    WOLFCERT_XFREE(headers_nt, heap);
    WOLFCERT_XFREE(rx.buf, heap);
    if (rc != WOLFCERT_OK) {
        WOLFCERT_XFREE(ct, heap);
        return rc;
    }

    resp->status_code     = status;
    resp->content_type    = ct;
    resp->retry_after_sec = retry_after;

    return WOLFCERT_OK;
}

/* ---- main --------------------------------------------------------------- */

int wolfcert_http_request(const WolfCertHttpRequest* req, WolfCertHttpResponse* resp)
{
    if (req == NULL || resp == NULL || req->url == NULL || req->method == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    if (req->connect_cb != NULL && req->transport != NULL)
        return WOLFCERT_ERR(WOLFCERT_ERR_BAD_ARG, "http",
            "set either connect_cb or transport, not both");

    memset(resp, 0, sizeof(*resp));
    void* heap = req->heap ? req->heap : wolfcert_default_heap();
    resp->heap = heap;
    size_t max_body = req->max_response_bytes
                    ? req->max_response_bytes : WOLFCERT_HTTP_DEFAULT_MAX_BODY;

    WolfCertUrl u;
    int rc = wolfcert_http_url_parse(req->url, &u, heap);
    if (rc != WOLFCERT_OK)
        return rc;

    WolfCertConn c = { .fd = -1, .ssl = NULL };
    WOLFSSL_CTX* ctx = NULL;

    c.fd = dial(u.host, u.port, req->timeout_ms, req->connect_cb, req->connect_ctx);
    if (c.fd < 0) {
        wolfcert_http_url_free(&u);
        return WOLFCERT_ERR_IO;
    }

    if (u.tls) {
        rc = setup_tls(&c, req, u.host, &ctx);

        if (rc == WOLFCERT_OK)
            rc = do_tls_handshake_blocking(&c);

        if (rc != WOLFCERT_OK) {
            if (c.ssl) {
                wolfSSL_free(c.ssl);
                c.ssl = NULL;
            }
            if (ctx) {
                wolfSSL_CTX_free(ctx);
                ctx = NULL;
            }

            close(c.fd);
            wolfcert_http_url_free(&u);

            return rc;
        }
    }

    rc = http_write_request(&c, &u, req, 0 /* close */, heap);
    if (rc != WOLFCERT_OK)
        goto out;

    rc = http_read_response(&c, max_body, resp, heap);

out:
    if (c.ssl) {
        wolfSSL_shutdown(c.ssl);
        wolfSSL_free(c.ssl);
    }
    if (ctx)
        wolfSSL_CTX_free(ctx);
    if (c.fd >= 0)
        close(c.fd);
    wolfcert_http_url_free(&u);

    return rc;
}

/* ---- keep-alive session ------------------------------------------------- */

int wolfcert_http_session_open(const WolfCertHttpSessionCfg* cfg,
                               WolfCertHttpSession** out)
{
    if (cfg == NULL || cfg->base_url == NULL || out == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    if (cfg->connect_cb != NULL && cfg->transport != NULL)
        return WOLFCERT_ERR(WOLFCERT_ERR_BAD_ARG, "http",
            "set either connect_cb or transport, not both");

    void* heap = cfg->heap ? cfg->heap : wolfcert_default_heap();

    WolfCertHttpSession* s = (WolfCertHttpSession*)WOLFCERT_XMALLOC(sizeof(*s), heap);
    if (s == NULL)
        return WOLFCERT_ERR_MEMORY;

    memset(s, 0, sizeof(*s));
    s->heap     = heap;
    s->conn.fd  = -1;
    s->max_body = cfg->max_response_bytes
                ? cfg->max_response_bytes : WOLFCERT_HTTP_DEFAULT_MAX_BODY;

    int rc = wolfcert_http_url_parse(cfg->base_url, &s->base, heap);
    if (rc != WOLFCERT_OK) {
        WOLFCERT_XFREE(s, heap);
        return rc;
    }

    s->conn.fd = dial(s->base.host, s->base.port, cfg->timeout_ms,
                      cfg->connect_cb, cfg->connect_ctx);
    if (s->conn.fd < 0) {
        wolfcert_http_session_close(s);
        return WOLFCERT_ERR_IO;
    }

    if (s->base.tls) {
        TlsDials dials = {
            .trust_anchors             = cfg->trust_anchors,
            .trust_anchors_len         = cfg->trust_anchors_len,
            .verify_server             = cfg->verify_server,
            .client_cert               = cfg->client_cert,
            .client_cert_len           = cfg->client_cert_len,
            .client_key                = cfg->client_key,
            .client_key_len            = cfg->client_key_len,
            .allow_post_handshake_auth = cfg->allow_post_handshake_auth,
        };

        rc = setup_tls_ex(&s->conn, &dials, s->base.host, &s->ctx);
        if (rc != WOLFCERT_OK) {
            wolfcert_http_session_close(s);
            return rc;
        }
    }

    if (cfg->nonblocking) {
        int fl = fcntl(s->conn.fd, F_GETFL, 0);

        if (fl < 0 || fcntl(s->conn.fd, F_SETFL, fl | O_NONBLOCK) < 0) {
            wolfcert_http_session_close(s);
            return WOLFCERT_ERR_IO;
        }
        s->nonblocking = 1;

        if (s->conn.ssl) {
            wolfSSL_set_using_nonblock(s->conn.ssl, 1);
            s->sm_state = SM_HANDSHAKE;
        }
        else {
            s->sm_state = SM_IDLE;
        }
    }
    else if (s->base.tls) {
        rc = do_tls_handshake_blocking(&s->conn);
        if (rc != WOLFCERT_OK) {
            wolfcert_http_session_close(s);
            return rc;
        }
    }

    *out = s;
    return WOLFCERT_OK;
}

int wolfcert_http_session_fd(const WolfCertHttpSession* s)
{
    return s != NULL ? s->conn.fd : -1;
}

int wolfcert_http_session_request(WolfCertHttpSession* s,
                                  const WolfCertHttpRequest* req,
                                  WolfCertHttpResponse* resp)
{
    if (s == NULL || s->closed || req == NULL || resp == NULL ||
        req->url == NULL || req->method == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    memset(resp, 0, sizeof(*resp));
    resp->heap = s->heap;

    /* Validate that the URL targets the session's host / scheme / port. */
    WolfCertUrl u;
    int rc = wolfcert_http_url_parse(req->url, &u, s->heap);
    if (rc != WOLFCERT_OK)
        return rc;

    if (u.tls != s->base.tls || u.port != s->base.port ||
        strcasecmp(u.host, s->base.host) != 0) {
        wolfcert_http_url_free(&u);
        return WOLFCERT_ERR(WOLFCERT_ERR_BAD_ARG, "http",
            "http session: request URL %s does not match session base %s://%s:%d",
            req->url, s->base.scheme, s->base.host, s->base.port);
    }

    rc = http_write_request(&s->conn, &u, req, 1 /* keep-alive */, s->heap);
    if (rc != WOLFCERT_OK) {
        wolfcert_http_url_free(&u);
        s->closed = 1;
        return rc;
    }

    rc = http_read_response(&s->conn, s->max_body, resp, s->heap);
    wolfcert_http_url_free(&u);
    if (rc != WOLFCERT_OK)
        s->closed = 1;

    return rc;
}

/* Release the stored request head. It carries the Authorization line, so clear
 * it rather than just releasing it. Every site that frees the head goes through
 * here. */
static void sm_drop_head(WolfCertHttpSession* s)
{
    if (s->sm_head != NULL)
        wc_ForceZero(s->sm_head, (word32)s->sm_head_len);
    WOLFCERT_XFREE(s->sm_head, s->heap);
    s->sm_head = NULL;
    s->sm_head_len = 0;
    s->sm_head_off = 0;
}

static void sm_reset(WolfCertHttpSession* s)
{
    sm_drop_head(s);
    WOLFCERT_XFREE(s->sm_rx,           s->heap);
    WOLFCERT_XFREE(s->sm_content_type, s->heap);
    s->sm_body = NULL;
    s->sm_body_len = 0;
    s->sm_body_off = 0;
    s->sm_rx = NULL;
    s->sm_rx_len = 0;
    s->sm_rx_cap = 0;
    s->sm_hdr_end = 0;
    s->sm_content_length = -1;
    s->sm_content_type = NULL;
    s->sm_status = 0;
    s->sm_resp = NULL;
    s->sm_retry_after_sec = 0;
}

/* Tear-down shortcut for state-machine error returns: drop per-request
 * scratch and mark the session closed. Mirrors the SM_DONE path's
 * explicit cleanup so buffers don't sit allocated until
 * wolfcert_http_session_close. */
static int sm_fail(WolfCertHttpSession* s, int rc)
{
    s->closed = 1;
    sm_reset(s);
    return rc;
}

void wolfcert_http_session_close(WolfCertHttpSession* s)
{
    if (s == NULL)
        return;

    if (s->conn.ssl) {
        wolfSSL_shutdown(s->conn.ssl);
        wolfSSL_free(s->conn.ssl);
    }

    if (s->ctx)
        wolfSSL_CTX_free(s->ctx);

    if (s->conn.fd >= 0)
        close(s->conn.fd);

    WOLFCERT_XFREE(s->residual, s->heap);
    sm_reset(s);
    wolfcert_http_url_free(&s->base);
    WOLFCERT_XFREE(s, s->heap);
}

/* ---- non-blocking request state machine --------------------------------- */

/* Non-blocking write step. Returns OK when all bytes sent,
 * WANT_READ/WRITE otherwise. */
static int nb_write(WolfCertConn* c, const uint8_t* buf, size_t len, size_t* off)
{
    while (*off < len) {
        if (c->ssl) {
            int w = wolfSSL_write(c->ssl, buf + *off, (int)(len - *off));
            if (w > 0) {
                *off += (size_t)w;
                continue;
            }

            int e = wolfSSL_get_error(c->ssl, w);
            if (e == WOLFSSL_ERROR_WANT_WRITE)
                return WOLFCERT_ERR_WANT_WRITE;
            if (e == WOLFSSL_ERROR_WANT_READ)
                return WOLFCERT_ERR_WANT_READ;

            return WOLFCERT_ERR_IO;
        }

        ssize_t r = send(c->fd, buf + *off, len - *off, 0);
        if (r > 0) {
            *off += (size_t)r;
            continue;
        }

        if (r < 0 && errno == EINTR)
            continue;

        if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
            return WOLFCERT_ERR_WANT_WRITE;

        return WOLFCERT_ERR_IO;
    }

    return WOLFCERT_OK;
}

/* Ensure the rx buffer has room for `need` more bytes. */
static int nb_rx_reserve(WolfCertHttpSession* s, size_t need)
{
    size_t want = s->sm_rx_len + need;
    if (want <= s->sm_rx_cap)
        return WOLFCERT_OK;

    size_t max = s->max_body + 8192;
    if (want > max)
        return WOLFCERT_ERR_PROTOCOL;

    size_t nc = s->sm_rx_cap ? s->sm_rx_cap : 1024;
    while (nc < want)
        nc *= 2;

    if (nc > max)
        nc = max;

    uint8_t* nb = (uint8_t*)WOLFCERT_XREALLOC(s->sm_rx, nc, s->heap);
    if (nb == NULL)
        return WOLFCERT_ERR_MEMORY;

    s->sm_rx = nb;
    s->sm_rx_cap = nc;

    return WOLFCERT_OK;
}

/* Read one chunk into the rx buffer. Returns OK (may still want more),
 * WANT_READ/WRITE, or an error. `ended` is set to 1 when the peer
 * closed cleanly (EOF) - used by the read-until-close body path. */
static int nb_read_some(WolfCertHttpSession* s, int* ended)
{
    *ended = 0;
    int rc = nb_rx_reserve(s, WOLFCERT_HTTP_READ_CHUNK);
    if (rc != WOLFCERT_OK)
        return rc;

    if (s->conn.ssl) {
        int r = wolfSSL_read(s->conn.ssl, s->sm_rx + s->sm_rx_len,
                             WOLFCERT_HTTP_READ_CHUNK);
        if (r > 0) {
            s->sm_rx_len += (size_t)r;
            return WOLFCERT_OK;
        }

        if (r == 0) {
            *ended = 1;
            return WOLFCERT_OK;
        }

        int e = wolfSSL_get_error(s->conn.ssl, r);
        if (e == WOLFSSL_ERROR_WANT_READ)
            return WOLFCERT_ERR_WANT_READ;
        if (e == WOLFSSL_ERROR_WANT_WRITE)
            return WOLFCERT_ERR_WANT_WRITE;
        if (e == WOLFSSL_ERROR_ZERO_RETURN) {
            *ended = 1;
            return WOLFCERT_OK;
        }

        return WOLFCERT_ERR_IO;
    }

    ssize_t r = recv(s->conn.fd, s->sm_rx + s->sm_rx_len,
                     WOLFCERT_HTTP_READ_CHUNK, 0);
    if (r > 0) {
        s->sm_rx_len += (size_t)r;
        return WOLFCERT_OK;
    }

    if (r == 0) {
        *ended = 1;
        return WOLFCERT_OK;
    }

    if (errno == EINTR)
        return WOLFCERT_OK; /* caller ticks again */
    if (errno == EAGAIN || errno == EWOULDBLOCK)
        return WOLFCERT_ERR_WANT_READ;

    return WOLFCERT_ERR_IO;
}

/* Build the outgoing HTTP request head into s->sm_head. */
static int build_head(WolfCertHttpSession* s, const WolfCertHttpRequest* req,
                      const WolfCertUrl* u)
{
    char auth[WOLFCERT_HTTP_AUTH_BUF_SZ] = { 0 };
    if (req->basic_user != NULL) {
        int n = basic_auth_header(req->basic_user, req->basic_pass,
                                  auth, sizeof(auth), s->heap);
        if (n < 0) {
            wc_ForceZero(auth, (word32)sizeof(auth));
            return n;
        }
    }

    char port_frag[16] = { 0 };
    if ((u->tls && u->port != 443) || (!u->tls && u->port != 80))
        snprintf(port_frag, sizeof(port_frag), ":%d", u->port);

    size_t head_cap = 1024 + (req->content_type ? strlen(req->content_type) : 0)
                           + (req->content_transfer_encoding ?
                              strlen(req->content_transfer_encoding) : 0)
                           + (req->accept ? strlen(req->accept) : 0)
                           + strlen(u->host) + strlen(u->path) + strlen(auth);
    char* head = (char*)WOLFCERT_XMALLOC(head_cap, s->heap);
    if (head == NULL) {
        wc_ForceZero(auth, (word32)sizeof(auth));
        return WOLFCERT_ERR_MEMORY;
    }

    int hn = snprintf(head, head_cap,
        "%s %s HTTP/1.1\r\n"
        "Host: %s%s\r\n"
        "User-Agent: wolfCert/%s\r\n"
        "Connection: keep-alive\r\n"
        "%s%s%s"
        "%s%s%s"
        "%s%s%s"
        "Content-Length: %zu\r\n"
        "%s"
        "\r\n",
        req->method, u->path,
        u->host, port_frag,
        WOLFCERT_VERSION_STRING,
        req->accept ? "Accept: " : "",
        req->accept ? req->accept : "",
        req->accept ? "\r\n" : "",
        req->content_type ? "Content-Type: " : "",
        req->content_type ? req->content_type : "",
        req->content_type ? "\r\n" : "",
        req->content_transfer_encoding ? "Content-Transfer-Encoding: " : "",
        req->content_transfer_encoding ? req->content_transfer_encoding : "",
        req->content_transfer_encoding ? "\r\n" : "",
        req->body_len,
        auth);

    /* The Authorization line has been copied into `head`; drop this copy. */
    wc_ForceZero(auth, (word32)sizeof(auth));

    if (hn < 0 || (size_t)hn >= head_cap) {
        wc_ForceZero(head, (word32)head_cap);
        WOLFCERT_XFREE(head, s->heap);
        return WOLFCERT_ERR_MEMORY;
    }

    s->sm_head = head;
    s->sm_head_len = (size_t)hn;
    s->sm_head_off = 0;

    return WOLFCERT_OK;
}

/* After reading headers, pull Content-Length / Transfer-Encoding /
 * Content-Type and decide which body-read mode to enter. */
static int inspect_headers(WolfCertHttpSession* s)
{
    char* hdrs = (char*)WOLFCERT_XMALLOC(s->sm_hdr_end + 1, s->heap);
    if (hdrs == NULL)
        return WOLFCERT_ERR_MEMORY;

    memcpy(hdrs, s->sm_rx, s->sm_hdr_end);
    hdrs[s->sm_hdr_end] = '\0';

    int status = 0;
    int rc = parse_status_line(hdrs, &status);
    if (rc != WOLFCERT_OK) {
        WOLFCERT_XFREE(hdrs, s->heap);
        return rc;
    }
    s->sm_status = status;

    char* te = find_header(hdrs, "Transfer-Encoding", s->heap);
    if (te != NULL && strcasecmp(te, "chunked") == 0) {
        WOLFCERT_XFREE(te, s->heap);
        WOLFCERT_XFREE(hdrs, s->heap);
        return WOLFCERT_ERR(WOLFCERT_ERR_UNSUPPORTED, "http",
            "async session: Transfer-Encoding: chunked not supported "
            "(use the blocking wolfcert_http_session_request instead)");
    }
    WOLFCERT_XFREE(te, s->heap);

    char* cl = find_header(hdrs, "Content-Length", s->heap);
    s->sm_content_length = (cl != NULL) ? strtol(cl, NULL, 10) : -1;
    WOLFCERT_XFREE(cl, s->heap);
    if (s->sm_content_length >= 0 &&
        (size_t)s->sm_content_length > s->max_body) {
        WOLFCERT_XFREE(hdrs, s->heap);
        return WOLFCERT_ERR_PROTOCOL;
    }

    s->sm_content_type = find_header(hdrs, "Content-Type", s->heap);
    s->sm_retry_after_sec = 0;
    char* ra = find_header(hdrs, "Retry-After", s->heap);
    if (ra != NULL) {
        const char* p = ra;
        while (*p == ' ' || *p == '\t')
            ++p;

        if (*p >= '0' && *p <= '9') {
            long v = strtol(p, NULL, 10);
            if (v > 0 && v <= 86400)
                s->sm_retry_after_sec = (int)v;
        }

        WOLFCERT_XFREE(ra, s->heap);
    }

    WOLFCERT_XFREE(hdrs, s->heap);
    return WOLFCERT_OK;
}

static int finalize_response(WolfCertHttpSession* s)
{
    size_t body_len = s->sm_rx_len - s->sm_hdr_end;
    uint8_t* body = NULL;

    if (body_len > 0) {
        body = (uint8_t*)WOLFCERT_XMALLOC(body_len, s->heap);
        if (body == NULL)
            return WOLFCERT_ERR_MEMORY;
        memcpy(body, s->sm_rx + s->sm_hdr_end, body_len);
    }

    s->sm_resp->status_code     = s->sm_status;
    s->sm_resp->body            = body;
    s->sm_resp->body_len        = body_len;
    s->sm_resp->content_type    = s->sm_content_type;
    s->sm_resp->retry_after_sec = s->sm_retry_after_sec;
    s->sm_content_type          = NULL;  /* ownership moved */

    return WOLFCERT_OK;
}

int wolfcert_http_session_request_nb(WolfCertHttpSession* s,
                                     const WolfCertHttpRequest* req,
                                     WolfCertHttpResponse* resp)
{
    if (s == NULL || s->closed || req == NULL || resp == NULL ||
        req->url == NULL || req->method == NULL) {
        return WOLFCERT_ERR_BAD_ARG;
    }

    if (!s->nonblocking) {
        return WOLFCERT_ERR(WOLFCERT_ERR_BAD_ARG, "http",
            "wolfcert_http_session_request_nb: session was not opened "
            "with WolfCertHttpSessionCfg.nonblocking = 1");
    }

    /* First call for this request: stash caller's resp, prep head +
     * body buffers. We do this regardless of whether the TLS handshake
     * is still in progress - the handshake step runs first in the
     * state-machine loop either way. */
    if (s->sm_resp == NULL) {
        memset(resp, 0, sizeof(*resp));
        resp->heap = s->heap;
        s->sm_resp = resp;

        WolfCertUrl u;
        int rc = wolfcert_http_url_parse(req->url, &u, s->heap);
        if (rc != WOLFCERT_OK) {
            s->sm_resp = NULL;
            return rc;
        }

        if (u.tls != s->base.tls || u.port != s->base.port ||
            strcasecmp(u.host, s->base.host) != 0) {
            wolfcert_http_url_free(&u);
            s->sm_resp = NULL;
            return WOLFCERT_ERR(WOLFCERT_ERR_BAD_ARG, "http",
                "http session: request URL %s does not match session base %s://%s:%d",
                req->url, s->base.scheme, s->base.host, s->base.port);
        }

        rc = build_head(s, req, &u);
        wolfcert_http_url_free(&u);
        if (rc != WOLFCERT_OK) {
            s->sm_resp = NULL;
            return rc;
        }

        s->sm_body     = req->body;
        s->sm_body_len = req->body_len;
        s->sm_body_off = 0;

        /* Seed rx with any residual bytes from the previous response. */
        if (s->residual_len > 0) {
            int rr = nb_rx_reserve(s, s->residual_len);
            if (rr != WOLFCERT_OK) {
                /* build_head has already stored the Authorization line in
                 * s->sm_head, so unwind through sm_fail: it scrubs the head
                 * and closes the session. Returning directly would leave the
                 * credentials allocated for the next build_head to overwrite
                 * unzeroized. */
                return sm_fail(s, rr);
            }
            memcpy(s->sm_rx, s->residual, s->residual_len);
            s->sm_rx_len = s->residual_len;
            WOLFCERT_XFREE(s->residual, s->heap);
            s->residual = NULL;
            s->residual_len = 0;
        }

        /* If the session is past the handshake (or plaintext), move
         * straight into writing the request head. */
        if (s->sm_state != SM_HANDSHAKE)
            s->sm_state = SM_WRITE_HEAD;
    }

    /* Drive the state machine. */
    for (;;) {
        switch (s->sm_state) {
            case SM_HANDSHAKE:
            {
                int rc = do_tls_handshake_step(&s->conn);
                if (rc != WOLFCERT_OK) {
                    if (rc == WOLFCERT_ERR_WANT_READ || rc == WOLFCERT_ERR_WANT_WRITE)
                        return rc;

                    return sm_fail(s, rc);
                }

                s->sm_state = SM_WRITE_HEAD;
                break;
            }
            case SM_WRITE_HEAD:
            {
                int rc = nb_write(&s->conn, (const uint8_t*)s->sm_head,
                                s->sm_head_len, &s->sm_head_off);
                if (rc == WOLFCERT_ERR_WANT_READ || rc == WOLFCERT_ERR_WANT_WRITE)
                    return rc;

                if (rc != WOLFCERT_OK)
                    return sm_fail(s, rc);

                s->sm_state = (s->sm_body_len > 0) ? SM_WRITE_BODY : SM_READ_HEAD;
                break;
            }
            case SM_WRITE_BODY:
            {
                int rc = nb_write(&s->conn, s->sm_body,
                                s->sm_body_len, &s->sm_body_off);
                if (rc == WOLFCERT_ERR_WANT_READ || rc == WOLFCERT_ERR_WANT_WRITE)
                    return rc;

                if (rc != WOLFCERT_OK)
                    return sm_fail(s, rc);

                s->sm_state = SM_READ_HEAD;
                break;
            }
            case SM_READ_HEAD:
            {
                /* Check for full header end in the accumulated rx first. */
                for (size_t i = 0; i + 3 < s->sm_rx_len; ++i) {
                    if (s->sm_rx[i] == '\r' && s->sm_rx[i+1] == '\n' &&
                        s->sm_rx[i+2] == '\r' && s->sm_rx[i+3] == '\n') {
                        s->sm_hdr_end = i + 4;
                        int rc = inspect_headers(s);
                        if (rc != WOLFCERT_OK)
                            return sm_fail(s, rc);

                        s->sm_state = (s->sm_content_length >= 0)
                                    ? SM_READ_BODY_CL : SM_READ_BODY_EOF;
                        goto state_loop_continue;
                    }
                }
                int ended = 0;
                int rc = nb_read_some(s, &ended);
                if (rc == WOLFCERT_ERR_WANT_READ || rc == WOLFCERT_ERR_WANT_WRITE)
                    return rc;

                if (rc != WOLFCERT_OK)
                    return sm_fail(s, rc);

                if (ended)
                    return sm_fail(s, WOLFCERT_ERR_IO);
                break;
            }
            case SM_READ_BODY_CL:
            {
                size_t have = s->sm_rx_len - s->sm_hdr_end;
                if (have >= (size_t)s->sm_content_length) {
                    /* Trim rx to exactly the body; stash extra as residual. */
                    size_t want = (size_t)s->sm_content_length;
                    size_t extra = have - want;
                    if (extra > 0) {
                        uint8_t* r = (uint8_t*)WOLFCERT_XMALLOC(extra, s->heap);
                        if (r == NULL)
                            return sm_fail(s, WOLFCERT_ERR_MEMORY);
                        memcpy(r, s->sm_rx + s->sm_hdr_end + want, extra);
                        s->residual = r;
                        s->residual_len = extra;
                        s->sm_rx_len = s->sm_hdr_end + want;
                    }

                    int rc = finalize_response(s);
                    if (rc != WOLFCERT_OK)
                        return sm_fail(s, rc);

                    s->sm_state = SM_DONE;
                    goto state_loop_continue;
                }

                int ended = 0;
                int rc = nb_read_some(s, &ended);
                if (rc == WOLFCERT_ERR_WANT_READ || rc == WOLFCERT_ERR_WANT_WRITE)
                    return rc;

                if (rc != WOLFCERT_OK)
                    return sm_fail(s, rc);

                if (ended)
                    return sm_fail(s, WOLFCERT_ERR_IO);
                break;
            }
            case SM_READ_BODY_EOF:
            {
                int ended = 0;
                int rc = nb_read_some(s, &ended);
                if (rc == WOLFCERT_ERR_WANT_READ || rc == WOLFCERT_ERR_WANT_WRITE)
                    return rc;

                if (rc != WOLFCERT_OK)
                    return sm_fail(s, rc);

                if (ended) {
                    int fr = finalize_response(s);
                    if (fr != WOLFCERT_OK)
                        return sm_fail(s, fr);

                    s->closed = 1;  /* peer closed; no more requests on this session */
                    s->sm_state = SM_DONE;
                }
                break;
            }
            case SM_DONE:
            {
                /* Release per-request scratch. sm_resp stays referenced
                * by the caller via the returned response. */
                sm_drop_head(s);
                WOLFCERT_XFREE(s->sm_rx,   s->heap);
                s->sm_rx = NULL;
                s->sm_rx_len = 0;
                s->sm_rx_cap = 0;
                s->sm_hdr_end = 0;
                s->sm_resp = NULL;
                s->sm_state = SM_IDLE;
                return WOLFCERT_OK;
            }
            case SM_IDLE:
                /* Shouldn't land here with sm_resp set; guard. */
                return sm_fail(s, WOLFCERT_ERR_GENERIC);
            }
state_loop_continue:
            (void)0;
    }
}

void wolfcert_http_response_free(WolfCertHttpResponse* resp)
{
    if (resp == NULL)
        return;

    WOLFCERT_XFREE(resp->content_type, resp->heap);
    WOLFCERT_XFREE(resp->body,         resp->heap);
    resp->content_type = NULL;
    resp->body         = NULL;
    resp->body_len     = 0;
}
