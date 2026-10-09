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

#include <wolfcert/http.h>
#include <wolfcert/errors.h>
#include <wolfcert/version.h>
#include "internal.h"

#include <wolfssl/ssl.h>
#include <wolfssl/error-ssl.h>
#include <wolfssl/wolfcrypt/coding.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define WOLFCERT_HTTP_MAX_HOST_LEN 256
/* Path plus query, which carries a SCEP GET pkiMessage. */
#ifndef WOLFCERT_HTTP_MAX_PATH_LEN
#define WOLFCERT_HTTP_MAX_PATH_LEN 8192
#endif
#if WOLFCERT_SCEP_MAX_GET_URL > WOLFCERT_HTTP_MAX_PATH_LEN
#error "WOLFCERT_SCEP_MAX_GET_URL exceeds WOLFCERT_HTTP_MAX_PATH_LEN; raise WOLFCERT_HTTP_MAX_PATH_LEN so the client accepts the largest GET URL it will build."
#endif
#define WOLFCERT_HTTP_DEFAULT_MAX_BODY  (64 * 1024)
#define WOLFCERT_HTTP_READ_CHUNK   2048
#define WOLFCERT_HTTP_MAX_INTERIM  8

/* ASCII-only case folding, independent of the C locale. */
static int ci_lower(int c)
{
    return (c >= 'A' && c <= 'Z') ? c + ('a' - 'A') : c;
}

static int ci_cmp(const char* a, const char* b)
{
    while (*a != '\0' &&
           ci_lower((unsigned char)*a) == ci_lower((unsigned char)*b)) {
        a++;
        b++;
    }

    return ci_lower((unsigned char)*a) - ci_lower((unsigned char)*b);
}

int wolfcert_ascii_ncasecmp(const char* a, const char* b, size_t n)
{
    size_t i;

    for (i = 0; i < n; i++) {
        int ca = ci_lower((unsigned char)a[i]);
        int cb = ci_lower((unsigned char)b[i]);

        if (ca != cb)
            return ca - cb;
        if (ca == '\0')
            return 0;
    }

    return 0;
}

int wolfcert_http_hdr_is(const char* line, size_t llen, const char* name)
{
    size_t n = strlen(name);

    return llen > n && line[n] == ':' &&
           wolfcert_ascii_ncasecmp(line, name, n) == 0;
}

WOLFCERT_TEST_VIS void wolfcert_http_url_free(WolfCertUrl* u)
{
    if (u == NULL)
        return;

    WOLFCERT_XFREE(u->scheme, u->heap);
    WOLFCERT_XFREE(u->host,   u->heap);
    WOLFCERT_XFREE(u->path,   u->heap);

    u->scheme = u->host = u->path = NULL;
}

/* IPv6 hosts are stored unbracketed; URLs and Host headers need brackets. */
static int host_is_ip_literal(const char* host)
{
    uint8_t ip[16];
    size_t  ip_len = 0;

    return wolfcert_parse_ip(host, ip, &ip_len) == WOLFCERT_OK && ip_len == 16;
}

/* "scheme://host[:port]" without a default port; free with WOLFCERT_XFREE. */
WOLFCERT_TEST_VIS int wolfcert_http_url_origin(const WolfCertUrl* u, void* heap,
                                               char** out_origin)
{
    size_t      origin_len;
    char*       origin;
    const char* open_br;
    const char* close_br;

    if (u == NULL || u->scheme == NULL || u->host == NULL || out_origin == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    open_br  = host_is_ip_literal(u->host) ? "[" : "";
    close_br = host_is_ip_literal(u->host) ? "]" : "";

    /* "://", then room for the brackets, ":65535" and the NUL. */
    origin_len = strlen(u->scheme) + 3 + strlen(u->host) + 16;
    origin = (char*)WOLFCERT_XMALLOC(origin_len, heap);
    if (origin == NULL)
        return WOLFCERT_ERR_MEMORY;

    if ((u->tls && u->port == 443) || (!u->tls && u->port == 80))
        snprintf(origin, origin_len, "%s://%s%s%s", u->scheme,
                 open_br, u->host, close_br);
    else
        snprintf(origin, origin_len, "%s://%s%s%s:%d", u->scheme,
                 open_br, u->host, close_br, u->port);

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

    /* A URL without a scheme is https. */
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

        if (ci_cmp(out->scheme, "https") == 0) {
            out->tls = 1;
            out->port = 443;
        }
        else if (ci_cmp(out->scheme, "http")  == 0) {
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
        while (*host_end && *host_end != ':' && *host_end != '/'
                && *host_end != '?' && *host_end != '#') {
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

    /* An empty path becomes "/" (RFC 7230 section 5.3.1) and the fragment is
     * never sent (section 5.1). */
    const char* frag = strchr(host_end, '#');
    size_t tlen = frag ? (size_t)(frag - host_end) : strlen(host_end);
    size_t plen = (*host_end == '/') ? tlen : tlen + 1;
    if (plen > WOLFCERT_HTTP_MAX_PATH_LEN) {
        wolfcert_http_url_free(out);
        return WOLFCERT_ERR_PARSE;
    }

    out->path = (char*)WOLFCERT_XMALLOC(plen + 1, heap);
    if (out->path == NULL) {
        wolfcert_http_url_free(out);
        return WOLFCERT_ERR_MEMORY;
    }

    if (*host_end == '/') {
        memcpy(out->path, host_end, tlen);
        out->path[tlen] = '\0';
    }
    else {
        out->path[0] = '/';
        memcpy(out->path + 1, host_end, tlen);
        out->path[tlen + 1] = '\0';
    }

    return WOLFCERT_OK;
}

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
        /* snprintf already wrote a truncated credential into out. */
        wc_ForceZero(out, (word32)out_cap);
        return WOLFCERT_ERR_MEMORY;
    }

    return n;
}

typedef struct {
    WolfCertTransport t;
    void*        handle;
    WOLFSSL*     ssl;
    int          io_timeout_ms;   /* 0 nonblocking, < 0 unbounded */
    unsigned int connected : 1;
} WolfCertConn;

/* Open a connection and take a copy of the transport that owns it. */
static int dial(WolfCertConn* c, const char* host, int port, int timeout_ms,
                const WolfCertTransport* transport)
{
    int cbs;
    int rc;

    cbs = (transport->connect != NULL) + (transport->read != NULL) +
          (transport->write != NULL) + (transport->disconnect != NULL);

    if (cbs == 4) {
        c->t = *transport;
    }
    else if (cbs != 0 || transport->ctx != NULL) {
        return WOLFCERT_ERR(WOLFCERT_ERR_BAD_ARG, "http",
            "transport must set all four callbacks, or nothing at all to take "
            "the built-in one");
    }
    else {
#ifdef WOLFCERT_HAVE_BUILTIN_TRANSPORT
        c->t = wolfcert_posix_transport;
#else
        return WOLFCERT_ERR(WOLFCERT_ERR_BAD_ARG, "http",
            "this build has no built-in transport");
#endif
    }

    rc = c->t.connect(c->t.ctx, host, port, timeout_ms, &c->handle);
    if (rc != WOLFCERT_OK)
        return rc < 0 ? rc : WOLFCERT_ERR(WOLFCERT_ERR_IO, "http",
            "transport connect returned %d, not 0 or a WOLFCERT_ERR_*", rc);

    c->connected = 1;
    return WOLFCERT_OK;
}

static void conn_close(WolfCertConn* c)
{
    if (c->connected) {
        (void)c->t.disconnect(c->t.ctx, c->handle);
        c->connected = 0;
    }
}

/* Async request state; the session owns its buffers across WANT_* returns. */
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
    /* Bytes read past the previous response, fed to the next parse. */
    uint8_t*      residual;
    size_t        residual_len;
    size_t        max_body;
    void*         heap;
    int           closed;

    int           nonblocking;
    SmState       sm_state;
    char*         sm_head;
    size_t        sm_head_len;
    size_t        sm_head_off;
    /* Borrowed from the caller; valid only until SM_DONE. */
    const uint8_t* sm_body;
    size_t         sm_body_len;
    size_t         sm_body_off;
    uint8_t*      sm_rx;
    size_t        sm_rx_len;
    size_t        sm_rx_cap;
    size_t        sm_hdr_end;
    long          sm_content_length;  /* -1 if unknown */
    char*         sm_content_type;     /* taken from headers */
    int           sm_status;
    int           sm_retry_after_sec;   /* seconds; 0 if absent */
    int           sm_head_request;
    int           sm_interim;           /* interim 1xx blocks dropped so far */
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
            w = c->t.write(c->t.ctx, c->handle, p + n, len - n,
                           c->io_timeout_ms);
            if (w > 0 && (size_t)w > len - n)
                return WOLFCERT_ERR_IO;
        }

        if (w <= 0)
            return WOLFCERT_ERR_IO;

        n += (size_t)w;
    }

    return WOLFCERT_OK;
}

/* wolfSSL I/O callbacks over the transport; ctx is the WolfCertConn. */
static int wolfcert_cbio_recv(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
    WolfCertConn* c = (WolfCertConn*)ctx;
    int r;

    (void)ssl;

    if (c == NULL || sz <= 0)
        return WOLFSSL_CBIO_ERR_GENERAL;

    r = c->t.read(c->t.ctx, c->handle, (uint8_t*)buf, (size_t)sz,
                  c->io_timeout_ms);
    if (r > sz)
        return WOLFSSL_CBIO_ERR_GENERAL;
    if (r > 0)
        return r;
    /* A recv()-style transport may report EOF as 0 despite the contract. */
    if (r == 0)
        return WOLFSSL_CBIO_ERR_CONN_CLOSE;

    switch (r) {
        case WOLFCERT_ERR_WANT_READ:
        case WOLFCERT_ERR_WANT_WRITE:
            return WOLFSSL_CBIO_ERR_WANT_READ;
        case WOLFCERT_ERR_CONN_CLOSED:
            return WOLFSSL_CBIO_ERR_CONN_CLOSE;
        default:
            return WOLFSSL_CBIO_ERR_GENERAL;
    }
}

static int wolfcert_cbio_send(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
    WolfCertConn* c = (WolfCertConn*)ctx;
    int r;

    (void)ssl;

    if (c == NULL || sz <= 0)
        return WOLFSSL_CBIO_ERR_GENERAL;

    r = c->t.write(c->t.ctx, c->handle, (const uint8_t*)buf, (size_t)sz,
                   c->io_timeout_ms);
    if (r > sz)
        return WOLFSSL_CBIO_ERR_GENERAL;
    if (r > 0)
        return r;

    switch (r) {
        case WOLFCERT_ERR_WANT_READ:
        case WOLFCERT_ERR_WANT_WRITE:
            return WOLFSSL_CBIO_ERR_WANT_WRITE;
        case WOLFCERT_ERR_CONN_CLOSED:
            return WOLFSSL_CBIO_ERR_CONN_CLOSE;
        default:
            return WOLFSSL_CBIO_ERR_GENERAL;
    }
}

/* Returns the byte count (> 0) or a negative WOLFCERT_ERR_*; an orderly peer
 * close is WOLFCERT_ERR_CONN_CLOSED, never 0. */
static int conn_read(WolfCertConn* c, void* buf, size_t len)
{
    int r;

    if (c->ssl == NULL) {
        r = c->t.read(c->t.ctx, c->handle, (uint8_t*)buf, len,
                      c->io_timeout_ms);
        if (r == 0)
            return WOLFCERT_ERR_CONN_CLOSED;
        if (r > 0 && (size_t)r > len)
            return WOLFCERT_ERR_IO;
        return r;
    }

    r = wolfSSL_read(c->ssl, buf, (int)len);
    if (r > 0)
        return r;
    if (r == 0 ||
        wolfSSL_get_error(c->ssl, r) == WOLFSSL_ERROR_ZERO_RETURN)
        return WOLFCERT_ERR_CONN_CLOSED;

    return WOLFCERT_ERR_IO;
}

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
        if (wolfcert_ascii_ncasecmp(p, name, nlen) == 0 && p[nlen] == ':') {
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

#define WOLFCERT_HTTP_MAX_RETRY_AFTER 86400
/* 2026-01-01 00:00:00 UTC; an earlier wc_Time() is a clock not yet set. */
#define WOLFCERT_HTTP_CLOCK_FLOOR     1767225600

static int only_ows(const char* p)
{
    while (*p == ' ' || *p == '\t')
        ++p;

    return *p == '\0';
}

#ifndef NO_ASN_TIME
static int take_digits(const char** p, int min, int max, int* out)
{
    int n = 0;
    int v = 0;

    while (n < max && **p >= '0' && **p <= '9') {
        v = v * 10 + (**p - '0');
        ++*p;
        ++n;
    }
    if (n < min)
        return -1;

    *out = v;
    return 0;
}

static int take_month(const char** p)
{
    static const char months[] = "JanFebMarAprMayJunJulAugSepOctNovDec";
    int i;

    for (i = 0; i < 12; i++) {
        if (strncmp(*p, months + i * 3, 3) == 0) {
            *p += 3;
            return i + 1;
        }
    }

    return 0;
}

static int take_time_of_day(const char** p, int* out)
{
    int h;
    int m;
    int sec;

    if (take_digits(p, 2, 2, &h) != 0 || *(*p)++ != ':' ||
        take_digits(p, 2, 2, &m) != 0 || *(*p)++ != ':' ||
        take_digits(p, 2, 2, &sec) != 0 || h > 23 || m > 59 || sec > 60)
        return -1;

    *out = h * 3600 + m * 60 + sec;
    return 0;
}

/* Seconds since 1970-01-01 00:00:00 UTC for a UTC date and time of day. */
static int64_t date_to_unix_time(int year, int mon, int day, int tod)
{
    int64_t y   = year - (mon <= 2);
    int64_t era = (y >= 0 ? y : y - 399) / 400;
    int64_t yoe = y - era * 400;
    int64_t doy = (153 * (mon + (mon > 2 ? -3 : 9)) + 2) / 5 + day - 1;

    return (era * 146097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719468)
           * 86400 + tod;
}

/* Seconds since 1970-01-01 00:00:00 UTC for an HTTP-date (RFC 9110
 * section 5.6.7), or -1. */
static int64_t http_date_to_unix_time(const char* s, int64_t now)
{
    static const unsigned char mdays[12] = {
        31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31
    };
    const char* p = s;
    int     day = 0;
    int     mon = 0;
    int     year = 0;
    int     tod = 0;
    int     two_digit = 0;

    while ((*p >= 'A' && *p <= 'Z') || (*p >= 'a' && *p <= 'z'))
        ++p;

    if (p[0] == ',' && p[1] == ' ') {
        p += 2;
        if (take_digits(&p, 2, 2, &day) != 0)
            return -1;

        if (*p == ' ') {
            ++p;
            mon = take_month(&p);
            if (mon == 0 || *p++ != ' ' || take_digits(&p, 4, 4, &year) != 0)
                return -1;
        }
        else if (*p == '-') {
            ++p;
            mon = take_month(&p);
            if (mon == 0 || *p++ != '-' || take_digits(&p, 2, 2, &year) != 0)
                return -1;
            two_digit = 1;
        }
        else {
            return -1;
        }

        if (*p++ != ' ' || take_time_of_day(&p, &tod) != 0 ||
            strncmp(p, " GMT", 4) != 0 || !only_ows(p + 4))
            return -1;
    }
    else if (p[0] == ' ') {
        ++p;
        mon = take_month(&p);
        if (mon == 0 || *p++ != ' ')
            return -1;
        if (*p == ' ')
            ++p;
        if (take_digits(&p, 1, 2, &day) != 0 || *p++ != ' ' ||
            take_time_of_day(&p, &tod) != 0 || *p++ != ' ' ||
            take_digits(&p, 4, 4, &year) != 0 || !only_ows(p))
            return -1;
    }
    else {
        return -1;
    }

    /* A two-digit year more than 50 years ahead is the most recent past one. */
    if (two_digit) {
        year += 1900;
        while (date_to_unix_time(year + 50, mon, day, tod) <= now)
            year += 100;
    }

    if (day < 1 || day > mdays[mon - 1] ||
        (mon == 2 && day == 29 &&
         !((year % 4 == 0 && year % 100 != 0) || year % 400 == 0)))
        return -1;

    return date_to_unix_time(year, mon, day, tod);
}
#endif

/* Retry-After as seconds to wait; see WolfCertHttpResponse.retry_after_sec. */
static int parse_retry_after(const char* v)
{
    int64_t delay = 0;

    if (*v >= '0' && *v <= '9') {
        while (*v >= '0' && *v <= '9') {
            if (delay <= WOLFCERT_HTTP_MAX_RETRY_AFTER)
                delay = delay * 10 + (*v - '0');
            ++v;
        }
        if (!only_ows(v))
            delay = 0;
    }
#ifndef NO_ASN_TIME
    else {
        int64_t now = (int64_t)wc_Time(NULL);
        int64_t when = -1;

        if (now >= WOLFCERT_HTTP_CLOCK_FLOOR)
            when = http_date_to_unix_time(v, now);
        if (when >= 0)
            delay = when - now;
    }
#endif

    if (delay <= 0)
        return 0;

    return (delay > WOLFCERT_HTTP_MAX_RETRY_AFTER)
               ? WOLFCERT_HTTP_MAX_RETRY_AFTER : (int)delay;
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

/* RFC 9110 section 15.2; no final HTTP response follows a 101. */
static int status_is_interim(int status)
{
    return status >= 100 && status < 200 && status != 101;
}

/* RFC 9112 section 6.3 for a final response: a reply to HEAD, and a 204 or
 * 304, has no body whatever Content-Length or Transfer-Encoding say. */
static int response_has_no_body(int status, int head_request)
{
    return head_request || status == 204 || status == 304;
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

/* Parse the chunk-size line at raw[ri..]; *next lands past its CRLF. Returns 0
 * ok, 1 if the CRLF has not arrived, -1 if malformed or over 0xFFFFFFFF. */
static int read_chunk_size(const uint8_t* raw, size_t raw_len, size_t ri,
                           size_t* csz, size_t* next)
{
    size_t he = ri;
    size_t v = 0;
    int parsed = 0;

    while (he + 1 < raw_len && !(raw[he] == '\r' && raw[he+1] == '\n')) {
        ++he;
    }

    if (he + 1 >= raw_len)
        return 1;

    for (size_t k = ri; k < he; ++k) {
        char c = (char)raw[k];
        if (c == ';')
            break; /* chunk-ext */

        /* RFC 9112 section 7.1.1: whitespace after the size may only lead
         * into a chunk-ext. */
        if (parsed != 0 && (c == ' ' || c == '\t')) {
            while (k < he && (raw[k] == ' ' || raw[k] == '\t')) {
                ++k;
            }
            if (k >= he || raw[k] != ';')
                return -1;

            break;
        }

        int d = (c >= '0' && c <= '9') ? c - '0'
              : (c >= 'a' && c <= 'f') ? c - 'a' + 10
              : (c >= 'A' && c <= 'F') ? c - 'A' + 10 : -1;
        if (d < 0 || v > 0x0FFFFFFFU)
            return -1; /* bad hex digit, or a size over 0xFFFFFFFF */

        v = (v << 4) | (size_t)d;
        parsed = 1;
    }
    if (parsed == 0)
        return -1; /* empty chunk-size line */

    *csz  = v;
    *next = he + 2;

    return 0;
}

/* Walk chunk framing over the bytes received so far. Returns 1 at a
 * zero-length chunk parsed on a chunk-header boundary whose trailer
 * section is closed, 0 when more bytes are needed, -1 when malformed. */
static int chunked_body_complete(const uint8_t* raw, size_t raw_len)
{
    size_t ri = 0;
    size_t ls = 0;

    while (ri < raw_len) {
        size_t csz = 0;
        size_t next = 0;
        int r = read_chunk_size(raw, raw_len, ri, &csz, &next);
        if (r > 0)
            return 0;
        if (r < 0)
            return -1;

        ri = next;
        if (csz == 0) {
            /* Consume the trailer section through its blank line; stopping
             * at "0\r\n" desyncs keep-alive. */
            while (ri < raw_len) {
                ls = ri;
                while (ri + 1 < raw_len &&
                       !(raw[ri] == '\r' && raw[ri + 1] == '\n')) {
                    ++ri;
                }

                if (ri + 1 >= raw_len)
                    return 0; /* trailer line CRLF not fully received */
                if (ri == ls)
                    return 1; /* blank line terminates the trailers */

                ri += 2;
            }

            return 0;
        }

        if (raw_len - ri < 2 || csz > raw_len - ri - 2)
            return 0; /* chunk payload plus trailing CRLF not yet received */

        if (raw[ri + csz] != '\r' || raw[ri + csz + 1] != '\n')
            return -1; /* no CRLF closing the chunk payload */

        ri += csz + 2;
    }

    return 0;
}

/* RFC 9112 section 7.1.2: the trailer section is zero or more field
 * lines, each needing a name before its colon, closed by a blank line. */
static int check_trailers(const uint8_t* raw, size_t raw_len)
{
    size_t ri = 0;

    while (ri < raw_len) {
        size_t ls = ri;
        size_t colon = raw_len;

        while (ri + 1 < raw_len &&
               !(raw[ri] == '\r' && raw[ri + 1] == '\n')) {
            if (colon == raw_len && raw[ri] == ':')
                colon = ri;
            ++ri;
        }

        if (ri + 1 >= raw_len)
            return WOLFCERT_ERR_PROTOCOL; /* the line carries no CRLF */
        if (ri == ls)
            return WOLFCERT_OK; /* blank line closes the section */

        /* An SP or HTAB line continues the previous field (RFC 9112
         * section 5.2). */
        if (ls != 0 && (raw[ls] == ' ' || raw[ls] == '\t')) {
            ri += 2;
            continue;
        }

        if (colon == raw_len || colon == ls)
            return WOLFCERT_ERR_PROTOCOL; /* no colon, or no field name */

        ri += 2;
    }

    return WOLFCERT_ERR_PROTOCOL;
}

static int decode_chunked(const uint8_t* in, size_t in_len,
                          uint8_t** out, size_t* out_len,
                          size_t max_bytes, void* heap)
{
    DynBuf body = { .heap = heap, .max = max_bytes };
    size_t p = 0;
    int rc;

    while (p < in_len) {
        size_t clen = 0;
        size_t next = 0;

        if (read_chunk_size(in, in_len, p, &clen, &next) != 0) {
            WOLFCERT_XFREE(body.buf, heap);
            return WOLFCERT_ERR_PROTOCOL;
        }

        p = next;
        if (clen == 0) {
            rc = check_trailers(in + p, in_len - p);
            if (rc != WOLFCERT_OK) {
                WOLFCERT_XFREE(body.buf, heap);
                return rc;
            }

            *out = body.buf;
            *out_len = body.len;
            return WOLFCERT_OK;
        }

        if (clen > max_bytes || p + 2 > in_len || clen > in_len - p - 2) {
            WOLFCERT_XFREE(body.buf, heap);
            return WOLFCERT_ERR_PROTOCOL;
        }

        rc = dyn_append(&body, in + p, clen);
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

    int chunked = (te != NULL && ci_cmp(te, "chunked") == 0);
    long length = -1;
    if (cl != NULL)
        length = strtol(cl, NULL, 10);

    WOLFCERT_XFREE(te, heap);
    WOLFCERT_XFREE(cl, heap);

    if (length >= 0 && (size_t)length > max_bytes)
        return WOLFCERT_ERR_PROTOCOL;

    if (chunked) {
        int framed;

        for (;;) {
            framed = chunked_body_complete(rx->buf + body_start,
                                           rx->len - body_start);
            if (framed != 0)
                break;

            uint8_t tmp[WOLFCERT_HTTP_READ_CHUNK];
            int r = conn_read(c, tmp, sizeof(tmp));
            if (r <= 0)
                return WOLFCERT_ERR_IO;

            int rc = dyn_append(rx, tmp, (size_t)r);
            if (rc != WOLFCERT_OK)
                return rc;
        }

        if (framed < 0)
            return WOLFCERT_ERR_PROTOCOL;

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
        uint8_t* b = NULL;

        if (n > 0) {
            b = (uint8_t*)WOLFCERT_XMALLOC(n, heap);
            if (b == NULL)
                return WOLFCERT_ERR_MEMORY;

            memcpy(b, rx->buf + body_start, n);
        }

        *out = b;
        *out_len = n;

        return WOLFCERT_OK;
    }

    /* read until close */
    while (1) {
        uint8_t tmp[WOLFCERT_HTTP_READ_CHUNK];

        int r = conn_read(c, tmp, sizeof(tmp));
        if (r == WOLFCERT_ERR_CONN_CLOSED)
            break;
        if (r < 0)
            return WOLFCERT_ERR_IO;

        int rc = dyn_append(rx, tmp, (size_t)r);
        if (rc != WOLFCERT_OK)
            return rc;
    }

    size_t n = rx->len - body_start;
    uint8_t* b = NULL;

    if (n > 0) {
        b = (uint8_t*)WOLFCERT_XMALLOC(n, heap);
        if (b == NULL)
            return WOLFCERT_ERR_MEMORY;

        memcpy(b, rx->buf + body_start, n);
    }

    *out = b;
    *out_len = n;

    return WOLFCERT_OK;
}

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

static int buf_filetype(const uint8_t* buf, size_t len)
{
    return wolfcert_buffer_is_der(buf, len) ? WOLFSSL_FILETYPE_ASN1
                                            : WOLFSSL_FILETYPE_PEM;
}

static int setup_tls_ex(WolfCertConn* c, const TlsDials* dials,
                        const char* sni_host, WOLFSSL_CTX** out_ctx)
{
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
        (void)wolfSSL_CTX_allow_post_handshake_auth(ctx);
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

    if (dials->client_cert != NULL && dials->client_key != NULL) {
        /* Load the identity on the CTX so a PHA request can still use it. */
        int rc = wolfSSL_CTX_use_certificate_buffer(ctx, dials->client_cert,
                (long)dials->client_cert_len,
                buf_filetype(dials->client_cert, dials->client_cert_len));
        if (rc != WOLFSSL_SUCCESS) {
            wolfSSL_CTX_free(ctx);
            return WOLFCERT_ERR_TLS;
        }

        rc = wolfSSL_CTX_use_PrivateKey_buffer(ctx, dials->client_key,
                (long)dials->client_key_len,
                buf_filetype(dials->client_key, dials->client_key_len));
        if (rc != WOLFSSL_SUCCESS) {
            wolfSSL_CTX_free(ctx);
            return WOLFCERT_ERR_TLS;
        }
    }

    WOLFSSL* ssl = wolfSSL_new(ctx);
    if (ssl == NULL) {
        wolfSSL_CTX_free(ctx);
        return WOLFCERT_ERR_TLS;
    }

    if (sni_host != NULL) {
#if defined(HAVE_SNI) && !defined(WOLFCERT_NO_SNI)
        wolfSSL_UseSNI(ssl, 0, sni_host, (word16)strlen(sni_host));
#endif

        if (dials->verify_server) {
            /* RFC 2818 section 3.1: an IP literal matches iPAddress SAN
             * entries only. */
            uint8_t ipbuf[16];
            size_t  iplen;
            if (wolfcert_parse_ip(sni_host, ipbuf, &iplen) == WOLFCERT_OK) {
                wolfSSL_check_ip_address(ssl, sni_host);
            } else {
                wolfSSL_check_domain_name(ssl, sni_host);
            }
        }
    }

    /* Nothing may run after this that rebinds wolfSSL's I/O context. */
    wolfSSL_SSLSetIORecv(ssl, wolfcert_cbio_recv);
    wolfSSL_SSLSetIOSend(ssl, wolfcert_cbio_send);
    wolfSSL_SetIOReadCtx(ssl, c);
    wolfSSL_SetIOWriteCtx(ssl, c);

    c->ssl = ssl;
    *out_ctx = ctx;

    return WOLFCERT_OK;
}

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

    const char* open_br  = host_is_ip_literal(u->host) ? "[" : "";
    const char* close_br = host_is_ip_literal(u->host) ? "]" : "";

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
        "Host: %s%s%s%s\r\n"
        "User-Agent: wolfCert/%s\r\n"
        "Connection: %s\r\n"
        "%s%s%s"
        "%s%s%s"
        "%s%s%s"
        "Content-Length: %zu\r\n"
        "%s"
        "\r\n",
        req->method, u->path,
        open_br, u->host, close_br, port_frag,
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

static size_t rx_max(size_t max_body)
{
    return max_body + WOLFCERT_HTTP_HEADER_BUDGET;
}

static int http_read_response(WolfCertConn* c,
                              const char* method,
                              size_t max_body,
                              WolfCertHttpResponse* resp,
                              void* heap)
{
    DynBuf rx = { .heap = heap, .max = rx_max(max_body) };
    char*  headers_nt = NULL;
    char*  ct = NULL;
    char*  ra = NULL;
    int    head_request = (strcmp(method, "HEAD") == 0);
    int    retry_after = 0;
    int    interim = 0;
    int    hdr_end = 0;
    int    status = 0;
    int    rc = WOLFCERT_OK;

    for (;;) {
        hdr_end = read_headers(c, &rx);
        if (hdr_end < 0) {
            rc = hdr_end;
            break;
        }

        WOLFCERT_XFREE(headers_nt, heap);
        headers_nt = (char*)WOLFCERT_XMALLOC((size_t)hdr_end + 1, heap);
        if (headers_nt == NULL) {
            rc = WOLFCERT_ERR_MEMORY;
            break;
        }

        memcpy(headers_nt, rx.buf, (size_t)hdr_end);
        headers_nt[hdr_end] = '\0';

        rc = parse_status_line(headers_nt, &status);
        if (rc != WOLFCERT_OK)
            break;

        if (status == 101) {
            rc = WOLFCERT_ERR(WOLFCERT_ERR_PROTOCOL, "http",
                "http: server sent 101 Switching Protocols, which wolfCert "
                "never asks for with an Upgrade header");
            break;
        }

        if (!status_is_interim(status))
            break;

        if (++interim > WOLFCERT_HTTP_MAX_INTERIM) {
            rc = WOLFCERT_ERR(WOLFCERT_ERR_PROTOCOL, "http",
                "http: more than %d interim 1xx responses arrived before a "
                "final one", WOLFCERT_HTTP_MAX_INTERIM);
            break;
        }

        memmove(rx.buf, rx.buf + hdr_end, rx.len - (size_t)hdr_end);
        rx.len -= (size_t)hdr_end;
    }

    if (rc == WOLFCERT_OK) {
        ct = find_header(headers_nt, "Content-Type", heap);
        ra = find_header(headers_nt, "Retry-After", heap);
        if (ra != NULL) {
            retry_after = parse_retry_after(ra);
            WOLFCERT_XFREE(ra, heap);
        }

        if (!response_has_no_body(status, head_request)) {
            rc = read_body(c, &rx, (size_t)hdr_end, headers_nt,
                           &resp->body, &resp->body_len, max_body, heap);
        }
    }

    if (rc == WOLFCERT_OK) {
        resp->status_code     = status;
        resp->content_type    = ct;
        resp->retry_after_sec = retry_after;
        ct = NULL;  /* ownership moved */
    }

    WOLFCERT_XFREE(ct,         heap);
    WOLFCERT_XFREE(headers_nt, heap);
    WOLFCERT_XFREE(rx.buf,     heap);

    return rc;
}

int wolfcert_http_request(const WolfCertHttpRequest* req, WolfCertHttpResponse* resp)
{
    if (req == NULL || resp == NULL || req->url == NULL || req->method == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    memset(resp, 0, sizeof(*resp));
    void* heap = req->heap ? req->heap : wolfcert_default_heap();
    resp->heap = heap;
    size_t max_body = req->max_response_bytes
                    ? req->max_response_bytes : WOLFCERT_HTTP_DEFAULT_MAX_BODY;

    WolfCertUrl u;
    int rc = wolfcert_http_url_parse(req->url, &u, heap);
    if (rc != WOLFCERT_OK)
        return rc;

    WolfCertConn c;
    WOLFSSL_CTX* ctx = NULL;

    memset(&c, 0, sizeof(c));
    c.io_timeout_ms = -1;
    rc = dial(&c, u.host, u.port, req->timeout_ms, &req->transport);
    if (rc != WOLFCERT_OK) {
        wolfcert_http_url_free(&u);
        return rc;
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

            conn_close(&c);
            wolfcert_http_url_free(&u);

            return rc;
        }
    }

    rc = http_write_request(&c, &u, req, 0 /* close */, heap);
    if (rc != WOLFCERT_OK)
        goto out;

    rc = http_read_response(&c, req->method, max_body, resp, heap);

out:
    if (c.ssl) {
        wolfSSL_shutdown(c.ssl);
        wolfSSL_free(c.ssl);
    }
    if (ctx)
        wolfSSL_CTX_free(ctx);
    conn_close(&c);
    wolfcert_http_url_free(&u);

    return rc;
}

int wolfcert_http_session_open(const WolfCertHttpSessionCfg* cfg,
                               WolfCertHttpSession** out)
{
    if (cfg == NULL || cfg->base_url == NULL || out == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    void* heap = cfg->heap ? cfg->heap : wolfcert_default_heap();

    WolfCertHttpSession* s = (WolfCertHttpSession*)WOLFCERT_XMALLOC(sizeof(*s), heap);
    if (s == NULL)
        return WOLFCERT_ERR_MEMORY;

    memset(s, 0, sizeof(*s));
    s->heap     = heap;
    s->max_body = cfg->max_response_bytes
                ? cfg->max_response_bytes : WOLFCERT_HTTP_DEFAULT_MAX_BODY;

    int rc = wolfcert_http_url_parse(cfg->base_url, &s->base, heap);
    if (rc != WOLFCERT_OK) {
        WOLFCERT_XFREE(s, heap);
        return rc;
    }

    s->conn.io_timeout_ms = cfg->nonblocking ? 0 : -1;
    rc = dial(&s->conn, s->base.host, s->base.port, cfg->timeout_ms,
              &cfg->transport);
    if (rc != WOLFCERT_OK) {
        wolfcert_http_session_close(s);
        return rc;
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
        /* io_timeout_ms carries the mode; the socket keeps its own state. */
        s->nonblocking = 1;

        if (s->conn.ssl) {
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
#ifdef WOLFCERT_HAVE_BUILTIN_TRANSPORT
    if (s == NULL || !s->conn.connected)
        return -1;

    return wolfcert_transport_fd(&s->conn.t, s->conn.handle);
#else
    (void)s;
    return -1;
#endif
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

    WolfCertUrl u;
    int rc = wolfcert_http_url_parse(req->url, &u, s->heap);
    if (rc != WOLFCERT_OK)
        return rc;

    if (u.tls != s->base.tls || u.port != s->base.port ||
        ci_cmp(u.host, s->base.host) != 0) {
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

    rc = http_read_response(&s->conn, req->method, s->max_body, resp,
                            s->heap);
    wolfcert_http_url_free(&u);
    if (rc != WOLFCERT_OK)
        s->closed = 1;

    return rc;
}

/* The request head carries the Authorization line, so it is wiped. */
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
    s->sm_head_request = 0;
    s->sm_interim = 0;
}

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

    conn_close(&s->conn);

    WOLFCERT_XFREE(s->residual, s->heap);
    sm_reset(s);
    wolfcert_http_url_free(&s->base);
    WOLFCERT_XFREE(s, s->heap);
}

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

        int r = c->t.write(c->t.ctx, c->handle, buf + *off, len - *off,
                           c->io_timeout_ms);
        if (r > 0 && (size_t)r > len - *off)
            return WOLFCERT_ERR_IO;
        if (r > 0) {
            *off += (size_t)r;
            continue;
        }

        if (r == WOLFCERT_ERR_WANT_READ || r == WOLFCERT_ERR_WANT_WRITE)
            return r;

        return WOLFCERT_ERR_IO;
    }

    return WOLFCERT_OK;
}

static int nb_rx_reserve(WolfCertHttpSession* s, size_t need)
{
    size_t want = s->sm_rx_len + need;
    if (want <= s->sm_rx_cap)
        return WOLFCERT_OK;

    size_t max = rx_max(s->max_body);
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

/* `ended` is set when the peer closed cleanly. */
static int nb_read_some(WolfCertHttpSession* s, int* ended)
{
    *ended = 0;

    /* Clamp to the allowance left, so a response ending in it still fits. */
    size_t room = rx_max(s->max_body) - s->sm_rx_len;
    uint8_t probe;
    uint8_t* dst;
    int probing = 0;

    if (room == 0) {
        /* An EOF-delimited body may end exactly on the allowance, so probe
         * one byte for the close; data instead overruns it. */
        dst     = &probe;
        room    = 1;
        probing = 1;
    }
    else {
        if (room > WOLFCERT_HTTP_READ_CHUNK)
            room = WOLFCERT_HTTP_READ_CHUNK;

        int rc = nb_rx_reserve(s, room);
        if (rc != WOLFCERT_OK)
            return rc;

        dst = s->sm_rx + s->sm_rx_len;
    }

    if (s->conn.ssl) {
        int r = wolfSSL_read(s->conn.ssl, dst, (int)room);
        if (r > 0) {
            if (probing)
                return WOLFCERT_ERR_PROTOCOL;

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

    int r = s->conn.t.read(s->conn.t.ctx, s->conn.handle, dst,
                           room, s->conn.io_timeout_ms);
    if (r > 0) {
        if ((size_t)r > room)
            return WOLFCERT_ERR_IO;
        if (probing)
            return WOLFCERT_ERR_PROTOCOL;

        s->sm_rx_len += (size_t)r;
        return WOLFCERT_OK;
    }

    if (r == 0 || r == WOLFCERT_ERR_CONN_CLOSED) {
        *ended = 1;
        return WOLFCERT_OK;
    }

    if (r == WOLFCERT_ERR_WANT_READ || r == WOLFCERT_ERR_WANT_WRITE)
        return r;

    return WOLFCERT_ERR_IO;
}

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

    const char* open_br  = host_is_ip_literal(u->host) ? "[" : "";
    const char* close_br = host_is_ip_literal(u->host) ? "]" : "";

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
        "Host: %s%s%s%s\r\n"
        "User-Agent: wolfCert/%s\r\n"
        "Connection: keep-alive\r\n"
        "%s%s%s"
        "%s%s%s"
        "%s%s%s"
        "Content-Length: %zu\r\n"
        "%s"
        "\r\n",
        req->method, u->path,
        open_br, u->host, close_br, port_frag,
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

    if (status == 101) {
        WOLFCERT_XFREE(hdrs, s->heap);
        return WOLFCERT_ERR(WOLFCERT_ERR_PROTOCOL, "http",
            "http: server sent 101 Switching Protocols, which wolfCert "
            "never asks for with an Upgrade header");
    }

    if (status_is_interim(status)) {
        WOLFCERT_XFREE(hdrs, s->heap);
        return WOLFCERT_OK;
    }

    if (response_has_no_body(status, s->sm_head_request)) {
        s->sm_content_length = 0;
    }
    else {
        char* te = find_header(hdrs, "Transfer-Encoding", s->heap);
        if (te != NULL && ci_cmp(te, "chunked") == 0) {
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
    }

    s->sm_content_type = find_header(hdrs, "Content-Type", s->heap);
    s->sm_retry_after_sec = 0;
    char* ra = find_header(hdrs, "Retry-After", s->heap);
    if (ra != NULL) {
        s->sm_retry_after_sec = parse_retry_after(ra);
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

    /* First call for this request. */
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
            ci_cmp(u.host, s->base.host) != 0) {
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

        s->sm_head_request = (strcmp(req->method, "HEAD") == 0);
        s->sm_interim      = 0;

        if (s->residual_len > 0) {
            int rr = nb_rx_reserve(s, s->residual_len);
            if (rr != WOLFCERT_OK) {
                /* Return via sm_fail() to zero the password in s->sm_head. */
                return sm_fail(s, rr);
            }
            memcpy(s->sm_rx, s->residual, s->residual_len);
            s->sm_rx_len = s->residual_len;
            WOLFCERT_XFREE(s->residual, s->heap);
            s->residual = NULL;
            s->residual_len = 0;
        }

        if (s->sm_state != SM_HANDSHAKE)
            s->sm_state = SM_WRITE_HEAD;
    }

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
                for (size_t i = 0; i + 3 < s->sm_rx_len; ++i) {
                    if (s->sm_rx[i] == '\r' && s->sm_rx[i+1] == '\n' &&
                        s->sm_rx[i+2] == '\r' && s->sm_rx[i+3] == '\n') {
                        s->sm_hdr_end = i + 4;
                        int rc = inspect_headers(s);
                        if (rc != WOLFCERT_OK)
                            return sm_fail(s, rc);

                        if (status_is_interim(s->sm_status)) {
                            if (++s->sm_interim > WOLFCERT_HTTP_MAX_INTERIM) {
                                return sm_fail(s, WOLFCERT_ERR(
                                    WOLFCERT_ERR_PROTOCOL, "http",
                                    "http: more than %d interim 1xx responses "
                                    "arrived before a final one",
                                    WOLFCERT_HTTP_MAX_INTERIM));
                            }

                            memmove(s->sm_rx, s->sm_rx + s->sm_hdr_end,
                                    s->sm_rx_len - s->sm_hdr_end);
                            s->sm_rx_len -= s->sm_hdr_end;
                            s->sm_hdr_end = 0;
                            goto state_loop_continue;
                        }

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

                    s->closed = 1;
                    s->sm_state = SM_DONE;
                }
                break;
            }
            case SM_DONE:
            {
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
