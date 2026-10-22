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

/* A caller-supplied WolfCertTransport drives the HTTP path with no socket. */

#include <wolfcert/wolfcert.h>
#include <wolfcert/http.h>
#include "../test_static_mem.h"
#include "internal.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

#define REQUIRE(cond) \
    do {                                                                    \
        if (!(cond)) {                                                      \
            fprintf(stderr, "FAIL %s:%d %s\n", __FILE__, __LINE__, #cond);  \
            return 1;                                                       \
        }                                                                   \
    } while (0)

/* Scripted peer feeding `resp` in `chunk`-sized pieces, then the close. */
typedef struct {
    const char* resp;
    size_t      off;
    size_t      chunk;
    int         connects;
    int         disconnects;
    int         zero_eof;   /* report EOF as 0, breaking the contract */
    int         open_rc;    /* peer stays connected, instead of closing */
    int         stall;      /* alternate every read with a WANT_READ */
    int         stall_now;
    int         fail_connect;
    int         fail_write;
    int         bogus_connect_rc;  /* positive return, breaking the contract */
    int         overcount;         /* report more bytes than written */
    int         read_timeout;      /* timeout_ms of the last read */
} Peer;

static int p_connect(void* ctx, const char* host, int port, int timeout_ms,
                     void** conn)
{
    Peer* p = (Peer*)ctx;

    (void)host; (void)port; (void)timeout_ms;
    if (p->fail_connect)
        return WOLFCERT_ERR_IO;
    if (p->bogus_connect_rc != 0)
        return p->bogus_connect_rc;
    p->connects++;
    *conn = (void*)0;   /* a wolfIP descriptor can be 0 */
    return WOLFCERT_OK;
}

static int p_read(void* ctx, void* conn, uint8_t* buf, size_t len,
                  int timeout_ms)
{
    Peer*  p = (Peer*)ctx;
    size_t n = strlen(p->resp) - p->off;

    (void)conn;
    p->read_timeout = timeout_ms;
    if (p->stall) {
        p->stall_now = !p->stall_now;
        if (p->stall_now)
            return WOLFCERT_ERR_WANT_READ;
    }

    if (n == 0) {
        if (p->open_rc != 0)
            return p->open_rc;

        return p->zero_eof ? 0 : WOLFCERT_ERR_CONN_CLOSED;
    }
    if (n > len)
        n = len;
    if (n > p->chunk)
        n = p->chunk;

    memcpy(buf, p->resp + p->off, n);
    p->off += n;
    if (p->overcount)
        return (int)len + 1;

    return (int)n;
}

static int p_write(void* ctx, void* conn, const uint8_t* buf, size_t len,
                   int timeout_ms)
{
    Peer* p = (Peer*)ctx;

    (void)conn; (void)buf; (void)timeout_ms;
    if (p->fail_write)
        return WOLFCERT_ERR_IO;
    return (int)len;
}

static int p_disconnect(void* ctx, void* conn)
{
    Peer* p = (Peer*)ctx;

    (void)conn;
    p->disconnects++;
    return WOLFCERT_OK;
}

static int fetch_m(Peer* p, const char* method, const char* resp, size_t chunk,
                   WolfCertHttpResponse* out)
{
    WolfCertTransport t = { p_connect, p_read, p_write, p_disconnect, p };
    WolfCertHttpRequest req = { .method = method, .url = "http://peer.test/" };

    p->resp = resp;
    p->off = 0;
    p->chunk = chunk;
    req.transport = t;

    return wolfcert_http_request(&req, out);
}

static int fetch(Peer* p, const char* resp, size_t chunk,
                 WolfCertHttpResponse* out)
{
    return fetch_m(p, "GET", resp, chunk, out);
}

static const char RESP_CL[] =
    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
    "Content-Length: 5\r\n\r\nhello";
static const char RESP_EOF[] =
    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nbye";

static const char RESP_EOF0[] =
    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n";
static const char RESP_CL0[] =
    "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n";

/* The peer closes inside the header block, after 3 of 10 body bytes, or
 * inside a chunk. */
static const char RESP_CUT_HEAD[] =
    "HTTP/1.1 200 OK\r\nContent-Type: text/pl";
static const char RESP_CUT_BODY[] =
    "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nhel";
static const char RESP_CUT_CHUNKED[] =
    "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhel";

/* None of these is terminated by a close. */
static const char RESP_204[] =
    "HTTP/1.1 204 No Content\r\nConnection: keep-alive\r\n\r\n";
static const char RESP_304[] =
    "HTTP/1.1 304 Not Modified\r\nETag: \"v1\"\r\n"
    "Connection: keep-alive\r\n\r\n";
static const char RESP_204_RETRY[] =
    "HTTP/1.1 204 No Content\r\nRetry-After: 30\r\n"
    "Connection: keep-alive\r\n\r\n";
static const char RESP_HEAD[] =
    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
    "Content-Length: 5\r\nConnection: keep-alive\r\n\r\n";

#define INTERIM_BLOCK "HTTP/1.1 100 Continue\r\n\r\n"
static const char RESP_INTERIM[] =
    INTERIM_BLOCK
    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
    "Content-Length: 5\r\nConnection: keep-alive\r\n\r\nhello";
/* Eight blocks, exactly WOLFCERT_HTTP_MAX_INTERIM. */
static const char RESP_INTERIM_MAX[] =
    INTERIM_BLOCK INTERIM_BLOCK INTERIM_BLOCK INTERIM_BLOCK
    INTERIM_BLOCK INTERIM_BLOCK INTERIM_BLOCK INTERIM_BLOCK
    "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
/* Nine blocks, one past WOLFCERT_HTTP_MAX_INTERIM. */
static const char RESP_INTERIM_FLOOD[] =
    INTERIM_BLOCK INTERIM_BLOCK INTERIM_BLOCK
    INTERIM_BLOCK INTERIM_BLOCK INTERIM_BLOCK
    INTERIM_BLOCK INTERIM_BLOCK INTERIM_BLOCK
    "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
/* A HEAD reply names the length a GET would have returned. */
static const char RESP_HEAD_BIG[] =
    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
    "Content-Length: 1000000\r\nConnection: keep-alive\r\n\r\n";
/* An interim block carrying header fields of its own, then the real ones. */
static const char RESP_INTERIM_HDRS[] =
    "HTTP/1.1 103 Early Hints\r\nLink: </s.css>; rel=preload\r\n"
    "Content-Type: text/interim\r\n\r\n"
    "HTTP/1.1 200 OK\r\nContent-Type: text/final\r\n"
    "Content-Length: 5\r\nConnection: keep-alive\r\n\r\nhello";
/* A long interim block, then a final header block shorter than it. */
static const char RESP_LONG_INTERIM_204[] =
    "HTTP/1.1 103 Early Hints\r\n"
    "Link: </assets/a-rather-long-stylesheet-name.css>; rel=preload\r\n\r\n"
    "HTTP/1.1 204 No Content\r\n\r\n";
/* A reply the server sends unasked, right behind the one requested. */
#define STALE_500 "HTTP/1.1 500 Stale\r\nContent-Length: 0\r\n\r\n"
static const char RESP_101[] =
    "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n";
static const char RESP_CHUNKED[] =
    "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n"
    "Connection: keep-alive\r\n\r\n"
    "5\r\nhello\r\n6;x=1\r\n world\r\n0\r\nX-T: 1\r\n\r\n";
/* A HEAD reply and a 204 that name a transfer coding but carry no body. */
static const char RESP_HEAD_CHUNKED[] =
    "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n"
    "Connection: keep-alive\r\n\r\n";
static const char RESP_204_CHUNKED[] =
    "HTTP/1.1 204 No Content\r\nTransfer-Encoding: chunked\r\n\r\n";
static const char RESP_CHUNKED_SHORT[] =
    "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
    "3\r\nabc\r\n0\r\n\r\n";

static int test_roundtrip(void)
{
    WolfCertHttpResponse resp = { 0 };
    Peer p = { 0 };

    REQUIRE(fetch(&p, RESP_CL, sizeof(RESP_CL), &resp) == WOLFCERT_OK);
    REQUIRE(resp.status_code == 200);
    REQUIRE(resp.body_len == 5 && memcmp(resp.body, "hello", 5) == 0);
    /* handle 0 must not read as "never connected". */
    REQUIRE(p.connects == 1 && p.disconnects == 1);
    wolfcert_http_response_free(&resp);
    return 0;
}

static int test_byte_at_a_time(void)
{
    WolfCertHttpResponse resp = { 0 };
    Peer p = { 0 };

    REQUIRE(fetch(&p, RESP_CL, 1, &resp) == WOLFCERT_OK);
    REQUIRE(resp.status_code == 200);
    REQUIRE(resp.body_len == 5 && memcmp(resp.body, "hello", 5) == 0);
    wolfcert_http_response_free(&resp);
    return 0;
}

static int test_body_ends_at_close(void)
{
    WolfCertHttpResponse resp = { 0 };
    Peer p = { 0 };

    REQUIRE(fetch(&p, RESP_EOF, sizeof(RESP_EOF), &resp) == WOLFCERT_OK);
    REQUIRE(resp.body_len == 3 && memcmp(resp.body, "bye", 3) == 0);
    REQUIRE(p.disconnects == 1);
    wolfcert_http_response_free(&resp);
    return 0;
}

/* With a 16-byte cap, a body that ends at the close may be 16 bytes; 17 is
 * ERR_PROTOCOL, arriving with the headers or in a later read. */
static int test_eof_body_capped(void)
{
    static const char hdr[] = "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n";
    WolfCertTransport t = { p_connect, p_read, p_write, p_disconnect, NULL };
    WolfCertHttpRequest req = { .method = "GET", .url = "http://peer.test/" };
    WolfCertHttpResponse resp = { 0 };
    const size_t hl = sizeof(hdr) - 1;
    char wire[sizeof(hdr) + 32];
    Peer p = { 0 };

    t.ctx = &p;
    req.transport = t;
    req.max_response_bytes = 16;
    memcpy(wire, hdr, hl);

    memset(wire + hl, 'B', 16);
    wire[hl + 16] = '\0';
    p.resp  = wire;
    p.chunk = sizeof(wire);
    REQUIRE(wolfcert_http_request(&req, &resp) == WOLFCERT_OK);
    REQUIRE(resp.body_len == 16);
    wolfcert_http_response_free(&resp);

    memset(wire + hl, 'B', 17);
    wire[hl + 17] = '\0';
    memset(&p, 0, sizeof(p));
    p.resp  = wire;
    p.chunk = sizeof(wire);
    REQUIRE(wolfcert_http_request(&req, &resp) == WOLFCERT_ERR_PROTOCOL);

    memset(&p, 0, sizeof(p));
    p.resp  = wire;
    p.chunk = hl + 16;
    REQUIRE(wolfcert_http_request(&req, &resp) == WOLFCERT_ERR_PROTOCOL);
    return 0;
}

#if defined(WOLFSSL_STATIC_MEMORY) && defined(WOLFSSL_NO_MALLOC)
/* With a 256 KiB cap no pool block holds the whole allowance: a short
 * chunked reply still arrives, and a 160 KiB one, larger than any block,
 * fails with a message naming the settings. */
static int test_chunked_over_pool_block(void)
{
    static const char head[] =
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n28000\r\n";
    static const char tail[] = "\r\n0\r\n\r\n";
    static char big[sizeof(head) + 0x28000 + sizeof(tail)];
    WolfCertTransport t = { p_connect, p_read, p_write, p_disconnect, NULL };
    WolfCertHttpRequest req = { .method = "GET", .url = "http://peer.test/" };
    WolfCertHttpResponse resp = { 0 };
    const size_t hl = sizeof(head) - 1;
    Peer p = { 0 };

    t.ctx = &p;
    req.transport = t;
    req.max_response_bytes = 256 * 1024;
    p.resp  = RESP_CHUNKED;
    p.chunk = sizeof(RESP_CHUNKED);
    REQUIRE(wolfcert_http_request(&req, &resp) == WOLFCERT_OK);
    REQUIRE(resp.body_len == 11 && memcmp(resp.body, "hello world", 11) == 0);
    wolfcert_http_response_free(&resp);

    memcpy(big, head, hl);
    memset(big + hl, 'A', 0x28000);
    memcpy(big + hl + 0x28000, tail, sizeof(tail));
    memset(&p, 0, sizeof(p));
    p.resp  = big;
    p.chunk = 4096;
    wolfcert_clear_error();
    REQUIRE(wolfcert_http_request(&req, &resp) == WOLFCERT_ERR_MEMORY);
    REQUIRE(strstr(wolfcert_last_error_message(), "max_response_bytes")
            != NULL);
    REQUIRE(resp.body == NULL);
    return 0;
}
#endif

/* A header block 100 bytes over the budget, arriving 1000 bytes per read so
 * one read could carry it past the budget, is refused with ERR_PROTOCOL. */
static int test_header_block_over_budget(void)
{
    static const char head[] =
        "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nX-Pad: ";
    static char wire[WOLFCERT_HTTP_HEADER_BUDGET + 128];
    const size_t total = WOLFCERT_HTTP_HEADER_BUDGET + 100;
    const size_t hl = sizeof(head) - 1;
    WolfCertHttpResponse resp = { 0 };
    Peer p = { 0 };

    memcpy(wire, head, hl);
    memset(wire + hl, 'A', total - hl - 4);
    memcpy(wire + total - 4, "\r\n\r\n", 5);
    wolfcert_clear_error();
    REQUIRE(fetch(&p, wire, 1000, &resp) == WOLFCERT_ERR_PROTOCOL);
    REQUIRE(strstr(wolfcert_last_error_message(), "header block") != NULL);
    return 0;
}

/* A close before the headers, the Content-Length body or the chunked body
 * are complete is ERR_IO with a message and no response. */
static int test_truncated_reply_is_io(void)
{
    static const char* const cut[] = {
        RESP_CUT_HEAD, RESP_CUT_BODY, RESP_CUT_CHUNKED
    };
    static const char* const why[] = {
        "inside the response header", "after 3 of 10 body bytes",
        "inside the chunked body"
    };
    WolfCertHttpResponse resp = { 0 };
    Peer p = { 0 };
    size_t i;

    for (i = 0; i < sizeof(cut) / sizeof(cut[0]); i++) {
        memset(&p, 0, sizeof(p));
        wolfcert_clear_error();
        REQUIRE(fetch(&p, cut[i], strlen(cut[i]) + 1, &resp)
                == WOLFCERT_ERR_IO);
        REQUIRE(strstr(wolfcert_last_error_message(), why[i]) != NULL);
        REQUIRE(resp.status_code == 0 && resp.body == NULL);
    }
    return 0;
}

/* A read() returning 0 is treated as a close. */
static int test_zero_is_not_data(void)
{
    WolfCertHttpResponse resp = { 0 };
    Peer p = { 0 };

    p.zero_eof = 1;
    REQUIRE(fetch(&p, RESP_EOF, sizeof(RESP_EOF), &resp) == WOLFCERT_OK);
    REQUIRE(resp.body_len == 3 && memcmp(resp.body, "bye", 3) == 0);
    REQUIRE(p.disconnects == 1);
    wolfcert_http_response_free(&resp);
    return 0;
}

static int test_read_overcount_rejected(void)
{
    WolfCertHttpResponse resp = { 0 };
    Peer p = { 0 };

    p.overcount = 1;
    REQUIRE(fetch(&p, RESP_CL, sizeof(RESP_CL), &resp) == WOLFCERT_ERR_IO);
    REQUIRE(p.connects == 1 && p.disconnects == 1);
    return 0;
}

/* A failed connect gets no disconnect; a failed write gets one. */
static int test_error_paths(void)
{
    WolfCertTransport t = { p_connect, p_read, p_write, p_disconnect, NULL };
    WolfCertHttpRequest req = { .method = "GET", .url = "http://peer.test/" };
    WolfCertHttpResponse resp = { 0 };
    Peer p = { 0 };

    t.ctx = &p;
    req.transport = t;

    p.fail_connect = 1;
    REQUIRE(wolfcert_http_request(&req, &resp) != WOLFCERT_OK);
    REQUIRE(p.disconnects == 0);

    p.fail_connect = 0;
    p.fail_write = 1;
    p.resp = RESP_CL;
    p.chunk = sizeof(RESP_CL);
    REQUIRE(wolfcert_http_request(&req, &resp) != WOLFCERT_OK);
    REQUIRE(p.connects == 1 && p.disconnects == 1);
    return 0;
}

/* A positive connect return surfaces as a negative error. */
static int test_positive_connect_rc(void)
{
    WolfCertTransport t = { p_connect, p_read, p_write, p_disconnect, NULL };
    WolfCertHttpRequest req = { .method = "GET", .url = "http://peer.test/" };
    WolfCertHttpResponse resp = { 0 };
    Peer p = { 0 };
    int rc;

    t.ctx = &p;
    req.transport = t;
    p.bogus_connect_rc = 1;

    rc = wolfcert_http_request(&req, &resp);
    REQUIRE(rc < 0);
    REQUIRE(p.disconnects == 0);
    return 0;
}

/* The vtable lives in this frame, so the session must keep its own copy. */
static int open_scoped(Peer* p, WolfCertHttpSession** out)
{
    WolfCertHttpSessionCfg cfg = { .base_url = "http://peer.test/" };
    WolfCertTransport t = { p_connect, p_read, p_write, p_disconnect, p };

    cfg.transport = t;
    return wolfcert_http_session_open(&cfg, out);
}

/* Overwrites the stack frame open_scoped() used. */
static int clobber_stack(void)
{
    volatile unsigned char junk[512];
    size_t i;

    for (i = 0; i < sizeof(junk); i++) {
        junk[i] = 0xAA;
    }

    return junk[0] == 0xAA;
}

static int test_transport_is_copied(void)
{
    WolfCertHttpRequest req = { .method = "GET", .url = "http://peer.test/" };
    WolfCertHttpResponse resp = { 0 };
    WolfCertHttpSession* s = NULL;
    Peer p = { 0 };

    p.resp  = RESP_CL;
    p.chunk = sizeof(RESP_CL);

    REQUIRE(open_scoped(&p, &s) == WOLFCERT_OK);
    REQUIRE(clobber_stack() == 1);

    REQUIRE(wolfcert_http_session_request(s, &req, &resp) == WOLFCERT_OK);
    REQUIRE(resp.status_code == 200);
    wolfcert_http_response_free(&resp);
    wolfcert_http_session_close(s);
    REQUIRE(p.connects == 1 && p.disconnects == 1);
    return 0;
}

/* Only an all-zero transport selects the built-in one. */
static int test_partial_vtable_rejected(void)
{
    WolfCertHttpRequest req = { .method = "GET", .url = "http://peer.test/" };
    WolfCertHttpSessionCfg cfg = { .base_url = "http://peer.test/" };
    WolfCertHttpResponse resp = { 0 };
    WolfCertHttpSession* s = NULL;
    WolfCertTransport t;
    Peer p = { 0 };

    memset(&t, 0, sizeof(t));
    t.read = p_read;
    t.write = p_write;
    t.disconnect = p_disconnect;
    req.transport = t;
    cfg.transport = t;
    REQUIRE(wolfcert_http_request(&req, &resp) == WOLFCERT_ERR_BAD_ARG);
    REQUIRE(wolfcert_http_session_open(&cfg, &s) == WOLFCERT_ERR_BAD_ARG);
    REQUIRE(s == NULL);

    memset(&t, 0, sizeof(t));
    t.ctx = &p;
    req.transport = t;
    cfg.transport = t;
    REQUIRE(wolfcert_http_request(&req, &resp) == WOLFCERT_ERR_BAD_ARG);
    REQUIRE(wolfcert_http_session_open(&cfg, &s) == WOLFCERT_ERR_BAD_ARG);

    memset(&t, 0, sizeof(t));
    t.connect = p_connect;
    t.write = p_write;
    t.disconnect = p_disconnect;
    t.ctx = &p;
    req.transport = t;
    REQUIRE(wolfcert_http_request(&req, &resp) == WOLFCERT_ERR_BAD_ARG);
    REQUIRE(p.connects == 0);
    return 0;
}

static int test_empty_body_is_null(void)
{
    WolfCertHttpResponse resp = { 0 };
    Peer p = { 0 };

    p.open_rc = WOLFCERT_ERR_IO;
    REQUIRE(fetch(&p, RESP_CL0, sizeof(RESP_CL0), &resp) == WOLFCERT_OK);
    REQUIRE(resp.status_code == 200);
    REQUIRE(resp.body == NULL && resp.body_len == 0);
    wolfcert_http_response_free(&resp);
    return 0;
}

static int test_204_no_body(void)
{
    WolfCertHttpResponse resp = { 0 };
    Peer p = { 0 };

    p.open_rc = WOLFCERT_ERR_IO;
    REQUIRE(fetch(&p, RESP_204, sizeof(RESP_204), &resp) == WOLFCERT_OK);
    REQUIRE(resp.status_code == 204);
    REQUIRE(resp.body == NULL && resp.body_len == 0);
    wolfcert_http_response_free(&resp);
    return 0;
}

/* A HEAD reply and a 204 carrying Transfer-Encoding: chunked have no body,
 * and the next GET on the session gets its own reply. */
static int test_no_body_ignores_chunked(void)
{
    static const char* const replies[] = {
        RESP_HEAD_CHUNKED, RESP_204_CHUNKED
    };
    static const char* const methods[] = { "HEAD", "GET" };
    WolfCertHttpRequest req = { .url = "http://peer.test/" };
    WolfCertHttpResponse resp = { 0 };
    WolfCertHttpSession* s = NULL;
    Peer p = { 0 };
    size_t i;

    p.open_rc = WOLFCERT_ERR_IO;
    REQUIRE(open_scoped(&p, &s) == WOLFCERT_OK);
    for (i = 0; i < sizeof(replies) / sizeof(replies[0]); i++) {
        p.resp  = replies[i];
        p.off   = 0;
        p.chunk = strlen(replies[i]);
        req.method = methods[i];
        REQUIRE(wolfcert_http_session_request(s, &req, &resp) == WOLFCERT_OK);
        REQUIRE(resp.body == NULL && resp.body_len == 0);
        wolfcert_http_response_free(&resp);

        p.resp  = RESP_CL;
        p.off   = 0;
        p.chunk = sizeof(RESP_CL);
        req.method = "GET";
        REQUIRE(wolfcert_http_session_request(s, &req, &resp) == WOLFCERT_OK);
        REQUIRE(resp.body_len == 5 && memcmp(resp.body, "hello", 5) == 0);
        wolfcert_http_response_free(&resp);
    }
    wolfcert_http_session_close(s);
    return 0;
}

static int test_304_no_body(void)
{
    WolfCertHttpResponse resp = { 0 };
    Peer p = { 0 };

    p.open_rc = WOLFCERT_ERR_IO;
    REQUIRE(fetch(&p, RESP_304, sizeof(RESP_304), &resp) == WOLFCERT_OK);
    REQUIRE(resp.status_code == 304);
    REQUIRE(resp.body == NULL && resp.body_len == 0);
    wolfcert_http_response_free(&resp);
    return 0;
}

static int test_204_keeps_retry_after(void)
{
    WolfCertHttpResponse resp = { 0 };
    Peer p = { 0 };

    p.open_rc = WOLFCERT_ERR_IO;
    REQUIRE(fetch(&p, RESP_204_RETRY, sizeof(RESP_204_RETRY), &resp)
            == WOLFCERT_OK);
    REQUIRE(resp.status_code == 204);
    REQUIRE(resp.retry_after_sec == 30);
    REQUIRE(resp.body == NULL && resp.body_len == 0);
    wolfcert_http_response_free(&resp);
    return 0;
}

static int test_head_ignores_content_length(void)
{
    WolfCertHttpResponse resp = { 0 };
    Peer p = { 0 };

    p.open_rc = WOLFCERT_ERR_IO;
    REQUIRE(fetch_m(&p, "HEAD", RESP_HEAD, sizeof(RESP_HEAD), &resp)
            == WOLFCERT_OK);
    REQUIRE(resp.status_code == 200);
    REQUIRE(resp.body == NULL && resp.body_len == 0);
    wolfcert_http_response_free(&resp);
    return 0;
}

static int test_lowercase_head_is_not_head(void)
{
    WolfCertHttpResponse resp = { 0 };
    Peer p = { 0 };

    REQUIRE(fetch_m(&p, "head", RESP_CL, sizeof(RESP_CL), &resp)
            == WOLFCERT_OK);
    REQUIRE(resp.status_code == 200);
    REQUIRE(resp.body_len == 5 && memcmp(resp.body, "hello", 5) == 0);
    wolfcert_http_response_free(&resp);
    return 0;
}

static int test_head_oversized_length_ok(void)
{
    WolfCertTransport t = { p_connect, p_read, p_write, p_disconnect, NULL };
    WolfCertHttpRequest req = { .method = "HEAD", .url = "http://peer.test/" };
    WolfCertHttpResponse resp = { 0 };
    Peer p = { 0 };

    t.ctx = &p;
    p.resp    = RESP_HEAD_BIG;
    p.chunk   = sizeof(RESP_HEAD_BIG);
    p.open_rc = WOLFCERT_ERR_IO;
    req.transport = t;
    req.max_response_bytes = 16;

    REQUIRE(wolfcert_http_request(&req, &resp) == WOLFCERT_OK);
    REQUIRE(resp.status_code == 200);
    REQUIRE(resp.body == NULL && resp.body_len == 0);
    wolfcert_http_response_free(&resp);
    return 0;
}

/* Fed both ways: the two responses together, then split byte by byte. */
static int test_interim_then_final(void)
{
    WolfCertHttpResponse resp = { 0 };
    Peer p = { 0 };

    p.open_rc = WOLFCERT_ERR_IO;
    REQUIRE(fetch(&p, RESP_INTERIM, sizeof(RESP_INTERIM), &resp)
            == WOLFCERT_OK);
    REQUIRE(resp.status_code == 200);
    REQUIRE(resp.body_len == 5 && memcmp(resp.body, "hello", 5) == 0);
    wolfcert_http_response_free(&resp);

    memset(&p, 0, sizeof(p));
    p.open_rc = WOLFCERT_ERR_IO;
    REQUIRE(fetch(&p, RESP_INTERIM, 1, &resp) == WOLFCERT_OK);
    REQUIRE(resp.status_code == 200);
    REQUIRE(resp.body_len == 5 && memcmp(resp.body, "hello", 5) == 0);
    wolfcert_http_response_free(&resp);
    return 0;
}

/* Fed one byte per read, a final header block shorter than the interim one
 * before it is still found: 204. */
static int test_short_final_after_long_interim(void)
{
    WolfCertHttpResponse resp = { 0 };
    Peer p = { 0 };

    REQUIRE(fetch(&p, RESP_LONG_INTERIM_204, 1, &resp) == WOLFCERT_OK);
    REQUIRE(resp.status_code == 204);
    REQUIRE(resp.body == NULL && resp.body_len == 0);
    wolfcert_http_response_free(&resp);
    return 0;
}

static int test_interim_headers_discarded(void)
{
    WolfCertHttpResponse resp = { 0 };
    Peer p = { 0 };

    p.open_rc = WOLFCERT_ERR_IO;
    REQUIRE(fetch(&p, RESP_INTERIM_HDRS, sizeof(RESP_INTERIM_HDRS), &resp)
            == WOLFCERT_OK);
    REQUIRE(resp.status_code == 200);
    REQUIRE(resp.content_type != NULL);
    REQUIRE(strcmp(resp.content_type, "text/final") == 0);
    REQUIRE(resp.body_len == 5 && memcmp(resp.body, "hello", 5) == 0);
    wolfcert_http_response_free(&resp);
    return 0;
}

static int test_interim_at_cap_accepted(void)
{
    WolfCertHttpResponse resp = { 0 };
    Peer p = { 0 };

    p.open_rc = WOLFCERT_ERR_IO;
    REQUIRE(fetch(&p, RESP_INTERIM_MAX, sizeof(RESP_INTERIM_MAX), &resp)
            == WOLFCERT_OK);
    REQUIRE(resp.status_code == 200);
    REQUIRE(resp.body_len == 5 && memcmp(resp.body, "hello", 5) == 0);
    wolfcert_http_response_free(&resp);
    return 0;
}

static int test_interim_flood_rejected(void)
{
    WolfCertHttpResponse resp = { 0 };
    Peer p = { 0 };

    p.open_rc = WOLFCERT_ERR_IO;
    REQUIRE(fetch(&p, RESP_INTERIM_FLOOD, sizeof(RESP_INTERIM_FLOOD), &resp)
            == WOLFCERT_ERR_PROTOCOL);
    return 0;
}

static int test_switching_protocols_rejected(void)
{
    WolfCertHttpResponse resp = { 0 };
    Peer p = { 0 };

    p.open_rc = WOLFCERT_ERR_IO;
    REQUIRE(fetch(&p, RESP_101, sizeof(RESP_101), &resp)
            == WOLFCERT_ERR_PROTOCOL);
    return 0;
}

/* Drives one request with a bounded number of steps. */
static int drive_nb(WolfCertHttpSession* s, const WolfCertHttpRequest* req,
                    WolfCertHttpResponse* out)
{
    int rc = WOLFCERT_ERR_WANT_READ;
    int i;

    for (i = 0; i < 1024; i++) {
        rc = wolfcert_http_session_request_nb(s, req, out);
        if (rc != WOLFCERT_ERR_WANT_READ && rc != WOLFCERT_ERR_WANT_WRITE)
            break;
    }

    return rc;
}

static int nb_fetch_m(Peer* p, const char* method, const char* bytes,
                      size_t chunk, WolfCertHttpResponse* out)
{
    WolfCertHttpSessionCfg cfg = { .base_url = "http://peer.test/" };
    WolfCertTransport t = { p_connect, p_read, p_write, p_disconnect, p };
    WolfCertHttpRequest req = { .method = method, .url = "http://peer.test/" };
    WolfCertHttpSession* s = NULL;
    int rc;

    p->resp    = bytes;
    p->off     = 0;
    p->chunk   = chunk;
    p->open_rc = WOLFCERT_ERR_WANT_READ;
    cfg.transport   = t;

    rc = wolfcert_http_session_open(&cfg, &s);
    if (rc != WOLFCERT_OK)
        return rc;

    rc = drive_nb(s, &req, out);
    wolfcert_http_session_close(s);

    return rc;
}

static int nb_fetch(Peer* p, const char* bytes, WolfCertHttpResponse* out)
{
    return nb_fetch_m(p, "GET", bytes, strlen(bytes), out);
}

static int retry_after_of(const char* value, int nb, int* out)
{
    WolfCertHttpResponse resp = { 0 };
    Peer p = { 0 };
    char raw[256];
    int rc;

    snprintf(raw, sizeof(raw),
             "HTTP/1.1 503 Service Unavailable\r\nRetry-After: %s\r\n"
             "Content-Length: 0\r\nConnection: keep-alive\r\n\r\n", value);
    p.open_rc = WOLFCERT_ERR_IO;
    rc = nb ? nb_fetch(&p, raw, &resp) : fetch(&p, raw, sizeof(raw), &resp);
    *out = resp.retry_after_sec;
    wolfcert_http_response_free(&resp);

    return rc;
}

/* delay-seconds is digits alone, apart from trailing whitespace. */
static int test_retry_after_delay_seconds(void)
{
    static const char* const bad[] = { "120junk", "12 0", "120s", "1.5" };
    size_t i;
    int nb;
    int sec;

    for (nb = 0; nb <= 1; nb++) {
        REQUIRE(retry_after_of("120 \t", nb, &sec) == WOLFCERT_OK);
        REQUIRE(sec == 120);
        REQUIRE(retry_after_of("99999999999999999999999", nb, &sec)
                == WOLFCERT_OK);
        REQUIRE(sec == 86400);
        for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
            REQUIRE(retry_after_of(bad[i], nb, &sec) == WOLFCERT_OK);
            if (sec != 0)
                fprintf(stderr, "accepted malformed delay \"%s\"\n", bad[i]);
            REQUIRE(sec == 0);
        }
    }

    return 0;
}

#ifndef NO_ASN_TIME
/* RFC 9110 section 5.6.7: IMF-fixdate, obsolete RFC 850 and asctime. */
static void retry_after_date(char* out, size_t sz, time_t t, int form)
{
    static const char* const wd[] = {
        "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"
    };
    static const char* const wdl[] = {
        "Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday",
        "Saturday"
    };
    static const char* const mon[] = {
        "Jan", "Feb", "Mar", "Apr", "May", "Jun",
        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
    };
    struct tm* g = gmtime(&t);

    if (form == 0) {
        snprintf(out, sz, "%s, %02d %s %04d %02d:%02d:%02d GMT",
                 wd[g->tm_wday], g->tm_mday, mon[g->tm_mon],
                 g->tm_year + 1900, g->tm_hour, g->tm_min, g->tm_sec);
    }
    else if (form == 1) {
        snprintf(out, sz, "%s, %02d-%s-%02d %02d:%02d:%02d GMT",
                 wdl[g->tm_wday], g->tm_mday, mon[g->tm_mon],
                 g->tm_year % 100, g->tm_hour, g->tm_min, g->tm_sec);
    }
    else {
        snprintf(out, sz, "%s %s %2d %02d:%02d:%02d %04d",
                 wd[g->tm_wday], mon[g->tm_mon], g->tm_mday,
                 g->tm_hour, g->tm_min, g->tm_sec, g->tm_year + 1900);
    }
}

static int test_retry_after_http_date(void)
{
    static const char* const bad[] = {
        "Sun, 06 Nov 2095 08:49",
        "Sun, 06 Nov 2095 08:49:37",
        "Sun, 06 Nov 2095 08:49:37 UTC",
        "Sun, 06 Nov 2095 08:49:37 GMTx",
        "Sun, 06 Nov 2095 08:49:37 GMT extra",
        "Sun, 06 Nov 2095 24:00:00 GMT",
        "Sun, 06 Foo 2095 08:49:37 GMT",
        "Sun, 6 Nov 2095 08:49:37 GMT",
        "Tue, 29 Feb 2095 08:49:37 GMT",
        "Mon, 29 Feb 2100 08:49:37 GMT",
        "Sunday, 06-Nov-95 08:49",
        "Sun Nov  6 08:49:37",
        "Sunday",
        "",
    };
    char date[64];
    size_t i;
    time_t t = time(NULL);
    int cy = gmtime(&t)->tm_year + 1900;
    int form;
    int nb;
    int sec;

    for (nb = 0; nb <= 1; nb++) {
        for (form = 0; form <= 2; form++) {
            retry_after_date(date, sizeof(date), time(NULL) + 120, form);
            REQUIRE(retry_after_of(date, nb, &sec) == WOLFCERT_OK);
            REQUIRE(sec >= 110 && sec <= 120);

            retry_after_date(date, sizeof(date), time(NULL) - 120, form);
            REQUIRE(retry_after_of(date, nb, &sec) == WOLFCERT_OK);
            REQUIRE(sec == 0);
        }

        /* RFC 850 years resolve against the current year. */
        snprintf(date, sizeof(date), "Monday, 01-Jan-%02d 00:00:00 GMT",
                 (cy + 45) % 100);
        REQUIRE(retry_after_of(date, nb, &sec) == WOLFCERT_OK);
        REQUIRE(sec == 86400);
        snprintf(date, sizeof(date), "Monday, 01-Jan-%02d 00:00:00 GMT",
                 (cy + 55) % 100);
        REQUIRE(retry_after_of(date, nb, &sec) == WOLFCERT_OK);
        REQUIRE(sec == 0);

        /* Exactly 50 calendar years ahead is still the future. */
        for (i = 0; i < 2; i++) {
            time_t at = time(NULL) + (i == 0 ? -60 : 120);
            struct tm g = *gmtime(&at);

            if (g.tm_mon == 1 && g.tm_mday == 29)
                break;
            strftime(date, sizeof(date), "Monday, %d-%b-", &g);
            snprintf(date + strlen(date), sizeof(date) - strlen(date),
                     "%02d %02d:%02d:%02d GMT", (g.tm_year + 1900 + 50) % 100,
                     g.tm_hour, g.tm_min, g.tm_sec);
            REQUIRE(retry_after_of(date, nb, &sec) == WOLFCERT_OK);
            REQUIRE(sec == (i == 0 ? 86400 : 0));
        }

        /* Future years throughout, so 0 can only mean the value was rejected. */
        for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
            REQUIRE(retry_after_of(bad[i], nb, &sec) == WOLFCERT_OK);
            if (sec != 0)
                fprintf(stderr, "accepted malformed date \"%s\"\n", bad[i]);
            REQUIRE(sec == 0);
        }
        REQUIRE(retry_after_of("Thu, 29 Feb 2096 08:49:37 GMT", nb, &sec)
                == WOLFCERT_OK);
        REQUIRE(sec == 86400);

        REQUIRE(retry_after_of("Sun, 06 Nov 2094 08:49:37 GMT", nb, &sec)
                == WOLFCERT_OK);
        REQUIRE(sec == 86400);
        REQUIRE(retry_after_of("172800", nb, &sec) == WOLFCERT_OK);
        REQUIRE(sec == 86400);
        REQUIRE(retry_after_of("Sun, 31 Nov 2094 08:49:37 GMT", nb, &sec)
                == WOLFCERT_OK);
        REQUIRE(sec == 0);
    }

    return 0;
}

static time_t unset_clock(time_t* t)
{
    if (t != NULL)
        *t = 1000;
    return 1000;
}

/* A device clock still near 1970 must not turn every date into a day's wait. */
static int test_retry_after_unset_clock(void)
{
    int sec = -1;
    int rc;

    REQUIRE(wc_SetTimeCb(unset_clock) == 0);
    rc = retry_after_of("Sun, 06 Nov 2094 08:49:37 GMT", 0, &sec);
    wc_SetTimeCb(NULL);
    REQUIRE(rc == WOLFCERT_OK);
    REQUIRE(sec == 0);
    REQUIRE(wc_SetTimeCb(unset_clock) == 0);
    rc = retry_after_of("120", 1, &sec);
    wc_SetTimeCb(NULL);
    REQUIRE(rc == WOLFCERT_OK);
    REQUIRE(sec == 120);
    return 0;
}
#endif

/* The peer closes with no body at all. */
static int test_eof_empty_body_is_null(void)
{
    WolfCertHttpResponse resp = { 0 };
    Peer p = { 0 };

    REQUIRE(fetch(&p, RESP_EOF0, sizeof(RESP_EOF0), &resp) == WOLFCERT_OK);
    REQUIRE(resp.status_code == 200);
    REQUIRE(resp.body == NULL && resp.body_len == 0);
    wolfcert_http_response_free(&resp);
    return 0;
}

/* One byte per read with a WANT_READ between, so parsing resumes inside
 * both the interim and the final header block. */
static int test_nb_interim_fragmented(void)
{
    WolfCertHttpResponse resp = { 0 };
    Peer p = { 0 };

    p.stall = 1;
    REQUIRE(nb_fetch_m(&p, "GET", RESP_INTERIM, 1, &resp) == WOLFCERT_OK);
    REQUIRE(resp.status_code == 200);
    REQUIRE(resp.body_len == 5 && memcmp(resp.body, "hello", 5) == 0);
    wolfcert_http_response_free(&resp);
    return 0;
}

static int test_nb_204_fragmented(void)
{
    WolfCertHttpResponse resp = { 0 };
    Peer p = { 0 };

    p.stall = 1;
    REQUIRE(nb_fetch_m(&p, "GET", RESP_204, 1, &resp) == WOLFCERT_OK);
    REQUIRE(resp.status_code == 204);
    REQUIRE(resp.body == NULL && resp.body_len == 0);
    wolfcert_http_response_free(&resp);
    return 0;
}

/* A stale 500 in the same read as a 204 or a chunked body leaves that reply
 * intact but closes the session: the next request gets
 * WOLFCERT_ERR_CONN_CLOSED with a message. */
static int test_session_closes_on_bytes_past_body(void)
{
    static const char* const first[] = { RESP_204, RESP_CHUNKED };
    static const int first_status[]  = { 204, 200 };
    WolfCertHttpRequest req = { .method = "GET", .url = "http://peer.test/" };
    WolfCertHttpResponse resp = { 0 };
    WolfCertHttpSession* s = NULL;
    Peer p = { 0 };
    char wire[512];
    size_t i;

    for (i = 0; i < sizeof(first) / sizeof(first[0]); i++) {
        snprintf(wire, sizeof(wire), "%s" STALE_500, first[i]);
        memset(&p, 0, sizeof(p));
        p.resp    = wire;
        p.chunk   = strlen(wire);
        p.open_rc = WOLFCERT_ERR_IO;

        REQUIRE(open_scoped(&p, &s) == WOLFCERT_OK);
        REQUIRE(wolfcert_http_session_request(s, &req, &resp) == WOLFCERT_OK);
        REQUIRE(resp.status_code == first_status[i]);
        wolfcert_http_response_free(&resp);

        wolfcert_clear_error();
        REQUIRE(wolfcert_http_session_request(s, &req, &resp)
                == WOLFCERT_ERR_CONN_CLOSED);
        REQUIRE(strstr(wolfcert_last_error_message(), "closed") != NULL);
        wolfcert_http_session_close(s);
    }

    return 0;
}

/* Two chunked replies on one non-blocking session, one byte per read with a
 * WANT_READ between: "hello world", then a shorter "abc". */
static int test_nb_chunked_fragmented(void)
{
    WolfCertHttpSessionCfg cfg = { .base_url = "http://peer.test/" };
    WolfCertTransport t = { p_connect, p_read, p_write, p_disconnect, NULL };
    WolfCertHttpRequest req = { .method = "GET", .url = "http://peer.test/" };
    WolfCertHttpResponse resp = { 0 };
    WolfCertHttpSession* s = NULL;
    Peer p = { 0 };

    t.ctx = &p;
    p.chunk   = 1;
    p.stall   = 1;
    p.open_rc = WOLFCERT_ERR_WANT_READ;
    cfg.transport   = t;

    REQUIRE(wolfcert_http_session_open(&cfg, &s) == WOLFCERT_OK);

    p.resp = RESP_CHUNKED;
    REQUIRE(drive_nb(s, &req, &resp) == WOLFCERT_OK);
    REQUIRE(resp.status_code == 200);
    REQUIRE(resp.body_len == 11 && memcmp(resp.body, "hello world", 11) == 0);
    wolfcert_http_response_free(&resp);

    p.resp = RESP_CHUNKED_SHORT;
    p.off  = 0;
    REQUIRE(drive_nb(s, &req, &resp) == WOLFCERT_OK);
    REQUIRE(resp.body_len == 3 && memcmp(resp.body, "abc", 3) == 0);
    wolfcert_http_response_free(&resp);

    wolfcert_http_session_close(s);
    return 0;
}

/* An _nb GET waits on WANT_READ with a 0 timeout. A blocking call, or an _nb
 * call with another resp, gets BAD_ARG; the _nb GET then completes, and the
 * next GET on the session runs blocking with a -1 timeout. */
static int test_in_flight_request(void)
{
    WolfCertHttpSessionCfg cfg = { .base_url = "http://peer.test/" };
    WolfCertTransport t = { p_connect, p_read, p_write, p_disconnect, NULL };
    WolfCertHttpRequest req = { .method = "GET", .url = "http://peer.test/" };
    WolfCertHttpResponse resp = { 0 };
    WolfCertHttpResponse other = { 0 };
    WolfCertHttpSession* s = NULL;
    Peer p = { 0 };

    t.ctx = &p;
    p.resp    = RESP_CL;
    p.chunk   = sizeof(RESP_CL);
    p.open_rc = WOLFCERT_ERR_WANT_READ;
    p.stall   = 1;
    cfg.transport   = t;

    REQUIRE(wolfcert_http_session_open(&cfg, &s) == WOLFCERT_OK);
    REQUIRE(wolfcert_http_session_request_nb(s, &req, &resp)
            == WOLFCERT_ERR_WANT_READ);
    REQUIRE(p.read_timeout == 0);

    REQUIRE(wolfcert_http_session_request_nb(s, &req, &other)
            == WOLFCERT_ERR_BAD_ARG);
    REQUIRE(wolfcert_http_session_request(s, &req, &resp)
            == WOLFCERT_ERR_BAD_ARG);
    REQUIRE(other.body == NULL && other.status_code == 0);

    p.stall = 0;
    REQUIRE(drive_nb(s, &req, &resp) == WOLFCERT_OK);
    REQUIRE(resp.status_code == 200);
    REQUIRE(resp.body_len == 5 && memcmp(resp.body, "hello", 5) == 0);
    wolfcert_http_response_free(&resp);

    p.resp = RESP_CL;
    p.off  = 0;
    REQUIRE(wolfcert_http_session_request(s, &req, &resp) == WOLFCERT_OK);
    REQUIRE(p.read_timeout == -1);
    REQUIRE(resp.body_len == 5 && memcmp(resp.body, "hello", 5) == 0);
    wolfcert_http_response_free(&resp);
    wolfcert_http_session_close(s);
    return 0;
}

/* A WANT_READ reaching a blocking session request is ERR_IO and closes the
 * session, so the next request gets CONN_CLOSED. */
static int test_blocking_want_read_is_io(void)
{
    WolfCertHttpRequest req = { .method = "GET", .url = "http://peer.test/" };
    WolfCertHttpResponse resp = { 0 };
    WolfCertHttpSession* s = NULL;
    Peer p = { 0 };

    p.resp  = RESP_CL;
    p.chunk = sizeof(RESP_CL);
    p.stall = 1;

    REQUIRE(open_scoped(&p, &s) == WOLFCERT_OK);
    wolfcert_clear_error();
    REQUIRE(wolfcert_http_session_request(s, &req, &resp) == WOLFCERT_ERR_IO);
    REQUIRE(strstr(wolfcert_last_error_message(), "WANT_READ") != NULL);
    REQUIRE(wolfcert_http_session_request(s, &req, &resp)
            == WOLFCERT_ERR_CONN_CLOSED);
    wolfcert_http_session_close(s);
    return 0;
}

/* A body that ends at the close gives "bye" and closes the blocking session,
 * so the next request gets CONN_CLOSED. */
static int test_blocking_eof_body_closes(void)
{
    WolfCertHttpRequest req = { .method = "GET", .url = "http://peer.test/" };
    WolfCertHttpResponse resp = { 0 };
    WolfCertHttpSession* s = NULL;
    Peer p = { 0 };

    p.resp  = RESP_EOF;
    p.chunk = sizeof(RESP_EOF);

    REQUIRE(open_scoped(&p, &s) == WOLFCERT_OK);
    REQUIRE(wolfcert_http_session_request(s, &req, &resp) == WOLFCERT_OK);
    REQUIRE(resp.body_len == 3 && memcmp(resp.body, "bye", 3) == 0);
    wolfcert_http_response_free(&resp);
    REQUIRE(wolfcert_http_session_request(s, &req, &resp)
            == WOLFCERT_ERR_CONN_CLOSED);
    wolfcert_http_session_close(s);
    return 0;
}

#ifdef WOLFCERT_HAVE_BUILTIN_TRANSPORT
/* A zeroed transport reaches the built-in one and fails at connect. */
static int test_zero_transport_takes_builtin(void)
{
    WolfCertHttpRequest req = { .method = "GET", .url = "http://127.0.0.1:1/" };
    WolfCertHttpResponse resp = { 0 };
    int rc;

    req.timeout_ms = 500;
    rc = wolfcert_http_request(&req, &resp);
    REQUIRE(rc != WOLFCERT_OK);
    REQUIRE(rc != WOLFCERT_ERR_BAD_ARG);
    return 0;
}
#endif

static int test_incomplete_vtable(void)
{
    WolfCertHttpResponse resp = { 0 };
    Peer p = { 0 };
    WolfCertTransport no_disc = { p_connect, p_read, p_write, NULL, &p };
    WolfCertHttpRequest req = { .method = "GET", .url = "http://peer.test/" };

    req.transport = no_disc;
    REQUIRE(wolfcert_http_request(&req, &resp) == WOLFCERT_ERR_BAD_ARG);
    REQUIRE(p.connects == 0);
    return 0;
}

static int test_no_fd(void)
{
    WolfCertTransport t = { p_connect, p_read, p_write, p_disconnect, NULL };
    WolfCertHttpSessionCfg cfg = { .base_url = "http://peer.test/" };
    WolfCertHttpSession* s = NULL;
    Peer p = { 0 };

    t.ctx = &p;
    p.resp = RESP_CL;
    p.chunk = sizeof(RESP_CL);
    cfg.transport = t;

    REQUIRE(wolfcert_http_session_open(&cfg, &s) == WOLFCERT_OK);
    REQUIRE(wolfcert_http_session_fd(s) == -1);
    wolfcert_http_session_close(s);
    REQUIRE(p.disconnects == 1);
    return 0;
}

#ifndef WOLFCERT_HAVE_BUILTIN_TRANSPORT
static int test_no_builtin_transport(void)
{
    WolfCertHttpRequest req = { .method = "GET", .url = "http://peer.test/" };
    WolfCertHttpSessionCfg cfg = { .base_url = "http://peer.test/" };
    WolfCertHttpResponse resp = { 0 };
    WolfCertHttpSession* s = NULL;

    REQUIRE(wolfcert_http_request(&req, &resp) == WOLFCERT_ERR_BAD_ARG);
    REQUIRE(wolfcert_http_session_open(&cfg, &s) == WOLFCERT_ERR_BAD_ARG);
    REQUIRE(s == NULL);
    return 0;
}
#endif

int main(void)
{
    REQUIRE(test_static_mem_init() == 0);
    REQUIRE(wolfcert_init(test_heap_hint()) == WOLFCERT_OK);
    if (test_roundtrip())
        return 1;
    if (test_byte_at_a_time())
        return 1;
    if (test_body_ends_at_close())
        return 1;
    if (test_truncated_reply_is_io())
        return 1;
    if (test_header_block_over_budget())
        return 1;
    if (test_eof_body_capped())
        return 1;
#if defined(WOLFSSL_STATIC_MEMORY) && defined(WOLFSSL_NO_MALLOC)
    if (test_chunked_over_pool_block())
        return 1;
#endif
    if (test_zero_is_not_data())
        return 1;
    if (test_read_overcount_rejected())
        return 1;
    if (test_error_paths())
        return 1;
    if (test_positive_connect_rc())
        return 1;
    if (test_transport_is_copied())
        return 1;
    if (test_partial_vtable_rejected())
        return 1;
    if (test_empty_body_is_null())
        return 1;
    if (test_204_no_body())
        return 1;
    if (test_304_no_body())
        return 1;
    if (test_no_body_ignores_chunked())
        return 1;
    if (test_204_keeps_retry_after())
        return 1;
    if (test_head_ignores_content_length())
        return 1;
    if (test_lowercase_head_is_not_head())
        return 1;
    if (test_interim_then_final())
        return 1;
    if (test_interim_headers_discarded())
        return 1;
    if (test_short_final_after_long_interim())
        return 1;
    if (test_interim_at_cap_accepted())
        return 1;
    if (test_interim_flood_rejected())
        return 1;
    if (test_switching_protocols_rejected())
        return 1;
    if (test_retry_after_delay_seconds())
        return 1;
#ifndef NO_ASN_TIME
    if (test_retry_after_http_date())
        return 1;
    if (test_retry_after_unset_clock())
        return 1;
#endif
    if (test_eof_empty_body_is_null())
        return 1;
    if (test_nb_interim_fragmented())
        return 1;
    if (test_nb_204_fragmented())
        return 1;
    if (test_nb_chunked_fragmented())
        return 1;
    if (test_in_flight_request())
        return 1;
    if (test_blocking_want_read_is_io())
        return 1;
    if (test_blocking_eof_body_closes())
        return 1;
    if (test_head_oversized_length_ok())
        return 1;
    if (test_session_closes_on_bytes_past_body())
        return 1;
#ifdef WOLFCERT_HAVE_BUILTIN_TRANSPORT
    if (test_zero_transport_takes_builtin())
        return 1;
#endif
    if (test_incomplete_vtable())
        return 1;
    if (test_no_fd())
        return 1;
#ifndef WOLFCERT_HAVE_BUILTIN_TRANSPORT
    if (test_no_builtin_transport())
        return 1;
#endif
    wolfcert_cleanup();
    printf("OK\n");
    return 0;
}
