/* wolfCert - client-side certificate lifecycle management
 *
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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

/*
 * A caller-supplied WolfCertTransport drives the whole HTTP path with no
 * socket, so these run on every target. Coverage: handle 0 is valid,
 * disconnect runs exactly once, an incomplete vtable is rejected, the parser
 * survives a byte-at-a-time feed, a body may end at CONN_CLOSED, and a build
 * with no built-in transport refuses a config that supplies none.
 */

#include <wolfcert/wolfcert.h>
#include <wolfcert/http.h>
#include "../test_static_mem.h"

#include <stdio.h>
#include <string.h>

#define REQUIRE(cond) \
    do {                                                                    \
        if (!(cond)) {                                                      \
            fprintf(stderr, "FAIL %s:%d %s\n", __FILE__, __LINE__, #cond);  \
            return 1;                                                       \
        }                                                                   \
    } while (0)

/* Scripted peer: hands back `resp` in `chunk`-sized pieces, then reports the
 * close. handle 0 is deliberate - a wolfIP descriptor starts there. */
typedef struct {
    const char* resp;
    size_t      off;
    size_t      chunk;
    int         connects;
    int         disconnects;
    int         zero_eof;   /* report EOF as 0, breaking the contract */
    int         fail_connect;
    int         fail_write;
} Peer;

static int p_connect(void* ctx, const char* host, int port, int timeout_ms,
                     void** conn)
{
    Peer* p = (Peer*)ctx;

    (void)host; (void)port; (void)timeout_ms;
    if (p->fail_connect)
        return WOLFCERT_ERR_IO;
    p->connects++;
    *conn = (void*)0;
    return WOLFCERT_OK;
}

static int p_read(void* ctx, void* conn, uint8_t* buf, size_t len,
                  int timeout_ms)
{
    Peer*  p = (Peer*)ctx;
    size_t n = strlen(p->resp) - p->off;

    (void)conn; (void)timeout_ms;
    if (n == 0)
        return p->zero_eof ? 0 : WOLFCERT_ERR_CONN_CLOSED;
    if (n > len)
        n = len;
    if (n > p->chunk)
        n = p->chunk;

    memcpy(buf, p->resp + p->off, n);
    p->off += n;
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

static int fetch(Peer* p, const char* resp, size_t chunk,
                 WolfCertHttpResponse* out)
{
    WolfCertTransport t = { p_connect, p_read, p_write, p_disconnect, p };
    WolfCertHttpRequest req = { .method = "GET", .url = "http://peer.test/" };

    p->resp = resp;
    p->off = 0;
    p->chunk = chunk;
    req.transport = &t;

    return wolfcert_http_request(&req, out);
}

static const char RESP_CL[] =
    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
    "Content-Length: 5\r\n\r\nhello";
static const char RESP_EOF[] =
    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nbye";

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

/* One byte per read splits the status line, the headers and the body across
 * calls, which is what a real stack does under load. */
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

/* No Content-Length and no chunking: the body ends at CONN_CLOSED. */
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

/* read() must never return 0, but a transport wrapping recv() is one line
 * away from doing so. wolfCert maps it to a close rather than looping. */
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

/* disconnect runs exactly once per successful connect, and never for one
 * that failed. */
static int test_error_paths(void)
{
    WolfCertTransport t = { p_connect, p_read, p_write, p_disconnect, NULL };
    WolfCertHttpRequest req = { .method = "GET", .url = "http://peer.test/" };
    WolfCertHttpResponse resp = { 0 };
    Peer p = { 0 };

    t.ctx = &p;
    req.transport = &t;

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

static int test_incomplete_vtable(void)
{
    WolfCertHttpResponse resp = { 0 };
    Peer p = { 0 };
    WolfCertTransport no_disc = { p_connect, p_read, p_write, NULL, &p };
    WolfCertHttpRequest req = { .method = "GET", .url = "http://peer.test/" };

    req.transport = &no_disc;
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
    cfg.transport = &t;

    REQUIRE(wolfcert_http_session_open(&cfg, &s) == WOLFCERT_OK);
    /* Nothing pollable exists, so the accessor must say so. */
    REQUIRE(wolfcert_http_session_fd(s) == -1);
    wolfcert_http_session_close(s);
    REQUIRE(p.disconnects == 1);
    return 0;
}

#ifndef WOLFCERT_HAVE_BUILTIN_TRANSPORT
/* Nothing can be dialled when the config names no transport and the build
 * carries no built-in one, so both entry points must refuse it. */
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
    REQUIRE(wolfcert_init(NULL) == WOLFCERT_OK);
    if (test_roundtrip())
        return 1;
    if (test_byte_at_a_time())
        return 1;
    if (test_body_ends_at_close())
        return 1;
    if (test_zero_is_not_data())
        return 1;
    if (test_error_paths())
        return 1;
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
