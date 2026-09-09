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
#define _DARWIN_C_SOURCE   /* expose memmem/strcasestr/INADDR_LOOPBACK on macOS */

#include <wolfcert/wolfcert.h>
#include "internal.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define REQUIRE(cond) \
    do {                                                                    \
        if (!(cond)) {                                                      \
            fprintf(stderr, "FAIL %s:%d %s\n", __FILE__, __LINE__, #cond);  \
            return 1;                                                       \
        }                                                                   \
    } while (0)

#ifndef WOLFCERT_HAVE_BUILTIN_TRANSPORT
/* Nothing below can open a socket in a build with no built-in transport. */
int main(void)
{
    return 77;
}
#else

static int test_url_parser(void)
{
    WolfCertUrl u;
    REQUIRE(wolfcert_http_url_parse("https://ca.example.com/.well-known/est/cacerts", &u, NULL) == WOLFCERT_OK);
    REQUIRE(strcmp(u.scheme, "https") == 0);
    REQUIRE(strcmp(u.host, "ca.example.com") == 0);
    REQUIRE(u.port == 443);
    REQUIRE(strcmp(u.path, "/.well-known/est/cacerts") == 0);
    REQUIRE(u.tls == 1);
    wolfcert_http_url_free(&u);

    REQUIRE(wolfcert_http_url_parse("http://localhost:8080/scep", &u, NULL) == WOLFCERT_OK);
    REQUIRE(u.port == 8080);
    wolfcert_http_url_free(&u);

    REQUIRE(wolfcert_http_url_parse("http://host", &u, NULL) == WOLFCERT_OK);
    REQUIRE(strcmp(u.path, "/") == 0);
    wolfcert_http_url_free(&u);

    REQUIRE(wolfcert_http_url_parse("https://[::1]:8443/p", &u, NULL) == WOLFCERT_OK);
    REQUIRE(strcmp(u.host, "::1") == 0);
    REQUIRE(u.port == 8443);
    wolfcert_http_url_free(&u);

    REQUIRE(wolfcert_http_url_parse("ftp://nope/", &u, NULL) == WOLFCERT_ERR_UNSUPPORTED);

    /* A pathless URL carrying a query: SCEP builds exactly this shape. The
     * query must not be absorbed into the host, and the request target has to
     * keep a leading slash. */
    REQUIRE(wolfcert_http_url_parse("http://ca.example?operation=GetCACaps", &u, NULL) == WOLFCERT_OK);
    REQUIRE(strcmp(u.host, "ca.example") == 0);
    REQUIRE(u.port == 80);
    REQUIRE(strcmp(u.path, "/?operation=GetCACaps") == 0);
    wolfcert_http_url_free(&u);

    REQUIRE(wolfcert_http_url_parse("http://ca.example:8080?operation=PKIOperation", &u, NULL) == WOLFCERT_OK);
    REQUIRE(strcmp(u.host, "ca.example") == 0);
    REQUIRE(u.port == 8080);
    REQUIRE(strcmp(u.path, "/?operation=PKIOperation") == 0);
    wolfcert_http_url_free(&u);

    REQUIRE(wolfcert_http_url_parse("https://[::1]?operation=GetCACaps", &u, NULL) == WOLFCERT_OK);
    REQUIRE(strcmp(u.host, "::1") == 0);
    REQUIRE(u.port == 443);
    REQUIRE(strcmp(u.path, "/?operation=GetCACaps") == 0);
    wolfcert_http_url_free(&u);

    /* RFC 7230 section 5.3: the fragment is client-side only, so it must not
     * reach the request target. */
    REQUIRE(wolfcert_http_url_parse("http://ca.example#frag", &u, NULL) == WOLFCERT_OK);
    REQUIRE(strcmp(u.host, "ca.example") == 0);
    REQUIRE(strcmp(u.path, "/") == 0);
    wolfcert_http_url_free(&u);

    REQUIRE(wolfcert_http_url_parse("http://ca.example/p#frag", &u, NULL) == WOLFCERT_OK);
    REQUIRE(strcmp(u.host, "ca.example") == 0);
    REQUIRE(strcmp(u.path, "/p") == 0);
    wolfcert_http_url_free(&u);

    REQUIRE(wolfcert_http_url_parse("http://ca.example/p?q=1#frag", &u, NULL) == WOLFCERT_OK);
    REQUIRE(strcmp(u.path, "/p?q=1") == 0);
    wolfcert_http_url_free(&u);

    /* A URL with no explicit scheme defaults to TLS (https). */
    REQUIRE(wolfcert_http_url_parse("ca.example.com:8443/p", &u, NULL) == WOLFCERT_OK);
    REQUIRE(strcmp(u.scheme, "https") == 0);
    REQUIRE(strcmp(u.host, "ca.example.com") == 0);
    REQUIRE(u.port == 8443);
    REQUIRE(u.tls == 1);
    wolfcert_http_url_free(&u);
    return 0;
}

/* wolfcert_http_url_origin: default-port omission, non-default port, and the
 * BAD_ARG guard - the helper is shared by the EST and SCEP session opens. */
static int test_url_origin(void)
{
    WolfCertUrl u;
    char* origin = NULL;

    /* Default ports (https:443, http:80) are omitted. */
    REQUIRE(wolfcert_http_url_parse("https://ca.example.com/scep", &u, NULL) == WOLFCERT_OK);
    REQUIRE(wolfcert_http_url_origin(&u, NULL, &origin) == WOLFCERT_OK);
    REQUIRE(strcmp(origin, "https://ca.example.com") == 0);
    WOLFCERT_XFREE(origin, NULL); origin = NULL;
    wolfcert_http_url_free(&u);

    REQUIRE(wolfcert_http_url_parse("http://host.example/x", &u, NULL) == WOLFCERT_OK);
    REQUIRE(wolfcert_http_url_origin(&u, NULL, &origin) == WOLFCERT_OK);
    REQUIRE(strcmp(origin, "http://host.example") == 0);
    WOLFCERT_XFREE(origin, NULL); origin = NULL;
    wolfcert_http_url_free(&u);

    /* A non-default port is included. */
    REQUIRE(wolfcert_http_url_parse("http://host.example:8080/x", &u, NULL) == WOLFCERT_OK);
    REQUIRE(wolfcert_http_url_origin(&u, NULL, &origin) == WOLFCERT_OK);
    REQUIRE(strcmp(origin, "http://host.example:8080") == 0);
    WOLFCERT_XFREE(origin, NULL); origin = NULL;
    wolfcert_http_url_free(&u);

    /* An IPv6 literal is re-bracketed, so parse -> origin -> parse round-trips
     * instead of collapsing into an unparsable "https://::1:8443". */
    REQUIRE(wolfcert_http_url_parse("https://[::1]:8443/p", &u, NULL) == WOLFCERT_OK);
    REQUIRE(wolfcert_http_url_origin(&u, NULL, &origin) == WOLFCERT_OK);
    REQUIRE(strcmp(origin, "https://[::1]:8443") == 0);
    wolfcert_http_url_free(&u);
    REQUIRE(wolfcert_http_url_parse(origin, &u, NULL) == WOLFCERT_OK);
    REQUIRE(strcmp(u.host, "::1") == 0);
    REQUIRE(u.port == 8443);
    WOLFCERT_XFREE(origin, NULL); origin = NULL;
    wolfcert_http_url_free(&u);

    /* Same for the default port, where no ":port" suffix follows the host. */
    REQUIRE(wolfcert_http_url_parse("https://[2001:db8::1]/p", &u, NULL) == WOLFCERT_OK);
    REQUIRE(wolfcert_http_url_origin(&u, NULL, &origin) == WOLFCERT_OK);
    REQUIRE(strcmp(origin, "https://[2001:db8::1]") == 0);
    wolfcert_http_url_free(&u);
    REQUIRE(wolfcert_http_url_parse(origin, &u, NULL) == WOLFCERT_OK);
    REQUIRE(strcmp(u.host, "2001:db8::1") == 0);
    REQUIRE(u.port == 443);
    WOLFCERT_XFREE(origin, NULL); origin = NULL;
    wolfcert_http_url_free(&u);

    /* NULL url and NULL out are rejected. */
    REQUIRE(wolfcert_http_url_origin(NULL, NULL, &origin) == WOLFCERT_ERR_BAD_ARG);
    REQUIRE(wolfcert_http_url_parse("https://h/x", &u, NULL) == WOLFCERT_OK);
    REQUIRE(wolfcert_http_url_origin(&u, NULL, NULL) == WOLFCERT_ERR_BAD_ARG);
    wolfcert_http_url_free(&u);

    return 0;
}

struct srv_ctx { int listen_fd; };

/* Bind a loopback listener and report the ephemeral port it landed on.
 * Callers run this before spawning the responder thread, so the port never
 * has to travel back across the thread boundary. */
static int listen_loopback(int* port)
{
    int ls = socket(AF_INET, SOCK_STREAM, 0);
    if (ls < 0)
        return -1;
    int yes = 1;
    setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    struct sockaddr_in sa = { .sin_family = AF_INET, .sin_port = htons(0),
                              .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    if (bind(ls, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
        close(ls);
        return -1;
    }
    if (listen(ls, 1) < 0) {
        close(ls);
        return -1;
    }
    socklen_t slen = sizeof(sa);
    if (getsockname(ls, (struct sockaddr*)&sa, &slen) < 0) {
        close(ls);
        return -1;
    }
    *port = ntohs(sa.sin_port);
    return ls;
}

/* Same on ::1. Returns -1 when the host has no IPv6 loopback, which the
 * callers treat as "skip" rather than "fail". */
static int listen_loopback6(int* port)
{
    struct sockaddr_in6 sa;
    socklen_t slen = sizeof(sa);
    int yes = 1;
    int ls = socket(AF_INET6, SOCK_STREAM, 0);

    if (ls < 0)
        return -1;

    setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    memset(&sa, 0, sizeof(sa));
    sa.sin6_family = AF_INET6;
    sa.sin6_port   = htons(0);
    sa.sin6_addr   = in6addr_loopback;
    if (bind(ls, (struct sockaddr*)&sa, sizeof(sa)) < 0 || listen(ls, 1) < 0 ||
            getsockname(ls, (struct sockaddr*)&sa, &slen) < 0) {
        close(ls);
        return -1;
    }

    *port = ntohs(sa.sin6_port);
    return ls;
}

static void* srv_thread(void* arg)
{
    struct srv_ctx* sc = (struct srv_ctx*)arg;
    int cs = accept(sc->listen_fd, NULL, NULL);
    close(sc->listen_fd);
    if (cs < 0)
        return NULL;

    char buf[4096];
    size_t n = 0;
    while (n < sizeof(buf) - 1) {
        ssize_t r = recv(cs, buf + n, sizeof(buf) - 1 - n, 0);
        if (r <= 0)
            break;
        n += (size_t)r;
        buf[n] = '\0';
        if (strstr(buf, "\r\n\r\n") != NULL)
            break;
    }

    const char* response =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/plain\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Connection: close\r\n"
        "\r\n"
        "6\r\nhello \r\n"
        "9\r\nwolfCert\n\r\n"
        "0\r\n\r\n";
    send(cs, response, strlen(response), 0);
    shutdown(cs, SHUT_WR);
    close(cs);
    return NULL;
}

static int test_loopback_http(void)
{
    struct srv_ctx sc = { 0 };
    pthread_t tid;
    int port = 0;
    sc.listen_fd = listen_loopback(&port);
    REQUIRE(sc.listen_fd >= 0);
    REQUIRE(pthread_create(&tid, NULL, srv_thread, &sc) == 0);

    char url[128];
    snprintf(url, sizeof(url), "http://127.0.0.1:%d/test", port);
    const char* body = "ping";
    WolfCertHttpRequest req = {
        .method = "POST", .url = url,
        .content_type = "application/octet-stream",
        .body = (const uint8_t*)body, .body_len = strlen(body),
        .basic_user = "alice", .basic_pass = "secret",
    };
    WolfCertHttpResponse resp = { 0 };
    REQUIRE(wolfcert_http_request(&req, &resp) == WOLFCERT_OK);
    REQUIRE(resp.status_code == 200);
    REQUIRE(resp.body_len == 15);
    REQUIRE(memcmp(resp.body, "hello wolfCert\n", 15) == 0);
    wolfcert_http_response_free(&resp);
    pthread_join(tid, NULL);
    return 0;
}

/* Keep-alive server: answers two requests on one connection. The first
 * response carries Retry-After, the second does not. */
static void* srv_retry_thread(void* arg)
{
    struct srv_ctx* sc = (struct srv_ctx*)arg;
    int cs = accept(sc->listen_fd, NULL, NULL);
    close(sc->listen_fd);
    if (cs < 0)
        return NULL;

    const char* responses[2] = {
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/plain\r\n"
        "Content-Length: 5\r\n"
        "Retry-After: 30\r\n"
        "\r\n"
        "first",
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/plain\r\n"
        "Content-Length: 6\r\n"
        "\r\n"
        "second"
    };

    char buf[4096];
    int reqno;
    for (reqno = 0; reqno < 2; ++reqno) {
        size_t n = 0;
        while (n < sizeof(buf) - 1) {
            ssize_t r = recv(cs, buf + n, sizeof(buf) - 1 - n, 0);
            if (r <= 0)
                break;
            n += (size_t)r;
            buf[n] = '\0';
            if (strstr(buf, "\r\n\r\n") != NULL)
                break;
        }
        send(cs, responses[reqno], strlen(responses[reqno]), 0);
    }

    shutdown(cs, SHUT_WR);
    close(cs);
    return NULL;
}

/* Emit a chunked response whose second chunk-size line is a 16-digit
 * value (0xFFFFFFFFFFFFFFFF). A decoder that parses the size without
 * bounding it wraps its arithmetic and memcpy's a wild length, so this
 * server response is what an on-path attacker would inject to crash a
 * blocking EST/SCEP client. */
static void* srv_thread_overflow(void* arg)
{
    struct srv_ctx* sc = (struct srv_ctx*)arg;
    int cs = accept(sc->listen_fd, NULL, NULL);
    close(sc->listen_fd);
    if (cs < 0)
        return NULL;

    char buf[4096];
    size_t n = 0;
    while (n < sizeof(buf) - 1) {
        ssize_t r = recv(cs, buf + n, sizeof(buf) - 1 - n, 0);
        if (r <= 0)
            break;
        n += (size_t)r;
        buf[n] = '\0';
        if (strstr(buf, "\r\n\r\n") != NULL)
            break;
    }

    const char* response =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/plain\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Connection: close\r\n"
        "\r\n"
        "1\r\nA\r\n"
        "FFFFFFFFFFFFFFFF\r\nXXXX\r\n"
        "0\r\n\r\n";
    send(cs, response, strlen(response), 0);
    shutdown(cs, SHUT_WR);
    close(cs);
    return NULL;
}

static int drive_nb(WolfCertHttpSession* s, const WolfCertHttpRequest* req,
                    WolfCertHttpResponse* resp)
{
    int fd = wolfcert_http_session_fd(s);
    struct pollfd pfd;
    for (;;) {
        int rc = wolfcert_http_session_request_nb(s, req, resp);
        if (rc == WOLFCERT_ERR_WANT_READ) {
            pfd.fd = fd;
            pfd.events = POLLIN;
            poll(&pfd, 1, 2000);
            continue;
        }
        if (rc == WOLFCERT_ERR_WANT_WRITE) {
            pfd.fd = fd;
            pfd.events = POLLOUT;
            poll(&pfd, 1, 2000);
            continue;
        }
        return rc;
    }
}

/* A non-blocking session reused across requests must not carry a stale
 * Retry-After from an earlier response into a later one. */
static int test_session_retry_after_reset(void)
{
    struct srv_ctx sc = { 0 };
    pthread_t tid;
    int port = 0;
    sc.listen_fd = listen_loopback(&port);
    REQUIRE(sc.listen_fd >= 0);
    REQUIRE(pthread_create(&tid, NULL, srv_retry_thread, &sc) == 0);

    char base[128];
    char url[160];
    snprintf(base, sizeof(base), "http://127.0.0.1:%d", port);
    snprintf(url, sizeof(url), "http://127.0.0.1:%d/test", port);

    WolfCertHttpSessionCfg cfg = {
        .base_url = base,
        .nonblocking = 1,
    };
    WolfCertHttpSession* s = NULL;
    REQUIRE(wolfcert_http_session_open(&cfg, &s) == WOLFCERT_OK);

    WolfCertHttpRequest req = { .method = "GET", .url = url };

    WolfCertHttpResponse resp1 = { 0 };
    REQUIRE(drive_nb(s, &req, &resp1) == WOLFCERT_OK);
    REQUIRE(resp1.status_code == 200);
    REQUIRE(resp1.retry_after_sec == 30);
    wolfcert_http_response_free(&resp1);

    WolfCertHttpResponse resp2 = { 0 };
    REQUIRE(drive_nb(s, &req, &resp2) == WOLFCERT_OK);
    REQUIRE(resp2.status_code == 200);
    REQUIRE(resp2.retry_after_sec == 0);
    wolfcert_http_response_free(&resp2);

    wolfcert_http_session_close(s);
    pthread_join(tid, NULL);
    return 0;
}

static int test_chunked_size_overflow(void)
{
    struct srv_ctx sc = { 0 };
    pthread_t tid;
    int port = 0;
    sc.listen_fd = listen_loopback(&port);
    REQUIRE(sc.listen_fd >= 0);
    REQUIRE(pthread_create(&tid, NULL, srv_thread_overflow, &sc) == 0);

    char url[128];
    snprintf(url, sizeof(url), "http://127.0.0.1:%d/test", port);
    const char* body = "ping";
    WolfCertHttpRequest req = {
        .method = "POST", .url = url,
        .content_type = "application/octet-stream",
        .body = (const uint8_t*)body, .body_len = strlen(body),
    };
    WolfCertHttpResponse resp = { 0 };
    /* The oversized chunk-size line must be rejected as a protocol error,
     * not memcpy'd with a wrapped length. */
    REQUIRE(wolfcert_http_request(&req, &resp) == WOLFCERT_ERR_PROTOCOL);
    REQUIRE(resp.body == NULL);
    REQUIRE(resp.body_len == 0);
    wolfcert_http_response_free(&resp);
    pthread_join(tid, NULL);
    return 0;
}

/* Size the reply to land exactly on the reader's accumulator allowance: a legal
 * response the blocking reader accepts, with less than one read quantum of
 * headroom left at the end. */
#define NEAR_CAP_MAX_BODY 1024
#define NEAR_CAP_TOTAL    (NEAR_CAP_MAX_BODY + WOLFCERT_HTTP_HEADER_BUDGET)
/* The reply is built as head + pad + tail; too small a budget underflows the
 * unsigned pad and memsets past the buffer. */
#if NEAR_CAP_TOTAL < 256
#error "test_session_near_cap_response needs WOLFCERT_HTTP_HEADER_BUDGET >= 256"
#endif

static void* srv_thread_near_cap(void* arg)
{
    struct srv_ctx* sc = (struct srv_ctx*)arg;
    int cs = accept(sc->listen_fd, NULL, NULL);
    close(sc->listen_fd);
    if (cs < 0)
        return NULL;

    char buf[4096];
    size_t n = 0;
    while (n < sizeof(buf) - 1) {
        ssize_t r = recv(cs, buf + n, sizeof(buf) - 1 - n, 0);
        if (r <= 0)
            break;
        n += (size_t)r;
        buf[n] = '\0';
        if (strstr(buf, "\r\n\r\n") != NULL)
            break;
    }

    const char* head =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/plain\r\n"
        "Content-Length: 5\r\n"
        "X-Pad: ";
    const char* tail = "\r\n\r\nready";
    size_t pad = NEAR_CAP_TOTAL - strlen(head) - strlen(tail);

    char response[NEAR_CAP_TOTAL];
    memcpy(response, head, strlen(head));
    memset(response + strlen(head), 'A', pad);
    memcpy(response + strlen(head) + pad, tail, strlen(tail));

    size_t off = 0;
    while (off < sizeof(response)) {
        ssize_t w = send(cs, response + off, sizeof(response) - off, 0);
        if (w <= 0)
            break;
        off += (size_t)w;
    }

    shutdown(cs, SHUT_WR);
    close(cs);
    return NULL;
}

/* A response whose total size stays within the configured allowance must be
 * accepted even when the reader is left with less than one read quantum of
 * headroom. */
static int test_session_near_cap_response(void)
{
    struct srv_ctx sc = { 0 };
    pthread_t tid;
    int port = 0;
    sc.listen_fd = listen_loopback(&port);
    REQUIRE(sc.listen_fd >= 0);
    REQUIRE(pthread_create(&tid, NULL, srv_thread_near_cap, &sc) == 0);

    char base[128];
    char url[160];
    snprintf(base, sizeof(base), "http://127.0.0.1:%d", port);
    snprintf(url, sizeof(url), "http://127.0.0.1:%d/test", port);

    WolfCertHttpSessionCfg cfg = {
        .base_url = base,
        .nonblocking = 1,
        .max_response_bytes = NEAR_CAP_MAX_BODY,
    };
    WolfCertHttpSession* s = NULL;
    REQUIRE(wolfcert_http_session_open(&cfg, &s) == WOLFCERT_OK);

    WolfCertHttpRequest req = { .method = "GET", .url = url };
    WolfCertHttpResponse resp = { 0 };
    REQUIRE(drive_nb(s, &req, &resp) == WOLFCERT_OK);
    REQUIRE(resp.status_code == 200);
    REQUIRE(resp.body_len == 5);
    REQUIRE(memcmp(resp.body, "ready", 5) == 0);
    wolfcert_http_response_free(&resp);

    wolfcert_http_session_close(s);
    pthread_join(tid, NULL);
    return 0;
}

static void* srv_thread_eof_cap(void* arg)
{
    struct srv_ctx* sc = (struct srv_ctx*)arg;
    int cs = accept(sc->listen_fd, NULL, NULL);
    close(sc->listen_fd);
    if (cs < 0)
        return NULL;

    char buf[4096];
    size_t n = 0;
    while (n < sizeof(buf) - 1) {
        ssize_t r = recv(cs, buf + n, sizeof(buf) - 1 - n, 0);
        if (r <= 0)
            break;
        n += (size_t)r;
        buf[n] = '\0';
        if (strstr(buf, "\r\n\r\n") != NULL)
            break;
    }

    /* No Content-Length and no chunking: the body runs to the close. */
    const char* head =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/plain\r\n"
        "Connection: close\r\n"
        "X-Pad: ";
    const char* tail = "\r\n\r\nready";
    size_t pad = NEAR_CAP_TOTAL - strlen(head) - strlen(tail);

    char response[NEAR_CAP_TOTAL];
    memcpy(response, head, strlen(head));
    memset(response + strlen(head), 'A', pad);
    memcpy(response + strlen(head) + pad, tail, strlen(tail));

    size_t off = 0;
    while (off < sizeof(response)) {
        ssize_t w = send(cs, response + off, sizeof(response) - off, 0);
        if (w <= 0)
            break;
        off += (size_t)w;
    }

    close(cs);
    return NULL;
}

/* An EOF-delimited response that fills the allowance exactly is complete: the
 * reader must look for the close rather than reject the full accumulator. */
static int test_session_eof_cap_response(void)
{
    struct srv_ctx sc = { 0 };
    pthread_t tid;
    int port = 0;
    sc.listen_fd = listen_loopback(&port);
    REQUIRE(sc.listen_fd >= 0);
    REQUIRE(pthread_create(&tid, NULL, srv_thread_eof_cap, &sc) == 0);

    char base[128];
    char url[160];
    snprintf(base, sizeof(base), "http://127.0.0.1:%d", port);
    snprintf(url, sizeof(url), "http://127.0.0.1:%d/test", port);

    WolfCertHttpSessionCfg cfg = {
        .base_url = base,
        .nonblocking = 1,
        .max_response_bytes = NEAR_CAP_MAX_BODY,
    };
    WolfCertHttpSession* s = NULL;
    REQUIRE(wolfcert_http_session_open(&cfg, &s) == WOLFCERT_OK);

    WolfCertHttpRequest req = { .method = "GET", .url = url };
    WolfCertHttpResponse resp = { 0 };
    REQUIRE(drive_nb(s, &req, &resp) == WOLFCERT_OK);
    REQUIRE(resp.status_code == 200);
    REQUIRE(resp.body_len >= 5);
    REQUIRE(memcmp(resp.body + resp.body_len - 5, "ready", 5) == 0);
    wolfcert_http_response_free(&resp);

    wolfcert_http_session_close(s);
    pthread_join(tid, NULL);
    return 0;
}

/* Capture the request headers a client sends so the test can inspect
 * which headers were emitted on the wire. */
struct capture_ctx {
    int  listen_fd;
    char request[4096];
};

static void* srv_thread_capture(void* arg)
{
    struct capture_ctx* cc = (struct capture_ctx*)arg;
    int cs = accept(cc->listen_fd, NULL, NULL);
    close(cc->listen_fd);
    if (cs < 0)
        return NULL;

    size_t n = 0;
    while (n < sizeof(cc->request) - 1) {
        ssize_t r = recv(cs, cc->request + n, sizeof(cc->request) - 1 - n, 0);
        if (r <= 0)
            break;
        n += (size_t)r;
        cc->request[n] = '\0';
        if (strstr(cc->request, "\r\n\r\n") != NULL)
            break;
    }

    const char* response =
        "HTTP/1.1 200 OK\r\n"
        "Content-Length: 0\r\n"
        "Connection: close\r\n"
        "\r\n";
    send(cs, response, strlen(response), 0);
    shutdown(cs, SHUT_WR);
    close(cs);
    return NULL;
}

/* RFC 7030 section 4.2.1: a base64-encoded enrollment body must be sent
 * with Content-Transfer-Encoding: base64 so the server decodes it. A
 * request that sets content_transfer_encoding must emit that header. */
static int test_request_transfer_encoding(void)
{
    struct capture_ctx cc = { 0 };
    pthread_t tid;
    int port = 0;
    cc.listen_fd = listen_loopback(&port);
    REQUIRE(cc.listen_fd >= 0);
    REQUIRE(pthread_create(&tid, NULL, srv_thread_capture, &cc) == 0);

    char url[128];
    snprintf(url, sizeof(url),
             "http://127.0.0.1:%d/.well-known/est/simpleenroll", port);
    const char* body = "Zm9vYmFy\r\n";
    WolfCertHttpRequest req = {
        .method = "POST", .url = url,
        .content_type = "application/pkcs10",
        .content_transfer_encoding = "base64",
        .body = (const uint8_t*)body, .body_len = strlen(body),
    };
    WolfCertHttpResponse resp = { 0 };
    REQUIRE(wolfcert_http_request(&req, &resp) == WOLFCERT_OK);
    REQUIRE(resp.status_code == 200);
    wolfcert_http_response_free(&resp);
    pthread_join(tid, NULL);

    REQUIRE(strstr(cc.request, "Content-Transfer-Encoding: base64") != NULL);
    return 0;
}

/* RFC 3986 section 3.2.2: an IPv6 literal stays bracketed in the Host header,
 * or a virtual-host match against "::1:8443" fails. Both request builders
 * carry their own copy of the bracketing, so drive each one. */
static int ipv6_host_header(int use_session)
{
    struct capture_ctx cc = { 0 };
    pthread_t tid;
    char base[128];
    char url[160];
    char expect[64];
    int port = 0;

    cc.listen_fd = listen_loopback6(&port);
    if (cc.listen_fd < 0) {
        printf("no IPv6 loopback, skipping Host-header check\n");
        return 0;
    }
    REQUIRE(pthread_create(&tid, NULL, srv_thread_capture, &cc) == 0);

    snprintf(base, sizeof(base), "http://[::1]:%d", port);
    snprintf(url, sizeof(url), "http://[::1]:%d/p", port);
    snprintf(expect, sizeof(expect), "Host: [::1]:%d\r\n", port);

    WolfCertHttpRequest req = { .method = "GET", .url = url };
    WolfCertHttpResponse resp = { 0 };

    if (use_session) {
        WolfCertHttpSessionCfg cfg = { .base_url = base };
        WolfCertHttpSession* s = NULL;

        REQUIRE(wolfcert_http_session_open(&cfg, &s) == WOLFCERT_OK);
        REQUIRE(wolfcert_http_session_request(s, &req, &resp) == WOLFCERT_OK);
        wolfcert_http_session_close(s);
    }
    else {
        REQUIRE(wolfcert_http_request(&req, &resp) == WOLFCERT_OK);
    }

    REQUIRE(resp.status_code == 200);
    wolfcert_http_response_free(&resp);
    pthread_join(tid, NULL);

    REQUIRE(strstr(cc.request, expect) != NULL);
    return 0;
}

static int test_request_host_header_ipv6(void)
{
    if (ipv6_host_header(0))
        return 1;

    return ipv6_host_header(1);
}

int main(void)
{
    REQUIRE(wolfcert_init(NULL) == WOLFCERT_OK);
    if (test_url_parser())
        return 1;
    if (test_url_origin())
        return 1;
    if (test_loopback_http())
        return 1;
    if (test_session_retry_after_reset())
        return 1;
    if (test_chunked_size_overflow())
        return 1;
    if (test_session_near_cap_response())
        return 1;
    if (test_session_eof_cap_response())
        return 1;
    if (test_request_transfer_encoding())
        return 1;
    if (test_request_host_header_ipv6())
        return 1;
    wolfcert_cleanup();
    printf("OK\n");
    return 0;
}

#endif
