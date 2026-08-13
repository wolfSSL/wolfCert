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

/* A complete vtable failing with a distinct code, so BAD_ARG can only come
 * from the conflict check and not from dial()'s completeness test. */
static int conflict_connect(void* ctx, const char* host, int port,
                            int timeout_ms, void** conn)
{
    (void)ctx; (void)host; (void)port; (void)timeout_ms;
    *conn = NULL;
    return WOLFCERT_ERR_IO;
}

static int conflict_read(void* ctx, void* conn, uint8_t* buf, size_t len,
                         int timeout_ms)
{
    (void)ctx; (void)conn; (void)buf; (void)len; (void)timeout_ms;
    return WOLFCERT_ERR_IO;
}

static int conflict_write(void* ctx, void* conn, const uint8_t* buf,
                          size_t len, int timeout_ms)
{
    (void)ctx; (void)conn; (void)buf; (void)len; (void)timeout_ms;
    return WOLFCERT_ERR_IO;
}

static int conflict_disconnect(void* ctx, void* conn)
{
    (void)ctx; (void)conn;
    return WOLFCERT_OK;
}

/* connect_cb is the deprecated spelling of transport, so a config carrying
 * both is ambiguous and rejected before anything is dialled. */
static int test_transport_conflict(void)
{
    static const WolfCertTransport t = { conflict_connect, conflict_read,
                                         conflict_write, conflict_disconnect,
                                         NULL };
    WolfCertHttpRequest req = { .method = "GET", .url = "http://127.0.0.1:1/",
                                .connect_cb = wolfcert_posix_connect,
                                .transport = &t };
    WolfCertHttpSessionCfg cfg = { .base_url = "http://127.0.0.1:1/",
                                   .connect_cb = wolfcert_posix_connect,
                                   .transport = &t };
    WolfCertHttpResponse resp = { 0 };
    WolfCertHttpSession* s = NULL;

    REQUIRE(wolfcert_http_request(&req, &resp) == WOLFCERT_ERR_BAD_ARG);
    REQUIRE(wolfcert_http_session_open(&cfg, &s) == WOLFCERT_ERR_BAD_ARG);
    return 0;
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
    if (test_request_transfer_encoding())
        return 1;
    if (test_transport_conflict())
        return 1;
    wolfcert_cleanup();
    printf("OK\n");
    return 0;
}
