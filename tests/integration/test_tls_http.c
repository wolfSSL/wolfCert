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

/* HTTPS requests to a one-shot loopback wolfSSL server. */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#define _DARWIN_C_SOURCE   /* expose memmem/strcasestr/INADDR_LOOPBACK on macOS */

#include <wolfcert/wolfcert.h>
#include "internal.h"

#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/wc_port.h>

#include "tls_test_util.h"
#include "../http_test_util.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define REQUIRE(cond) \
    do {                                                                    \
        if (!(cond)) {                                                      \
            fprintf(stderr, "FAIL %s:%d %s\n", __FILE__, __LINE__, #cond);  \
            return 1;                                                       \
        }                                                                   \
    } while (0)

#ifndef WOLFCERT_HAVE_BUILTIN_TRANSPORT
int main(void)
{
    return 77;
}
#else

struct srv_ctx {
    /* Set by srv_thread once bound and polled by main; atomic for TSan. */
    wolfSSL_Atomic_Int port;
    uint8_t* cert_pem;
    size_t cert_pem_len;
    uint8_t* key_pem;
    size_t key_pem_len;
    const char* version;
    int sni_len;    /* SNI HostName length the client sent, 0 if none */
};

#ifdef HAVE_SNI
static int sni_cb(WOLFSSL* ssl, int* ad, void* arg)
{
    void* name = NULL;

    (void)ad;
    ((struct srv_ctx*)arg)->sni_len =
        wolfSSL_SNI_GetRequest(ssl, WOLFSSL_SNI_HOST_NAME, &name);
    return 0;
}
#endif

static void* srv_thread(void* arg)
{
    struct srv_ctx* sc = (struct srv_ctx*)arg;
    /* Single-version peer: TLS 1.2 where wolfSSL has it, TLS 1.3 otherwise. */
#ifdef WOLFSSL_NO_TLS12
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(wolfTLSv1_3_server_method());
#else
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(wolfTLSv1_2_server_method());
#endif
    if (ctx == NULL)
        return NULL;

    if (wolfSSL_CTX_use_certificate_buffer(ctx, sc->cert_pem,
            (long)sc->cert_pem_len, WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS) return NULL;
    if (wolfSSL_CTX_use_PrivateKey_buffer(ctx, sc->key_pem,
            (long)sc->key_pem_len, WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS) return NULL;
#ifdef HAVE_SNI
    wolfSSL_CTX_set_servername_callback(ctx, sni_cb);
    wolfSSL_CTX_set_servername_arg(ctx, sc);
#endif

    int ls = socket(AF_INET, SOCK_STREAM, 0);
    if (ls < 0)
        return NULL;
    int yes = 1;
    setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    struct sockaddr_in sa = { .sin_family = AF_INET, .sin_port = htons(0),
                              .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    bind(ls, (struct sockaddr*)&sa, sizeof(sa));
    listen(ls, 1);
    socklen_t slen = sizeof(sa);
    getsockname(ls, (struct sockaddr*)&sa, &slen);
    WOLFSSL_ATOMIC_STORE(sc->port, ntohs(sa.sin_port));

    int cs = accept(ls, NULL, NULL);
    close(ls);
    if (cs < 0) {
        wolfSSL_CTX_free(ctx);
        return NULL;
    }
    WOLFSSL* ssl = wolfSSL_new(ctx);
    wolfSSL_set_fd(ssl, cs);
    if (wolfSSL_accept(ssl) == WOLFSSL_SUCCESS) {
        sc->version = wolfSSL_get_version(ssl);
        char req[2048];
        int n;
        do {
            n = wolfSSL_read(ssl, req, sizeof(req) - 1);
        }
        while (n > 0 && strstr(req, "\r\n\r\n") == NULL);
        const char* resp = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
                           "Content-Length: 2\r\nConnection: close\r\n\r\nok";
        wolfSSL_write(ssl, resp, (int)strlen(resp));
        wolfSSL_shutdown(ssl);
    }
    wolfSSL_free(ssl);
    close(cs);
    wolfSSL_CTX_free(ctx);
    return NULL;
}

/* Start srv_thread on sc and write its https URL to url; 0 once it listens.
 * A thread that never reports its port is detached, since it may block. */
static int start_srv(struct srv_ctx* sc, pthread_t* tid, char* url,
                     size_t url_sz)
{
    int i;

    WOLFSSL_ATOMIC_STORE(sc->port, 0);
    sc->sni_len = 0;
    if (pthread_create(tid, NULL, srv_thread, sc) != 0)
        return -1;
    for (i = 0; i < 200 && WOLFSSL_ATOMIC_LOAD(sc->port) == 0; ++i) {
        test_sleep_ms(5);
    }
    if (WOLFSSL_ATOMIC_LOAD(sc->port) == 0) {
        pthread_detach(*tid);
        return -1;
    }

    snprintf(url, url_sz, "https://127.0.0.1:%d/",
             WOLFSSL_ATOMIC_LOAD(sc->port));
    return 0;
}

/* Start srv_thread on sc, then GET https://127.0.0.1:port/ with verify_server
 * set and ta as the only trust anchor, on a session that closes after the
 * request; open_rc, when not NULL, gets the session open's result. */
static int get_once(struct srv_ctx* sc, const uint8_t* ta, size_t ta_len,
                    int* open_rc, WolfCertHttpResponse* resp)
{
    WolfCertHttpRequest req = { .method = "GET" };
    WolfCertHttpSessionCfg cfg = { .verify_server = 1 };
    WolfCertHttpSession* s = NULL;
    pthread_t tid;
    char url[128];
    int rc;

    if (start_srv(sc, &tid, url, sizeof(url)) != 0)
        return WOLFCERT_ERR_GENERIC;
    req.url               = url;
    cfg.base_url          = url;
    cfg.trust_anchors     = ta;
    cfg.trust_anchors_len = ta_len;

    if (open_rc == NULL) {
        rc = test_http_request(&cfg, &req, resp);
    }
    else {
        rc = *open_rc = wolfcert_http_session_open(&cfg, &s);
        if (rc == WOLFCERT_OK)
            rc = wolfcert_http_session_request(s, &req, resp);
        wolfcert_http_session_close(s);
    }
    pthread_join(tid, NULL);

    return rc;
}

static int lo_dialed;

/* Transport that reaches srv_thread on 127.0.0.1 whatever host the URL
 * names, so the name the client checks can differ from where it connects. */
static int lo_connect(void* ctx, const char* host, int port, int timeout_ms,
                      void** conn)
{
    (void)host;
    lo_dialed = 1;
    return wolfcert_posix_transport.connect(ctx, "127.0.0.1", port,
                                            timeout_ms, conn);
}

static WolfCertTransport lo_transport(void)
{
    WolfCertTransport t = wolfcert_posix_transport;

    t.connect = lo_connect;
    return t;
}

/* Connect to port once and close, so a srv_thread still in accept() exits. */
static void unblock_srv(int port)
{
    struct sockaddr_in sa = { .sin_family = AF_INET,
                              .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    int fd = socket(AF_INET, SOCK_STREAM, 0);

    if (fd < 0)
        return;
    sa.sin_port = htons((uint16_t)port);
    (void)connect(fd, (struct sockaddr*)&sa, sizeof(sa));
    close(fd);
}

/* GET https://<host>:<port>/ over lo_connect, trusting sc's own cert; the
 * session open's result goes to open_rc. */
static int get_as(struct srv_ctx* sc, const char* host, int verify,
                  int* open_rc)
{
    WolfCertTransport t = lo_transport();
    WolfCertHttpSessionCfg cfg = { .verify_server = verify };
    WolfCertHttpRequest req = { .method = "GET" };
    WolfCertHttpResponse resp = { 0 };
    WolfCertHttpSession* s = NULL;
    pthread_t tid;
    char url[128];
    int rc;

    if (start_srv(sc, &tid, url, sizeof(url)) != 0)
        return WOLFCERT_ERR_GENERIC;
    snprintf(url, sizeof(url), "https://%s:%d/", host,
             WOLFSSL_ATOMIC_LOAD(sc->port));
    cfg.base_url          = url;
    cfg.trust_anchors     = sc->cert_pem;
    cfg.trust_anchors_len = sc->cert_pem_len;
    cfg.transport         = t;
    req.url               = url;

    lo_dialed = 0;
    rc = *open_rc = wolfcert_http_session_open(&cfg, &s);
    if (rc == WOLFCERT_OK)
        rc = wolfcert_http_session_request(s, &req, &resp);
    wolfcert_http_response_free(&resp);
    wolfcert_http_session_close(s);
    if (!lo_dialed)
        unblock_srv(WOLFSSL_ATOMIC_LOAD(sc->port));
    pthread_join(tid, NULL);

    return rc;
}

#if defined(USE_WOLFSSL_MEMORY) && !defined(WOLFSSL_STATIC_MEMORY) && \
    !defined(WOLFSSL_DEBUG_MEMORY)
#define TEST_ALLOC_FAILURES
#endif

#ifdef TEST_ALLOC_FAILURES
/* Only the main thread's allocations count, so srv_thread never fails. */
static pthread_t g_main_thread;
/* Allocations left before failing_malloc() returns NULL; -1 never fails. */
static int g_allocs_left = -1;
static int g_alloc_failed;

static int alloc_fails(void)
{
    if (!pthread_equal(pthread_self(), g_main_thread))
        return 0;
    if (g_allocs_left == 0) {
        g_alloc_failed = 1;
        return 1;
    }
    if (g_allocs_left > 0)
        g_allocs_left--;
    return 0;
}

static void* failing_malloc(size_t sz)
{
    return alloc_fails() ? NULL : malloc(sz);
}

static void failing_free(void* ptr)
{
    free(ptr);
}

static void* failing_realloc(void* ptr, size_t sz)
{
    return alloc_fails() ? NULL : realloc(ptr, sz);
}

/* Lets `n` main-thread allocations succeed and fails the rest. */
static void oom_arm(int n)
{
    g_allocs_left = n;
    g_alloc_failed = 0;
}

/* Stops failing; 1 when an allocation was failed, 0 if not. */
static int oom_disarm(void)
{
    g_allocs_left = -1;
    return g_alloc_failed;
}

/* Failing each allocation of a session's first request in turn: one of them
 * falls in the handshake and gives WOLFCERT_ERR_MEMORY with the wolfSSL code,
 * blocking (nb 0) or non-blocking. */
static int handshake_oom_case(struct srv_ctx* sc, int nb)
{
    WolfCertHttpSessionCfg cfg = { .verify_server = 1 };
    WolfCertHttpRequest req = { .method = "GET" };
    WolfCertHttpResponse resp = { 0 };
    WolfCertHttpSession* s = NULL;
    struct pollfd pfd;
    pthread_t tid;
    char url[128];
    int fails;
    int failed = 1;
    int found = 0;
    int rc;

    cfg.trust_anchors     = sc->cert_pem;
    cfg.trust_anchors_len = sc->cert_pem_len;
    for (fails = 0; !found && failed == 1; fails++) {
        REQUIRE(start_srv(sc, &tid, url, sizeof(url)) == 0);
        cfg.base_url = url;
        req.url      = url;
        REQUIRE(wolfcert_http_session_open(&cfg, &s) == WOLFCERT_OK);

        wolfcert_clear_error();
        oom_arm(fails);
        do {
            rc = nb ? wolfcert_http_session_request_nb(s, &req, &resp)
                    : wolfcert_http_session_request(s, &req, &resp);
            if (rc == WOLFCERT_ERR_WANT_READ || rc == WOLFCERT_ERR_WANT_WRITE) {
                pfd.fd = wolfcert_http_session_fd(s);
                pfd.events = (rc == WOLFCERT_ERR_WANT_READ) ? POLLIN : POLLOUT;
                (void)poll(&pfd, 1, 2000);
            }
        } while (rc == WOLFCERT_ERR_WANT_READ || rc == WOLFCERT_ERR_WANT_WRITE);
        failed = oom_disarm();

        found = rc == WOLFCERT_ERR_MEMORY && wolfcert_last_wolfssl_err() != 0;
        wolfcert_http_response_free(&resp);
        wolfcert_http_session_close(s);
        pthread_join(tid, NULL);
    }

    REQUIRE(found);
    return 0;
}

/* Failing each allocation of a session open in turn: the SNI one gives
 * WOLFCERT_ERR_MEMORY with MEMORY_E, the name check's with MEMORY_ERROR. */
static int name_check_oom_case(struct srv_ctx* sc)
{
    WolfCertTransport t = lo_transport();
    WolfCertHttpSessionCfg cfg = { .verify_server = 1 };
    WolfCertHttpSession* s = NULL;
    struct pollfd pfd;
    uint16_t port;
    char url[64];
    int failed = 1;
    int found = 0;
    int sni_oom = 0;
    int fails;
    int ls;
    int fd;
    int rc;

    ls = black_hole_listener(&port);
    REQUIRE(ls >= 0);
    snprintf(url, sizeof(url), "https://ca.example:%d/", port);
    cfg.base_url          = url;
    cfg.trust_anchors     = sc->cert_pem;
    cfg.trust_anchors_len = sc->cert_pem_len;
    cfg.transport         = t;

    for (fails = 0; !found && failed == 1; fails++) {
        wolfcert_clear_error();
        oom_arm(fails);
        rc = wolfcert_http_session_open(&cfg, &s);
        failed = oom_disarm();
        if (rc == WOLFCERT_ERR_MEMORY &&
                wolfcert_last_wolfssl_err() == MEMORY_E)
            sni_oom = 1;
        found = rc == WOLFCERT_ERR_MEMORY &&
                wolfcert_last_wolfssl_err() == MEMORY_ERROR;
        wolfcert_http_session_close(s);
        s = NULL;
        pfd.fd = ls;
        pfd.events = POLLIN;
        while (poll(&pfd, 1, 0) > 0 && (fd = accept(ls, NULL, NULL)) >= 0)
            close(fd);
    }
    close(ls);

#if defined(HAVE_SNI) && !defined(WOLFCERT_NO_SNI)
    REQUIRE(sni_oom);
#else
    (void)sni_oom;
#endif
    REQUIRE(found);
    return 0;
}
#endif

int main(void)
{
    REQUIRE(wolfcert_init(NULL) == WOLFCERT_OK);
    struct srv_ctx sc = { 0 };
    struct srv_ctx other = { 0 };
    struct srv_ctx dns = { 0 };
    struct srv_ctx lh = { 0 };
    int open_rc = -1;
#ifdef TEST_ALLOC_FAILURES
    /* Installed before any thread starts; they fail nothing until armed. */
    g_main_thread = pthread_self();
    REQUIRE(wolfSSL_SetAllocators(failing_malloc, failing_free,
                                  failing_realloc) == 0);
#endif
    REQUIRE(gen_server_identity(&sc.cert_pem, &sc.cert_pem_len,
                                &sc.key_pem, &sc.key_pem_len) == 0);
    REQUIRE(gen_server_identity(&other.cert_pem, &other.cert_pem_len,
                                &other.key_pem, &other.key_pem_len) == 0);
    /* A CA cert has no SAN, so wolfSSL matches ca.example against its CN. */
    REQUIRE(mint_self_id("ca.example", 1, &dns.cert_pem, &dns.cert_pem_len,
                         &dns.key_pem, &dns.key_pem_len) == 0);
    REQUIRE(mint_self_id("localhost", 1, &lh.cert_pem, &lh.cert_pem_len,
                         &lh.key_pem, &lh.key_pem_len) == 0);

    WolfCertHttpResponse resp = { 0 };
    REQUIRE(get_once(&sc, sc.cert_pem, sc.cert_pem_len, NULL, &resp)
            == WOLFCERT_OK);
    REQUIRE(resp.status_code == 200);
    REQUIRE(resp.body_len == 2 && memcmp(resp.body, "ok", 2) == 0);
    wolfcert_http_response_free(&resp);
#ifdef WOLFSSL_NO_TLS12
    REQUIRE(sc.version != NULL && strcmp(sc.version, "TLSv1.3") == 0);
#else
    REQUIRE(sc.version != NULL && strcmp(sc.version, "TLSv1.2") == 0);
#endif

    /* Trusting another self-signed cert fails the handshake with ERR_TLS
     * and the wolfSSL code on a session's first request, after its open
     * succeeds. */
    wolfcert_clear_error();
    REQUIRE(get_once(&sc, other.cert_pem, other.cert_pem_len, &open_rc, &resp)
            == WOLFCERT_ERR_TLS);
    REQUIRE(open_rc == WOLFCERT_OK);
    REQUIRE(wolfcert_last_wolfssl_err() != 0);
    REQUIRE(resp.body == NULL && resp.status_code == 0);

    /* RFC 6066 section 3: no SNI for an IP literal; a DNS name gets one. */
    REQUIRE(get_as(&sc, "127.0.0.1", 0, &open_rc) == WOLFCERT_OK);
    REQUIRE(sc.sni_len == 0);
    REQUIRE(get_as(&sc, "[::1]", 0, &open_rc) == WOLFCERT_OK);
    REQUIRE(sc.sni_len == 0);
#if defined(HAVE_SNI) && !defined(WOLFCERT_NO_SNI)
    REQUIRE(get_as(&sc, "ca.example", 0, &open_rc) == WOLFCERT_OK);
    REQUIRE(sc.sni_len == (int)strlen("ca.example"));
    REQUIRE(get_as(&sc, "ca.example.", 0, &open_rc) == WOLFCERT_OK);
    REQUIRE(sc.sni_len == (int)strlen("ca.example"));
#endif

    /* A trusted cert for 127.0.0.1 does not pass as ca.example. */
    REQUIRE(get_as(&sc, "ca.example", 1, &open_rc) == WOLFCERT_ERR_TLS);
    REQUIRE(open_rc == WOLFCERT_OK);
    /* A name wolfSSL will not check fails the open, before any handshake. */
    wolfcert_clear_error();
    REQUIRE(get_as(&sc, "ca.bad_label", 1, &open_rc) == WOLFCERT_ERR_TLS);
    REQUIRE(open_rc == WOLFCERT_ERR_TLS);
    REQUIRE(wolfcert_last_wolfssl_err() == BAD_FUNC_ARG);
    REQUIRE(get_as(&sc, "est_ca", 1, &open_rc) == WOLFCERT_ERR_TLS);
#ifndef WOLFSSL_ALLOW_SINGLE_LABEL_HOSTNAME
    REQUIRE(get_as(&sc, "estserver", 1, &open_rc) == WOLFCERT_ERR_TLS);
    REQUIRE(get_as(&sc, "estserver.", 1, &open_rc) == WOLFCERT_ERR_TLS);
#endif
    /* A URL the parser rejects fails the open before any connect. */
    REQUIRE(get_as(&sc, "ca example", 1, &open_rc) == WOLFCERT_ERR_PARSE);
    REQUIRE(open_rc == WOLFCERT_ERR_PARSE);

    /* The name check takes an absolute name with its trailing dot. */
    REQUIRE(get_as(&dns, "ca.example", 1, &open_rc) == WOLFCERT_OK);
    REQUIRE(get_as(&dns, "ca.example.", 1, &open_rc) == WOLFCERT_OK);
    /* wolfSSL exempts localhost from its two-label rule. */
    REQUIRE(get_as(&lh, "localhost", 1, &open_rc) == WOLFCERT_OK);

#ifdef TEST_ALLOC_FAILURES
    REQUIRE(handshake_oom_case(&sc, 0) == 0);
    REQUIRE(handshake_oom_case(&sc, 1) == 0);
    REQUIRE(name_check_oom_case(&sc) == 0);
#endif

    free(sc.cert_pem);
    free(sc.key_pem);
    free(other.cert_pem);
    free(other.key_pem);
    free(dns.cert_pem);
    free(dns.key_pem);
    free(lh.cert_pem);
    free(lh.key_pem);
    wolfcert_cleanup();
    printf("OK\n");
    return 0;
}

#endif
