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
#include <sys/time.h>
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
    const uint8_t* client_ca;   /* demand a client cert from this CA */
    size_t client_ca_len;
    int tls13;      /* serve TLS 1.3 only */
    int drop;       /* close after the ClientHello, without TLS */
    const uint8_t* alert;   /* answer the ClientHello with this level, code */
    int hello12;    /* send a TLS 1.2 ServerHello before the alert */
    int pha;        /* refuse the client cert after a TLS 1.3 PHA request */
    int silent;     /* never answer the request; close after 10 s */
    short min_rsa_bits; /* lower the server's own RSA key minimum */
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

/* Read n bytes from fd into out, or discard them if out is NULL; 0 once
 * all arrived. */
static int recv_n(int fd, uint8_t* out, size_t n)
{
    struct pollfd pfd = { .fd = fd, .events = POLLIN };
    uint8_t tmp[256];

    while (n > 0) {
        size_t want = n < sizeof(tmp) ? n : sizeof(tmp);
        ssize_t r;

        if (poll(&pfd, 1, 2000) <= 0)
            return -1;
        r = recv(fd, out != NULL ? out : tmp, want, 0);
        if (r <= 0)
            return -1;
        if (out != NULL)
            out += r;
        n -= (size_t)r;
    }
    return 0;
}

/* Fill sh with a TLS 1.2 ServerHello picking the first ECDHE suite of the
 * ClientHello ch, with an empty renegotiation_info; 0 on success. */
static int fake_server_hello(const uint8_t* ch, size_t n, uint8_t sh[54])
{
    static const uint8_t head[11] = {
        0x16, 0x03, 0x03, 0x00, 0x31, 0x02, 0x00, 0x00, 0x2d, 0x03, 0x03
    };
    static const uint8_t ext[7] = { 0x00, 0x05, 0xff, 0x01, 0x00, 0x01, 0x00 };
    size_t off = 38;
    size_t cs_len;
    size_t i;

    if (n < off + 1 || n < off + 1 + ch[off] + 2)
        return -1;
    off += 1 + ch[off];
    cs_len = ((size_t)ch[off] << 8) | ch[off + 1];
    off += 2;
    if (n < off + cs_len)
        return -1;
    for (i = 0; i + 1 < cs_len; i += 2) {
        if (ch[off + i] == 0xC0 || ch[off + i] == 0xCC)
            break;
    }
    if (i + 1 >= cs_len)
        return -1;
    memcpy(sh, head, sizeof(head));
    memset(sh + 11, 0x11, 32);
    sh[43] = 0;
    sh[44] = ch[off + i];
    sh[45] = ch[off + i + 1];
    sh[46] = 0;
    memcpy(sh + 47, ext, sizeof(ext));
    return 0;
}

/* Answer the first record on fd with a plaintext alert, after a TLS 1.2
 * ServerHello if hello12, then wait for the peer to close. */
static void send_raw_alert(int fd, const uint8_t* alert, int hello12)
{
    uint8_t rec[7] = { 0x15, 0x03, 0x03, 0x00, 0x02, 0, 0 };
    uint8_t hdr[5];
    uint8_t ch[4096];
    uint8_t sh[54];
    size_t n;

    if (recv_n(fd, hdr, sizeof(hdr)) != 0)
        return;
    n = ((size_t)hdr[3] << 8) | hdr[4];
    if (n > sizeof(ch) || recv_n(fd, ch, n) != 0)
        return;
    if (hello12) {
        if (fake_server_hello(ch, n, sh) != 0)
            return;
        (void)send(fd, sh, sizeof(sh), 0);
    }
    rec[5] = alert[0];
    rec[6] = alert[1];
    (void)send(fd, rec, sizeof(rec), 0);
    (void)shutdown(fd, SHUT_WR);
    while (recv_n(fd, NULL, 1) == 0) {
    }
}

/* With sc->pha, request the client cert and read the answer; 1 if it did. */
static int serve_pha(const struct srv_ctx* sc, WOLFSSL* ssl)
{
#if defined(WOLFSSL_POST_HANDSHAKE_AUTH) && defined(WOLFSSL_TLS13)
    char buf[64];

    if (!sc->pha)
        return 0;
    wolfSSL_set_verify(ssl, WOLFSSL_VERIFY_PEER |
                       WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    if (wolfSSL_request_certificate(ssl) == WOLFSSL_SUCCESS)
        (void)wolfSSL_read(ssl, buf, sizeof(buf));
    return 1;
#else
    (void)sc;
    (void)ssl;
    return 0;
#endif
}

static void* srv_thread(void* arg)
{
    struct srv_ctx* sc = (struct srv_ctx*)arg;
    /* Single-version peer: TLS 1.2 where wolfSSL has it, TLS 1.3 otherwise. */
#ifdef WOLFSSL_NO_TLS12
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(wolfTLSv1_3_server_method());
#elif defined(WOLFSSL_TLS13)
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(sc->tls13 ? wolfTLSv1_3_server_method()
                                                 : wolfTLSv1_2_server_method());
#else
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(wolfTLSv1_2_server_method());
#endif
    if (ctx == NULL)
        return NULL;
    if (sc->client_ca != NULL) {
        if (wolfSSL_CTX_load_verify_buffer(ctx, sc->client_ca,
                (long)sc->client_ca_len, WOLFSSL_FILETYPE_PEM)
                != WOLFSSL_SUCCESS) {
            wolfSSL_CTX_free(ctx);
            return NULL;
        }
        if (!sc->pha) {
            wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER |
                                   WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
        }
    }

#ifndef NO_RSA
    if (sc->min_rsa_bits != 0)
        (void)wolfSSL_CTX_SetMinRsaKey_Sz(ctx, sc->min_rsa_bits);
#endif
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
    if (sc->drop) {
        char hello[64];

        (void)recv(cs, hello, sizeof(hello), 0);
        close(cs);
        wolfSSL_CTX_free(ctx);
        return NULL;
    }
    if (sc->alert != NULL) {
        send_raw_alert(cs, sc->alert, sc->hello12);
        close(cs);
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
        if (sc->silent) {
            struct timeval tv = { 10, 0 };

            (void)setsockopt(cs, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            while (wolfSSL_read(ssl, req, sizeof(req)) > 0)
                ;
        }
        else if (!serve_pha(sc, ssl)) {
            const char* resp = "HTTP/1.1 200 OK\r\n"
                "Content-Type: text/plain\r\nContent-Length: 2\r\n"
                "Connection: close\r\n\r\nok";
            wolfSSL_write(ssl, resp, (int)strlen(resp));
            wolfSSL_shutdown(ssl);
        }
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

static int g_verify = 1;

/* GET from srv_thread presenting cert/key (none if NULL); nb 1 non-blocking. */
static int get_with_id(struct srv_ctx* sc, const uint8_t* cert,
                       size_t cert_len, const uint8_t* key, size_t key_len,
                       int nb)
{
    WolfCertHttpSessionCfg cfg = { .verify_server = g_verify };
    WolfCertHttpRequest req = { .method = "GET" };
    WolfCertHttpResponse resp = { 0 };
    WolfCertHttpSession* s = NULL;
    struct pollfd pfd;
    pthread_t tid;
    char url[128];
    int rc;

    if (start_srv(sc, &tid, url, sizeof(url)) != 0)
        return WOLFCERT_ERR_GENERIC;
    cfg.transport         = lo_transport();
    cfg.base_url          = url;
    cfg.trust_anchors     = sc->cert_pem;
    cfg.trust_anchors_len = sc->cert_pem_len;
    cfg.client_cert       = cert;
    cfg.client_cert_len   = cert_len;
    cfg.client_key        = key;
    cfg.client_key_len    = key_len;
    cfg.allow_post_handshake_auth = sc->pha;
    req.url               = url;

    lo_dialed = 0;
    rc = wolfcert_http_session_open(&cfg, &s);
    while (rc == WOLFCERT_OK || rc == WOLFCERT_ERR_WANT_READ ||
           rc == WOLFCERT_ERR_WANT_WRITE) {
        if (rc != WOLFCERT_OK) {
            pfd.fd = wolfcert_http_session_fd(s);
            pfd.events = (rc == WOLFCERT_ERR_WANT_READ) ? POLLIN : POLLOUT;
            (void)poll(&pfd, 1, 2000);
        }
        rc = nb ? wolfcert_http_session_request_nb(s, &req, &resp)
                : wolfcert_http_session_request(s, &req, &resp);
        if (rc == WOLFCERT_OK)
            break;
    }
    wolfcert_http_response_free(&resp);
    wolfcert_http_session_close(s);
    if (!lo_dialed)
        unblock_srv(WOLFSSL_ATOMIC_LOAD(sc->port));
    pthread_join(tid, NULL);

    return rc;
}

static int test_client_cert_rejected(struct srv_ctx* sc,
                                     const struct srv_ctx* other)
{
    int tls13;
    int nb;

    sc->client_ca     = sc->cert_pem;
    sc->client_ca_len = sc->cert_pem_len;
    for (tls13 = 0; tls13 <= 1; tls13++) {
#if defined(WOLFSSL_NO_TLS12)
        if (!tls13)
            continue;
#elif !defined(WOLFSSL_TLS13)
        if (tls13)
            continue;
#endif
        sc->tls13 = tls13;
        for (nb = 0; nb <= 1; nb++) {
            REQUIRE(get_with_id(sc, sc->cert_pem, sc->cert_pem_len,
                                sc->key_pem, sc->key_pem_len, nb)
                    == WOLFCERT_OK);
            wolfcert_clear_error();
            REQUIRE(get_with_id(sc, other->cert_pem, other->cert_pem_len,
                                other->key_pem, other->key_pem_len, nb)
                    == (tls13 ? WOLFCERT_ERR_TLS_PEER_REJECTED
                              : WOLFCERT_ERR_TLS));
            REQUIRE(strstr(wolfcert_last_error_message(),
                           tls13 ? "refused the client certificate"
                                 : "unauthenticated alert") != NULL);
        }
#ifdef WOLFSSL_TLS13
        /* certificate_required without a configured cert is no rejection. */
        if (tls13) {
            int rc = get_with_id(sc, NULL, 0, NULL, 0, 0);

            REQUIRE(rc == WOLFCERT_ERR_TLS);
            REQUIRE(strstr(wolfcert_last_error_message(),
                           "with alert 116 (certificate_required)") != NULL);
            /* Nor is a refusal from a server that was never verified. */
            g_verify = 0;
            wolfcert_clear_error();
            rc = get_with_id(sc, other->cert_pem, other->cert_pem_len,
                             other->key_pem, other->key_pem_len, 0);
            g_verify = 1;
            REQUIRE(rc == WOLFCERT_ERR_TLS);
            REQUIRE(strstr(wolfcert_last_error_message(),
                           "unauthenticated alert") != NULL);
        }
#endif
    }
    sc->client_ca = NULL;
    sc->client_ca_len = 0;
    sc->tls13 = 0;

    sc->drop = 1;
    for (nb = 0; nb <= 1; nb++) {
        int rc = get_with_id(sc, other->cert_pem, other->cert_pem_len,
                             other->key_pem, other->key_pem_len, nb);

        REQUIRE(rc == WOLFCERT_ERR_TLS || rc == WOLFCERT_ERR_IO);
    }
    sc->drop = 0;
    return 0;
}

/* A plaintext alert answering the ClientHello, alone or after a forged TLS 1.2
 * ServerHello, which anyone on the path can send. */
static int test_forged_alert(struct srv_ctx* sc, const struct srv_ctx* other)
{
    static const uint8_t bad_cert[2]   = { 2, 42 };
    static const uint8_t warn_cert[2]  = { 1, 42 };
    static const uint8_t hs_failure[2] = { 2, 40 };
    int rc;

    sc->alert = bad_cert;
    rc = get_with_id(sc, other->cert_pem, other->cert_pem_len,
                     other->key_pem, other->key_pem_len, 0);
    REQUIRE(rc == WOLFCERT_ERR_TLS);
    REQUIRE(strstr(wolfcert_last_error_message(),
                   "unauthenticated alert 42") != NULL);
#if defined(WOLFSSL_TLS13) && !defined(WOLFSSL_NO_TLS12)
    sc->hello12 = 1;
    rc = get_with_id(sc, other->cert_pem, other->cert_pem_len,
                     other->key_pem, other->key_pem_len, 0);
    sc->hello12 = 0;
    REQUIRE(rc == WOLFCERT_ERR_TLS);
    REQUIRE(strstr(wolfcert_last_error_message(),
                   "unauthenticated alert 42") != NULL);
#endif
    sc->alert = warn_cert;
    rc = get_with_id(sc, other->cert_pem, other->cert_pem_len,
                     other->key_pem, other->key_pem_len, 0);
    REQUIRE(rc == WOLFCERT_ERR_TLS || rc == WOLFCERT_ERR_IO);
    sc->alert = hs_failure;
    REQUIRE(get_with_id(sc, other->cert_pem, other->cert_pem_len,
                        other->key_pem, other->key_pem_len, 0)
            == WOLFCERT_ERR_TLS);
    sc->alert = NULL;
    return 0;
}

#if defined(WOLFSSL_POST_HANDSHAKE_AUTH) && defined(WOLFSSL_TLS13)
static int test_pha_rejected(struct srv_ctx* sc, const struct srv_ctx* other)
{
    int rc;

    sc->tls13         = 1;
    sc->pha           = 1;
    sc->client_ca     = other->cert_pem;
    sc->client_ca_len = other->cert_pem_len;
    wolfcert_clear_error();
    rc = get_with_id(sc, sc->cert_pem, sc->cert_pem_len, sc->key_pem,
                     sc->key_pem_len, 0);
    sc->tls13         = 0;
    sc->pha           = 0;
    sc->client_ca     = NULL;
    sc->client_ca_len = 0;
    REQUIRE(rc == WOLFCERT_ERR_TLS_PEER_REJECTED);
    REQUIRE(strstr(wolfcert_last_error_message(), "wolfSSL_read") != NULL);
    return 0;
}
#endif

static int g_big_write_rc;

/* Fails every write of 4 KiB or more with g_big_write_rc. */
static int big_write(void* ctx, void* conn, const uint8_t* buf, size_t len,
                     int timeout_ms)
{
    if (len >= 4096)
        return g_big_write_rc;
    return wolfcert_posix_transport.write(ctx, conn, buf, len, timeout_ms);
}

/* POST a body the transport refuses with write_rc; the result of a
 * second request on the same session goes to again_rc. */
static int post_refused(struct srv_ctx* sc, int write_rc, int* again_rc)
{
    static uint8_t body[8000];
    WolfCertHttpSessionCfg cfg = { .verify_server = 1 };
    WolfCertHttpRequest req = { .method = "POST" };
    WolfCertHttpResponse resp = { 0 };
    WolfCertHttpSession* s = NULL;
    pthread_t tid;
    char url[128];
    int rc;

    if (start_srv(sc, &tid, url, sizeof(url)) != 0)
        return WOLFCERT_ERR_GENERIC;
    cfg.transport         = lo_transport();
    cfg.transport.write   = big_write;
    cfg.base_url          = url;
    cfg.trust_anchors     = sc->cert_pem;
    cfg.trust_anchors_len = sc->cert_pem_len;
    req.url               = url;
    req.content_type      = "application/octet-stream";
    req.body              = body;
    req.body_len          = sizeof(body);
    g_big_write_rc        = write_rc;

    lo_dialed = 0;
    rc = wolfcert_http_session_open(&cfg, &s);
    if (rc == WOLFCERT_OK)
        rc = wolfcert_http_session_request(s, &req, &resp);
    if (rc == WOLFCERT_OK && resp.status_code != 200)
        rc = WOLFCERT_ERR_HTTP;
    wolfcert_http_response_free(&resp);
    if (rc == WOLFCERT_OK) {
        *again_rc = wolfcert_http_session_request(s, &req, &resp);
        wolfcert_http_response_free(&resp);
    }
    wolfcert_http_session_close(s);
    if (!lo_dialed)
        unblock_srv(WOLFSSL_ATOMIC_LOAD(sc->port));
    pthread_join(tid, NULL);

    return rc;
}

static int posix_read_copy(void* ctx, void* conn, uint8_t* buf, size_t len,
                           int timeout_ms)
{
    return wolfcert_posix_transport.read(ctx, conn, buf, len, timeout_ms);
}

/* With a read of its own, a transport's CONN_CLOSED write fails at once
 * instead of waiting for a reply the silent server never sends. */
static int test_custom_write_closed(struct srv_ctx* sc)
{
    static uint8_t body[8000];
    WolfCertHttpSessionCfg cfg = { .verify_server = 1 };
    WolfCertHttpRequest req = { .method = "POST" };
    WolfCertHttpResponse resp = { 0 };
    WolfCertHttpSession* s = NULL;
    pthread_t tid;
    int64_t start;
    char url[128];
    int rc;

    sc->silent = 1;
    if (start_srv(sc, &tid, url, sizeof(url)) != 0) {
        sc->silent = 0;
        return 1;
    }
    cfg.transport         = lo_transport();
    cfg.transport.read    = posix_read_copy;
    cfg.transport.write   = big_write;
    cfg.base_url          = url;
    cfg.trust_anchors     = sc->cert_pem;
    cfg.trust_anchors_len = sc->cert_pem_len;
    req.url               = url;
    req.content_type      = "application/octet-stream";
    req.body              = body;
    req.body_len          = sizeof(body);
    g_big_write_rc        = WOLFCERT_ERR_CONN_CLOSED;

    lo_dialed = 0;
    start = wolfcert_mono_ms();
    rc = wolfcert_http_session_open(&cfg, &s);
    if (rc == WOLFCERT_OK)
        rc = wolfcert_http_session_request(s, &req, &resp);
    start = wolfcert_mono_ms() - start;
    wolfcert_http_response_free(&resp);
    wolfcert_http_session_close(s);
    if (!lo_dialed)
        unblock_srv(WOLFSSL_ATOMIC_LOAD(sc->port));
    pthread_join(tid, NULL);
    sc->silent = 0;
    REQUIRE(rc == WOLFCERT_ERR_IO);
    REQUIRE(start < 3000);
    return 0;
}

static int test_refused_write(struct srv_ctx* sc)
{
    int again_rc = 0;

    /* A closed peer's reply still arrives; the session is then closed. */
    REQUIRE(post_refused(sc, WOLFCERT_ERR_CONN_CLOSED, &again_rc)
            == WOLFCERT_OK);
    REQUIRE(again_rc == WOLFCERT_ERR_CONN_CLOSED);

    wolfcert_clear_error();
    REQUIRE(post_refused(sc, WOLFCERT_ERR_IO, &again_rc) == WOLFCERT_ERR_IO);
    REQUIRE(strstr(wolfcert_last_error_message(), "wolfSSL_write") != NULL);
    return 0;
}

#ifndef NO_ASN_TIME
static time_t unset_clock(time_t* t)
{
    if (t != NULL)
        *t = 1000;
    return 1000;
}
#endif

#ifndef NO_ASN_TIME
static time_t late_clock(time_t* t)
{
    if (t != NULL)
        *t = (time_t)INT32_MAX;   /* 2038-01-19, fits a 32-bit time_t */
    return (time_t)INT32_MAX;
}

/* A server certificate past its validity at handshake time is UNTRUSTED. */
static int test_expired_server(struct srv_ctx* sc)
{
    WolfCertHttpSessionCfg cfg = { .verify_server = 1 };
    WolfCertHttpRequest req = { .method = "GET" };
    WolfCertHttpResponse resp = { 0 };
    WolfCertHttpSession* s = NULL;
    pthread_t tid;
    char url[128];
    int rc;

    if (start_srv(sc, &tid, url, sizeof(url)) != 0)
        return 1;
    cfg.base_url          = url;
    cfg.trust_anchors     = sc->cert_pem;
    cfg.trust_anchors_len = sc->cert_pem_len;
    req.url               = url;
    wolfcert_clear_error();
    rc = wolfcert_http_session_open(&cfg, &s);
    if (rc == WOLFCERT_OK) {
        (void)wc_SetTimeCb(late_clock);
        rc = wolfcert_http_session_request(s, &req, &resp);
        wc_SetTimeCb(NULL);
    }
    wolfcert_http_response_free(&resp);
    wolfcert_http_session_close(s);
    pthread_join(tid, NULL);
    /* wolfSSL built with --enable-all skips the date check. */
    if (rc != WOLFCERT_OK) {
        REQUIRE(rc == WOLFCERT_ERR_TLS_UNTRUSTED);
        REQUIRE(wolfcert_last_wolfssl_err() == ASN_AFTER_DATE_E);
    }
    return 0;
}
#endif

#ifndef NO_RSA
/* 768-bit RSA key, below wolfSSL's default 1024-bit peer minimum. */
static const uint8_t small_rsa_der[] = {
    0x30, 0x82, 0x01, 0xc9, 0x02, 0x01, 0x00, 0x02, 0x61, 0x00, 0xb9, 0x01,
    0x74, 0x6e, 0xb2, 0xe6, 0x19, 0xba, 0x61, 0x48, 0xf6, 0xc7, 0x8b, 0xd6,
    0xc8, 0x9e, 0x1e, 0x3d, 0xf7, 0x1f, 0xd1, 0xfa, 0x19, 0xde, 0x48, 0x3e,
    0xfe, 0xd4, 0x92, 0xb7, 0x80, 0x9b, 0xb5, 0x5f, 0xdb, 0x25, 0xb9, 0xa4,
    0x8c, 0xe5, 0xe4, 0x08, 0x3f, 0x37, 0xd1, 0x68, 0x6c, 0x33, 0x11, 0x39,
    0xdf, 0x11, 0x29, 0xbb, 0x10, 0x4d, 0x4d, 0xf2, 0xd4, 0x58, 0x81, 0xd5,
    0x6c, 0x2a, 0x24, 0xe4, 0x28, 0x05, 0x6a, 0x70, 0xff, 0xde, 0x2d, 0x21,
    0x1a, 0x86, 0x6e, 0x47, 0x3d, 0xf4, 0x18, 0x63, 0x39, 0x23, 0x43, 0x26,
    0xea, 0x56, 0x95, 0xcd, 0xac, 0xac, 0x87, 0xb2, 0x1e, 0xe5, 0x02, 0x03,
    0x01, 0x00, 0x01, 0x02, 0x60, 0x41, 0x01, 0x95, 0xdb, 0xdf, 0xd8, 0xa2,
    0x69, 0xaf, 0x0d, 0x68, 0x49, 0x2d, 0x85, 0xc6, 0xf0, 0x68, 0x47, 0xf5,
    0xb1, 0xa4, 0xa2, 0x70, 0xbc, 0x7e, 0x3e, 0x44, 0x64, 0x85, 0x39, 0x1d,
    0x63, 0x99, 0x13, 0x99, 0x79, 0x64, 0x05, 0xc1, 0xcc, 0x75, 0x97, 0xc0,
    0x3e, 0xe8, 0xc1, 0xfc, 0x62, 0x4c, 0x2e, 0xa6, 0x72, 0x42, 0xd5, 0x0c,
    0x78, 0xc4, 0x48, 0x08, 0x6e, 0x08, 0x27, 0x42, 0x02, 0xf3, 0xd3, 0x63,
    0x53, 0xad, 0xe5, 0x72, 0x9f, 0x86, 0x0b, 0x36, 0xf6, 0x08, 0x77, 0x06,
    0xa3, 0xb2, 0x38, 0xb6, 0xdc, 0xe3, 0x5a, 0xc7, 0xbb, 0x23, 0xf1, 0x4c,
    0xca, 0xc5, 0xee, 0x36, 0x81, 0x02, 0x31, 0x00, 0xe3, 0xb5, 0x88, 0x6a,
    0x0f, 0xfc, 0xe8, 0xaf, 0x81, 0x57, 0xe8, 0xd2, 0xfb, 0x04, 0x40, 0xb8,
    0xcc, 0xb8, 0x52, 0x48, 0x91, 0xe5, 0xb5, 0xa9, 0x01, 0xe0, 0x6a, 0x18,
    0x8f, 0x90, 0xe9, 0x1d, 0x3f, 0x94, 0x32, 0x88, 0xba, 0x29, 0x0c, 0x64,
    0x49, 0x73, 0x4e, 0x3e, 0xc4, 0x06, 0xf3, 0x99, 0x02, 0x31, 0x00, 0xcf,
    0xfd, 0xb4, 0xb1, 0x0c, 0x0d, 0xef, 0xf7, 0x9d, 0x8c, 0xae, 0xb6, 0x1f,
    0x8c, 0x88, 0x38, 0xd9, 0xa2, 0x87, 0x43, 0x42, 0x02, 0x3c, 0x25, 0x27,
    0x38, 0x5c, 0xd0, 0xf3, 0x3e, 0x97, 0x10, 0xd2, 0xb6, 0x4a, 0x2d, 0x35,
    0x87, 0x97, 0xe3, 0x7e, 0x81, 0xef, 0xd6, 0x47, 0x03, 0xd5, 0x2d, 0x02,
    0x30, 0x73, 0x32, 0x8c, 0x6f, 0xb3, 0xe4, 0xeb, 0xc6, 0x96, 0x35, 0xe6,
    0x18, 0x8e, 0x5b, 0x09, 0x6f, 0x34, 0x4a, 0x6f, 0x7e, 0x3d, 0x29, 0x2b,
    0xec, 0xf3, 0x81, 0x17, 0xcb, 0x93, 0x1d, 0xe9, 0x81, 0x1d, 0x80, 0x18,
    0xcc, 0xa8, 0xf9, 0x49, 0x46, 0x97, 0x0e, 0x19, 0x60, 0x91, 0x85, 0x3e,
    0xc9, 0x02, 0x30, 0x4a, 0x9c, 0xc2, 0xb3, 0x38, 0x95, 0xcf, 0x5d, 0xce,
    0xa0, 0xe7, 0x13, 0xe2, 0x61, 0x71, 0x84, 0xa3, 0x5e, 0x10, 0x93, 0xea,
    0x1c, 0x0f, 0x23, 0x6c, 0xdc, 0x65, 0x3f, 0x77, 0xe3, 0x1e, 0x22, 0x24,
    0xd4, 0xcb, 0xeb, 0x47, 0xe6, 0xaa, 0x70, 0x2b, 0xb3, 0xc5, 0x2b, 0xe3,
    0x31, 0xd6, 0xc9, 0x02, 0x30, 0x27, 0x15, 0x0c, 0xbd, 0xc1, 0x2c, 0x69,
    0xc3, 0x33, 0xd6, 0xf2, 0xb6, 0xfc, 0x4a, 0xd2, 0x5a, 0x01, 0xea, 0x0a,
    0x68, 0x39, 0x92, 0xf2, 0x65, 0x47, 0x11, 0xa1, 0xdf, 0x43, 0xcc, 0xf9,
    0x19, 0x5c, 0x07, 0xfd, 0x92, 0x25, 0x32, 0x4c, 0xee, 0x7c, 0x63, 0xd2,
    0xde, 0xed, 0x6c, 0x41, 0x2d,
};

static int dup_buf(uint8_t** out, size_t* out_len, const uint8_t* in, int n)
{
    if (n <= 0 || (*out = (uint8_t*)malloc((size_t)n)) == NULL)
        return -1;
    memcpy(*out, in, (size_t)n);
    *out_len = (size_t)n;
    return 0;
}

/* Server identity for 127.0.0.1 with small_rsa_der, issued by ca. */
static int mint_small_server(const struct srv_ctx* ca, struct srv_ctx* out)
{
    static const uint8_t san_seq[] = { 0x30, 0x06, 0x87, 0x04, 127, 0, 0, 1 };
    RsaKey ca_key;
    RsaKey key;
    WC_RNG rng;
    Cert cert;
    uint8_t ca_der[4096];
    uint8_t der[4096];
    uint8_t pem[8192];
    word32 idx = 0;
    int ca_len;
    int n;
    int ret = -1;

    if (wc_InitRng(&rng) != 0)
        return -1;
    if (wc_InitRsaKey(&ca_key, NULL) != 0) {
        wc_FreeRng(&rng);
        return -1;
    }
    if (wc_InitRsaKey(&key, NULL) != 0)
        goto out_ca;

    ca_len = wc_CertPemToDer(ca->cert_pem, (int)ca->cert_pem_len, ca_der,
                             (int)sizeof(ca_der), CERT_TYPE);
    n = wc_KeyPemToDer(ca->key_pem, (int)ca->key_pem_len, der,
                       (int)sizeof(der), NULL);
    if (ca_len <= 0 || n <= 0 ||
            wc_RsaPrivateKeyDecode(der, &idx, &ca_key, (word32)n) != 0)
        goto out;
    idx = 0;
    if (wc_RsaPrivateKeyDecode(small_rsa_der, &idx, &key,
                               (word32)sizeof(small_rsa_der)) != 0)
        goto out;

    wc_InitCert(&cert);
    strcpy(cert.subject.commonName, "127.0.0.1");
    cert.sigType = CTC_SHA256wRSA;
    cert.daysValid = 1;
    memcpy(cert.altNames, san_seq, sizeof(san_seq));
    cert.altNamesSz = (int)sizeof(san_seq);
    if (wc_SetIssuerBuffer(&cert, ca_der, ca_len) != 0 ||
            wc_MakeCert(&cert, der, sizeof(der), &key, NULL, &rng) <= 0)
        goto out;
    n = wc_SignCert(cert.bodySz, cert.sigType, der, sizeof(der), &ca_key,
                    NULL, &rng);
    if (n <= 0)
        goto out;
    n = wc_DerToPem(der, (word32)n, pem, sizeof(pem), CERT_TYPE);
    if (dup_buf(&out->cert_pem, &out->cert_pem_len, pem, n) != 0)
        goto out;
    n = wc_DerToPem(small_rsa_der, sizeof(small_rsa_der), pem, sizeof(pem),
                    PRIVATEKEY_TYPE);
    if (dup_buf(&out->key_pem, &out->key_pem_len, pem, n) != 0) {
        free(out->cert_pem);
        out->cert_pem = NULL;
        goto out;
    }
    ret = 0;
out:
    wc_FreeRsaKey(&key);
out_ca:
    wc_FreeRsaKey(&ca_key);
    wc_FreeRng(&rng);
    return ret;
}

/* A server key below wolfSSL's minimum size is UNTRUSTED. */
static int test_small_server_key(const struct srv_ctx* ca)
{
    struct srv_ctx small = { .min_rsa_bits = 512 };
    WolfCertHttpResponse resp = { 0 };
    int open_rc = -1;
    int rc;

    REQUIRE(mint_small_server(ca, &small) == 0);
    wolfcert_clear_error();
    rc = get_once(&small, ca->cert_pem, ca->cert_pem_len, &open_rc, &resp);
    wolfcert_http_response_free(&resp);
    free(small.cert_pem);
    free(small.key_pem);
    REQUIRE(open_rc == WOLFCERT_OK);
    REQUIRE(rc == WOLFCERT_ERR_TLS_UNTRUSTED);
    REQUIRE(wolfcert_last_wolfssl_err() == RSA_KEY_SIZE_E);
    return 0;
}
#endif

static int test_setup_failure_detail(struct srv_ctx* sc)
{
    static const uint8_t junk[] = "not a certificate";
    WolfCertHttpSessionCfg cfg = { .verify_server = 1 };
    WolfCertHttpSession* s = NULL;
    uint16_t port;
    char url[64];
    int ls;
    int rc;

    ls = black_hole_listener(&port);
    REQUIRE(ls >= 0);
    snprintf(url, sizeof(url), "https://127.0.0.1:%d/", port);
    cfg.base_url          = url;
    cfg.trust_anchors     = sc->cert_pem;
    cfg.trust_anchors_len = sc->cert_pem_len;
    cfg.client_cert       = junk;
    cfg.client_cert_len   = sizeof(junk) - 1;
    cfg.client_key        = sc->key_pem;
    cfg.client_key_len    = sc->key_pem_len;
    wolfcert_clear_error();
    rc = wolfcert_http_session_open(&cfg, &s);
    REQUIRE(rc == WOLFCERT_ERR_TLS);
    REQUIRE(s == NULL);
    REQUIRE(strstr(wolfcert_last_error_message(), "client_cert") != NULL);

#ifndef NO_ASN_TIME
    cfg.client_cert = NULL;
    cfg.client_cert_len = 0;
    cfg.client_key = NULL;
    cfg.client_key_len = 0;
    wolfcert_clear_error();
    REQUIRE(wc_SetTimeCb(unset_clock) == 0);
    rc = wolfcert_http_session_open(&cfg, &s);
    wc_SetTimeCb(NULL);
    /* wolfSSL built with --enable-all loads the anchor regardless. */
    if (rc == WOLFCERT_OK) {
        wolfcert_http_session_close(s);
        s = NULL;
    }
    else {
        REQUIRE(rc == WOLFCERT_ERR_TLS_UNTRUSTED);
        REQUIRE(s == NULL);
        REQUIRE(strstr(wolfcert_last_error_message(), "trust_anchors")
                != NULL);
        REQUIRE(wolfcert_last_wolfssl_err() == ASN_BEFORE_DATE_E);
    }
#endif
    close(ls);
    return 0;
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
#ifndef OPENSSL_EXTRA
        /* OPENSSL_EXTRA reports some anchor-load OOM as a parse error. */
        REQUIRE(!failed || rc == WOLFCERT_ERR_MEMORY);
#endif
        if (rc == WOLFCERT_ERR_MEMORY &&
                wolfcert_last_wolfssl_err() == MEMORY_E &&
                strstr(wolfcert_last_error_message(), "SNI") != NULL)
            sni_oom = 1;
        found = rc == WOLFCERT_ERR_MEMORY &&
                wolfcert_last_wolfssl_err() == MEMORY_ERROR &&
                strstr(wolfcert_last_error_message(), "name to check") != NULL;
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

    /* Trusting another self-signed cert fails a session's first request,
     * after its open succeeds. */
    wolfcert_clear_error();
    REQUIRE(get_once(&sc, other.cert_pem, other.cert_pem_len, &open_rc, &resp)
            == WOLFCERT_ERR_TLS_UNTRUSTED);
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
    REQUIRE(get_as(&sc, "ca.example", 1, &open_rc)
            == WOLFCERT_ERR_TLS_UNTRUSTED);
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

    REQUIRE(test_client_cert_rejected(&sc, &other) == 0);
    REQUIRE(test_forged_alert(&sc, &other) == 0);
#if defined(WOLFSSL_POST_HANDSHAKE_AUTH) && defined(WOLFSSL_TLS13)
    REQUIRE(test_pha_rejected(&sc, &other) == 0);
#endif
    REQUIRE(test_refused_write(&sc) == 0);
    REQUIRE(test_custom_write_closed(&sc) == 0);
#ifndef NO_ASN_TIME
    REQUIRE(test_expired_server(&sc) == 0);
#endif
#ifndef NO_RSA
    REQUIRE(test_small_server_key(&dns) == 0);
#endif
    REQUIRE(test_setup_failure_detail(&sc) == 0);

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
