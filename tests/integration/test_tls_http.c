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

/*
 * Exercises the TLS path of wolfcert_http_request: stands up a single-
 * shot wolfSSL TLS server on loopback with a freshly-generated self-
 * signed RSA cert, then fires an HTTPS request at it. Verifies that
 * wolfCert's trust-anchor handling, SNI, and hostname check all work.
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#define _DARWIN_C_SOURCE   /* expose memmem/strcasestr/INADDR_LOOPBACK on macOS */

#include <wolfcert/wolfcert.h>

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/wc_port.h>

#include "tls_test_util.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
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
/* Nothing below can open a socket in a build with no built-in transport. */
int main(void)
{
    return 77;
}
#else

struct srv_ctx {
    /* Published by srv_thread once the ephemeral listener is bound, then
     * polled by the main thread. Atomic so the cross-thread handoff has a
     * happens-before edge (this is what ThreadSanitizer requires). */
    wolfSSL_Atomic_Int port;
    uint8_t* cert_pem;
    size_t cert_pem_len;
    uint8_t* key_pem;
    size_t key_pem_len;
};

static void* srv_thread(void* arg)
{
    struct srv_ctx* sc = (struct srv_ctx*)arg;
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(wolfTLSv1_2_server_method());
    if (ctx == NULL)
        return NULL;
    if (wolfSSL_CTX_use_certificate_buffer(ctx, sc->cert_pem,
            (long)sc->cert_pem_len, WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS) return NULL;
    if (wolfSSL_CTX_use_PrivateKey_buffer(ctx, sc->key_pem,
            (long)sc->key_pem_len, WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS) return NULL;

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

int main(void)
{
    REQUIRE(wolfcert_init(NULL) == WOLFCERT_OK);
    struct srv_ctx sc = { 0 };
    REQUIRE(gen_server_identity(&sc.cert_pem, &sc.cert_pem_len,
                                &sc.key_pem, &sc.key_pem_len) == 0);

    pthread_t tid;
    REQUIRE(pthread_create(&tid, NULL, srv_thread, &sc) == 0);
    for (int i = 0; i < 200 && WOLFSSL_ATOMIC_LOAD(sc.port) == 0; ++i) {
        const struct timespec ts = { 0, 5 * 1000 * 1000 };
        nanosleep(&ts, NULL);
    }
    REQUIRE(WOLFSSL_ATOMIC_LOAD(sc.port) != 0);

    char url[128];
    snprintf(url, sizeof(url), "https://127.0.0.1:%d/", WOLFSSL_ATOMIC_LOAD(sc.port));

    WolfCertHttpRequest req = {
        .method            = "GET",
        .url               = url,
        .trust_anchors     = sc.cert_pem,
        .trust_anchors_len = sc.cert_pem_len,
        .verify_server     = 1,
    };
    WolfCertHttpResponse resp = { 0 };
    int rc = wolfcert_http_request(&req, &resp);
    REQUIRE(rc == WOLFCERT_OK);
    REQUIRE(resp.status_code == 200);
    REQUIRE(resp.body_len == 2 && memcmp(resp.body, "ok", 2) == 0);
    wolfcert_http_response_free(&resp);

    pthread_join(tid, NULL);
    free(sc.cert_pem);
    free(sc.key_pem);
    wolfcert_cleanup();
    printf("OK\n");
    return 0;
}

#endif
