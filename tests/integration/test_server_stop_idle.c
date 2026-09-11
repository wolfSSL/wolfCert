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
 * Shutdown coverage for the accept loop in src/server.c: a peer that
 * connects and then sends nothing must not pin the serving thread past
 * wolfcert_server_stop().
 *
 * Four blocking points are exercised, each entered only once the peer has seen
 * the server reach it, so no case can pass without the server parked:
 *   1. A ClientHello answered by the server's flight, so the server is parked
 *      in wolfSSL_accept() waiting for the rest of the handshake.
 *   2. A completed TLS handshake with no request bytes, so the server is
 *      parked in the protocol handler's read.
 *   3. A served GetCACaps on a plaintext SCEP listener, so the keep-alive
 *      loop is parked in recv() on the next request.
 *   4. The same listener with a peer that trickles an unterminated request, so
 *      every receive succeeds and no timeout ever expires.
 *
 * In each case the test requires the server to still be running, calls
 * wolfcert_server_stop(), and requires wolfcert_server_run() to return
 * WOLFCERT_OK inside a bounded wait; a thread still running at the deadline
 * cannot be joined, so the test reports the failure and exits immediately
 * rather than hanging.
 *
 * A fifth case covers the other entry point: wolfcert_server_serve_fd()
 * runs on a caller-supplied fd that the accept loop never armed, so a
 * would-block read there must fail instead of retrying forever.
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#define _DARWIN_C_SOURCE
#define _GNU_SOURCE

#include <wolfcert/wolfcert.h>
#include <wolfcert/server.h>

#include "tls_test_util.h"

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/wc_port.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>
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

/* How long wolfcert_server_run() gets to return after stop(), and the
 * granularity the test polls at. */
#define STOP_DEADLINE_MS 5000
#define POLL_STEP_MS     10

/* The accept loop is what these cases exercise, so any compiled-in protocol
 * will do for the TLS listener; SCEP is absent from any NO_RSA build. */
#if defined(WOLFCERT_HAVE_EST)
    #define TLS_LISTENER_PROTO WOLFCERT_PROTO_EST
#else
    #define TLS_LISTENER_PROTO WOLFCERT_PROTO_SCEP
#endif

typedef struct {
    WolfCertServer*    srv;
    int                run_rc;
    /* Atomic, not volatile: the poll below needs a happens-before edge
     * against the serving thread, the same way srv->stopping does. */
    wolfSSL_Atomic_Int returned;
} ServerCtx;

static void* server_thread(void* arg)
{
    ServerCtx* ctx = (ServerCtx*)arg;

    ctx->run_rc = wolfcert_server_run(ctx->srv);
    WOLFSSL_ATOMIC_STORE(ctx->returned, 1);

    return NULL;
}

static void sleep_ms(int ms)
{
    struct timespec ts;

    ts.tv_sec  = ms / 1000;
    ts.tv_nsec = (long)(ms % 1000) * 1000000L;
    nanosleep(&ts, NULL);
}

#ifdef WOLFCERT_HAVE_SCEP
/* Connect to 127.0.0.1:port. Returns the fd, or -1. */
static int connect_loopback(uint16_t port)
{
    struct sockaddr_in sa;
    int fd;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;

    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port   = htons(port);
    if (inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr) != 1 ||
            connect(fd, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
        close(fd);
        return -1;
    }

    return fd;
}

/* Drive one plaintext GetCACaps to completion, so the reply proves the handler
 * ran and the keep-alive loop is now parked reading the next request. */
static int connect_after_getcacaps(uint16_t port)
{
    static const char req[] =
        "GET /?operation=GetCACaps HTTP/1.1\r\n"
        "Host: 127.0.0.1\r\n"
        "\r\n";
    struct timeval to;
    char buf[64];
    int fd;

    fd = connect_loopback(port);
    if (fd < 0)
        return -1;

    to.tv_sec  = STOP_DEADLINE_MS / 1000;
    to.tv_usec = 0;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &to, sizeof(to)) != 0 ||
            send(fd, req, sizeof(req) - 1, 0) != (ssize_t)(sizeof(req) - 1) ||
            recv(fd, buf, sizeof(buf), 0) <= 0) {
        close(fd);
        return -1;
    }

    return fd;
}
#endif /* WOLFCERT_HAVE_SCEP */

/* Stop the server and wait for its thread to leave wolfcert_server_run().
 * Returns 0 when it did, -1 on the deadline, -2 if it had already returned --
 * a case that must not be scored as a successful shutdown. */
static int stop_and_wait(ServerCtx* ctx)
{
    int waited;

    if (WOLFSSL_ATOMIC_LOAD(ctx->returned))
        return -2;

    if (wolfcert_server_stop(ctx->srv) != WOLFCERT_OK)
        return -1;

    for (waited = 0; waited < STOP_DEADLINE_MS; waited += POLL_STEP_MS) {
        if (WOLFSSL_ATOMIC_LOAD(ctx->returned))
            return 0;

        sleep_ms(POLL_STEP_MS);
    }

    return -1;
}

static int fail_stop(const char* which, int rc)
{
    if (rc == -2) {
        fprintf(stderr, "FAIL %s: server returned before stop() was called\n",
                which);
        return 1;
    }

    fprintf(stderr, "FAIL %s: did not return within %d ms\n",
            which, STOP_DEADLINE_MS);
    fflush(stderr);

    /* The serving thread is still blocked, so it cannot be joined. */
    _exit(1);
}

#ifdef WOLFCERT_HAVE_SCEP
/* A peer that keeps supplying bytes never lets a receive time out, so the
 * handler only leaves its read if the server checks the stopping flag. Sends
 * a request header that never terminates, a byte at a time. */
typedef struct {
    int                fd;
    wolfSSL_Atomic_Int halt;
} TrickleCtx;

/* Outlast the shutdown deadline several times over, so a server that keeps
 * consuming cannot reach the end of the trickle and pass by timing out. */
#define TRICKLE_STEP_MS 20
#define TRICKLE_MAX     ((STOP_DEADLINE_MS * 3) / TRICKLE_STEP_MS)

static void* trickle_thread(void* arg)
{
    TrickleCtx* ctx = (TrickleCtx*)arg;
    static const char head[] = "GET /?operation=GetCACaps&pad=";
    int i;

    if (send(ctx->fd, head, sizeof(head) - 1, 0) != (ssize_t)(sizeof(head) - 1))
        return NULL;

    for (i = 0; i < TRICKLE_MAX && !WOLFSSL_ATOMIC_LOAD(ctx->halt); i++) {
        if (send(ctx->fd, "a", 1, 0) != 1)
            break;

        sleep_ms(TRICKLE_STEP_MS);
    }

    return NULL;
}

typedef struct {
    WolfCertServer*    srv;
    int                fd;
    wolfSSL_Atomic_Int returned;
} ServeFdCtx;

static void* serve_fd_thread(void* arg)
{
    ServeFdCtx* ctx = (ServeFdCtx*)arg;

    (void)wolfcert_server_serve_fd(ctx->srv, ctx->fd);
    WOLFSSL_ATOMIC_STORE(ctx->returned, 1);

    return NULL;
}
#endif

int main(void)
{
    uint8_t* tls_cert = NULL;
    size_t   tls_cert_len = 0;
    uint8_t* tls_key = NULL;
    size_t   tls_key_len = 0;
    WolfCertServerCfgSrv cfg;
    ServerCtx ctx;
    pthread_t tid;
    TestTlsConn conn;
    int stop_rc;
#ifdef WOLFCERT_HAVE_SCEP
    ServeFdCtx serve_ctx;
    TrickleCtx trickle;
    pthread_t ttid;
    int fd;
    int sp[2];
    int waited;
#endif

    /* The trickle peer keeps writing into a connection the server tears down
     * on stop, so the test must survive the reset. */
    signal(SIGPIPE, SIG_IGN);

    REQUIRE(wolfcert_init(NULL) == WOLFCERT_OK);
    REQUIRE(gen_server_identity(&tls_cert, &tls_cert_len,
                                &tls_key, &tls_key_len) == 0);

    memset(&cfg, 0, sizeof(cfg));
    cfg.protocol         = TLS_LISTENER_PROTO;
    cfg.bind_host        = "127.0.0.1";
    cfg.bind_port        = 0;
    cfg.tls_cert_pem     = tls_cert;
    cfg.tls_cert_pem_len = tls_cert_len;
    cfg.tls_key_pem      = tls_key;
    cfg.tls_key_pem_len  = tls_key_len;

    /* 1. Parked in wolfSSL_accept(): TCP is up, no ClientHello follows. */
    memset(&ctx, 0, sizeof(ctx));
    REQUIRE(wolfcert_server_start(&cfg, &ctx.srv) == WOLFCERT_OK);
    REQUIRE(pthread_create(&tid, NULL, server_thread, &ctx) == 0);

    REQUIRE(test_tls_connect_partial(&conn, wolfcert_server_port(ctx.srv),
                                     tls_cert, tls_cert_len,
                                     STOP_DEADLINE_MS) == 0);

    stop_rc = stop_and_wait(&ctx);
    if (stop_rc != 0)
        return fail_stop("idle before handshake", stop_rc);

    REQUIRE(pthread_join(tid, NULL) == 0);
    REQUIRE(ctx.run_rc == WOLFCERT_OK);
    test_tls_close(&conn);
    wolfcert_server_free(ctx.srv);

    /* 2. Parked in the handler's read: handshake done, no request bytes. */
    memset(&ctx, 0, sizeof(ctx));
    REQUIRE(wolfcert_server_start(&cfg, &ctx.srv) == WOLFCERT_OK);
    REQUIRE(pthread_create(&tid, NULL, server_thread, &ctx) == 0);

    REQUIRE(test_tls_connect(&conn, wolfcert_server_port(ctx.srv),
                             tls_cert, tls_cert_len) == 0);

    stop_rc = stop_and_wait(&ctx);
    if (stop_rc != 0)
        return fail_stop("idle after handshake", stop_rc);

    REQUIRE(pthread_join(tid, NULL) == 0);
    REQUIRE(ctx.run_rc == WOLFCERT_OK);
    test_tls_close(&conn);
    wolfcert_server_free(ctx.srv);

#ifdef WOLFCERT_HAVE_SCEP
    /* 3. Parked in recv() on a plaintext listener. */
    memset(&cfg, 0, sizeof(cfg));
    cfg.protocol  = WOLFCERT_PROTO_SCEP;
    cfg.bind_host = "127.0.0.1";
    cfg.bind_port = 0;

    memset(&ctx, 0, sizeof(ctx));
    REQUIRE(wolfcert_server_start(&cfg, &ctx.srv) == WOLFCERT_OK);
    REQUIRE(pthread_create(&tid, NULL, server_thread, &ctx) == 0);

    fd = connect_after_getcacaps(wolfcert_server_port(ctx.srv));
    REQUIRE(fd >= 0);

    stop_rc = stop_and_wait(&ctx);
    if (stop_rc != 0)
        return fail_stop("idle on plaintext listener", stop_rc);

    REQUIRE(pthread_join(tid, NULL) == 0);
    REQUIRE(ctx.run_rc == WOLFCERT_OK);
    close(fd);
    wolfcert_server_free(ctx.srv);

    /* 4. Parked in recv() with a peer that keeps trickling: no timeout ever
     *    expires, so only a stopping check can end the handler's read. */
    memset(&ctx, 0, sizeof(ctx));
    REQUIRE(wolfcert_server_start(&cfg, &ctx.srv) == WOLFCERT_OK);
    REQUIRE(pthread_create(&tid, NULL, server_thread, &ctx) == 0);

    fd = connect_after_getcacaps(wolfcert_server_port(ctx.srv));
    REQUIRE(fd >= 0);

    memset(&trickle, 0, sizeof(trickle));
    trickle.fd = fd;
    REQUIRE(pthread_create(&ttid, NULL, trickle_thread, &trickle) == 0);
    sleep_ms(TRICKLE_STEP_MS * 5);

    stop_rc = stop_and_wait(&ctx);
    WOLFSSL_ATOMIC_STORE(trickle.halt, 1);
    REQUIRE(pthread_join(ttid, NULL) == 0);
    if (stop_rc != 0)
        return fail_stop("trickling peer", stop_rc);

    REQUIRE(pthread_join(tid, NULL) == 0);
    REQUIRE(ctx.run_rc == WOLFCERT_OK);
    close(fd);
    wolfcert_server_free(ctx.srv);

    /* 5. serve_fd() on a non-blocking fd the accept loop never armed: the
     *    read must surface the error instead of spinning on EAGAIN. */
    memset(&ctx, 0, sizeof(ctx));
    REQUIRE(wolfcert_server_start(&cfg, &ctx.srv) == WOLFCERT_OK);

    REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0);
    REQUIRE(fcntl(sp[0], F_SETFL, O_NONBLOCK) == 0);

    memset(&serve_ctx, 0, sizeof(serve_ctx));
    serve_ctx.srv = ctx.srv;
    serve_ctx.fd  = sp[0];
    REQUIRE(pthread_create(&tid, NULL, serve_fd_thread, &serve_ctx) == 0);

    for (waited = 0; waited < STOP_DEADLINE_MS &&
            !WOLFSSL_ATOMIC_LOAD(serve_ctx.returned);
            waited += POLL_STEP_MS) {
        sleep_ms(POLL_STEP_MS);
    }

    if (!WOLFSSL_ATOMIC_LOAD(serve_ctx.returned))
        return fail_stop("serve_fd on a non-blocking fd", -1);

    REQUIRE(pthread_join(tid, NULL) == 0);
    close(sp[0]);
    close(sp[1]);
    wolfcert_server_free(ctx.srv);
#endif

    free(tls_cert);
    free(tls_key);
    wolfcert_cleanup();

    printf("server stop idle: OK\n");
    return 0;
}
