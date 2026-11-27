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

/* Built-in POSIX transport: connect timeouts, signals, SIGPIPE suppression. */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#define _DARWIN_C_SOURCE   /* expose INADDR_LOOPBACK on macOS */

#include <wolfcert/wolfcert.h>
#include <wolfcert/http.h>
#include "internal.h"
#include "../test_static_mem.h"
#include "../net_test_util.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define REQUIRE(cond) \
    do {                                                                    \
        if (!(cond)) {                                                      \
            fprintf(stderr, "FAIL %s:%d %s\n", __FILE__, __LINE__, #cond);  \
            return 1;                                                       \
        }                                                                   \
    } while (0)

static volatile sig_atomic_t g_sigpipe_raised;

static void note_sigpipe(int sig)
{
    (void)sig;
    g_sigpipe_raised = 1;
}

/* `nosigpipe` sets the socket option; `raw` sends with flags 0. */
static int write_to_dead_peer(int nosigpipe, int raw, int* out_rc)
{
    static const uint8_t body[256] = { 0 };
    struct sigaction     sa, old;
    int                  sv[2];

    /* SO_NOSIGPIPE fails with EINVAL once the peer is closed. */
    REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    if (nosigpipe)
        wolfcert_sock_nosigpipe(sv[0]);
    close(sv[1]);

    /* Catch the signal since CI runs every test with SIGPIPE ignored. */
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = note_sigpipe;
    sigemptyset(&sa.sa_mask);
    REQUIRE(sigaction(SIGPIPE, &sa, &old) == 0);
    g_sigpipe_raised = 0;

    if (raw)
        *out_rc = (int)send(sv[0], body, sizeof(body), 0);
    else
        *out_rc = wolfcert_posix_transport.write(NULL, (void*)(intptr_t)sv[0],
                                                 body, sizeof(body), 0);

    REQUIRE(sigaction(SIGPIPE, &old, NULL) == 0);
    close(sv[0]);

    return 0;
}

static int test_no_sigpipe_on_dead_peer(void)
{
    int rc = 0;

    REQUIRE(write_to_dead_peer(1, 0, &rc) == 0);
    REQUIRE(g_sigpipe_raised == 0);
    REQUIRE(rc == WOLFCERT_ERR_IO);

    return 0;
}

#ifdef MSG_NOSIGNAL
static int test_send_flag_alone_suppresses(void)
{
    int rc = 0;

    REQUIRE(write_to_dead_peer(0, 0, &rc) == 0);
    REQUIRE(g_sigpipe_raised == 0);
    REQUIRE(rc == WOLFCERT_ERR_IO);

    return 0;
}
#endif

#ifdef SO_NOSIGPIPE
static int test_sock_nosigpipe_suppresses(void)
{
    int rc = 0;

    REQUIRE(write_to_dead_peer(1, 1, &rc) == 0);
    REQUIRE(g_sigpipe_raised == 0);
    REQUIRE(rc < 0);

    return 0;
}
#endif

static void note_alarm(int sig)
{
    (void)sig;
}

/* SIGALRM every 20 ms without SA_RESTART, so blocking calls see EINTR. */
static int alarms_start(void)
{
    struct sigaction sa;
    struct itimerval it;
    sigset_t alrm;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = note_alarm;
    sigemptyset(&sa.sa_mask);
    sigemptyset(&alrm);
    sigaddset(&alrm, SIGALRM);
    REQUIRE(sigaction(SIGALRM, &sa, NULL) == 0);
    REQUIRE(sigprocmask(SIG_UNBLOCK, &alrm, NULL) == 0);

    memset(&it, 0, sizeof(it));
    it.it_interval.tv_usec = 20000;
    it.it_value.tv_usec    = 20000;
    REQUIRE(setitimer(ITIMER_REAL, &it, NULL) == 0);
    return 0;
}

static int alarms_stop(void)
{
    struct itimerval off;

    memset(&off, 0, sizeof(off));
    REQUIRE(setitimer(ITIMER_REAL, &off, NULL) == 0);
    return 0;
}

/* Signals during a timed connect must not stretch or cut short its deadline.
 * Needs a host where 10.255.255.1 times out; baseline_ms is that timeout. */
static int test_connect_eintr_keeps_deadline(int64_t baseline_ms)
{
    int64_t t0;
    int64_t elapsed;
    int fd;

    if (baseline_ms < 240) {
        printf("skip: 10.255.255.1 is refused here, not blackholed\n");
        return 0;
    }

    if (alarms_start())
        return 1;
    t0 = wolfcert_mono_ms();
    fd = wolfcert_posix_connect("10.255.255.1", 9, 300, NULL);
    elapsed = wolfcert_mono_ms() - t0;
    if (alarms_stop())
        return 1;
    if (fd >= 0)
        close(fd);

    REQUIRE(fd < 0);
    REQUIRE(elapsed >= 250);
    REQUIRE(elapsed < 3000);
    printf("connect under signals returned in %ldms\n", (long)elapsed);
    return 0;
}

/* An unresolvable host and a refused loopback connect fail with IO; the
 * refusal sets errno ECONNREFUSED. */
static int test_connect_errno(void)
{
    void* conn = NULL;
    uint16_t port = 0;
    int ls = black_hole_listener(&port);

    REQUIRE(ls >= 0);
    close(ls);

    REQUIRE(wolfcert_posix_transport.connect(NULL, "", 443, 1000, &conn)
            == WOLFCERT_ERR_IO);
    REQUIRE(wolfcert_posix_connect("127.0.0.1", port, 1000, NULL) < 0);
    REQUIRE(errno == ECONNREFUSED);
    REQUIRE(wolfcert_posix_transport.connect(NULL, "127.0.0.1", port, 1000,
                                             &conn) == WOLFCERT_ERR_IO);
    return 0;
}

/* The built-in connect to 10.255.255.1 with 250 ms returns TIMEOUT. Needs a
 * host where that address times out; baseline_ms is that timeout. */
static int test_connect_times_out(int64_t baseline_ms)
{
    void* conn = NULL;

    if (baseline_ms < 240)
        return 0;
    REQUIRE(wolfcert_posix_transport.connect(NULL, "10.255.255.1", 9, 250,
                                             &conn) == WOLFCERT_ERR_TIMEOUT);
    return 0;
}

/* A transport write to a peer that stops reading fails with TIMEOUT after
 * timeout_ms. */
static int test_write_times_out(void)
{
    static const uint8_t chunk[4096] = { 0 };
    int64_t t0;
    int64_t elapsed;
    int sv[2];
    int rc;

    REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    rc = fcntl(sv[0], F_SETFL, fcntl(sv[0], F_GETFL, 0) | O_NONBLOCK);
    while (rc == 0 && send(sv[0], chunk, sizeof(chunk), 0) > 0)
        ;
    if (rc != 0) {
        close(sv[0]);
        close(sv[1]);
        return 1;
    }

    t0 = wolfcert_mono_ms();
    rc = wolfcert_posix_transport.write(NULL, (void*)(intptr_t)sv[0], chunk,
                                        sizeof(chunk), 300);
    elapsed = wolfcert_mono_ms() - t0;
    close(sv[0]);
    close(sv[1]);

    REQUIRE(rc == WOLFCERT_ERR_TIMEOUT);
    REQUIRE(elapsed >= 250);
    REQUIRE(elapsed < 3000);
    return 0;
}

/* A blocking request to a peer that never answers fails with TIMEOUT after
 * timeout_ms, over plain HTTP and in the TLS handshake, signals or not. */
static int test_silent_peer_times_out(const char* scheme, int signals)
{
    WolfCertHttpRequest req = { .method = "GET" };
    WolfCertHttpSessionCfg cfg = { 0 };
    WolfCertHttpResponse resp = { 0 };
    WolfCertHttpSession* s = NULL;
    char url[64];
    int64_t t0;
    int64_t elapsed;
    uint16_t port = 0;
    int ls = black_hole_listener(&port);
    int rc;

    REQUIRE(ls >= 0);
    snprintf(url, sizeof(url), "%s://127.0.0.1:%d/", scheme, port);
    req.url        = url;
    cfg.base_url   = url;
    cfg.timeout_ms = 300;
    rc = wolfcert_http_session_open(&cfg, &s);
    if (rc != WOLFCERT_OK)
        close(ls);
    REQUIRE(rc == WOLFCERT_OK);

    if (signals && alarms_start()) {
        wolfcert_http_session_close(s);
        close(ls);
        return 1;
    }
    t0 = wolfcert_mono_ms();
    rc = wolfcert_http_session_request(s, &req, &resp);
    elapsed = wolfcert_mono_ms() - t0;
    if (signals && alarms_stop()) {
        wolfcert_http_session_close(s);
        close(ls);
        return 1;
    }
    wolfcert_http_response_free(&resp);
    wolfcert_http_session_close(s);
    close(ls);

    REQUIRE(rc == WOLFCERT_ERR_TIMEOUT);
    REQUIRE(elapsed >= 250);
    REQUIRE(elapsed < 3000);
    return 0;
}

int main(void)
{
    REQUIRE(test_static_mem_init() == 0);

    /* Connect with a 1000 ms timeout to a loopback listener succeeds. */
    int ls = socket(AF_INET, SOCK_STREAM, 0);
    REQUIRE(ls >= 0);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family      = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port        = 0;
    REQUIRE(bind(ls, (struct sockaddr*)&sa, sizeof(sa)) == 0);
    REQUIRE(listen(ls, 8) == 0);
    socklen_t slen = sizeof(sa);
    REQUIRE(getsockname(ls, (struct sockaddr*)&sa, &slen) == 0);
    int port = ntohs(sa.sin_port);

    int fd = wolfcert_posix_connect("127.0.0.1", port, 1000, NULL);
    REQUIRE(fd >= 0);
    close(fd);
    fd = wolfcert_posix_connect("127.0.0.1", port, 0, NULL);
    REQUIRE(fd >= 0);
    close(fd);
    close(ls);

    /* An unroutable address must fail well under the OS default (~75s). */
    int64_t t0 = wolfcert_mono_ms();
    int fd2 = wolfcert_posix_connect("10.255.255.1", 9, 250, NULL);
    int64_t elapsed = wolfcert_mono_ms() - t0;
    REQUIRE(fd2 < 0);
    REQUIRE(elapsed < 3000);

    if (test_connect_eintr_keeps_deadline(elapsed) ||
        test_connect_times_out(elapsed) || test_connect_errno())
        return 1;

    REQUIRE(wolfcert_init(test_heap_hint()) == WOLFCERT_OK);
    if (test_silent_peer_times_out("http", 0) ||
        test_silent_peer_times_out("https", 0) ||
        test_silent_peer_times_out("http", 1))
        return 1;
    wolfcert_cleanup();

    if (test_write_times_out())
        return 1;

    if (test_no_sigpipe_on_dead_peer())
        return 1;

#ifdef MSG_NOSIGNAL
    if (test_send_flag_alone_suppresses())
        return 1;
#endif

#ifdef SO_NOSIGPIPE
    if (test_sock_nosigpipe_suppresses())
        return 1;
#endif

    printf("OK (unreachable connect returned in %ldms)\n", (long)elapsed);
    return 0;
}
