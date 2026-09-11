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
 * Covers the built-in POSIX transport (wolfcert_posix_connect), in particular
 * the timeout path: a positive timeout_ms must drive the non-blocking
 * connect + poll machinery (success case against a local listener) and must
 * bound a connect to an unreachable host instead of hanging on the OS default
 * (~75s).
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#define _DARWIN_C_SOURCE   /* expose INADDR_LOOPBACK on macOS */

#include <wolfcert/wolfcert.h>
#include <wolfcert/http.h>
#include "internal.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
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

static long mono_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* Set by note_sigpipe(); a library write must leave it clear. */
static volatile sig_atomic_t g_sigpipe_raised;

static void note_sigpipe(int sig)
{
    (void)sig;
    g_sigpipe_raised = 1;
}

/* Write to a socketpair whose peer is closed, handler armed. `nosigpipe`
 * applies the socket option wolfcert_posix_connect() sets. */
static int write_to_dead_peer(int nosigpipe, int* out_rc)
{
    static const uint8_t body[256] = { 0 };
    struct sigaction     sa, old;
    int                  sv[2];

    /* Before closing the peer: setsockopt(SO_NOSIGPIPE) fails with EINVAL
     * once the peer is gone. */
    REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    if (nosigpipe)
        wolfcert_sock_nosigpipe(sv[0]);
    close(sv[1]);

    /* Catch, not ignore, so "not raised" differs from "raised and
     * swallowed"; CI runs every test with SIGPIPE ignored. */
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = note_sigpipe;
    sigemptyset(&sa.sa_mask);
    REQUIRE(sigaction(SIGPIPE, &sa, &old) == 0);
    g_sigpipe_raised = 0;

    *out_rc = wolfcert_posix_transport.write(NULL, (void*)(intptr_t)sv[0],
                                             body, sizeof(body), 0);

    REQUIRE(sigaction(SIGPIPE, &old, NULL) == 0);
    close(sv[0]);

    return 0;
}

/* Both arms in force. WOLFCERT_ERR_IO pins that the write reached send(). */
static int test_no_sigpipe_on_dead_peer(void)
{
    int rc = 0;

    REQUIRE(write_to_dead_peer(1, &rc) == 0);
    REQUIRE(g_sigpipe_raised == 0);
    REQUIRE(rc == WOLFCERT_ERR_IO);

    return 0;
}

#ifdef MSG_NOSIGNAL
/* No socket option: the send flag alone must suppress the signal. */
static int test_send_flag_alone_suppresses(void)
{
    int rc = 0;

    REQUIRE(write_to_dead_peer(0, &rc) == 0);
    REQUIRE(g_sigpipe_raised == 0);
    REQUIRE(rc == WOLFCERT_ERR_IO);

    return 0;
}
#endif

int main(void)
{
    /* Success path with a positive timeout: stand up a loopback listener and
     * connect to it. timeout_ms > 0 exercises the non-blocking connect + poll
     * + SO_ERROR branch deterministically. */
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
    close(ls);

    /* Timeout path: an unroutable address must fail (fd < 0) and return fast.
     * Without the timeout this would block on the OS default (~75s); we only
     * assert it stays well under that, so the test is robust whether the host
     * times out at ~250ms or fast-fails with no route. */
    long t0 = mono_ms();
    int fd2 = wolfcert_posix_connect("10.255.255.1", 9, 250, NULL);
    long elapsed = mono_ms() - t0;
    REQUIRE(fd2 < 0);
    REQUIRE(elapsed < 3000);

    if (test_no_sigpipe_on_dead_peer())
        return 1;

#ifdef MSG_NOSIGNAL
    if (test_send_flag_alone_suppresses())
        return 1;
#endif

    printf("OK (unreachable connect returned in %ldms)\n", elapsed);
    return 0;
}
