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

/* Built-in BSD-sockets WolfCertTransport. */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#define _DARWIN_C_SOURCE

#include <wolfcert/http.h>
#include <wolfcert/errors.h>
#include "internal.h"

#include <errno.h>
#include <limits.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

/* Suppress SIGPIPE per send(); the process disposition is the application's. */
#ifdef MSG_NOSIGNAL
#define WOLFCERT_SEND_FLAGS MSG_NOSIGNAL
#else
#define WOLFCERT_SEND_FLAGS 0
#endif

void wolfcert_sock_nosigpipe(int fd)
{
#ifdef SO_NOSIGPIPE
    int on = 1;

    (void)setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof(on));
#else
    (void)fd;
#endif
}

int64_t wolfcert_mono_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* timeout_ms <= 0 blocks. Returns 0 on success, -1 on error or timeout. */
static int connect_timeout(int fd, const struct sockaddr* addr, socklen_t alen,
                           int timeout_ms)
{
    if (timeout_ms <= 0) {
        int rc;
        do {
            rc = connect(fd, addr, alen);
        }
        while (rc != 0 && errno == EINTR);

        return rc == 0 ? 0 : -1;
    }

    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0)
        return -1;

    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        return -1;
    }

    int rc = connect(fd, addr, alen);
    if (rc != 0 && errno == EINPROGRESS) {
        struct pollfd pfd = { .fd = fd, .events = POLLOUT };
        int pr;
        do {
            pr = poll(&pfd, 1, timeout_ms);
        }
        while (pr < 0 && errno == EINTR);

        if (pr <= 0) {
            rc = -1;
        }
        else {
            int err = 0;
            socklen_t elen = sizeof(err);
            if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &elen) < 0 || err != 0)
                rc = -1;
            else
                rc = 0;
        }
    }
    else if (rc != 0) {
        rc = -1;
    }

    (void)fcntl(fd, F_SETFL, flags);

    return rc;
}

int wolfcert_posix_connect(const char* host, int port, int timeout_ms, void* ctx)
{
    (void)ctx;
    if (host == NULL)
        return -1;

    char port_s[16];
    snprintf(port_s, sizeof(port_s), "%d", port);

    struct addrinfo hints, *res, *rp;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host, port_s, &hints, &res) != 0)
        return -1;

    /* timeout_ms bounds the whole connect across all candidate addresses. */
    int64_t deadline = (timeout_ms > 0) ? wolfcert_mono_ms() + timeout_ms : 0;

    int fd = -1;
    for (rp = res; rp != NULL; rp = rp->ai_next) {
        int attempt_ms = timeout_ms;
        if (timeout_ms > 0) {
            attempt_ms = (int)(deadline - wolfcert_mono_ms());
            if (attempt_ms <= 0) {
                break;
            }
        }
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0)
            continue;

        wolfcert_sock_nosigpipe(fd);

        if (connect_timeout(fd, rp->ai_addr, rp->ai_addrlen, attempt_ms) == 0)
            break;

        close(fd);
        fd = -1;
    }

    freeaddrinfo(res);
    return fd;
}

/* Returns `want` when fd is not ready and timeout_ms is 0. */
static int posix_wait(int fd, short events, int timeout_ms, int want)
{
    struct pollfd pfd;
    int pr;

    pfd.fd      = fd;
    pfd.events  = events;
    pfd.revents = 0;

    do {
        pr = poll(&pfd, 1, timeout_ms);
    } while (pr < 0 && errno == EINTR);

    if (pr < 0)
        return WOLFCERT_ERR_IO;
    if (pr == 0)
        return (timeout_ms == 0) ? want : WOLFCERT_ERR_IO;

    return WOLFCERT_OK;
}

#if defined(EWOULDBLOCK) && EWOULDBLOCK != EAGAIN
    #define WOLFCERT_WOULDBLOCK(e) ((e) == EAGAIN || (e) == EWOULDBLOCK)
#else
    #define WOLFCERT_WOULDBLOCK(e) ((e) == EAGAIN)
#endif

/* poll() readiness only promises one byte, so owned sockets stay O_NONBLOCK. */
static int set_nonblock(int fd)
{
    int fl = fcntl(fd, F_GETFL, 0);

    if (fl < 0 || fcntl(fd, F_SETFL, fl | O_NONBLOCK) < 0)
        return WOLFCERT_ERR_IO;

    return WOLFCERT_OK;
}

static int posix_connect(void* ctx, const char* host, int port,
                         int timeout_ms, void** conn)
{
    int fd;

    if (host == NULL || conn == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    fd = wolfcert_posix_connect(host, port, timeout_ms, ctx);
    if (fd < 0)
        return WOLFCERT_ERR_IO;

    if (set_nonblock(fd) != WOLFCERT_OK) {
        (void)close(fd);
        return WOLFCERT_ERR_IO;
    }

    *conn = (void*)(intptr_t)fd;
    return WOLFCERT_OK;
}

static int posix_read(void* ctx, void* conn, uint8_t* buf, size_t len,
                      int timeout_ms)
{
    int fd = (int)(intptr_t)conn;
    ssize_t n;
    int rc;

    (void)ctx;

    if (buf == NULL || len == 0)
        return WOLFCERT_ERR_BAD_ARG;
    if (len > INT_MAX)
        len = INT_MAX;

    for (;;) {
        rc = posix_wait(fd, POLLIN, timeout_ms, WOLFCERT_ERR_WANT_READ);
        if (rc != WOLFCERT_OK)
            return rc;

        do {
            n = recv(fd, buf, len, 0);
        } while (n < 0 && errno == EINTR);

        if (n > 0)
            return (int)n;
        if (n == 0)
            return WOLFCERT_ERR_CONN_CLOSED;

        /* Readiness can be spurious; only an unbounded caller retries. */
        if (!WOLFCERT_WOULDBLOCK(errno))
            return WOLFCERT_ERR_IO;
        if (timeout_ms >= 0)
            return WOLFCERT_ERR_WANT_READ;
    }
}

static int posix_write(void* ctx, void* conn, const uint8_t* buf, size_t len,
                       int timeout_ms)
{
    int fd = (int)(intptr_t)conn;
    ssize_t n;
    int rc;

    (void)ctx;

    if (buf == NULL || len == 0)
        return WOLFCERT_ERR_BAD_ARG;
    if (len > INT_MAX)
        len = INT_MAX;

    for (;;) {
        rc = posix_wait(fd, POLLOUT, timeout_ms, WOLFCERT_ERR_WANT_WRITE);
        if (rc != WOLFCERT_OK)
            return rc;

        do {
            n = send(fd, buf, len, WOLFCERT_SEND_FLAGS);
        } while (n < 0 && errno == EINTR);

        if (n > 0)
            return (int)n;
        if (n == 0)
            return WOLFCERT_ERR_IO;

        if (!WOLFCERT_WOULDBLOCK(errno))
            return WOLFCERT_ERR_IO;
        if (timeout_ms >= 0)
            return WOLFCERT_ERR_WANT_WRITE;
    }
}

static int posix_disconnect(void* ctx, void* conn)
{
    (void)ctx;

    if (close((int)(intptr_t)conn) != 0)
        return WOLFCERT_ERR_IO;

    return WOLFCERT_OK;
}

const WolfCertTransport wolfcert_posix_transport = {
    posix_connect, posix_read, posix_write, posix_disconnect, NULL
};

int wolfcert_transport_fd(const WolfCertTransport* t, void* conn)
{
    if (t == NULL || t->connect != posix_connect)
        return -1;

    return (int)(intptr_t)conn;
}
