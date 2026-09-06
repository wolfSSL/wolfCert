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
 * Built-in POSIX/BSD-sockets WolfCertTransport, used when a config leaves
 * `transport` NULL. It lives in its own translation unit so the core HTTP/TLS
 * logic holds no syscalls, and so a platform without BSD sockets can supply
 * its own transport and leave this file out of the link.
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

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

static long mono_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* Connect `fd` to `addr`, giving up after timeout_ms (<= 0 = block until the
 * OS gives up). Returns 0 on success, -1 on error/timeout. The socket is left
 * in blocking mode on success so the rest of the stack (and wolfSSL) sees a
 * normal fd. */
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
        /* nothing changed; nothing to restore */
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
            /* timeout (0) or poll error (<0) */
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
        /* immediate failure */
        rc = -1;
    }

    /* restore blocking mode */
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

    /* timeout_ms bounds the whole connect, not each candidate address: with a
     * multi-homed host we shrink the per-attempt budget by what already
     * elapsed so the total stays within the caller's deadline. */
    long deadline = (timeout_ms > 0) ? mono_ms() + timeout_ms : 0;

    int fd = -1;
    for (rp = res; rp != NULL; rp = rp->ai_next) {
        int attempt_ms = timeout_ms;
        if (timeout_ms > 0) {
            attempt_ms = (int)(deadline - mono_ms());
            if (attempt_ms <= 0) {
                /* budget exhausted */
                break;
            }
        }
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0)
            continue;

        if (connect_timeout(fd, rp->ai_addr, rp->ai_addrlen, attempt_ms) == 0)
            break;

        close(fd);
        fd = -1;
    }

    freeaddrinfo(res);
    return fd;
}

/* ---- WolfCertTransport instance ----------------------------------------- */

/* Wait for readiness. timeout_ms follows the transport contract: 0 polls,
 * > 0 caps the wait, < 0 blocks. `want` is what to report on a 0 timeout. */
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

/* A failed transfer is an I/O error unless it merely would block, so this is
 * the one errno the byte path reads. */
#if defined(EWOULDBLOCK) && EWOULDBLOCK != EAGAIN
    #define WOLFCERT_WOULDBLOCK(e) ((e) == EAGAIN || (e) == EWOULDBLOCK)
#else
    #define WOLFCERT_WOULDBLOCK(e) ((e) == EAGAIN)
#endif

/* poll() only promises that one byte can move, so the transfer must never
 * block; the wait is poll's job. Sockets the transport owns stay O_NONBLOCK. */
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

    /* This socket is ours, so poll() can own the timeout semantics. */
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

        /* poll() can report a readiness the transfer then declines. Only an
         * unbounded caller waits again; the others report it. */
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
            n = send(fd, buf, len, 0);
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

/* Dial through the deprecated connect_cb, keeping every fd detail in this file.
 * The descriptor belongs to the application, so only a non-blocking session
 * changes its mode; a blocking one leaves it exactly as supplied. */
int wolfcert_legacy_connect(WolfCertConnectFn cb, void* cb_ctx,
                            const char* host, int port, int timeout_ms,
                            int nonblocking, void** conn)
{
    int fd;

    if (cb == NULL || conn == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    fd = cb(host, port, timeout_ms, cb_ctx);
    if (fd < 0)
        return WOLFCERT_ERR_IO;

    if (nonblocking && set_nonblock(fd) != WOLFCERT_OK) {
        (void)close(fd);
        return WOLFCERT_ERR_IO;
    }

    *conn = (void*)(intptr_t)fd;
    return WOLFCERT_OK;
}

/* Byte path for a connection opened by wolfcert_legacy_connect. */
static int legacy_read(void* ctx, void* conn, uint8_t* buf, size_t len,
                       int timeout_ms)
{
    int fd = (int)(intptr_t)conn;
    ssize_t n;

    if (timeout_ms >= 0)
        return posix_read(ctx, conn, buf, len, timeout_ms);

    if (buf == NULL || len == 0)
        return WOLFCERT_ERR_BAD_ARG;
    if (len > INT_MAX)
        len = INT_MAX;

    do {
        n = recv(fd, buf, len, 0);
    } while (n < 0 && errno == EINTR);

    if (n > 0)
        return (int)n;
    if (n == 0)
        return WOLFCERT_ERR_CONN_CLOSED;

    /* A would-block here is the descriptor's own timeout expiring. */
    return WOLFCERT_ERR_IO;
}

static int legacy_write(void* ctx, void* conn, const uint8_t* buf, size_t len,
                        int timeout_ms)
{
    int fd = (int)(intptr_t)conn;
    ssize_t n;

    if (timeout_ms >= 0)
        return posix_write(ctx, conn, buf, len, timeout_ms);

    if (buf == NULL || len == 0)
        return WOLFCERT_ERR_BAD_ARG;
    if (len > INT_MAX)
        len = INT_MAX;

    do {
        n = send(fd, buf, len, 0);
    } while (n < 0 && errno == EINTR);

    if (n > 0)
        return (int)n;
    if (n == 0)
        return WOLFCERT_ERR_IO;

    return WOLFCERT_ERR_IO;
}

const WolfCertTransport wolfcert_legacy_transport = {
    NULL, legacy_read, legacy_write, posix_disconnect, NULL
};

int wolfcert_transport_is_fd_backed(const WolfCertTransport* t)
{
    return t == &wolfcert_posix_transport || t == &wolfcert_legacy_transport;
}
