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

#include <wolfssl/wolfio.h>
#include <wolfssl/error-ssl.h>

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

/* wolfIO_* return CBIO codes, which carry no direction: WANT_READ and
 * WANT_WRITE are the same value, so the caller supplies `want`. */
static int map_io(int n, int want)
{
    if (n > 0)
        return n;
    /* wolfSSL passes a 0-length read straight through, so map it here. */
    if (n == 0)
        return WOLFCERT_ERR_CONN_CLOSED;

    switch (n) {
        case WOLFSSL_CBIO_ERR_WANT_READ:  /* == WANT_WRITE */
            return want;
        case WOLFSSL_CBIO_ERR_CONN_CLOSE:
        case WOLFSSL_CBIO_ERR_CONN_RST:
            return WOLFCERT_ERR_CONN_CLOSED;
        default:
            return WOLFCERT_ERR_IO;
    }
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

    *conn = (void*)(intptr_t)fd;
    return WOLFCERT_OK;
}

static int posix_read(void* ctx, void* conn, uint8_t* buf, size_t len,
                      int timeout_ms)
{
    int fd = (int)(intptr_t)conn;
    int rc;
    int n;

    (void)ctx;

    if (buf == NULL || len == 0)
        return WOLFCERT_ERR_BAD_ARG;
    if (len > INT_MAX)
        len = INT_MAX;

    rc = posix_wait(fd, POLLIN, timeout_ms, WOLFCERT_ERR_WANT_READ);
    if (rc != WOLFCERT_OK)
        return rc;

    /* TranslateIoReturnCode reports EINTR rather than retrying. */
    do {
        n = wolfIO_Recv(fd, (char*)buf, (int)len, 0);
    } while (n == WOLFSSL_CBIO_ERR_ISR);

    return map_io(n, WOLFCERT_ERR_WANT_READ);
}

static int posix_write(void* ctx, void* conn, const uint8_t* buf, size_t len,
                       int timeout_ms)
{
    int fd = (int)(intptr_t)conn;
    int rc;
    int n;

    (void)ctx;

    if (buf == NULL || len == 0)
        return WOLFCERT_ERR_BAD_ARG;
    if (len > INT_MAX)
        len = INT_MAX;

    rc = posix_wait(fd, POLLOUT, timeout_ms, WOLFCERT_ERR_WANT_WRITE);
    if (rc != WOLFCERT_OK)
        return rc;

    do {
        n = wolfIO_Send(fd, (char*)(uintptr_t)buf, (int)len, 0);
    } while (n == WOLFSSL_CBIO_ERR_ISR);

    return map_io(n, WOLFCERT_ERR_WANT_WRITE);
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

/* Adapter for the deprecated connect_cb: http.c opens the connection itself
 * and attaches this, so the byte path stays the one above. */
const WolfCertTransport wolfcert_legacy_transport = {
    NULL, posix_read, posix_write, posix_disconnect, NULL
};

int wolfcert_transport_is_fd_backed(const WolfCertTransport* t)
{
    return t == &wolfcert_posix_transport || t == &wolfcert_legacy_transport;
}
