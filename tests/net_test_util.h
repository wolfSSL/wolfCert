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

/* Loopback socket helpers for tests that need no TLS identity. */

#ifndef WOLFCERT_TEST_NET_UTIL_H
#define WOLFCERT_TEST_NET_UTIL_H

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* Loopback listener that never accepts. Returns the fd and sets *out_port,
 * or -1. */
static inline int black_hole_listener(uint16_t* out_port)
{
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_port        = 0;   /* ephemeral */
    if (inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr) != 1 ||
            bind(fd, (struct sockaddr*)&addr, sizeof(addr)) != 0 ||
            listen(fd, 16) != 0 ||
            getsockname(fd, (struct sockaddr*)&addr, &addr_len) != 0) {
        close(fd);
        return -1;
    }

    *out_port = ntohs(addr.sin_port);
    return fd;
}

#endif /* WOLFCERT_TEST_NET_UTIL_H */
