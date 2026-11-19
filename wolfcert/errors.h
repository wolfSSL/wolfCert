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

#ifndef WOLFCERT_ERRORS_H
#define WOLFCERT_ERRORS_H

#include <wolfcert/api.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
    WOLFCERT_OK              =   0,
    WOLFCERT_ERR_GENERIC     =  -1,
    WOLFCERT_ERR_BAD_ARG     =  -2,
    WOLFCERT_ERR_MEMORY      =  -3,
    WOLFCERT_ERR_IO          =  -4,
    WOLFCERT_ERR_TLS         =  -5,
    WOLFCERT_ERR_HTTP        =  -6,
    WOLFCERT_ERR_PROTOCOL    =  -7,
    WOLFCERT_ERR_AUTH        =  -8,
    WOLFCERT_ERR_CRYPTO      =  -9,
    WOLFCERT_ERR_PARSE       = -10,
    WOLFCERT_ERR_NOT_FOUND   = -11,
    WOLFCERT_ERR_UNSUPPORTED = -12,
    /* Enrollment parked for approval: wolfcert_client_enroll and _reenroll
     * return it with their result PENDING; the other enroll calls return OK. */
    WOLFCERT_ERR_PENDING     = -13,

    /* Returned by the _nb calls when the socket would block. The same call
     * with the same arguments resumes once the session fd is ready. */
    WOLFCERT_ERR_WANT_READ   = -14,
    WOLFCERT_ERR_WANT_WRITE  = -15,

    WOLFCERT_ERR_CONN_CLOSED = -16
};

/* Returns a human-readable description of a wolfCert error code. */
WOLFCERT_API const char* wolfcert_strerror(int err);

#ifdef __cplusplus
}
#endif

#endif /* WOLFCERT_ERRORS_H */
