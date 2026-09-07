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
    /* Enrollment was accepted but is not yet ready:
     *   - SCEP PKCSReq / RenewalReq returned pkiStatus=3 (pending manual
     *     approval) - callers that used the richer `wolfcert_scep_*_ex`
     *     API see this through `WolfCertScepResult.status` instead.
     *   - EST /simpleenroll or /simplereenroll returned 202 Accepted
     *     (RFC 7030 section 4.2.3) - `wolfcert_est_simple_enroll_ex` /
     *     `_simple_reenroll_ex` surface the same state plus the
     *     `Retry-After` hint through `WolfCertEstResult.status`.
     * The error code is returned only by the simple-result entry points
     * that can't carry a richer result struct. */
    WOLFCERT_ERR_PENDING     = -13,

    /* Non-blocking session I/O: the call could not make progress
     * because the socket would block. The caller should wait for the
     * session fd to be readable / writable and re-invoke the same
     * call with the same arguments to resume. Only returned by the
     * *_nb entry points. */
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
