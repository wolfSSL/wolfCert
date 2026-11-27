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
    /* Enrollment accepted but not issued yet (EST 202 Accepted, RFC 7030
     * section 4.2.3), from wolfcert_client_enroll and _reenroll. Calls that
     * fill a result struct report it in its status instead. */
    WOLFCERT_ERR_PENDING     = -13,

    /* Returned by the _nb calls when the socket would block. The same call
     * with the same arguments resumes once the session fd is ready. */
    WOLFCERT_ERR_WANT_READ   = -14,
    WOLFCERT_ERR_WANT_WRITE  = -15,

    WOLFCERT_ERR_CONN_CLOSED = -16,

    /* The server refused the client certificate with an alert about it, such
     * as unknown_ca or certificate_expired, after a TLS 1.3 handshake. The
     * alert is authenticated only with verify_server, which EST and HTTPS SCEP
     * require. It is reported when wolfSSL reads the alert before a write to
     * the closed connection fails; otherwise the request gets WOLFCERT_ERR_TLS
     * or WOLFCERT_ERR_IO. Any other alert, including a TLS 1.2 one that may be
     * forged, gives WOLFCERT_ERR_TLS with the alert named in the error
     * message. */
    WOLFCERT_ERR_TLS_PEER_REJECTED = -17,
    /* The server certificate failed verification against trust_anchors, for
     * example an unknown issuer, outside its validity period, a name mismatch,
     * a key usage, path length or critical extension violation, or a key below
     * wolfSSL's minimum size. Session open returns it when a trust anchor is
     * not valid at the device time. */
    WOLFCERT_ERR_TLS_UNTRUSTED     = -18,

    /* A transport wait outlasted its bound: timeout_ms of the config, or the
     * transport's own. */
    WOLFCERT_ERR_TIMEOUT           = -19
};

/* Returns a human-readable description of a wolfCert error code. */
WOLFCERT_API const char* wolfcert_strerror(int err);

#ifdef __cplusplus
}
#endif

#endif /* WOLFCERT_ERRORS_H */
