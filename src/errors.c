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

#include <wolfcert/errors.h>

const char* wolfcert_strerror(int err)
{
    switch (err) {
        case WOLFCERT_OK:
            return "ok";
        case WOLFCERT_ERR_GENERIC:
            return "generic error";
        case WOLFCERT_ERR_BAD_ARG:
            return "bad argument";
        case WOLFCERT_ERR_MEMORY:
            return "out of memory";
        case WOLFCERT_ERR_IO:
            return "I/O error";
        case WOLFCERT_ERR_TLS:
            return "TLS error";
        case WOLFCERT_ERR_HTTP:
            return "HTTP error";
        case WOLFCERT_ERR_PROTOCOL:
            return "protocol error";
        case WOLFCERT_ERR_AUTH:
            return "authentication error";
        case WOLFCERT_ERR_CRYPTO:
            return "cryptographic error";
        case WOLFCERT_ERR_PARSE:
            return "parse error";
        case WOLFCERT_ERR_NOT_FOUND:
            return "not found";
        case WOLFCERT_ERR_UNSUPPORTED:
            return "unsupported";
        case WOLFCERT_ERR_PENDING:
            return "pending (SCEP pkiStatus=3)";
        case WOLFCERT_ERR_WANT_READ:
            return "would block (want read)";
        case WOLFCERT_ERR_WANT_WRITE:
            return "would block (want write)";
        case WOLFCERT_ERR_CONN_CLOSED:
            return "connection closed by peer";
        default:
            return "unknown error";
    }
}
