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

/**
 * @file status.h
 * Detail behind the last WOLFCERT_ERR_* code. The state is per-thread when
 * wolfSSL's THREAD_LS_T is thread-local (HAVE_THREAD_LS without NO_THREAD_LS,
 * outside FreeRTOS and Zephyr), and global otherwise.
 */

#ifndef WOLFCERT_STATUS_H
#define WOLFCERT_STATUS_H

#include <wolfcert/api.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Message for the most recent error, or "" if none. Valid until the error
 * state next changes. */
WOLFCERT_API const char* wolfcert_last_error_message(void);

/* wolfSSL error code behind the last failure; 0 if it was not a wolfSSL
 * failure or none occurred. */
WOLFCERT_API int wolfcert_last_wolfssl_err(void);

/* Reset the error state. */
WOLFCERT_API void wolfcert_clear_error(void);

#ifdef __cplusplus
}
#endif

#endif /* WOLFCERT_STATUS_H */
