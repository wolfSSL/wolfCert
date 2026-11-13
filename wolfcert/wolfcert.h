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
 * @file wolfcert.h
 * Umbrella header for the wolfCert library.
 */

#ifndef WOLFCERT_H
#define WOLFCERT_H

#include <wolfcert/version.h>
#include <wolfcert/api.h>
#include <wolfcert/errors.h>
#include <wolfcert/status.h>
#include <wolfcert/log.h>
#include <wolfcert/types.h>
#include <wolfcert/memory.h>
#include <wolfcert/keygen.h>
#include <wolfcert/csr.h>
#include <wolfcert/http.h>
#ifdef WOLFCERT_HAVE_EST
#  include <wolfcert/est.h>
#endif
#ifdef WOLFCERT_HAVE_SCEP
#  include <wolfcert/scep.h>
#endif
#include <wolfcert/client.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Process init, including wolfSSL_Init(). heap sets the default heap hint
 * (NULL = system allocator). Calls nest in matched pairs with
 * wolfcert_cleanup(). */
WOLFCERT_API int wolfcert_init(void* heap);
WOLFCERT_API void wolfcert_cleanup(void);

#ifdef __cplusplus
}
#endif

#endif /* WOLFCERT_H */
