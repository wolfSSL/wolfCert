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

/* Failing wolfSSL allocators for the out-of-memory sweeps. */

#ifndef WOLFCERT_TEST_OOM_H
#define WOLFCERT_TEST_OOM_H

#include <wolfcert/wolfcert.h>

#if defined(USE_WOLFSSL_MEMORY) && !defined(WOLFSSL_STATIC_MEMORY) && \
    !defined(WOLFSSL_DEBUG_MEMORY) && !defined(WOLFSSL_TRACK_MEMORY)
#define TEST_OOM

/* OPENSSL_EXTRA's GetCertName reports a failed X509_NAME allocation as
 * ASN_PARSE_E, indistinguishable from a bad certificate. */
#if !defined(OPENSSL_EXTRA) && !defined(OPENSSL_EXTRA_X509_SMALL)
#define TEST_OOM_CERT_NAME
#endif

#include <wolfssl/wolfcrypt/memory.h>

#include <stdlib.h>

/* Zephyr's main thread is not a pthread; only it calls wolfSSL in the test
 * images. */
#ifndef WOLFSSL_ZEPHYR
#include <pthread.h>

static pthread_t g_oom_thread;
#endif
/* Allocations left before the refused one; -1 refuses none. */
static int g_oom_fail_at = -1;
static int g_oom_failed;

static inline int test_oom_refuse(void)
{
#ifndef WOLFSSL_ZEPHYR
    if (!pthread_equal(pthread_self(), g_oom_thread))
        return 0;
#endif
    if (g_oom_fail_at < 0)
        return 0;
    if (g_oom_fail_at-- == 0) {
        g_oom_failed = 1;
        return 1;
    }
    return 0;
}

static inline void* test_oom_malloc(size_t sz)
{
    return test_oom_refuse() ? NULL : malloc(sz);
}

static inline void* test_oom_realloc(void* ptr, size_t sz)
{
    return test_oom_refuse() ? NULL : realloc(ptr, sz);
}

/* Installs the allocators, counting the calling thread's allocations; 0 on
 * success. Safe only before any other thread starts. */
static inline int test_oom_init(void)
{
#ifndef WOLFSSL_ZEPHYR
    g_oom_thread = pthread_self();
#endif
    return wolfSSL_SetAllocators(test_oom_malloc, free, test_oom_realloc);
}

/* Refuses allocation n (from 0) of the counted thread, and only that one. */
static inline void test_oom_arm(int n)
{
    g_oom_fail_at = n;
    g_oom_failed  = 0;
}

/* Stops refusing; 1 when an allocation was refused since the arm, else 0. */
static inline int test_oom_disarm(void)
{
    g_oom_fail_at = -1;
    return g_oom_failed;
}

#else

static inline int test_oom_init(void) { return 0; }

#endif /* TEST_OOM */

#endif /* WOLFCERT_TEST_OOM_H */
