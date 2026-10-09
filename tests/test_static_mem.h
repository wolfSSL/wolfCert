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
 * Static-memory pool for WOLFSSL_NO_MALLOC test builds, a no-op elsewhere.
 * test_static_mem_init() runs before wolfcert_init() so wolfSSL_Init() uses it.
 */

#ifndef WOLFCERT_TEST_STATIC_MEM_H
#define WOLFCERT_TEST_STATIC_MEM_H

#include <wolfcert/wolfcert.h>

#if defined(WOLFSSL_STATIC_MEMORY) && defined(WOLFSSL_NO_MALLOC)

#include <wolfssl/wolfcrypt/memory.h>

/* Sized for the unit tests' peak use, up to a loopback TLS handshake. */
static unsigned char g_test_static_pool[4 * 1024 * 1024];
static WOLFSSL_HEAP_HINT* g_test_heap_hint = NULL;

static inline int test_static_mem_init(void)
{
    if (wc_LoadStaticMemory(&g_test_heap_hint, g_test_static_pool,
                            sizeof(g_test_static_pool), WOLFMEM_GENERAL, 1) != 0)
        return -1;
    wolfSSL_SetGlobalHeapHint(g_test_heap_hint);
    return 0;
}

static inline void* test_heap_hint(void)
{
    return g_test_heap_hint;
}

#else

static inline int test_static_mem_init(void) { return 0; }
static inline void* test_heap_hint(void) { return NULL; }

#endif /* WOLFSSL_STATIC_MEMORY && WOLFSSL_NO_MALLOC */

#endif /* WOLFCERT_TEST_STATIC_MEM_H */
