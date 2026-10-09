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

#include <wolfcert/wolfcert.h>
#include "../test_static_mem.h"

#include <stdio.h>
#include <string.h>

/* wolfSSL leaves THREAD_LS_T empty on FreeRTOS and Zephyr. */
#if defined(HAVE_THREAD_LS) && !defined(NO_THREAD_LS) && \
    !defined(FREERTOS) && !defined(FREERTOS_TCP) && !defined(WOLFSSL_ZEPHYR)
#define TEST_ERR_PER_THREAD
#endif

#ifdef TEST_ERR_PER_THREAD
#include <pthread.h>

static void* fail_keygen(void* arg)
{
    WolfCertKeyCfg cfg = { .type = (WolfCertKeyType)999 };
    WolfCertKey* key = NULL;
    int* ok = (int*)arg;

    *ok = wolfcert_key_generate(&cfg, &key) == WOLFCERT_ERR_UNSUPPORTED &&
          wolfcert_last_error_message()[0] != '\0';
    return NULL;
}

/* An error on another thread leaves this thread's error state alone. */
static int error_state_is_per_thread(void)
{
    pthread_t t;
    int ok = 0;

    wolfcert_clear_error();
    if (pthread_create(&t, NULL, fail_keygen, &ok) != 0 ||
            pthread_join(t, NULL) != 0 || !ok)
        return 1;
    if (wolfcert_last_error_message()[0] != '\0') {
        fprintf(stderr, "error state leaked across threads: %s\n",
                wolfcert_last_error_message());
        return 1;
    }
    return 0;
}
#endif

int main(void)
{
    if (test_static_mem_init() != 0) {
        fprintf(stderr, "static mem init failed\n");
        return 1;
    }
    if (wolfcert_init(test_heap_hint()) != WOLFCERT_OK) {
        fprintf(stderr, "wolfcert_init failed\n");
        return 1;
    }
    const char* v = wolfcert_version_string();
    if (v == NULL || strlen(v) == 0) {
        wolfcert_cleanup();
        return 1;
    }
    if (strcmp(wolfcert_strerror(WOLFCERT_OK), "ok") != 0) {
        wolfcert_cleanup();
        return 1;
    }
#ifdef TEST_ERR_PER_THREAD
    if (error_state_is_per_thread() != 0) {
        wolfcert_cleanup();
        return 1;
    }
#endif
    printf("wolfCert %s\n", v);
    wolfcert_cleanup();
    return 0;
}
