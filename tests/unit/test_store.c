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

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#define _DARWIN_C_SOURCE   /* expose memmem/strcasestr/INADDR_LOOPBACK on macOS */

#include <wolfcert/wolfcert.h>
#include "../test_static_mem.h"

#include "../integration/tls_test_util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define REQUIRE(cond) \
    do {                                                                    \
        if (!(cond)) {                                                      \
            fprintf(stderr, "FAIL %s:%d %s\n", __FILE__, __LINE__, #cond);  \
            return 1;                                                       \
        }                                                                   \
    } while (0)

#ifdef WOLFCERT_HAVE_POSIX_STORE
static int test_posix(void)
{
    char dir[] = "/tmp/wolfcert_store_XXXXXX";
    REQUIRE(mkdtemp(dir) != NULL);

    WolfCertStoreOps* store = wolfcert_store_posix_open(dir, NULL);
    REQUIRE(store != NULL);

    WolfCertKeyCfg cfg = { .type = TEST_ENROLL_KEY_TYPE, .param = TEST_ENROLL_KEY_PARAM,
                           .dev_id = WOLFCERT_DEVID_SOFTWARE };
    WolfCertKey* k = NULL;
    REQUIRE(wolfcert_key_generate(&cfg, &k) == WOLFCERT_OK);
    REQUIRE(wolfcert_store_write_key(store, "device.key.pem", k) == WOLFCERT_OK);

    struct stat st;
    char p[512];
    snprintf(p, sizeof(p), "%s/device.key.pem", dir);
    REQUIRE(stat(p, &st) == 0);
    REQUIRE((st.st_mode & 0777) == 0600);

    WolfCertKey* k2 = NULL;
    REQUIRE(wolfcert_store_read_key(store, "device.key.pem", &k2) == WOLFCERT_OK);
    REQUIRE(k2 != NULL);

    const uint8_t fake_cert[] = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";
    REQUIRE(wolfcert_store_write_cert(store, "device.crt", fake_cert, sizeof(fake_cert)-1) == WOLFCERT_OK);
    WolfCertBuffer rb = { 0 };
    REQUIRE(wolfcert_store_read_cert(store, "device.crt", &rb) == WOLFCERT_OK);
    REQUIRE(rb.len == sizeof(fake_cert)-1);
    REQUIRE(memcmp(rb.data, fake_cert, rb.len) == 0);

    wolfcert_buffer_free(&rb);
    wolfcert_key_free(k);
    wolfcert_key_free(k2);
    wolfcert_store_posix_close(store);

    char p2[512];
    snprintf(p2, sizeof(p2), "%s/device.crt", dir);
    unlink(p);
    unlink(p2);
    rmdir(dir);
    return 0;
}

#endif /* WOLFCERT_HAVE_POSIX_STORE */

static int test_memory(void)
{
    WolfCertStoreOps* store = wolfcert_store_memory_open(NULL);
    REQUIRE(store != NULL);

    const uint8_t d[] = "hello";
    REQUIRE(wolfcert_store_write_cert(store, "x", d, sizeof(d)-1) == WOLFCERT_OK);
    WolfCertBuffer r = { 0 };
    REQUIRE(wolfcert_store_read_cert(store, "x", &r) == WOLFCERT_OK);
    REQUIRE(r.len == sizeof(d)-1 && memcmp(r.data, d, r.len) == 0);
    wolfcert_buffer_free(&r);

    REQUIRE(store->remove(store->ctx, "x") == WOLFCERT_OK);
    REQUIRE(wolfcert_store_read_cert(store, "x", &r) == WOLFCERT_ERR_NOT_FOUND);

    wolfcert_store_memory_close(store);
    return 0;
}

int main(void)
{
    REQUIRE(test_static_mem_init() == 0);
    REQUIRE(wolfcert_init(NULL) == WOLFCERT_OK);
#ifdef WOLFCERT_HAVE_POSIX_STORE
    if (test_posix())
        return 1;
#endif
    if (test_memory())
        return 1;
    wolfcert_cleanup();
    printf("OK\n");
    return 0;
}
