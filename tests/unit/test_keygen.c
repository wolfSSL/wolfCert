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

#define REQUIRE(cond) \
    do {                                                                    \
        if (!(cond)) {                                                      \
            fprintf(stderr, "FAIL %s:%d %s\n", __FILE__, __LINE__, #cond);  \
            return 1;                                                       \
        }                                                                   \
    } while (0)

static int roundtrip(WolfCertKeyType type, int param)
{
    WolfCertKeyCfg cfg = { .type = type, .param = param,
                           .dev_id = WOLFCERT_DEVID_SOFTWARE };
    WolfCertKey* k = NULL;
    REQUIRE(wolfcert_key_generate(&cfg, &k) == WOLFCERT_OK);
    REQUIRE(k != NULL);

    WolfCertBuffer pem = { 0 };
    REQUIRE(wolfcert_key_to_pem(k, &pem) == WOLFCERT_OK);
    REQUIRE(pem.len > 0);
    REQUIRE(memchr(pem.data, '-', pem.len) != NULL);

    WolfCertKey* k2 = NULL;
    REQUIRE(wolfcert_key_from_pem(pem.data, pem.len, NULL, &k2) == WOLFCERT_OK);
    REQUIRE(k2 != NULL);

    /* Re-import the key from its DER export; 0x30 is the SEQUENCE tag. */
    WolfCertBuffer der = { 0 };
    REQUIRE(wolfcert_key_to_der(k, &der) == WOLFCERT_OK);
    REQUIRE(der.len > 0);
    REQUIRE(der.data[0] == 0x30);

    WolfCertKey* k3 = NULL;
    REQUIRE(wolfcert_key_from_pem(der.data, der.len, NULL, &k3) == WOLFCERT_OK);
    REQUIRE(k3 != NULL);

    wolfcert_buffer_free(&pem);
    wolfcert_buffer_free(&der);
    wolfcert_key_free(k);
    wolfcert_key_free(k2);
    wolfcert_key_free(k3);
    return 0;
}

int main(void)
{
    REQUIRE(test_static_mem_init() == 0);
    REQUIRE(wolfcert_init(test_heap_hint()) == WOLFCERT_OK);
#ifdef WOLFCERT_HAVE_ECC
    if (roundtrip(WOLFCERT_KEY_ECC, 256))
        return 1;
    if (roundtrip(WOLFCERT_KEY_ECC, 384))
        return 1;
#endif
#ifdef WOLFCERT_HAVE_RSA
    if (roundtrip(WOLFCERT_KEY_RSA, 2048))
        return 1;
#endif
#ifdef WOLFCERT_HAVE_ED25519
    if (roundtrip(WOLFCERT_KEY_ED25519, 0))
        return 1;
#endif
#ifdef WOLFCERT_HAVE_ED448
    if (roundtrip(WOLFCERT_KEY_ED448, 0))
        return 1;
#endif
#ifdef WOLFCERT_HAVE_MLDSA
#ifndef WOLFSSL_NO_ML_DSA_44
    if (roundtrip(WOLFCERT_KEY_MLDSA44, 0))
        return 1;
#endif
#ifndef WOLFSSL_NO_ML_DSA_65
    if (roundtrip(WOLFCERT_KEY_MLDSA65, 0))
        return 1;
#endif
#ifndef WOLFSSL_NO_ML_DSA_87
    if (roundtrip(WOLFCERT_KEY_MLDSA87, 0))
        return 1;
#endif
#else
    /* Runtime rejection when the wolfSSL build lacks Dilithium. */
    {
        WolfCertKeyCfg cfg = { .type = WOLFCERT_KEY_MLDSA44, .param = 0,
                               .dev_id = WOLFCERT_DEVID_SOFTWARE };
        WolfCertKey* k = NULL;
        REQUIRE(wolfcert_key_generate(&cfg, &k) == WOLFCERT_ERR_UNSUPPORTED);
    }
#endif

    WolfCertKeyCfg bad = { .type = WOLFCERT_KEY_ECC, .param = 123,
                           .dev_id = WOLFCERT_DEVID_SOFTWARE };
    WolfCertKey* k = NULL;
    REQUIRE(wolfcert_key_generate(&bad, &k) != WOLFCERT_OK);

    wolfcert_cleanup();
    printf("OK\n");
    return 0;
}
