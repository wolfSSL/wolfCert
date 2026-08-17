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

#define _GNU_SOURCE
#define _DARWIN_C_SOURCE   /* expose memmem/strcasestr/INADDR_LOOPBACK on macOS */

#include <wolfcert/wolfcert.h>
#include "../test_static_mem.h"

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/asn_public.h>

#include <stdio.h>
#include <string.h>

#define REQUIRE(cond) \
    do {                                                                    \
        if (!(cond)) {                                                      \
            fprintf(stderr, "FAIL %s:%d %s\n", __FILE__, __LINE__, #cond);  \
            return 1;                                                       \
        }                                                                   \
    } while (0)

static int build_and_reparse(WolfCertKeyType kt, int param)
{
    WolfCertKeyCfg cfg = { .type = kt, .param = param,
                           .dev_id = WOLFCERT_DEVID_SOFTWARE };
    WolfCertKey* key = NULL;
    REQUIRE(wolfcert_key_generate(&cfg, &key) == WOLFCERT_OK);

    const char* dns[] = { "device-1.local", "alt.example.com" };
    const char* ips[] = { "192.0.2.10" };
    WolfCertCertMeta meta = {
        .subject_dn = "CN=device-1,O=Acme,OU=Devices,C=US",
        .san_dns = dns, .san_dns_len = 2,
        .san_ip  = ips, .san_ip_len  = 1,
    };

    WolfCertBuffer der = { 0 };
    REQUIRE(wolfcert_csr_build(key, &meta, &der) == WOLFCERT_OK);
    REQUIRE(der.len > 0);

    DecodedCert dc;
    wc_InitDecodedCert(&dc, der.data, (word32)der.len, NULL);
    int rc = wc_ParseCert(&dc, CERTREQ_TYPE, NO_VERIFY, NULL);
    REQUIRE(rc == 0);
    REQUIRE(dc.subjectCN != NULL);
    REQUIRE(strncmp(dc.subjectCN, "device-1", 8) == 0);
    wc_FreeDecodedCert(&dc);

    WolfCertBuffer pem = { 0 };
    REQUIRE(wolfcert_csr_der_to_pem(der.data, der.len, &pem) == WOLFCERT_OK);
    REQUIRE(memmem(pem.data, pem.len, "BEGIN CERTIFICATE REQUEST", 25) != NULL);

    WolfCertBuffer der2 = { 0 };
    REQUIRE(wolfcert_csr_pem_to_der(pem.data, pem.len, &der2) == WOLFCERT_OK);
    REQUIRE(der2.len == der.len);
    REQUIRE(memcmp(der.data, der2.data, der.len) == 0);

    wolfcert_buffer_free(&der);
    wolfcert_buffer_free(&der2);
    wolfcert_buffer_free(&pem);
    wolfcert_key_free(key);
    return 0;
}

/* Verifies that the new metadata fields flow end-to-end: a UID in the
 * DN string lands in the parsed DecodedCert, and an rfc822Name SAN
 * shows up as the tag-0x81 GeneralName inside the SAN extension. */
static int build_with_extras(void)
{
    WolfCertKeyCfg cfg = { .type = WOLFCERT_KEY_ECC, .param = 256,
                           .dev_id = WOLFCERT_DEVID_SOFTWARE };
    WolfCertKey* key = NULL;
    REQUIRE(wolfcert_key_generate(&cfg, &key) == WOLFCERT_OK);

    const char* dns[]   = { "device-42.local" };
    const char* emails[]= { "ops@example.com" };
    WolfCertCertMeta meta = {
        .subject_dn   = "CN=device-42,UID=factory-0xABCD,O=Acme,L=Portland,"
                        "postalCode=94103,C=US",
        .san_dns      = dns,     .san_dns_len   = 1,
        .san_email    = emails,  .san_email_len = 1,
    };
    WolfCertBuffer der = { 0 };
    REQUIRE(wolfcert_csr_build(key, &meta, &der) == WOLFCERT_OK);

    DecodedCert dc;
    wc_InitDecodedCert(&dc, der.data, (word32)der.len, NULL);
    REQUIRE(wc_ParseCert(&dc, CERTREQ_TYPE, NO_VERIFY, NULL) == 0);
    /* CN still parses. */
    REQUIRE(dc.subjectCN != NULL);
    REQUIRE(strncmp(dc.subjectCN, "device-42", 9) == 0);
    /* One-character RDN keys reach their CertName field. */
    REQUIRE(dc.subjectL != NULL && dc.subjectLLen == 8);
    REQUIRE(strncmp(dc.subjectL, "Portland", 8) == 0);
    /* UID is carried in dc.uidRaw / dc.uidRawLen on this wolfSSL build;
     * fall back to a raw scan of the subjectRaw bytes otherwise. The
     * UID OID (0.9.2342.19200300.100.1.1) encodes to bytes
     * 09 92 26 89 93 F2 2C 64 01 01 - assert its presence. */
    static const uint8_t UID_OID[] = {
        0x09, 0x92, 0x26, 0x89, 0x93, 0xF2, 0x2C, 0x64, 0x01, 0x01
    };
    REQUIRE(dc.subjectRaw != NULL && dc.subjectRawLen > 0);
    REQUIRE(memmem(dc.subjectRaw, (size_t)dc.subjectRawLen,
                   UID_OID, sizeof(UID_OID)) != NULL);
    wc_FreeDecodedCert(&dc);

    /* rfc822Name SAN - check the raw CSR contains the email bytes
     * preceded by tag 0x81 (GeneralName [1] IMPLICIT IA5String). */
    static const uint8_t rfc822_prefix[] = {
        0x81, 0x0F, 'o','p','s','@','e','x','a','m','p','l','e','.','c','o','m'
    };
    REQUIRE(memmem(der.data, der.len, rfc822_prefix, sizeof(rfc822_prefix)) != NULL);

    wolfcert_buffer_free(&der);
    wolfcert_key_free(key);
    return 0;
}

int main(void)
{
    REQUIRE(test_static_mem_init() == 0);
    REQUIRE(wolfcert_init(NULL) == WOLFCERT_OK);
#ifdef WOLFCERT_HAVE_ECC
    if (build_and_reparse(WOLFCERT_KEY_ECC, 256))
        return 1;
#endif
#ifdef WOLFCERT_HAVE_RSA
    if (build_and_reparse(WOLFCERT_KEY_RSA, 2048))
        return 1;
#endif
#ifdef WOLFCERT_HAVE_ED25519
    if (build_and_reparse(WOLFCERT_KEY_ED25519, 0))
        return 1;
#endif
#ifdef WOLFCERT_HAVE_ED448
    if (build_and_reparse(WOLFCERT_KEY_ED448, 0))
        return 1;
#endif
#ifdef WOLFCERT_HAVE_ECC
    if (build_with_extras())
        return 1;
#endif
    wolfcert_cleanup();
    printf("OK\n");
    return 0;
}
