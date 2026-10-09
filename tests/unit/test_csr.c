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
#include "internal.h"
#include "../test_static_mem.h"

#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/asn_public.h>

#include <wolfssl/wolfcrypt/random.h>

#include <stdio.h>
#include <stdlib.h>
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

/* UID, rfc822Name and iPAddress meta fields reach the built CSR. */
static int build_with_extras(void)
{
    WolfCertKeyCfg cfg = { .type = WOLFCERT_KEY_ECC, .param = 256,
                           .dev_id = WOLFCERT_DEVID_SOFTWARE };
    WolfCertKey* key = NULL;
    REQUIRE(wolfcert_key_generate(&cfg, &key) == WOLFCERT_OK);

    const char* dns[]   = { "device-42.local" };
    const char* emails[]= { "ops@example.com" };
    const char* ips[]   = { "192.0.2.10", "2001:db8::1" };
    WolfCertCertMeta meta = {
        .subject_dn   = "CN=device-42,UID=factory-0xABCD,O=Acme,L=Portland,"
                        "postalCode=94103,C=US",
        .san_dns      = dns,     .san_dns_len   = 1,
        .san_email    = emails,  .san_email_len = 1,
        .san_ip       = ips,     .san_ip_len    = 2,
    };
    WolfCertBuffer der = { 0 };
    REQUIRE(wolfcert_csr_build(key, &meta, &der) == WOLFCERT_OK);

    DecodedCert dc;
    wc_InitDecodedCert(&dc, der.data, (word32)der.len, NULL);
    REQUIRE(wc_ParseCert(&dc, CERTREQ_TYPE, NO_VERIFY, NULL) == 0);
    REQUIRE(dc.subjectCN != NULL);
    REQUIRE(strncmp(dc.subjectCN, "device-42", 9) == 0);
    /* One-character RDN keys reach their CertName field. */
    REQUIRE(dc.subjectL != NULL && dc.subjectLLen == 8);
    REQUIRE(strncmp(dc.subjectL, "Portland", 8) == 0);
    /* The UID attribute OID, 0.9.2342.19200300.100.1.1. */
    static const uint8_t UID_OID[] = {
        0x09, 0x92, 0x26, 0x89, 0x93, 0xF2, 0x2C, 0x64, 0x01, 0x01
    };
    REQUIRE(dc.subjectRaw != NULL && dc.subjectRawLen > 0);
    REQUIRE(memmem(dc.subjectRaw, (size_t)dc.subjectRawLen,
                   UID_OID, sizeof(UID_OID)) != NULL);
    wc_FreeDecodedCert(&dc);

    /* rfc822Name SAN: GeneralName [1] IMPLICIT IA5String, tag 0x81. */
    static const uint8_t rfc822_prefix[] = {
        0x81, 0x0F, 'o','p','s','@','e','x','a','m','p','l','e','.','c','o','m'
    };
    REQUIRE(memmem(der.data, der.len, rfc822_prefix, sizeof(rfc822_prefix)) != NULL);

    /* iPAddress SANs - tag 0x87 GeneralName [7], 4 bytes for v4, 16 for v6. */
    static const uint8_t ip4[]  = { 0x87, 0x04, 192, 0, 2, 10 };
    static const uint8_t ip6[]  = { 0x87, 0x10, 0x20, 0x01, 0x0d, 0xb8,
                                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    REQUIRE(memmem(der.data, der.len, ip4, sizeof(ip4)) != NULL);
    REQUIRE(memmem(der.data, der.len, ip6, sizeof(ip6)) != NULL);

    wolfcert_buffer_free(&der);
    wolfcert_key_free(key);
    return 0;
}

#ifdef WOLFCERT_HAVE_SERVER
/* A hand-filled DecodedCert with a CTC_NAME_SIZE-byte CN, which no
 * wolfSSL-built CSR can carry, gets BAD_ARG from wolfcert_copy_csr_subject. */
static int subject_copy_rejects_oversized_rdn(void)
{
    char longcn[CTC_NAME_SIZE + 8];
    DecodedCert dc;
    Cert nc;

    memset(longcn, 'A', sizeof(longcn));
    memset(&dc, 0, sizeof(dc));
    REQUIRE(wc_InitCert(&nc) == 0);

    dc.subjectCN    = longcn;
    dc.subjectCNLen = CTC_NAME_SIZE;
    dc.subjectCNEnc = CTC_PRINTABLE;
    REQUIRE(wolfcert_copy_csr_subject(&dc, &nc) == WOLFCERT_ERR_BAD_ARG);

    /* One byte under the limit still copies, and carries its encoding. */
    dc.subjectCNLen = CTC_NAME_SIZE - 1;
    REQUIRE(wolfcert_copy_csr_subject(&dc, &nc) == WOLFCERT_OK);
    REQUIRE(strlen(nc.subject.commonName) == CTC_NAME_SIZE - 1);
    REQUIRE(nc.subject.commonNameEnc == CTC_PRINTABLE);

    return 0;
}
#endif

#ifdef WOLFCERT_HAVE_ECC
static int csr_build_rejects_oversized_rdn(void)
{
    WolfCertKeyCfg cfg = { .type = WOLFCERT_KEY_ECC, .param = 256,
                           .dev_id = WOLFCERT_DEVID_SOFTWARE };
    WolfCertKey* key = NULL;
    WolfCertCertMeta meta = { 0 };
    WolfCertBuffer der = { 0 };
    char dn[3 + CTC_NAME_SIZE + 8];

    REQUIRE(wolfcert_key_generate(&cfg, &key) == WOLFCERT_OK);

    memset(dn, 'A', sizeof(dn));
    memcpy(dn, "CN=", 3);
    dn[sizeof(dn) - 1] = '\0';
    meta.subject_dn = dn;
    REQUIRE(wolfcert_csr_build(key, &meta, &der) == WOLFCERT_ERR_BAD_ARG);
    REQUIRE(der.data == NULL && der.len == 0);

    /* Exactly CTC_NAME_SIZE is refused too, since the NUL needs a byte. */
    dn[3 + CTC_NAME_SIZE] = '\0';
    REQUIRE(wolfcert_csr_build(key, &meta, &der) == WOLFCERT_ERR_BAD_ARG);
    REQUIRE(der.data == NULL && der.len == 0);

    /* The longest value that fits, CTC_NAME_SIZE - 1 bytes, still builds. */
    dn[3 + CTC_NAME_SIZE - 1] = '\0';
    REQUIRE(wolfcert_csr_build(key, &meta, &der) == WOLFCERT_OK);
    REQUIRE(der.len > 0);

    wolfcert_buffer_free(&der);
    wolfcert_key_free(key);
    return 0;
}
#endif

#ifdef WOLFCERT_HAVE_ECC
/* Self-sign the subject and SAN set in c with the test's ECC key, then free
 * c; returns the DER length. */
static int make_self_cert(Cert* c, const WolfCertKey* key, byte* out, int cap)
{
    WC_RNG rng;
    int len = -1;

    if (wc_InitRng(&rng) == 0) {
        c->sigType    = CTC_SHA256wECDSA;
        c->selfSigned = 1;
        if (wc_MakeCert_ex(c, out, (word32)cap, ECC_TYPE, key->impl,
                           &rng) > 0)
            len = wc_SignCert_ex(c->bodySz, c->sigType, out, (word32)cap,
                                 ECC_TYPE, key->impl, &rng);
        wc_FreeRng(&rng);
    }
    wc_CertFree(c);
    return len;
}

/* A caller callback that names the CSR itself: CN=cb, DNS:cb.example. */
static int add_identity_customize(void* wolfssl_cert, void* ctx)
{
    static const byte san[] = { 0x30, 0x0c, 0x82, 0x0a, 'c', 'b', '.', 'e',
                                'x', 'a', 'm', 'p', 'l', 'e' };
    Cert* c = (Cert*)wolfssl_cert;

    *(int*)ctx = 1;
    snprintf(c->subject.commonName, sizeof(c->subject.commonName), "%s", "cb");
    memcpy(c->altNames, san, sizeof(san));
    c->altNamesSz = (int)sizeof(san);
    return WOLFCERT_OK;
}

/* Renew a cert that has an empty subject and a SAN, critical or not. */
static int renewal_keeps_empty_subject(int san_crit)
{
    static const byte san[] = { 0x30, 0x0d, 0x82, 0x0b, 'd', 'e', 'v', '.',
                                'e', 'x', 'a', 'm', 'p', 'l', 'e' };
    WolfCertKeyCfg cfg = { .type = WOLFCERT_KEY_ECC, .param = 256,
                           .dev_id = WOLFCERT_DEVID_SOFTWARE };
    WolfCertKey* key = NULL;
    WolfCertCertMeta meta = { 0 };
    WolfCertBuffer csr = { 0 };
    byte cert[1024];
    int cert_len;
    int called = 0;
    Cert* c;
    DecodedCert dc;

    REQUIRE(wolfcert_key_generate(&cfg, &key) == WOLFCERT_OK);
    REQUIRE((c = wc_CertNew(NULL)) != NULL);
    memcpy(c->altNames, san, sizeof(san));
    c->altNamesSz   = (int)sizeof(san);
    c->altNamesCrit = san_crit ? 1 : 0;
    cert_len = make_self_cert(c, key, cert, (int)sizeof(cert));
    REQUIRE(cert_len > 0);

    meta.customize     = add_identity_customize;
    meta.customize_ctx = &called;
    REQUIRE(wolfcert_csr_build_ex(key, &meta, cert, (size_t)cert_len, &csr)
            == WOLFCERT_OK);
    REQUIRE(called == 1);

    wc_InitDecodedCert(&dc, csr.data, (word32)csr.len, NULL);
    REQUIRE(wc_ParseCert(&dc, CERTREQ_TYPE, NO_VERIFY, NULL) == 0);
    REQUIRE(dc.subjectRaw != NULL && dc.subjectRawLen == 0);
    REQUIRE(dc.extSubjAltNameCrit == (san_crit ? 1 : 0));
    REQUIRE(dc.altNames != NULL && dc.altNames->next == NULL);
    REQUIRE(dc.altNames->type == ASN_DNS_TYPE && dc.altNames->len == 11);
    REQUIRE(memcmp(dc.altNames->name, "dev.example", 11) == 0);
    wc_FreeDecodedCert(&dc);

    wolfcert_buffer_free(&csr);
    wolfcert_key_free(key);
    return 0;
}

/* CN=crit,OU=Devices,O=Acme,C=US in that order (C as a PrintableString),
 * then SKID, an unknown critical extension and DNS:dev.example. */
static const byte crit_ext_cert[] = {
    0x30, 0x82, 0x01, 0xcb, 0x30, 0x82, 0x01, 0x71, 0xa0, 0x03, 0x02, 0x01,
    0x02, 0x02, 0x14, 0x1f, 0xb1, 0xc9, 0xdd, 0x7e, 0x9c, 0xbe, 0x2b, 0xf9,
    0xea, 0x9c, 0x44, 0x25, 0x5f, 0x82, 0x21, 0x86, 0xb2, 0xe3, 0xbd, 0x30,
    0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30,
    0x3d, 0x31, 0x0d, 0x30, 0x0b, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x04,
    0x63, 0x72, 0x69, 0x74, 0x31, 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x04,
    0x0b, 0x0c, 0x07, 0x44, 0x65, 0x76, 0x69, 0x63, 0x65, 0x73, 0x31, 0x0d,
    0x30, 0x0b, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x04, 0x41, 0x63, 0x6d,
    0x65, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02,
    0x55, 0x53, 0x30, 0x20, 0x17, 0x0d, 0x32, 0x36, 0x30, 0x39, 0x32, 0x39,
    0x31, 0x32, 0x30, 0x35, 0x31, 0x30, 0x5a, 0x18, 0x0f, 0x32, 0x31, 0x32,
    0x36, 0x30, 0x39, 0x30, 0x35, 0x31, 0x32, 0x30, 0x35, 0x31, 0x30, 0x5a,
    0x30, 0x3d, 0x31, 0x0d, 0x30, 0x0b, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c,
    0x04, 0x63, 0x72, 0x69, 0x74, 0x31, 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55,
    0x04, 0x0b, 0x0c, 0x07, 0x44, 0x65, 0x76, 0x69, 0x63, 0x65, 0x73, 0x31,
    0x0d, 0x30, 0x0b, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x04, 0x41, 0x63,
    0x6d, 0x65, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13,
    0x02, 0x55, 0x53, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48,
    0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03,
    0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x22, 0x45, 0x76, 0xfe, 0xee, 0x7c,
    0xef, 0xec, 0xaa, 0x4e, 0x47, 0x76, 0x00, 0xe0, 0x93, 0x85, 0x3d, 0x3d,
    0x71, 0x25, 0xaf, 0x25, 0x46, 0x31, 0x97, 0x9c, 0x83, 0xf8, 0x9e, 0xc9,
    0x3b, 0x2f, 0x7c, 0xe4, 0xa1, 0x01, 0x5a, 0x80, 0x44, 0x19, 0x29, 0xc2,
    0xef, 0x37, 0xce, 0x72, 0x43, 0x97, 0x02, 0x57, 0xc9, 0x56, 0xb8, 0x95,
    0x0d, 0x76, 0x98, 0xf8, 0xba, 0x43, 0x0d, 0xad, 0x80, 0x25, 0xa3, 0x4d,
    0x30, 0x4b, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04,
    0x14, 0x5f, 0xd9, 0xac, 0x6d, 0x30, 0x06, 0x20, 0x97, 0xb3, 0x21, 0x64,
    0x88, 0x96, 0xb8, 0x92, 0x11, 0xa2, 0x08, 0xba, 0xe5, 0x30, 0x12, 0x06,
    0x09, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x86, 0x8d, 0x1f, 0x01, 0x01, 0x01,
    0xff, 0x04, 0x02, 0x05, 0x00, 0x30, 0x16, 0x06, 0x03, 0x55, 0x1d, 0x11,
    0x04, 0x0f, 0x30, 0x0d, 0x82, 0x0b, 0x64, 0x65, 0x76, 0x2e, 0x65, 0x78,
    0x61, 0x6d, 0x70, 0x6c, 0x65, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48,
    0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x48, 0x00, 0x30, 0x45, 0x02, 0x20,
    0x2a, 0xb4, 0xe2, 0x45, 0xf6, 0x83, 0xf1, 0x6c, 0x16, 0x30, 0x57, 0xf5,
    0x84, 0x7e, 0x56, 0x21, 0xcd, 0x1c, 0x50, 0xb3, 0x2f, 0xe2, 0x6a, 0xe1,
    0x6f, 0x18, 0xbe, 0x11, 0xee, 0x22, 0x54, 0xf9, 0x02, 0x21, 0x00, 0x98,
    0x92, 0xf7, 0xed, 0x15, 0x7c, 0x0a, 0xf6, 0xfc, 0x53, 0xd6, 0x61, 0x11,
    0xa5, 0x63, 0x73, 0x92, 0xe6, 0x66, 0xfa, 0x06, 0x93, 0x19, 0x2d, 0x90,
    0xeb, 0xea, 0x57, 0x1f, 0x00, 0x06, 0x00
};

/* Renew a CA-shaped cert: reverse-order RDNs, other extensions before the
 * SAN, one of them critical and unknown. */
static int renewal_reads_past_unknown_critical_ext(void)
{
    WolfCertKeyCfg cfg = { .type = WOLFCERT_KEY_ECC, .param = 256,
                           .dev_id = WOLFCERT_DEVID_SOFTWARE };
    WolfCertKey* key = NULL;
    WolfCertCertMeta meta = { 0 };
    WolfCertBuffer csr = { 0 };
    DecodedCert cc;
    DecodedCert dc;

    wc_InitDecodedCert(&cc, crit_ext_cert, sizeof(crit_ext_cert), NULL);
    REQUIRE(wc_ParseCert(&cc, CERT_TYPE, NO_VERIFY, NULL) == ASN_CRIT_EXT_E);

    REQUIRE(wolfcert_key_generate(&cfg, &key) == WOLFCERT_OK);
    REQUIRE(wolfcert_csr_build_ex(key, &meta, crit_ext_cert,
                                  sizeof(crit_ext_cert), &csr) == WOLFCERT_OK);

    wc_InitDecodedCert(&dc, csr.data, (word32)csr.len, NULL);
    REQUIRE(wc_ParseCert(&dc, CERTREQ_TYPE, NO_VERIFY, NULL) == 0);
    REQUIRE(dc.subjectRawLen == cc.subjectRawLen);
    REQUIRE(memcmp(dc.subjectRaw, cc.subjectRaw,
                   (size_t)cc.subjectRawLen) == 0);
    REQUIRE(dc.extSubjAltNameCrit == 0);
    REQUIRE(dc.altNames != NULL && dc.altNames->next == NULL);
    REQUIRE(dc.altNames->type == ASN_DNS_TYPE && dc.altNames->len == 11);
    REQUIRE(memcmp(dc.altNames->name, "dev.example", 11) == 0);
    wc_FreeDecodedCert(&dc);
    wc_FreeDecodedCert(&cc);

    wolfcert_buffer_free(&csr);
    wolfcert_key_free(key);
    return 0;
}

/* CN=bmp as a BMPString, which puts 0x00 bytes in the Name. */
static const byte bmp_subject_cert[] = {
    0x30, 0x82, 0x01, 0x5e, 0x30, 0x82, 0x01, 0x05, 0xa0, 0x03, 0x02, 0x01,
    0x02, 0x02, 0x14, 0x43, 0x68, 0xe0, 0xfb, 0x08, 0x34, 0x31, 0x5d, 0xca,
    0xdf, 0x05, 0x66, 0xdb, 0xb3, 0x73, 0x4b, 0x98, 0x20, 0xb9, 0xda, 0x30,
    0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30,
    0x11, 0x31, 0x0f, 0x30, 0x0d, 0x06, 0x03, 0x55, 0x04, 0x03, 0x1e, 0x06,
    0x00, 0x62, 0x00, 0x6d, 0x00, 0x70, 0x30, 0x20, 0x17, 0x0d, 0x32, 0x36,
    0x30, 0x39, 0x32, 0x39, 0x31, 0x32, 0x30, 0x35, 0x31, 0x31, 0x5a, 0x18,
    0x0f, 0x32, 0x31, 0x32, 0x36, 0x30, 0x39, 0x30, 0x35, 0x31, 0x32, 0x30,
    0x35, 0x31, 0x31, 0x5a, 0x30, 0x11, 0x31, 0x0f, 0x30, 0x0d, 0x06, 0x03,
    0x55, 0x04, 0x03, 0x1e, 0x06, 0x00, 0x62, 0x00, 0x6d, 0x00, 0x70, 0x30,
    0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42,
    0x00, 0x04, 0x33, 0x7c, 0xb9, 0xd0, 0x1f, 0xec, 0xec, 0x91, 0x82, 0x33,
    0x14, 0x87, 0xea, 0xd3, 0x5f, 0x63, 0xd4, 0x0b, 0xc8, 0xd3, 0x65, 0x21,
    0x5d, 0x27, 0x95, 0xcd, 0xc4, 0xd9, 0x04, 0x97, 0x17, 0x2e, 0x6f, 0xcf,
    0x6c, 0x02, 0x40, 0x1b, 0x92, 0xdc, 0x52, 0xdd, 0xe8, 0x05, 0x7d, 0x41,
    0x20, 0x00, 0xcd, 0x5c, 0x33, 0x16, 0x27, 0xf6, 0xab, 0x6b, 0x56, 0x7a,
    0x16, 0x3e, 0x13, 0x9e, 0x3f, 0x34, 0xa3, 0x39, 0x30, 0x37, 0x30, 0x16,
    0x06, 0x03, 0x55, 0x1d, 0x11, 0x04, 0x0f, 0x30, 0x0d, 0x82, 0x0b, 0x64,
    0x65, 0x76, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x30, 0x1d,
    0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0xab, 0x01, 0x31,
    0xe8, 0x49, 0x21, 0xdf, 0x6d, 0x69, 0x97, 0x4d, 0x8e, 0x38, 0xa3, 0xbe,
    0xbc, 0x30, 0xdd, 0x89, 0xc6, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48,
    0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x47, 0x00, 0x30, 0x44, 0x02, 0x20,
    0x43, 0x42, 0x4c, 0xb0, 0x4c, 0x42, 0xc1, 0xb2, 0xed, 0xfd, 0xb0, 0x0a,
    0x56, 0xc7, 0xd5, 0x38, 0xc1, 0x1f, 0x46, 0x56, 0x55, 0xa8, 0x05, 0x8d,
    0xa2, 0xfd, 0xea, 0x80, 0xdb, 0x98, 0x14, 0xc9, 0x02, 0x20, 0x38, 0x11,
    0x0d, 0xac, 0x84, 0xef, 0x6e, 0x93, 0x0d, 0xed, 0x51, 0x86, 0xb7, 0x54,
    0xac, 0x00, 0x27, 0x8f, 0xa7, 0x84, 0xf6, 0xa4, 0xd5, 0x97, 0x6b, 0x4b,
    0x4f, 0xac, 0x26, 0xd0, 0xc7, 0x4e
};

/* A subject the CSR cannot carry is refused rather than truncated. */
static int renewal_refuses_bmpstring_subject(void)
{
    WolfCertKeyCfg cfg = { .type = WOLFCERT_KEY_ECC, .param = 256,
                           .dev_id = WOLFCERT_DEVID_SOFTWARE };
    WolfCertKey* key = NULL;
    WolfCertCertMeta meta = { 0 };
    WolfCertBuffer csr = { 0 };

    REQUIRE(wolfcert_key_generate(&cfg, &key) == WOLFCERT_OK);
    REQUIRE(wolfcert_csr_build_ex(key, &meta, bmp_subject_cert,
                                  sizeof(bmp_subject_cert), &csr)
            == WOLFCERT_ERR_UNSUPPORTED);
    REQUIRE(csr.data == NULL);

    wolfcert_key_free(key);
    return 0;
}

/* Renew a cert with no SAN while the caller's callback adds one. */
static int renewal_drops_callback_san(void)
{
    WolfCertKeyCfg cfg = { .type = WOLFCERT_KEY_ECC, .param = 256,
                           .dev_id = WOLFCERT_DEVID_SOFTWARE };
    WolfCertKey* key = NULL;
    WolfCertCertMeta meta = { 0 };
    WolfCertBuffer csr = { 0 };
    byte cert[1024];
    int cert_len;
    int called = 0;
    Cert* c;
    DecodedCert dc;

    REQUIRE(wolfcert_key_generate(&cfg, &key) == WOLFCERT_OK);
    REQUIRE((c = wc_CertNew(NULL)) != NULL);
    strcpy(c->subject.commonName, "plain");
    cert_len = make_self_cert(c, key, cert, (int)sizeof(cert));
    REQUIRE(cert_len > 0);

    meta.customize     = add_identity_customize;
    meta.customize_ctx = &called;
    REQUIRE(wolfcert_csr_build_ex(key, &meta, cert, (size_t)cert_len, &csr)
            == WOLFCERT_OK);
    REQUIRE(called == 1);

    wc_InitDecodedCert(&dc, csr.data, (word32)csr.len, NULL);
    REQUIRE(wc_ParseCert(&dc, CERTREQ_TYPE, NO_VERIFY, NULL) == 0);
    REQUIRE(dc.subjectCN != NULL && dc.subjectCNLen == 5);
    REQUIRE(memcmp(dc.subjectCN, "plain", 5) == 0);
    REQUIRE(dc.altNames == NULL && dc.extSubjAltNameSet == 0);
    wc_FreeDecodedCert(&dc);

    wolfcert_buffer_free(&csr);
    wolfcert_key_free(key);
    return 0;
}

/* Renew a CA-shaped cert whose extensions carry no SAN. */
static int renewal_walks_extensions_without_san(void)
{
    WolfCertKeyCfg cfg = { .type = WOLFCERT_KEY_ECC, .param = 256,
                           .dev_id = WOLFCERT_DEVID_SOFTWARE };
    WolfCertKey* key = NULL;
    WolfCertCertMeta meta = { 0 };
    WolfCertBuffer csr = { 0 };
    byte cert[1024];
    int cert_len;
    Cert* c;
    DecodedCert dc;

    REQUIRE(wolfcert_key_generate(&cfg, &key) == WOLFCERT_OK);
    REQUIRE((c = wc_CertNew(NULL)) != NULL);
    strcpy(c->subject.commonName, "nosan");
    c->isCA = 1;
    REQUIRE(wc_SetKeyUsage(c, "digitalSignature,keyCertSign") == 0);
    cert_len = make_self_cert(c, key, cert, (int)sizeof(cert));
    REQUIRE(cert_len > 0);

    REQUIRE(wolfcert_csr_build_ex(key, &meta, cert, (size_t)cert_len, &csr)
            == WOLFCERT_OK);

    wc_InitDecodedCert(&dc, csr.data, (word32)csr.len, NULL);
    REQUIRE(wc_ParseCert(&dc, CERTREQ_TYPE, NO_VERIFY, NULL) == 0);
    REQUIRE(dc.subjectCN != NULL && dc.subjectCNLen == 5);
    REQUIRE(memcmp(dc.subjectCN, "nosan", 5) == 0);
    REQUIRE(dc.altNames == NULL && dc.extSubjAltNameSet == 0);
    wc_FreeDecodedCert(&dc);

    wolfcert_buffer_free(&csr);
    wolfcert_key_free(key);
    return 0;
}

/* Pass a private key PEM where the certificate being renewed belongs. */
static int renewal_rejects_non_certificate(void)
{
    WolfCertKeyCfg cfg = { .type = WOLFCERT_KEY_ECC, .param = 256,
                           .dev_id = WOLFCERT_DEVID_SOFTWARE };
    WolfCertKey* key = NULL;
    WolfCertCertMeta meta = { 0 };
    WolfCertBuffer key_pem = { 0 };
    WolfCertBuffer csr = { 0 };

    REQUIRE(wolfcert_key_generate(&cfg, &key) == WOLFCERT_OK);
    REQUIRE(wolfcert_key_to_pem(key, &key_pem) == WOLFCERT_OK);
    REQUIRE(wolfcert_csr_build_ex(key, &meta, key_pem.data, key_pem.len,
                                  &csr) == WOLFCERT_ERR_PARSE);
    REQUIRE(csr.data == NULL);
    REQUIRE(strstr(wolfcert_last_error_message(), "not PEM or DER") != NULL);

    wolfcert_buffer_free(&key_pem);
    wolfcert_key_free(key);
    return 0;
}

/* An enroll meta reused for a renewal is refused for each identity field. */
static int renewal_rejects_meta_identity(void)
{
    static const char* const one[] = { "x" };
    WolfCertKeyCfg cfg = { .type = WOLFCERT_KEY_ECC, .param = 256,
                           .dev_id = WOLFCERT_DEVID_SOFTWARE };
    WolfCertKey* key = NULL;
    WolfCertCertMeta meta;
    WolfCertBuffer csr = { 0 };
    int i;

    REQUIRE(wolfcert_key_generate(&cfg, &key) == WOLFCERT_OK);
    for (i = 0; i < 5; i++) {
        memset(&meta, 0, sizeof(meta));
        switch (i) {
            case 0:
                meta.subject_dn = "CN=x";
                break;
            case 1:
                meta.san_dns = one;
                meta.san_dns_len = 1;
                break;
            case 2:
                meta.san_ip = one;
                meta.san_ip_len = 1;
                break;
            case 3:
                meta.san_uri = one;
                meta.san_uri_len = 1;
                break;
            default:
                meta.san_email = one;
                meta.san_email_len = 1;
                break;
        }
        REQUIRE(wolfcert_csr_build_ex(key, &meta, crit_ext_cert,
                                      sizeof(crit_ext_cert), &csr)
                == WOLFCERT_ERR_BAD_ARG);
        REQUIRE(csr.data == NULL);
    }

    wolfcert_key_free(key);
    return 0;
}

#define LARGE_SAN_COUNT 60

static int count_csr_sans(const WolfCertBuffer* csr)
{
    DecodedCert dc;
    DNS_entry* e;
    int n = 0;

    wc_InitDecodedCert(&dc, csr->data, (word32)csr->len, NULL);
    if (wc_ParseCert(&dc, CERTREQ_TYPE, NO_VERIFY, NULL) == 0) {
        for (e = dc.altNames; e != NULL; e = e->next)
            n++;
    }
    wc_FreeDecodedCert(&dc);
    return n;
}

/* 60 dNSNames, about 2 KB of SAN, from meta and from a renewed cert. */
static int csr_carries_large_san(void)
{
    WolfCertKeyCfg cfg = { .type = WOLFCERT_KEY_ECC, .param = 256,
                           .dev_id = WOLFCERT_DEVID_SOFTWARE };
    char names[LARGE_SAN_COUNT][40];
    const char* dns[LARGE_SAN_COUNT];
    WolfCertKey* key = NULL;
    WolfCertCertMeta meta = { 0 };
    WolfCertBuffer csr = { 0 };
    DNS_entry* list = NULL;
    byte cert[4096];
    int cert_len;
    int i;
    Cert* c;

    REQUIRE(wolfcert_key_generate(&cfg, &key) == WOLFCERT_OK);
    REQUIRE((c = wc_CertNew(NULL)) != NULL);
    for (i = 0; i < LARGE_SAN_COUNT; i++) {
        snprintf(names[i], sizeof(names[i]), "device-%02d.fleet.example.com",
                 i);
        dns[i] = names[i];
        REQUIRE(wc_SetDNSEntry(NULL, names[i], (int)strlen(names[i]),
                               ASN_DNS_TYPE, &list) == 0);
    }
    REQUIRE(wc_SetAltNamesFromList(c, list) == 0);
    FreeAltNames(list, NULL);
    strcpy(c->subject.commonName, "big");
    cert_len = make_self_cert(c, key, cert, (int)sizeof(cert));
    REQUIRE(cert_len > 0);


    meta.subject_dn  = "CN=big";
    meta.san_dns     = dns;
    meta.san_dns_len = LARGE_SAN_COUNT;
    REQUIRE(wolfcert_csr_build(key, &meta, &csr) == WOLFCERT_OK);
    REQUIRE(count_csr_sans(&csr) == LARGE_SAN_COUNT);
    wolfcert_buffer_free(&csr);

    memset(&meta, 0, sizeof(meta));
    REQUIRE(wolfcert_csr_build_ex(key, &meta, cert, (size_t)cert_len, &csr)
            == WOLFCERT_OK);
    REQUIRE(count_csr_sans(&csr) == LARGE_SAN_COUNT);

    wolfcert_buffer_free(&csr);
    wolfcert_key_free(key);
    return 0;
}

/* Write a DER tag and length; returns the header size. */
static word32 der_hdr(byte* out, byte tag, word32 len)
{
    word32 n = 0;

    out[n++] = tag;
    if (len >= 0x100) {
        out[n++] = 0x82;
        out[n++] = (byte)(len >> 8);
    }
    else if (len >= 0x80) {
        out[n++] = 0x81;
    }
    out[n++] = (byte)len;
    return n;
}

/* Wrap the len bytes at buf in a tag and length; returns the new length. */
static word32 der_wrap(byte* buf, word32 len, byte tag)
{
    byte hdr[4];
    word32 n = der_hdr(hdr, tag, len);

    memmove(buf + n, buf, len);
    memcpy(buf, hdr, n);
    return n + len;
}

#define OU_VALUE_MAX 250

/* Encoded size of one OU RDN holding v value bytes. */
static word32 ou_rdn_len(word32 v)
{
    byte hdr[4];
    word32 atv = 5 + der_hdr(hdr, ASN_UTF8STRING, v) + v;
    word32 seq = der_hdr(hdr, ASN_SEQUENCE | ASN_CONSTRUCTED, atv) + atv;

    return der_hdr(hdr, ASN_SET | ASN_CONSTRUCTED, seq) + seq;
}

/* The value size of the one OU RDN that encodes to exactly len bytes, or 0. */
static word32 ou_value_for(word32 len)
{
    word32 v;

    for (v = 1; v <= OU_VALUE_MAX; v++) {
        if (ou_rdn_len(v) == len)
            return v;
    }
    return 0;
}

/* OU RDNs whose encoding is exactly len (>= 12) bytes, in few enough RDNs for
 * the 16 an OPENSSL_EXTRA wolfSSL parses. */
static word32 put_ou_rdns(byte* out, word32 len)
{
    static const byte ou_oid[] = { 0x06, 0x03, 0x55, 0x04, 0x0b };
    word32 p = 0;
    word32 start;
    word32 rest;
    word32 v;
    word32 w;

    while (p < len) {
        v = ou_value_for(len - p);
        for (w = OU_VALUE_MAX; v == 0 && w > 0; w--) {
            if (ou_rdn_len(w) + 12 <= len - p) {
                rest = len - p - ou_rdn_len(w);
                if (rest > ou_rdn_len(OU_VALUE_MAX) || ou_value_for(rest) != 0)
                    v = w;
            }
        }
        start = p;
        memcpy(out + p, ou_oid, sizeof(ou_oid));
        p += (word32)sizeof(ou_oid);
        p += der_hdr(out + p, ASN_UTF8STRING, v);
        memset(out + p, 'a', v);
        p += v;
        p = start + der_wrap(out + start, p - start,
                             ASN_SEQUENCE | ASN_CONSTRUCTED);
        p = start + der_wrap(out + start, p - start, ASN_SET | ASN_CONSTRUCTED);
    }
    return p;
}

/* A GeneralNames of dNSNames that is exactly len (>= 260) bytes; returns the
 * number of names. */
static int put_dns_names(byte* out, word32 len)
{
    word32 p = der_hdr(out, ASN_SEQUENCE | ASN_CONSTRUCTED, len - 4);
    word32 v;
    int n = 0;

    while (p < len) {
        v = (len - p >= 105) ? 100 : len - p - 2;
        out[p++] = ASN_CONTEXT_SPECIFIC | ASN_DNS_TYPE;
        out[p++] = (byte)v;
        memset(out + p, 'a', v);
        p += v;
        n++;
    }
    return n;
}

/* An unsigned cert whose Subject contents are subj_len bytes and whose SAN,
 * if san_len is not 0, is san_len bytes; *names gets the SAN's name count. */
static int make_sized_cert(const WolfCertKey* key, word32 subj_len,
                           word32 san_len, byte* out, int* names)
{
    static const byte tbs_head[] = {
        0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x01, 0x01,
        0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02,
        0x30, 0x0c, 0x31, 0x0a, 0x30, 0x08, 0x06, 0x03, 0x55, 0x04, 0x03,
        0x0c, 0x01, 'i',
        0x30, 0x1e,
        0x17, 0x0d, '2', '6', '0', '1', '0', '1', '0', '0', '0', '0', '0', '0',
        'Z',
        0x17, 0x0d, '3', '6', '0', '1', '0', '1', '0', '0', '0', '0', '0', '0',
        'Z'
    };
    static const byte sig_tail[] = {
        0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02,
        0x03, 0x09, 0x00, 0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01
    };
    static const byte san_oid[] = { 0x06, 0x03, 0x55, 0x1d, 0x11 };
    word32 p = (word32)sizeof(tbs_head);
    word32 start;
    word32 ext;
    int spki;

    memcpy(out, tbs_head, sizeof(tbs_head));
    start = p;
    p += put_ou_rdns(out + p, subj_len);
    p = start + der_wrap(out + start, p - start,
                         ASN_SEQUENCE | ASN_CONSTRUCTED);
    spki = wc_EccPublicKeyToDer((ecc_key*)key->impl, out + p, 512, 1);
    if (spki <= 0)
        return -1;
    p += (word32)spki;

    if (san_len != 0) {
        ext = p;
        memcpy(out + p, san_oid, sizeof(san_oid));
        p += (word32)sizeof(san_oid);
        *names = put_dns_names(out + p, san_len);
        p += der_wrap(out + p, san_len, ASN_OCTET_STRING);
        p = ext + der_wrap(out + ext, p - ext, ASN_SEQUENCE | ASN_CONSTRUCTED);
        p = ext + der_wrap(out + ext, p - ext, ASN_SEQUENCE | ASN_CONSTRUCTED);
        p = ext + der_wrap(out + ext, p - ext,
                           ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED | 3);
    }

    p = der_wrap(out, p, ASN_SEQUENCE | ASN_CONSTRUCTED);
    memcpy(out + p, sig_tail, sizeof(sig_tail));
    p += (word32)sizeof(sig_tail);
    return (int)der_wrap(out, p, ASN_SEQUENCE | ASN_CONSTRUCTED);
}

/* The largest Subject and SAN a renewal carries, and one byte past each. */
static int renewal_size_limits(void)
{
    const word32 name_max = (word32)sizeof(((Cert*)NULL)->sbjRaw) - 1;
    const word32 san_max = (word32)sizeof(((Cert*)NULL)->altNames);
    WolfCertKeyCfg cfg = { .type = WOLFCERT_KEY_ECC, .param = 256,
                           .dev_id = WOLFCERT_DEVID_SOFTWARE };
    WolfCertKey* key = NULL;
    WolfCertCertMeta meta = { 0 };
    WolfCertBuffer csr = { 0 };
    DecodedCert cc;
    DecodedCert dc;
    byte* cert;
    int cert_len;
    int names = 0;
    int same;

    REQUIRE(wolfcert_key_generate(&cfg, &key) == WOLFCERT_OK);
    REQUIRE((cert = (byte*)malloc(name_max + san_max + 1024)) != NULL);

    cert_len = make_sized_cert(key, name_max, 0, cert, &names);
    REQUIRE(cert_len > 0);
    REQUIRE(wolfcert_csr_build_ex(key, &meta, cert, (size_t)cert_len, &csr)
            == WOLFCERT_OK);
    wc_InitDecodedCert(&cc, cert, (word32)cert_len, NULL);
    wc_InitDecodedCert(&dc, csr.data, (word32)csr.len, NULL);
    same = wc_ParseCert(&cc, CERT_TYPE, NO_VERIFY, NULL) == 0 &&
           wc_ParseCert(&dc, CERTREQ_TYPE, NO_VERIFY, NULL) == 0 &&
           cc.subjectRawLen == (int)name_max &&
           dc.subjectRawLen == (int)name_max &&
           memcmp(cc.subjectRaw, dc.subjectRaw, name_max) == 0;
    wc_FreeDecodedCert(&dc);
    wc_FreeDecodedCert(&cc);
    REQUIRE(same);
    wolfcert_buffer_free(&csr);

    cert_len = make_sized_cert(key, name_max + 1, 0, cert, &names);
    REQUIRE(cert_len > 0);
    REQUIRE(wolfcert_csr_build_ex(key, &meta, cert, (size_t)cert_len, &csr)
            == WOLFCERT_ERR_UNSUPPORTED);
    REQUIRE(csr.data == NULL);

    cert_len = make_sized_cert(key, 12, san_max, cert, &names);
    REQUIRE(cert_len > 0);
    REQUIRE(wolfcert_csr_build_ex(key, &meta, cert, (size_t)cert_len, &csr)
            == WOLFCERT_OK);
    REQUIRE(count_csr_sans(&csr) == names);
    wolfcert_buffer_free(&csr);

    cert_len = make_sized_cert(key, 12, san_max + 1, cert, &names);
    REQUIRE(cert_len > 0);
    REQUIRE(wolfcert_csr_build_ex(key, &meta, cert, (size_t)cert_len, &csr)
            == WOLFCERT_ERR_UNSUPPORTED);
    REQUIRE(csr.data == NULL);

    free(cert);
    wolfcert_key_free(key);
    return 0;
}
#endif

int main(void)
{
    REQUIRE(test_static_mem_init() == 0);
    REQUIRE(wolfcert_init(test_heap_hint()) == WOLFCERT_OK);

#ifdef WOLFCERT_HAVE_SERVER
    if (subject_copy_rejects_oversized_rdn())
        return 1;
#endif
#ifdef WOLFCERT_HAVE_ECC
    if (csr_build_rejects_oversized_rdn())
        return 1;
    if (renewal_keeps_empty_subject(1) || renewal_keeps_empty_subject(0))
        return 1;
    if (renewal_reads_past_unknown_critical_ext())
        return 1;
    if (renewal_refuses_bmpstring_subject())
        return 1;
    if (renewal_drops_callback_san())
        return 1;
    if (renewal_rejects_meta_identity())
        return 1;
    if (renewal_walks_extensions_without_san())
        return 1;
    if (renewal_rejects_non_certificate())
        return 1;
    if (csr_carries_large_san())
        return 1;
    if (renewal_size_limits())
        return 1;
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
