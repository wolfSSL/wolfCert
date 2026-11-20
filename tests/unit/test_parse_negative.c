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

/* Negative-path tests for the parsers that ingest untrusted bytes. */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include <wolfcert/wolfcert.h>
#include "../test_static_mem.h"
#include "internal.h"

#include <stdio.h>
#include <string.h>

#if defined(WOLFCERT_HAVE_SCEP) && defined(WOLFCERT_HAVE_RSA)
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/random.h>
#endif

#define REQUIRE(cond) \
    do {                                                                    \
        if (!(cond)) {                                                      \
            fprintf(stderr, "FAIL %s:%d %s\n", __FILE__, __LINE__, #cond);  \
            return 1;                                                       \
        }                                                                   \
    } while (0)

static int test_url(void)
{
    WolfCertUrl u;
    /* A missing scheme defaults to TLS, so only the bad port fails. */
    REQUIRE(wolfcert_http_url_parse("no-scheme:0/p", &u, NULL) == WOLFCERT_ERR_PARSE);
    /* Empty bracketed IPv6. */
    REQUIRE(wolfcert_http_url_parse("http://[:/p", &u, NULL) == WOLFCERT_ERR_PARSE);
    /* Unknown scheme. */
    REQUIRE(wolfcert_http_url_parse("ftp://x/", &u, NULL) == WOLFCERT_ERR_UNSUPPORTED);
    /* Port out of range. */
    REQUIRE(wolfcert_http_url_parse("http://x:0/", &u, NULL) == WOLFCERT_ERR_PARSE);
    REQUIRE(wolfcert_http_url_parse("http://x:99999/", &u, NULL) == WOLFCERT_ERR_PARSE);
    /* Bytes that would reach the request line or Host header raw. */
    static const char* const bad[] = {
        "http://x/a\r\nX-Injected: 1",
        "http://x/a b",
        "http://x/a\tb",
        "http://x\r\nX-Injected: 1/",
        "http://x/a\x7f",
        "http://x/\xc3\xa4",
        "http://user@x/",
        "http://user:pw@x/",
        "http://[::1]junk/",
        "http://x:80junk/",
        "http://x:+80/",
        "http://[ca.example]/",
        "http://[127.0.0.1]/",
        "http://[::1/x]",
        "http://[]/",
        "http:///x",
        "https://:8443/",
        "/x",
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        if (wolfcert_http_url_parse(bad[i], &u, NULL) != WOLFCERT_ERR_PARSE) {
            fprintf(stderr, "accepted bad URL #%zu\n", i);
            return 1;
        }
    }
    /* Hostname longer than the cap. */
    char big[400];
    memset(big, 'a', sizeof(big) - 1);
    big[sizeof(big) - 1] = '\0';
    char url[512];
    snprintf(url, sizeof(url), "http://%s/", big);
    REQUIRE(wolfcert_http_url_parse(url, &u, NULL) == WOLFCERT_ERR_PARSE);
    return 0;
}

static int test_base64(void)
{
    WolfCertBuffer out = { 0 };
    /* Garbage chars. */
    const uint8_t bad[] = "!!!!";
    REQUIRE(wolfcert_base64_decode(bad, sizeof(bad) - 1, &out, NULL) != WOLFCERT_OK);
    /* Whitespace only decodes to nothing. */
    const uint8_t ws[] = "\r\n";
    out.data = (uint8_t*)1;
    REQUIRE(wolfcert_base64_decode(ws, sizeof(ws) - 1, &out, NULL) == WOLFCERT_OK);
    REQUIRE(out.data == NULL && out.len == 0);
    return 0;
}

#if defined(WOLFCERT_HAVE_EST) || defined(WOLFCERT_HAVE_SCEP)
static int test_pkcs7(void)
{
    /* Zero-length input. */
    WolfCertBuffer out = { 0 };
    REQUIRE(wolfcert_pkcs7_certs_to_pem(NULL, 0, &out, NULL) == WOLFCERT_ERR_BAD_ARG);

    /* Garbage DER. */
    uint8_t buf[32];
    memset(buf, 0xFF, sizeof(buf));
    REQUIRE(wolfcert_pkcs7_certs_to_pem(buf, sizeof(buf), &out, NULL) != WOLFCERT_OK);

    /* Truncated SEQUENCE. */
    uint8_t trunc[] = { 0x30, 0x10, 0x06 };
    REQUIRE(wolfcert_pkcs7_certs_to_pem(trunc, sizeof(trunc), &out, NULL) != WOLFCERT_OK);

    /* certs_only build rejects non-SEQUENCE cert input. */
    const uint8_t junk[8] = { 0x00 };
    const uint8_t* certs[1] = { junk };
    size_t lens[1] = { sizeof(junk) };
    REQUIRE(wolfcert_pkcs7_build_certs_only(certs, lens, 1, &out, NULL)
            == WOLFCERT_ERR_PARSE);
    return 0;
}
#endif

#if defined(WOLFCERT_HAVE_SCEP) && defined(WOLFCERT_HAVE_RSA)
static int oid_present(const uint8_t* hay, size_t hl,
                       const uint8_t* needle, size_t nl)
{
    size_t i;
    if (nl > hl)
        return 0;

    for (i = 0; i + nl <= hl; ++i) {
        if (memcmp(hay + i, needle, nl) == 0)
            return 1;
    }

    return 0;
}

/* AES128CBCb envelopes carry the AES-128-CBC OID and no AES-256-CBC OID;
 * DES3b envelopes carry the 3DES-CBC OID. */
static int test_scep_envelop_alg(void)
{
    static const uint8_t OID_AES128_CBC[] =
        { 0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x01,0x02 };
    static const uint8_t OID_AES256_CBC[] =
        { 0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x01,0x2A };
#ifndef NO_DES3
    static const uint8_t OID_DES3_CBC[] =
        { 0x06,0x08,0x2A,0x86,0x48,0x86,0xF7,0x0D,0x03,0x07 };
#endif
    static const uint8_t payload[] = { 0x04, 0x03, 0x61, 0x62, 0x63 };

    RsaKey key;
    WC_RNG rng;
    uint8_t* ra_der = NULL;
    size_t ra_len = 0;
    WolfCertBuffer env = { 0 };
    Cert* req = NULL;
    uint8_t* csr_der = NULL;
    int csr_body = 0;
    int csr_len = 0;

    REQUIRE(wc_InitRng(&rng) == 0);
    REQUIRE(wc_InitRsaKey(&key, NULL) == 0);
    REQUIRE(wc_MakeRsaKey(&key, 2048, 65537L, &rng) == 0);

    /* A minimal CSR for wolfcert_scep_self_signed_rsa, which copies its subject
     * into the signer cert; the CN value is arbitrary. */
    req = wc_CertNew(NULL);
    REQUIRE(req != NULL);
    wc_InitCert_ex(req, NULL, INVALID_DEVID);
    req->version = 0;
    strncpy(req->subject.commonName, "scep-test", CTC_NAME_SIZE - 1);
    req->subject.commonName[CTC_NAME_SIZE - 1] = '\0';
    req->sigType = CTC_SHA256wRSA;

    csr_der = (uint8_t*)WOLFCERT_XMALLOC(4096, NULL);
    REQUIRE(csr_der != NULL);
    csr_body = wc_MakeCertReq(req, csr_der, 4096, &key, NULL);
    REQUIRE(csr_body > 0);
    csr_len = wc_SignCert(csr_body, CTC_SHA256wRSA, csr_der, 4096, &key, NULL,
                          &rng);
    REQUIRE(csr_len > 0);

    REQUIRE(wolfcert_scep_self_signed_rsa(&key, csr_der, (size_t)csr_len,
                                          &ra_der, &ra_len, INVALID_DEVID, NULL) == WOLFCERT_OK);

    REQUIRE(wolfcert_scep_envelop(ra_der, ra_len, payload, sizeof(payload),
                                  AES128CBCb, &env, INVALID_DEVID, NULL) == WOLFCERT_OK);

    REQUIRE(oid_present(env.data, env.len,
                        OID_AES128_CBC, sizeof(OID_AES128_CBC)));
    REQUIRE(!oid_present(env.data, env.len,
                         OID_AES256_CBC, sizeof(OID_AES256_CBC)));

    wolfcert_buffer_free(&env);

#ifndef NO_DES3
    REQUIRE(wolfcert_scep_envelop(ra_der, ra_len, payload, sizeof(payload),
                                  DES3b, &env, INVALID_DEVID, NULL) == WOLFCERT_OK);

    REQUIRE(oid_present(env.data, env.len,
                        OID_DES3_CBC, sizeof(OID_DES3_CBC)));

    wolfcert_buffer_free(&env);
#endif

    WOLFCERT_XFREE(ra_der, NULL);
    WOLFCERT_XFREE(csr_der, NULL);
    wc_CertFree(req);
    wc_FreeRsaKey(&key);
    wc_FreeRng(&rng);
    return 0;
}
#endif

static int test_ip_literal(void)
{
    static const struct {
        const char*   text;
        size_t        len;
        const uint8_t bytes[16];
    } good[] = {
        { "192.0.2.10",       4, { 192, 0, 2, 10 } },
        { "::",              16, { 0 } },
        { "::1",             16, { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1 } },
        { "fe80::1",         16, { 0xfe,0x80,0,0,0,0,0,0,0,0,0,0,0,0,0,1 } },
        { "::ffff:192.0.2.1", 16,
          { 0,0,0,0,0,0,0,0,0,0,0xff,0xff,192,0,2,1 } },
        { "1:2:3:4:5:6:7:8", 16, { 0,1,0,2,0,3,0,4,0,5,0,6,0,7,0,8 } }
    };
    static const char* const bad[] = {
        "010.1.1.1", "256.1.1.1", "1.2.3", "1.2.3.4.5",
        "fe80::1%eth0", "2001:db8::/32", "1::2::3", "12345::", "g::1", ""
    };
    uint8_t out[16];
    size_t len;
    size_t i;

    for (i = 0; i < sizeof(good) / sizeof(good[0]); ++i) {
        len = 0;
        REQUIRE(wolfcert_parse_ip(good[i].text, out, &len) == WOLFCERT_OK);
        REQUIRE(len == good[i].len);
        REQUIRE(memcmp(out, good[i].bytes, len) == 0);
    }

    for (i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i) {
        len = 0;
        REQUIRE(wolfcert_parse_ip(bad[i], out, &len) == WOLFCERT_ERR_PARSE);
    }

    REQUIRE(wolfcert_parse_ip(NULL, out, &len) == WOLFCERT_ERR_BAD_ARG);
    return 0;
}

static int test_csr_pem(void)
{
    WolfCertBuffer der = { 0 };
    REQUIRE(wolfcert_csr_pem_to_der((const uint8_t*)"not pem", 7, &der) == WOLFCERT_ERR_PARSE);
    return 0;
}

/* A size of 0 on a wolfSSL failure path must not map to success. */
static int test_wc_err_zero(void)
{
    REQUIRE(wolfcert_map_wc_err(0) != WOLFCERT_OK);
    return 0;
}

static int test_der_next(void)
{
    static const uint8_t two[] = { 0x30, 0x01, 0xAA, '\n', 0xFF, 0x00,
                                   0x30, 0x00, '\r', '\n', 0xFF };
    static const uint8_t overrun[] = { 0x30, 0x01, 0xAA, 0x30, 0x05, 0x01 };
    static const uint8_t stray[] = { 0x30, 0x00, 0x02, 0x01, 0x00 };
    static const uint8_t lead[] = { 0xA5, 0x30, 0x00 };
    static const uint8_t pad_lead[] = { '\n', 0xA5, 0x30, 0x00 };
    static const uint8_t blank[] = { '\n', 0x00, 0xFF };
    static const uint8_t zero_nl[] = { 0x30, 0x00, '0', '\n' };
    const uint8_t* item = NULL;
    size_t item_len = 0;
    size_t off = 0;

    REQUIRE(wolfcert_der_next(two, sizeof(two), &off, &item, &item_len) == 1);
    REQUIRE(item == two && item_len == 3 && off == 3);
    REQUIRE(wolfcert_der_next(two, sizeof(two), &off, &item, &item_len) == 1);
    REQUIRE(item == two + 6 && item_len == 2);
    REQUIRE(wolfcert_der_next(two, sizeof(two), &off, &item, &item_len) == 0);
    REQUIRE(off == sizeof(two));

    off = 3;
    REQUIRE(wolfcert_der_next(overrun, sizeof(overrun), &off, &item,
                              &item_len) == 0);
    REQUIRE(off == 3);
    off = 0;
    REQUIRE(wolfcert_der_next(overrun + 3, sizeof(overrun) - 3, &off, &item,
                              &item_len) == WOLFCERT_ERR_PARSE);
    off = 0;
    REQUIRE(wolfcert_der_next(zero_nl, sizeof(zero_nl), &off, &item,
                              &item_len) == 1);
    REQUIRE(wolfcert_der_next(zero_nl, sizeof(zero_nl), &off, &item,
                              &item_len) == 0);
    REQUIRE(off == 2);
    off = 0;
    REQUIRE(wolfcert_der_next(stray, sizeof(stray), &off, &item,
                              &item_len) == 1);
    REQUIRE(wolfcert_der_next(stray, sizeof(stray), &off, &item,
                              &item_len) == 0);
    REQUIRE(off == 2);
    off = 0;
    REQUIRE(wolfcert_der_next(lead, sizeof(lead), &off, &item,
                              &item_len) == WOLFCERT_ERR_PARSE);
    off = 0;
    REQUIRE(wolfcert_der_next(pad_lead, sizeof(pad_lead), &off, &item,
                              &item_len) == WOLFCERT_ERR_PARSE);
    off = 0;
    REQUIRE(wolfcert_der_next(blank, sizeof(blank), &off, &item,
                              &item_len) == WOLFCERT_ERR_PARSE);
    off = sizeof(two) + 1;
    REQUIRE(wolfcert_der_next(two, sizeof(two), &off, &item,
                              &item_len) == WOLFCERT_ERR_BAD_ARG);

    return 0;
}

static int test_der_is_cert(void)
{
    static const uint8_t cert[] = { 0x30, 0x17, 0x30, 0x10, 0xA0, 0x03, 0x02,
                                    0x01, 0x02, 0x02, 0x01, 0x01, 0x30, 0x02,
                                    0x06, 0x00, 0x30, 0x00, 0x30, 0x00, 0x30,
                                    0x00, 0x03, 0x01, 0x00 };
    static const uint8_t no_version[] = { 0x30, 0x12, 0x30, 0x0B, 0x02, 0x01,
                                          0x01, 0x30, 0x02, 0x06, 0x00, 0x30,
                                          0x00, 0x30, 0x00, 0x30, 0x00, 0x03,
                                          0x01, 0x00 };
    static const uint8_t csr[] = { 0x30, 0x12, 0x30, 0x0B, 0x02, 0x01, 0x00,
                                   0x30, 0x02, 0x31, 0x00, 0x30, 0x00, 0xA0,
                                   0x00, 0x30, 0x00, 0x03, 0x01, 0x00 };
    static const uint8_t crl[] = { 0x30, 0x12, 0x30, 0x0B, 0x02, 0x01, 0x01,
                                   0x30, 0x02, 0x06, 0x00, 0x30, 0x00, 0x17,
                                   0x00, 0x30, 0x00, 0x03, 0x01, 0x00 };
    uint8_t buf[sizeof(cert) + 1];

    REQUIRE(wolfcert_der_is_cert(cert, sizeof(cert)) == 1);
    REQUIRE(wolfcert_der_is_cert(cert, 1) == 0);
    REQUIRE(wolfcert_der_is_cert(cert, sizeof(cert) - 1) == 0);
    REQUIRE(wolfcert_der_is_cert(no_version, sizeof(no_version)) == 1);
    REQUIRE(wolfcert_der_is_cert(csr, sizeof(csr)) == 0);
    REQUIRE(wolfcert_der_is_cert(crl, sizeof(crl)) == 0);

    memcpy(buf, cert, sizeof(cert));
    buf[1] = 0x18;
    buf[sizeof(cert)] = 0x00;
    REQUIRE(wolfcert_der_is_cert(buf, sizeof(buf)) == 0);
    memcpy(buf, cert, sizeof(cert));
    buf[20] = 0x31;
    REQUIRE(wolfcert_der_is_cert(buf, sizeof(cert)) == 0);
    memcpy(buf, cert, sizeof(cert));
    buf[22] = 0x04;
    REQUIRE(wolfcert_der_is_cert(buf, sizeof(cert)) == 0);
    memcpy(buf, cert, sizeof(cert));
    buf[3] = 0x0F;
    REQUIRE(wolfcert_der_is_cert(buf, sizeof(cert)) == 0);
    memcpy(buf, cert, sizeof(cert));
    buf[14] = 0x05;
    REQUIRE(wolfcert_der_is_cert(buf, sizeof(cert)) == 0);

    return 0;
}

int main(void)
{
    REQUIRE(test_static_mem_init() == 0);
    REQUIRE(wolfcert_init(test_heap_hint()) == WOLFCERT_OK);
    if (test_url())
        return 1;
    if (test_base64())
        return 1;
#if defined(WOLFCERT_HAVE_EST) || defined(WOLFCERT_HAVE_SCEP)
    if (test_pkcs7())
        return 1;
#endif
    if (test_csr_pem())
        return 1;
    if (test_ip_literal())
        return 1;
#if defined(WOLFCERT_HAVE_SCEP) && defined(WOLFCERT_HAVE_RSA)
    if (test_scep_envelop_alg())
        return 1;
#endif
    if (test_wc_err_zero())
        return 1;
    if (test_der_next())
        return 1;
    if (test_der_is_cert())
        return 1;
    wolfcert_cleanup();
    printf("OK\n");
    return 0;
}
