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

#include <wolfcert/wolfcert.h>
#include <wolfcert/server.h>
#include "internal.h"
#include "../test_static_mem.h"
#include "../integration/tls_test_util.h"

#include <wolfssl/wolfcrypt/asn.h>

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

#ifdef WOLFCERT_HAVE_ECC
    #define CA_KEY_TYPE   WOLFCERT_KEY_ECC
    #define CA_KEY_PARAM  256
#else
    #define CA_KEY_TYPE   0
    #define CA_KEY_PARAM  0
#endif

/* SCEP is absent from NO_RSA builds, and EST needs a server identity. */
#if defined(WOLFCERT_HAVE_EST)
    #define CA_TEST_PROTO WOLFCERT_PROTO_EST
    #define CA_TEST_NEEDS_TLS 1
#else
    #define CA_TEST_PROTO WOLFCERT_PROTO_SCEP
    #define CA_TEST_NEEDS_TLS 0
#endif

#if CA_TEST_NEEDS_TLS
static uint8_t* srv_cert_pem;
static size_t   srv_cert_pem_len;
static uint8_t* srv_key_pem;
static size_t   srv_key_pem_len;
#endif

/* A server config issuing from cert and key; both NULL generates a CA. */
static void ca_cfg(WolfCertServerCfgSrv* cfg, const WolfCertBuffer* cert,
                   const WolfCertBuffer* key)
{
    memset(cfg, 0, sizeof(*cfg));
    cfg->protocol     = CA_TEST_PROTO;
#if CA_TEST_NEEDS_TLS
    cfg->tls_cert_pem     = srv_cert_pem;
    cfg->tls_cert_pem_len = srv_cert_pem_len;
    cfg->tls_key_pem      = srv_key_pem;
    cfg->tls_key_pem_len  = srv_key_pem_len;
    cfg->est_allow_anonymous_enroll = 1;
#endif
    cfg->bind_host    = "127.0.0.1";
    cfg->ca_key_type  = CA_KEY_TYPE;
    cfg->ca_key_param = CA_KEY_PARAM;
    if (cert != NULL) {
        cfg->ca_cert     = cert->data;
        cfg->ca_cert_len = cert->len;
    }
    if (key != NULL) {
        cfg->ca_key     = key->data;
        cfg->ca_key_len = key->len;
    }
}

static int ca_key_param(WolfCertKeyType t)
{
    if (t == WOLFCERT_KEY_RSA)
        return 2048;
    if (t == WOLFCERT_KEY_ECC)
        return 256;
    return 0;
}

/* A server start generates a CA of type; the pair is copied out as enc. */
static int generate_ca(WolfCertKeyType type, WolfCertEncoding enc,
                       WolfCertBuffer* cert, WolfCertBuffer* key)
{
    WolfCertServerCfgSrv cfg;
    WolfCertServer* srv = NULL;
    int rc;

    ca_cfg(&cfg, NULL, NULL);
    cfg.ca_key_type  = type;
    cfg.ca_key_param = ca_key_param(type);
    REQUIRE(wolfcert_server_start(&cfg, &srv) == WOLFCERT_OK);
    rc = wolfcert_server_get_ca(srv, enc, cert, key);
    wolfcert_server_free(srv);
    REQUIRE(rc == WOLFCERT_OK);
    return 0;
}

/* A server start with cert and key gets want and, on failure, no server. */
static int start_gets(const WolfCertBuffer* cert, const WolfCertBuffer* key,
                      int want)
{
    WolfCertServerCfgSrv cfg;
    WolfCertServer* srv = NULL;

    ca_cfg(&cfg, cert, key);
    REQUIRE(wolfcert_server_start(&cfg, &srv) == want);
    if (want != WOLFCERT_OK)
        REQUIRE(srv == NULL);
    wolfcert_server_free(srv);
    return 0;
}

static int test_corrupt_ca_rejected(void)
{
    uint8_t junk[] = { 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA };
    WolfCertBuffer bad = { junk, sizeof(junk), NULL };

    return start_gets(&bad, &bad, WOLFCERT_ERR_PARSE);
}

/* One half of the pair, or an empty half, is refused before any work. */
static int test_half_ca_rejected(void)
{
    uint8_t der[] = { 0x30, 0x03, 0x02, 0x01, 0x01 };
    WolfCertBuffer half  = { der, sizeof(der), NULL };
    WolfCertBuffer empty = { der, 0, NULL };
    WolfCertServerCfgSrv cfg;
    WolfCertServer* srv = NULL;

    if (start_gets(&half, NULL, WOLFCERT_ERR_BAD_ARG))
        return 1;
    if (start_gets(NULL, &half, WOLFCERT_ERR_BAD_ARG))
        return 1;
    if (start_gets(&half, &empty, WOLFCERT_ERR_BAD_ARG))
        return 1;
    if (start_gets(&empty, &half, WOLFCERT_ERR_BAD_ARG))
        return 1;

    /* A length without its pointer is not a request to generate a CA. */
    ca_cfg(&cfg, NULL, NULL);
    cfg.ca_cert_len = sizeof(der);
    cfg.ca_key_len  = sizeof(der);
    REQUIRE(wolfcert_server_start(&cfg, &srv) == WOLFCERT_ERR_BAD_ARG);
    REQUIRE(srv == NULL);
    return 0;
}

/* A generated CA handed back in, as DER or PEM, is the one the server uses. */
static int test_ca_round_trip(void)
{
    WolfCertBuffer der_cert = { 0 };
    WolfCertBuffer der_key  = { 0 };
    WolfCertBuffer pem_cert = { 0 };
    WolfCertBuffer pem_key  = { 0 };
    WolfCertBuffer again    = { 0 };
    WolfCertServerCfgSrv cfg;
    WolfCertServer* srv = NULL;
    int rc;

    ca_cfg(&cfg, NULL, NULL);
    REQUIRE(wolfcert_server_start(&cfg, &srv) == WOLFCERT_OK);
    REQUIRE(wolfcert_server_get_ca(srv, WOLFCERT_ENCODING_DER, &der_cert,
                                   &der_key) == WOLFCERT_OK);
    REQUIRE(wolfcert_server_get_ca(srv, WOLFCERT_ENCODING_PEM, &pem_cert,
                                   &pem_key) == WOLFCERT_OK);
    wolfcert_server_free(srv);
    srv = NULL;
    REQUIRE(der_cert.data[0] == 0x30 && der_key.data[0] == 0x30);
    REQUIRE(memcmp(pem_cert.data, "-----BEGIN CERTIFICATE-----", 27) == 0);
    REQUIRE(memcmp(pem_key.data, "-----BEGIN ", 11) == 0);

    ca_cfg(&cfg, &pem_cert, &pem_key);
    REQUIRE(wolfcert_server_start(&cfg, &srv) == WOLFCERT_OK);
    rc = wolfcert_server_get_ca(srv, WOLFCERT_ENCODING_DER, &again, NULL);
    wolfcert_server_free(srv);
    srv = NULL;
    REQUIRE(rc == WOLFCERT_OK);
    REQUIRE(again.len == der_cert.len);
    REQUIRE(memcmp(again.data, der_cert.data, der_cert.len) == 0);
    wolfcert_buffer_free(&again);

    ca_cfg(&cfg, &der_cert, &der_key);
    REQUIRE(wolfcert_server_start(&cfg, &srv) == WOLFCERT_OK);
    rc = wolfcert_server_get_ca(srv, WOLFCERT_ENCODING_DER, &again, NULL);
    wolfcert_server_free(srv);
    srv = NULL;
    REQUIRE(rc == WOLFCERT_OK);
    REQUIRE(again.len == der_cert.len);
    REQUIRE(memcmp(again.data, der_cert.data, der_cert.len) == 0);
    wolfcert_buffer_free(&again);

    /* Each half may use its own encoding. */
    ca_cfg(&cfg, &pem_cert, &der_key);
    REQUIRE(wolfcert_server_start(&cfg, &srv) == WOLFCERT_OK);
    rc = wolfcert_server_get_ca(srv, WOLFCERT_ENCODING_DER, &again, NULL);
    wolfcert_server_free(srv);
    REQUIRE(rc == WOLFCERT_OK);
    REQUIRE(again.len == der_cert.len);
    REQUIRE(memcmp(again.data, der_cert.data, der_cert.len) == 0);

    wolfcert_buffer_free(&again);
    wolfcert_buffer_free(&der_cert);
    wolfcert_buffer_free_secure(&der_key);
    wolfcert_buffer_free(&pem_cert);
    wolfcert_buffer_free_secure(&pem_key);
    return 0;
}

static int test_get_ca_args(void)
{
    WolfCertServerCfgSrv cfg;
    WolfCertServer* srv = NULL;
    WolfCertBuffer cert = { 0 };
    WolfCertBuffer key  = { 0 };

    ca_cfg(&cfg, NULL, NULL);
    REQUIRE(wolfcert_server_start(&cfg, &srv) == WOLFCERT_OK);

    REQUIRE(wolfcert_server_get_ca(NULL, WOLFCERT_ENCODING_DER, &cert, &key)
            == WOLFCERT_ERR_BAD_ARG);
    REQUIRE(wolfcert_server_get_ca(srv, WOLFCERT_ENCODING_DER, NULL, &key)
            == WOLFCERT_ERR_BAD_ARG);
    REQUIRE(wolfcert_server_get_ca(srv, (WolfCertEncoding)7, &cert, &key)
            == WOLFCERT_ERR_BAD_ARG);
    REQUIRE(strstr(wolfcert_last_error_message(), "encoding") != NULL);
    REQUIRE(cert.data == NULL && key.data == NULL);

    REQUIRE(wolfcert_server_get_ca(srv, WOLFCERT_ENCODING_PEM, &cert, NULL)
            == WOLFCERT_OK);
    REQUIRE(cert.data != NULL && cert.len > 0);

    wolfcert_buffer_free(&cert);
    wolfcert_server_free(srv);
    return 0;
}

#if defined(USE_WOLFSSL_MEMORY) && !defined(WOLFSSL_STATIC_MEMORY) && \
    !defined(WOLFSSL_DEBUG_MEMORY)
/* Index of the one allocation fail_one_malloc() refuses; -1 refuses none. */
static int g_fail_at = -1;
static int g_allocs;

static void* fail_one_malloc(size_t sz)
{
    return g_allocs++ == g_fail_at ? NULL : malloc(sz);
}

static void fail_one_free(void* ptr)
{
    free(ptr);
}

static void* fail_one_realloc(void* ptr, size_t sz)
{
    return g_allocs++ == g_fail_at ? NULL : realloc(ptr, sz);
}

/* A start that survives any single failed allocation keeps every credential. */
static int test_start_oom_keeps_credentials(void)
{
    WolfCertBuffer cert = { 0 };
    WolfCertBuffer key  = { 0 };
    WolfCertServerCfgSrv cfg;
    WolfCertServer* srv = NULL;
    wolfSSL_Malloc_cb  mf;
    wolfSSL_Free_cb    ff;
    wolfSSL_Realloc_cb rf;
    int fail_at;
    int rc;

    if (generate_ca(CA_KEY_TYPE, WOLFCERT_ENCODING_PEM, &cert, &key))
        return 1;
    ca_cfg(&cfg, &cert, &key);
    cfg.http_basic_user    = "alice";
    cfg.http_basic_pass    = "secret";
    cfg.challenge_password = "otp";

    REQUIRE(wolfSSL_GetAllocators(&mf, &ff, &rf) == 0);
    for (fail_at = 0; ; fail_at++) {
        srv = NULL;
        g_fail_at = fail_at;
        g_allocs = 0;
        wolfcert_clear_error();
        REQUIRE(wolfSSL_SetAllocators(fail_one_malloc, fail_one_free,
                                      fail_one_realloc) == 0);
        rc = wolfcert_server_start(&cfg, &srv);
        REQUIRE(wolfSSL_SetAllocators(mf, ff, rf) == 0);
        if (rc != WOLFCERT_OK) {
            REQUIRE(srv == NULL);
            REQUIRE(strstr(wolfcert_last_error_message(), "does not match")
                    == NULL);
            continue;
        }
        REQUIRE(srv->cfg_basic_user != NULL &&
                strcmp(srv->cfg_basic_user, "alice") == 0);
        REQUIRE(srv->cfg_basic_pass != NULL &&
                strcmp(srv->cfg_basic_pass, "secret") == 0);
        REQUIRE(srv->cfg_challenge != NULL &&
                strcmp(srv->cfg_challenge, "otp") == 0);
        wolfcert_server_free(srv);
        if (g_allocs <= fail_at)
            break;
    }
    g_fail_at = -1;
    REQUIRE(fail_at > 4);

    wolfcert_buffer_free(&cert);
    wolfcert_buffer_free_secure(&key);
    return 0;
}
#endif

static const WolfCertKeyType CA_KEY_TYPES[] = {
#ifdef WOLFCERT_HAVE_RSA
    WOLFCERT_KEY_RSA,
#endif
#ifdef WOLFCERT_HAVE_ECC
    WOLFCERT_KEY_ECC,
#endif
#ifdef WOLFCERT_HAVE_ED25519
    WOLFCERT_KEY_ED25519,
#endif
#ifdef WOLFCERT_HAVE_ED448
    WOLFCERT_KEY_ED448,
#endif
#ifdef WOLFCERT_HAVE_MLDSA
#ifndef WOLFSSL_NO_ML_DSA_44
    WOLFCERT_KEY_MLDSA44,
#endif
#ifndef WOLFSSL_NO_ML_DSA_65
    WOLFCERT_KEY_MLDSA65,
#endif
#ifndef WOLFSSL_NO_ML_DSA_87
    WOLFCERT_KEY_MLDSA87,
#endif
#endif
};

/* The loaded CA issues a leaf that verifies against it. */
static int loaded_ca_signs(const WolfCertBuffer* cert, const WolfCertBuffer* key)
{
    /* Any compiled algorithm serves as the leaf; the first entry always is. */
    WolfCertKeyCfg kcfg = { .type = CA_KEY_TYPES[0],
                            .param = ca_key_param(CA_KEY_TYPES[0]),
                            .dev_id = INVALID_DEVID };
    WolfCertCertMeta meta = { .subject_dn = "CN=leaf" };
    WolfCertKey* leaf_key = NULL;
    WolfCertBuffer csr = { 0 };
    WolfCertCa ca;
    uint8_t* issued = NULL;
    size_t issued_len = 0;
    WOLFSSL_CERT_MANAGER* cm = NULL;
    int rc;

    REQUIRE(wolfcert_key_generate(&kcfg, &leaf_key) == WOLFCERT_OK);
    REQUIRE(wolfcert_csr_build(leaf_key, &meta, &csr) == WOLFCERT_OK);
    wolfcert_key_free(leaf_key);

    REQUIRE(wolfcert_ca_load(&ca, cert->data, cert->len, key->data, key->len,
                             NULL) == WOLFCERT_OK);
    rc = wolfcert_ca_issue(&ca, csr.data, csr.len, &issued, &issued_len);
    wolfcert_buffer_free(&csr);
    REQUIRE(rc == WOLFCERT_OK);

    cm = wolfSSL_CertManagerNew();
    REQUIRE(cm != NULL);
    REQUIRE(wolfSSL_CertManagerLoadCABuffer(cm, ca.cert_der,
                (long)ca.cert_der_len, WOLFSSL_FILETYPE_ASN1) == WOLFSSL_SUCCESS);
    rc = wolfSSL_CertManagerVerifyBuffer(cm, issued, (long)issued_len,
                                         WOLFSSL_FILETYPE_ASN1);
    wolfSSL_CertManagerFree(cm);

    WOLFCERT_XFREE(issued, ca.heap);
    wolfcert_ca_free(&ca);

    REQUIRE(rc == WOLFSSL_SUCCESS);
    return 0;
}

/* Every algorithm's CA loads back from both encodings and still signs. */
static int test_every_alg_reloads(void)
{
    size_t i;
    int e;

    for (i = 0; i < sizeof(CA_KEY_TYPES) / sizeof(CA_KEY_TYPES[0]); ++i) {
        WolfCertBuffer cert[2] = { { 0 }, { 0 } };
        WolfCertBuffer key[2]  = { { 0 }, { 0 } };
        WolfCertServerCfgSrv cfg;
        WolfCertServer* srv = NULL;
        int rc;

        ca_cfg(&cfg, NULL, NULL);
        cfg.ca_key_type  = CA_KEY_TYPES[i];
        cfg.ca_key_param = ca_key_param(CA_KEY_TYPES[i]);
        REQUIRE(wolfcert_server_start(&cfg, &srv) == WOLFCERT_OK);
        rc = wolfcert_server_get_ca(srv, WOLFCERT_ENCODING_DER, &cert[0],
                                    &key[0]);
        if (rc == WOLFCERT_OK)
            rc = wolfcert_server_get_ca(srv, WOLFCERT_ENCODING_PEM, &cert[1],
                                        &key[1]);
        wolfcert_server_free(srv);
        REQUIRE(rc == WOLFCERT_OK);

        for (e = 0; e < 2; ++e) {
            if (start_gets(&cert[e], &key[e], WOLFCERT_OK))
                return 1;
            if (loaded_ca_signs(&cert[e], &key[e]))
                return 1;
            wolfcert_buffer_free(&cert[e]);
            wolfcert_buffer_free_secure(&key[e]);
        }
    }
    return 0;
}

#ifdef WOLFCERT_HAVE_ECC
/* A SEC1 CA key without its optional public point still loads. */
static int test_ecc_key_without_public_point(void)
{
    WolfCertBuffer cert = { 0 };
    WolfCertBuffer key  = { 0 };
    WolfCertBuffer bare = { 0 };
    ecc_key ek;
    word32 idx = 0;
    uint8_t der[256];
    int n;

    if (generate_ca(WOLFCERT_KEY_ECC, WOLFCERT_ENCODING_DER, &cert, &key))
        return 1;
    REQUIRE(wc_ecc_init(&ek) == 0);
    REQUIRE(wc_EccPrivateKeyDecode(key.data, &idx, &ek, (word32)key.len) == 0);
    n = wc_EccPrivateKeyToDer(&ek, der, sizeof(der));
    wc_ecc_free(&ek);
    REQUIRE(n > 0 && (size_t)n < key.len);

    bare.data = der;
    bare.len  = (size_t)n;
    if (start_gets(&cert, &bare, WOLFCERT_OK))
        return 1;

    wc_ForceZero(der, sizeof(der));
    wolfcert_buffer_free(&cert);
    wolfcert_buffer_free_secure(&key);
    return 0;
}
#endif

#ifdef WOLFCERT_HAVE_SCEP
/* With a split RA, get_ca returns the CA, not the RA certificate. */
static int test_split_ra_get_ca_is_ca(void)
{
    WolfCertServerCfgSrv cfg;
    WolfCertServer* srv = NULL;
    WolfCertBuffer cert = { 0 };
    DecodedCert dc;
    int rc;

    ca_cfg(&cfg, NULL, NULL);
    cfg.protocol      = WOLFCERT_PROTO_SCEP;
    cfg.ca_key_type   = WOLFCERT_KEY_RSA;
    cfg.ca_key_param  = 2048;
    cfg.scep_split_ra = 1;
    REQUIRE(wolfcert_server_start(&cfg, &srv) == WOLFCERT_OK);
    rc = wolfcert_server_get_ca(srv, WOLFCERT_ENCODING_DER, &cert, NULL);
    wolfcert_server_free(srv);
    REQUIRE(rc == WOLFCERT_OK);

    wc_InitDecodedCert(&dc, cert.data, (word32)cert.len, NULL);
    rc = wc_ParseCert(&dc, CERT_TYPE, NO_VERIFY, NULL);
    if (rc == 0 && !dc.isCA)
        rc = -1;
    wc_FreeDecodedCert(&dc);
    wolfcert_buffer_free(&cert);
    REQUIRE(rc == 0);
    return 0;
}
#endif

/* Have the CA in cert/key issue a CSR carrying san; *rc_out is the result. */
static int issue_with_san(const WolfCertBuffer* cert, const WolfCertBuffer* key,
                          const uint8_t* san, size_t san_len, int* rc_out,
                          uint8_t** issued, size_t* issued_len)
{
    WolfCertCa ca;
    WC_RNG rng;
    test_signkey skey;
    Cert req;
    uint8_t csr[CTC_MAX_ALT_SIZE + 4096];
    int csr_len;

    REQUIRE(wc_InitRng(&rng) == 0);
    REQUIRE(test_signkey_make(&skey, &rng) == 0);
    REQUIRE(wc_InitCert(&req) == 0);
    strncpy(req.subject.commonName, "san-leaf", CTC_NAME_SIZE - 1);
    memcpy(req.altNames, san, san_len);
    req.altNamesSz = (int)san_len;
    req.sigType = TEST_CERT_SIGTYPE;
    csr_len = test_sign_certreq(&req, csr, (int)sizeof(csr), &skey, &rng);
    test_signkey_free(&skey);
    wc_FreeRng(&rng);
    REQUIRE(csr_len > 0);

    REQUIRE(wolfcert_ca_load(&ca, cert->data, cert->len, key->data, key->len,
                             NULL) == WOLFCERT_OK);
    *rc_out = wolfcert_ca_issue(&ca, csr, (size_t)csr_len, issued, issued_len);
    wolfcert_ca_free(&ca);
    return 0;
}

/* Issued SANs match the CSR in order; unsupported GeneralName forms fail. */
static int test_issued_san_verbatim(void)
{
    static const uint8_t san[] = {
        0x30, 0x20,
        0x82, 0x09, 'b', '.', 'e', 'x', 'a', 'm', 'p', 'l', 'e',
        0x81, 0x0d, 'a', '@', 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o',
        'm',
        0x87, 0x04, 127, 0, 0, 1
    };
    static const uint8_t dir_san[] = {
        0x30, 0x12,
        0xa4, 0x10, 0x30, 0x0e, 0x31, 0x0c, 0x30, 0x0a, 0x06, 0x03, 0x55, 0x04,
        0x03, 0x0c, 0x03, 'd', 'i', 'r'
    };
    WolfCertBuffer ca_cert = { 0 };
    WolfCertBuffer ca_key = { 0 };
    uint8_t* issued = NULL;
    size_t issued_len = 0;
    DecodedCert dc;
    const byte* got = NULL;
    word32 got_len = 0;
    uint8_t big_san[10 * 1024];
    size_t big_len = 4;
    int rc = -1;

    if (generate_ca(CA_KEY_TYPES[0], WOLFCERT_ENCODING_DER, &ca_cert, &ca_key))
        return 1;

    REQUIRE(issue_with_san(&ca_cert, &ca_key, dir_san, sizeof(dir_san), &rc,
                           &issued, &issued_len) == 0);
    REQUIRE(rc == WOLFCERT_ERR_UNSUPPORTED);

    /* Over 8 KB of SAN in few entries, so a static-memory pool can parse it. */
    while (big_len + 3 + 240 <= sizeof(big_san)) {
        big_san[big_len] = 0x82;
        big_san[big_len + 1] = 0x81;
        big_san[big_len + 2] = 240;
        memset(big_san + big_len + 3, 'a', 240);
        big_san[big_len + 3 + 60] = '.';
        big_san[big_len + 3 + 120] = '.';
        big_san[big_len + 3 + 180] = '.';
        big_len += 3 + 240;
    }
    big_san[0] = 0x30;
    big_san[1] = 0x82;
    big_san[2] = (uint8_t)((big_len - 4) >> 8);
    big_san[3] = (uint8_t)(big_len - 4);
    REQUIRE(issue_with_san(&ca_cert, &ca_key, big_san, big_len, &rc, &issued,
                           &issued_len) == 0);
    REQUIRE(rc == WOLFCERT_OK);
    WOLFCERT_XFREE(issued, wolfcert_default_heap());
    issued = NULL;
    REQUIRE(issue_with_san(&ca_cert, &ca_key, san, sizeof(san), &rc, &issued,
                           &issued_len) == 0);
    wolfcert_buffer_free(&ca_cert);
    wolfcert_buffer_free_secure(&ca_key);
    REQUIRE(rc == WOLFCERT_OK);

    wc_InitDecodedCert(&dc, issued, (word32)issued_len, NULL);
    rc = wc_ParseCert(&dc, CERT_TYPE, NO_VERIFY, NULL);
    if (rc == 0)
        rc = wolfcert_find_san(&dc, &got, &got_len);
    if (rc == 0 && (got_len != sizeof(san) ||
                    memcmp(got, san, sizeof(san)) != 0))
        rc = -1;
    wc_FreeDecodedCert(&dc);
    WOLFCERT_XFREE(issued, wolfcert_default_heap());
    REQUIRE(rc == 0);
    return 0;
}

static int mismatched_ca_rejected(WolfCertKeyType type)
{
    WolfCertBuffer cert_a = { 0 };
    WolfCertBuffer key_a  = { 0 };
    WolfCertBuffer cert_b = { 0 };
    WolfCertBuffer key_b  = { 0 };

    if (generate_ca(type, WOLFCERT_ENCODING_DER, &cert_a, &key_a))
        return 1;
    if (generate_ca(type, WOLFCERT_ENCODING_DER, &cert_b, &key_b))
        return 1;
    REQUIRE(key_a.len != key_b.len || memcmp(key_a.data, key_b.data, key_a.len) != 0);

    if (start_gets(&cert_a, &key_b, WOLFCERT_ERR_PARSE))
        return 1;

    wolfcert_buffer_free(&cert_a);
    wolfcert_buffer_free_secure(&key_a);
    wolfcert_buffer_free(&cert_b);
    wolfcert_buffer_free_secure(&key_b);
    return 0;
}

static int test_mismatched_ca_rejected(void)
{
    size_t i;

    for (i = 0; i < sizeof(CA_KEY_TYPES) / sizeof(CA_KEY_TYPES[0]); ++i) {
        if (mismatched_ca_rejected(CA_KEY_TYPES[i]))
            return 1;
    }
    return 0;
}

/* The generated CA's key usages and critical basicConstraints. */
static int ca_key_usage_set(WolfCertKeyType type)
{
    WolfCertBuffer cert = { 0 };
    WolfCertBuffer key  = { 0 };
    DecodedCert dc;
    int rc = 0;

    if (generate_ca(type, WOLFCERT_ENCODING_DER, &cert, &key))
        return 1;

    wc_InitDecodedCert(&dc, cert.data, (word32)cert.len, NULL);
    REQUIRE(wc_ParseCert(&dc, CERT_TYPE, NO_VERIFY, NULL) == 0);

    if (dc.extBasicConstSet == 0 || dc.extBasicConstCrit == 0 || dc.isCA == 0) {
        rc = 1;
    }
    else if (dc.extKeyUsageSet == 0 ||
            (dc.extKeyUsage & KEYUSE_KEY_CERT_SIGN) == 0 ||
            (dc.extKeyUsage & KEYUSE_CRL_SIGN) == 0 ||
            (dc.extKeyUsage & KEYUSE_DIGITAL_SIG) == 0) {
        rc = 1;
    }
    /* Only the RSA CA has keyEncipherment, for the SCEP pkcsPKIEnvelope. */
    else if (((dc.extKeyUsage & KEYUSE_KEY_ENCIPHER) != 0) !=
            (type == WOLFCERT_KEY_RSA)) {
        rc = 1;
    }

    wc_FreeDecodedCert(&dc);
    wolfcert_buffer_free(&cert);
    wolfcert_buffer_free_secure(&key);

    REQUIRE(rc == 0);
    return 0;
}

static int test_ca_key_usage(void)
{
    size_t i;

    for (i = 0; i < sizeof(CA_KEY_TYPES) / sizeof(CA_KEY_TYPES[0]); ++i) {
        if (ca_key_usage_set(CA_KEY_TYPES[i]))
            return 1;
    }
    return 0;
}

static int test_corrupt_ca_cert_rejected(void)
{
    uint8_t junk[] = { 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA };
    WolfCertBuffer bad  = { junk, sizeof(junk), NULL };
    WolfCertBuffer cert = { 0 };
    WolfCertBuffer key  = { 0 };
    WolfCertBuffer padded = { 0 };

    if (generate_ca(CA_KEY_TYPE, WOLFCERT_ENCODING_DER, &cert, &key))
        return 1;
    if (start_gets(&bad, &key, WOLFCERT_ERR_PARSE))
        return 1;
    REQUIRE(strstr(wolfcert_last_error_message(), "ca_cert") != NULL);
    if (start_gets(&cert, &bad, WOLFCERT_ERR_PARSE))
        return 1;
    REQUIRE(strstr(wolfcert_last_error_message(), "ca_key") != NULL);

    /* DER that is not a certificate fails the same way. */
    if (start_gets(&key, &key, WOLFCERT_ERR_PARSE))
        return 1;

    /* So does a certificate with bytes after it. */
    padded.data = (uint8_t*)malloc(cert.len + 1);
    REQUIRE(padded.data != NULL);
    memcpy(padded.data, cert.data, cert.len);
    padded.data[cert.len] = 0;
    padded.len = cert.len + 1;
    if (start_gets(&padded, &key, WOLFCERT_ERR_PARSE))
        return 1;
    free(padded.data);

    /* And a DER key with bytes after it. */
    padded.data = (uint8_t*)malloc(key.len + 1);
    REQUIRE(padded.data != NULL);
    memcpy(padded.data, key.data, key.len);
    padded.data[key.len] = 0;
    padded.len = key.len + 1;
    if (start_gets(&cert, &padded, WOLFCERT_ERR_PARSE))
        return 1;
    REQUIRE(strstr(wolfcert_last_error_message(), "ca_key") != NULL);
    wc_ForceZero(padded.data, (word32)padded.len);
    free(padded.data);

    wolfcert_buffer_free(&cert);
    wolfcert_buffer_free_secure(&key);
    return 0;
}

#if !defined(NO_PKCS8) && \
    (defined(WOLFCERT_HAVE_RSA) || defined(WOLFCERT_HAVE_ECC))
/* A PKCS#8 CA key comes back in the form its PEM label names. */
static int test_pkcs8_ca_key_normalized(void)
{
#ifdef WOLFCERT_HAVE_RSA
    const WolfCertKeyType type = WOLFCERT_KEY_RSA;
    const int algo = RSAk;
    const byte* curve = NULL;
    word32 curve_sz = 0;
    const char* label = "-----BEGIN RSA PRIVATE KEY-----";
#else
    const WolfCertKeyType type = WOLFCERT_KEY_ECC;
    const int algo = ECDSAk;
    const byte* curve = NULL;
    word32 curve_sz = 0;
    const char* label = "-----BEGIN EC PRIVATE KEY-----";
#endif
    WolfCertBuffer cert = { 0 };
    WolfCertBuffer key  = { 0 };
    WolfCertBuffer p8   = { 0 };
    WolfCertBuffer out_cert = { 0 };
    WolfCertBuffer out_key  = { 0 };
    WolfCertServerCfgSrv cfg;
    WolfCertServer* srv = NULL;
    word32 p8_len = 0;
    int rc;

    if (generate_ca(type, WOLFCERT_ENCODING_DER, &cert, &key))
        return 1;
#ifndef WOLFCERT_HAVE_RSA
    REQUIRE(wc_ecc_get_oid(ECC_SECP256R1_OID, &curve, &curve_sz) > 0);
#endif
    REQUIRE(wc_CreatePKCS8Key(NULL, &p8_len, key.data, (word32)key.len, algo,
                              curve, curve_sz) == LENGTH_ONLY_E);
    p8.data = (uint8_t*)malloc(p8_len);
    REQUIRE(p8.data != NULL);
    rc = wc_CreatePKCS8Key(p8.data, &p8_len, key.data, (word32)key.len, algo,
                           curve, curve_sz);
    REQUIRE(rc > 0);
    p8.len = (size_t)rc;
    REQUIRE(p8.len != key.len || memcmp(p8.data, key.data, key.len) != 0);

    ca_cfg(&cfg, &cert, &p8);
    REQUIRE(wolfcert_server_start(&cfg, &srv) == WOLFCERT_OK);
    rc = wolfcert_server_get_ca(srv, WOLFCERT_ENCODING_DER, &out_cert,
                                &out_key);
    REQUIRE(rc == WOLFCERT_OK);
    REQUIRE(out_key.len == key.len &&
            memcmp(out_key.data, key.data, key.len) == 0);
    wolfcert_buffer_free(&out_cert);
    wolfcert_buffer_free_secure(&out_key);

    rc = wolfcert_server_get_ca(srv, WOLFCERT_ENCODING_PEM, &out_cert,
                                &out_key);
    wolfcert_server_free(srv);
    REQUIRE(rc == WOLFCERT_OK);
    REQUIRE(out_key.len > strlen(label) &&
            memcmp(out_key.data, label, strlen(label)) == 0);

    wolfcert_buffer_free(&out_cert);
    wolfcert_buffer_free_secure(&out_key);
    free(p8.data);
    wolfcert_buffer_free(&cert);
    wolfcert_buffer_free_secure(&key);
    return 0;
}
#endif

#ifdef WOLFCERT_HAVE_ECC
/* A self-signed certificate with a skid_len-byte subject key id, or none, and
 * its key. */
static int make_self_pair(int is_ca, int skid_len, WolfCertBuffer* cert_out,
                          WolfCertBuffer* key_out)
{
    WolfCertKeyCfg kcfg = { .type = WOLFCERT_KEY_ECC, .param = 256,
                            .dev_id = INVALID_DEVID };
    WolfCertKey* dk = NULL;
    ecc_key wck;
    word32 idx = 0;
    Cert cert;
    WC_RNG rng;
    uint8_t der[4096];
    int body, sz;

    REQUIRE(wolfcert_key_generate(&kcfg, &dk) == WOLFCERT_OK);
    REQUIRE(wolfcert_key_to_der(dk, key_out) == WOLFCERT_OK);
    wolfcert_key_free(dk);

    REQUIRE(wc_ecc_init(&wck) == 0);
    REQUIRE(wc_EccPrivateKeyDecode(key_out->data, &idx, &wck,
                                   (word32)key_out->len) == 0);

    wc_InitCert(&cert);
    snprintf(cert.subject.commonName, sizeof(cert.subject.commonName),
             "%s", "wolfCert Leaf");
    cert.isCA       = is_ca;
    cert.selfSigned = 1;
    memset(cert.skid, 0x5a, (size_t)skid_len);
    cert.skidSz     = skid_len;
    cert.daysValid  = 30;
    cert.sigType    = CTC_SHA256wECDSA;

    REQUIRE(wc_InitRng(&rng) == 0);
    body = wc_MakeCert(&cert, der, sizeof(der), NULL, &wck, &rng);
    REQUIRE(body > 0);
    sz = wc_SignCert(body, cert.sigType, der, sizeof(der), NULL, &wck, &rng);
    REQUIRE(sz > 0);
    wc_FreeRng(&rng);
    wc_ecc_free(&wck);

    cert_out->data = (uint8_t*)WOLFCERT_XMALLOC((size_t)sz, NULL);
    REQUIRE(cert_out->data != NULL);
    memcpy(cert_out->data, der, (size_t)sz);
    cert_out->len  = (size_t)sz;
    cert_out->heap = NULL;
    return 0;
}

static int test_leaf_ca_rejected(void)
{
    WolfCertBuffer cert = { 0 };
    WolfCertBuffer key  = { 0 };

    if (make_self_pair(0, 0, &cert, &key))
        return 1;
    if (start_gets(&cert, &key, WOLFCERT_ERR_PARSE))
        return 1;

    wolfcert_buffer_free(&cert);
    wolfcert_buffer_free_secure(&key);
    return 0;
}

/* A loaded CA without a subject key id, or with one wolfSSL would hash,
 * issues without an authority key id; a generated CA's leaves carry it. */
static int test_issued_key_ids(void)
{
    static const uint8_t san[] = {
        0x30, 0x0b, 0x82, 0x09, 'k', '.', 'e', 'x', 'a', 'm', 'p', 'l', 'e'
    };
    WolfCertBuffer cert = { 0 };
    WolfCertBuffer key  = { 0 };
    uint8_t* issued = NULL;
    size_t issued_len = 0;
    DecodedCert ca_dc;
    DecodedCert leaf_dc;
    int skid_len;
    int rc = -1;
    int ok;

    for (skid_len = 0; skid_len <= 8; skid_len += 8) {
        if (make_self_pair(1, skid_len, &cert, &key))
            return 1;
        REQUIRE(issue_with_san(&cert, &key, san, sizeof(san), &rc, &issued,
                               &issued_len) == 0);
        wolfcert_buffer_free(&cert);
        wolfcert_buffer_free_secure(&key);
        REQUIRE(rc == WOLFCERT_OK);
        wc_InitDecodedCert(&leaf_dc, issued, (word32)issued_len, NULL);
        ok = wc_ParseCert(&leaf_dc, CERT_TYPE, NO_VERIFY, NULL) == 0 &&
             !leaf_dc.extAuthKeyIdSet;
        wc_FreeDecodedCert(&leaf_dc);
        WOLFCERT_XFREE(issued, wolfcert_default_heap());
        issued = NULL;
        REQUIRE(ok);
    }

    if (generate_ca(WOLFCERT_KEY_ECC, WOLFCERT_ENCODING_DER, &cert, &key))
        return 1;
    REQUIRE(issue_with_san(&cert, &key, san, sizeof(san), &rc, &issued,
                           &issued_len) == 0);
    REQUIRE(rc == WOLFCERT_OK);
    wc_InitDecodedCert(&ca_dc, cert.data, (word32)cert.len, NULL);
    wc_InitDecodedCert(&leaf_dc, issued, (word32)issued_len, NULL);
    ok = wc_ParseCert(&ca_dc, CERT_TYPE, NO_VERIFY, NULL) == 0 &&
         wc_ParseCert(&leaf_dc, CERT_TYPE, NO_VERIFY, NULL) == 0 &&
         ca_dc.extSubjKeyIdSet && leaf_dc.extAuthKeyIdSet &&
         memcmp(ca_dc.extSubjKeyId, leaf_dc.extAuthKeyId,
                sizeof(ca_dc.extSubjKeyId)) == 0;
    wc_FreeDecodedCert(&leaf_dc);
    wc_FreeDecodedCert(&ca_dc);
    WOLFCERT_XFREE(issued, wolfcert_default_heap());
    wolfcert_buffer_free(&cert);
    wolfcert_buffer_free_secure(&key);
    REQUIRE(ok);
    return 0;
}
#endif /* WOLFCERT_HAVE_ECC */

static int test_bad_bind_host_rejected(void)
{
    static const char* const hosts[] = {
        "localhost", "::1", "", "127.0.0.300", "127.0.0.1 "
    };
    WolfCertServerCfgSrv cfg;
    WolfCertServer* srv = NULL;
    size_t i;

    for (i = 0; i < sizeof(hosts) / sizeof(hosts[0]); i++) {
        ca_cfg(&cfg, NULL, NULL);
        cfg.bind_host = hosts[i];
        REQUIRE(wolfcert_server_start(&cfg, &srv) == WOLFCERT_ERR_BAD_ARG);
        REQUIRE(srv == NULL);
    }

    /* NULL binds every interface and must still start. */
    ca_cfg(&cfg, NULL, NULL);
    cfg.bind_host = NULL;
    REQUIRE(wolfcert_server_start(&cfg, &srv) == WOLFCERT_OK);
    REQUIRE(wolfcert_server_port(srv) != 0);
    wolfcert_server_free(srv);

    return 0;
}

int main(void)
{
    REQUIRE(test_static_mem_init() == 0);
    REQUIRE(wolfcert_init(test_heap_hint()) == WOLFCERT_OK);

#if CA_TEST_NEEDS_TLS
    REQUIRE(gen_server_identity(&srv_cert_pem, &srv_cert_pem_len,
                                &srv_key_pem, &srv_key_pem_len) == 0);
#endif

    if (test_corrupt_ca_rejected())
        return 1;
    if (test_half_ca_rejected())
        return 1;
    if (test_ca_round_trip())
        return 1;
    if (test_get_ca_args())
        return 1;
#if defined(USE_WOLFSSL_MEMORY) && !defined(WOLFSSL_STATIC_MEMORY) && \
    !defined(WOLFSSL_DEBUG_MEMORY)
    if (test_start_oom_keeps_credentials())
        return 1;
#endif
    if (test_every_alg_reloads())
        return 1;
#ifdef WOLFCERT_HAVE_ECC
    if (test_ecc_key_without_public_point())
        return 1;
#endif
#ifdef WOLFCERT_HAVE_SCEP
    if (test_split_ra_get_ca_is_ca())
        return 1;
#endif
    if (test_mismatched_ca_rejected())
        return 1;
    if (test_corrupt_ca_cert_rejected())
        return 1;
#if !defined(NO_PKCS8) && \
    (defined(WOLFCERT_HAVE_RSA) || defined(WOLFCERT_HAVE_ECC))
    if (test_pkcs8_ca_key_normalized())
        return 1;
#endif
    if (test_issued_san_verbatim())
        return 1;
#ifdef WOLFCERT_HAVE_ECC
    if (test_issued_key_ids())
        return 1;
    if (test_leaf_ca_rejected())
        return 1;
#endif
    if (test_ca_key_usage())
        return 1;
    if (test_bad_bind_host_rejected())
        return 1;

#if CA_TEST_NEEDS_TLS
    free(srv_cert_pem);
    free(srv_key_pem);
#endif
    wolfcert_cleanup();
    printf("OK\n");
    return 0;
}
