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

/* EST over mutual TLS: enrollment with and without a client cert, and the
 * /simplereenroll identity checks. */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#define _DARWIN_C_SOURCE   /* expose memmem/strcasestr/INADDR_LOOPBACK on macOS */
#define _GNU_SOURCE

#include <wolfcert/wolfcert.h>
#include <wolfcert/est.h>
#include <wolfcert/server.h>

#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/random.h>

#include "tls_test_util.h"
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/ecc.h>

#include <poll.h>
#include <pthread.h>
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

static void* server_thread(void* arg) { wolfcert_server_run((WolfCertServer*)arg); return NULL; }

#ifdef KEEP_PEER_CERT
/* Wait on the session fd in the direction a WANT_* return asked for. */
static int wait_io(WolfCertEstSession* s, int rc)
{
    struct pollfd p = { .fd = wolfcert_est_session_fd(s),
        .events = (rc == WOLFCERT_ERR_WANT_WRITE) ? POLLOUT : POLLIN };
    return poll(&p, 1, 5000) > 0 ? 0 : -1;
}

/* Re-enroll the trusted cli_cert while cfg carries an identity the server
 * does not trust; the handshake must present the cert being renewed. */
static int test_reenroll_ignores_cfg_identity(const char* url,
                                              const uint8_t* tls_cert, size_t tls_cert_len,
                                              const uint8_t* cli_cert, size_t cli_cert_len,
                                              const uint8_t* cli_key, size_t cli_key_len)
{
    uint8_t* stale_cert = NULL;
    size_t stale_cert_len = 0;
    uint8_t* stale_key = NULL;
    size_t stale_key_len = 0;
    WolfCertKey* cur_key = NULL;
    WolfCertKey* dk = NULL;
    WolfCertBuffer csr = { 0 };
    WolfCertEstResult issued = { 0 };
    WolfCertBuffer ca_pem = { 0 };
    WolfCertEstSession* sess = NULL;
    WolfCertEstResult res = { 0 };
    WolfCertKeyCfg kcfg = { .type = TEST_ENROLL_KEY_TYPE, .param = TEST_ENROLL_KEY_PARAM,
                            .dev_id = INVALID_DEVID };
    WolfCertCertMeta meta = { .subject_dn = "CN=factory-bootstrap" };
    WolfCertServerCfg cli = {
        .protocol          = WOLFCERT_PROTO_EST,
        .server_url        = url,
        .trust_anchors     = tls_cert,
        .trust_anchors_len = tls_cert_len,
        .verify_server     = 1,
    };
    int rc;

    REQUIRE(mint_self_id("stale-identity", 1, &stale_cert, &stale_cert_len,
                         &stale_key, &stale_key_len) == 0);
    cli.client_cert     = stale_cert;
    cli.client_cert_len = stale_cert_len;
    cli.client_key      = stale_key;
    cli.client_key_len  = stale_key_len;

    /* The server refuses the stale identity on its own */
    rc = wolfcert_est_get_cacerts(&cli, WOLFCERT_ENCODING_PEM, &ca_pem);
    wolfcert_buffer_free(&ca_pem);
    REQUIRE(rc != WOLFCERT_OK);

    REQUIRE(wolfcert_key_from_pem(cli_key, cli_key_len, NULL, &cur_key) == WOLFCERT_OK);
    REQUIRE(wolfcert_key_generate(&kcfg, &dk) == WOLFCERT_OK);
    REQUIRE(wolfcert_csr_build(dk, &meta, &csr) == WOLFCERT_OK);

    rc = wolfcert_est_simple_reenroll(&cli, cli_cert, cli_cert_len, cur_key,
                                      csr.data, csr.len, &issued);
    if (rc != WOLFCERT_OK)
        fprintf(stderr, "mtls reenroll rc=%d (%s)\n", rc, wolfcert_strerror(rc));
    REQUIRE(rc == WOLFCERT_OK && issued.status == WOLFCERT_EST_STATUS_SUCCESS);
    REQUIRE(memmem(issued.cert_pem.data, issued.cert_pem.len,
                   "BEGIN CERTIFICATE", 17) != NULL);

    /* A session reenrolls with the identity it was opened with. */
    cli.client_cert     = cli_cert;
    cli.client_cert_len = cli_cert_len;
    cli.client_key      = cli_key;
    cli.client_key_len  = cli_key_len;
    REQUIRE(wolfcert_est_session_open(&cli, &sess) == WOLFCERT_OK);
    rc = wolfcert_est_session_simple_reenroll(sess, csr.data, csr.len, &res);
    REQUIRE(rc == WOLFCERT_OK && res.status == WOLFCERT_EST_STATUS_SUCCESS);
    wolfcert_est_result_free(&res);

    while ((rc = wolfcert_est_session_simple_reenroll_nb(sess, csr.data,
                                                         csr.len, &res))
               == WOLFCERT_ERR_WANT_READ || rc == WOLFCERT_ERR_WANT_WRITE)
        REQUIRE(wait_io(sess, rc) == 0);
    wolfcert_est_session_close(sess);
    REQUIRE(rc == WOLFCERT_OK && res.status == WOLFCERT_EST_STATUS_SUCCESS);
    wolfcert_est_result_free(&res);

    wolfcert_est_result_free(&issued);
    wolfcert_buffer_free(&csr);
    wolfcert_key_free(dk);
    wolfcert_key_free(cur_key);
    free(stale_cert);
    free(stale_key);
    return 0;
}

static int test_reenroll_rejects_identity_change(const char* url,
                                                 const uint8_t* tls_cert, size_t tls_cert_len,
                                                 const uint8_t* cli_cert, size_t cli_cert_len,
                                                 const uint8_t* cli_key, size_t cli_key_len)
{
    static const char* const dns[] = { "other.example" };
    const WolfCertCertMeta metas[2] = {
        { .subject_dn = "CN=someone-else" },
        { .subject_dn = "CN=factory-bootstrap", .san_dns = dns, .san_dns_len = 1 },
    };
    WolfCertKeyCfg kcfg = { .type = TEST_ENROLL_KEY_TYPE, .param = TEST_ENROLL_KEY_PARAM,
                            .dev_id = INVALID_DEVID };
    WolfCertServerCfg cli = {
        .protocol          = WOLFCERT_PROTO_EST,
        .server_url        = url,
        .trust_anchors     = tls_cert,
        .trust_anchors_len = tls_cert_len,
        .verify_server     = 1,
    };
    WolfCertKey* cur_key = NULL;
    WolfCertKey* dk = NULL;

    REQUIRE(wolfcert_key_from_pem(cli_key, cli_key_len, NULL, &cur_key) == WOLFCERT_OK);
    REQUIRE(wolfcert_key_generate(&kcfg, &dk) == WOLFCERT_OK);

    for (size_t i = 0; i < sizeof(metas) / sizeof(metas[0]); ++i) {
        WolfCertBuffer csr = { 0 };
        WolfCertEstResult issued = { 0 };
        int rc;

        REQUIRE(wolfcert_csr_build(dk, &metas[i], &csr) == WOLFCERT_OK);
        rc = wolfcert_est_simple_reenroll(&cli, cli_cert, cli_cert_len, cur_key,
                                          csr.data, csr.len, &issued);
        wolfcert_buffer_free(&csr);
        if (rc == WOLFCERT_OK)
            fprintf(stderr, "reenroll with changed identity %zu was issued\n", i);
        REQUIRE(rc == WOLFCERT_ERR_HTTP);
        REQUIRE(issued.cert_pem.data == NULL);
    }

    wolfcert_key_free(dk);
    wolfcert_key_free(cur_key);
    return 0;
}

/* A DER reenroll body that is not PKCS#10 gets a 400. */
static int test_reenroll_rejects_non_csr(const char* url,
                                         const uint8_t* tls_cert, size_t tls_cert_len,
                                         const uint8_t* cli_cert, size_t cli_cert_len,
                                         const uint8_t* cli_key, size_t cli_key_len)
{
    static const uint8_t not_csr[] = { 0x30, 0x03, 0x02, 0x01, 0x00 };
    WolfCertServerCfg cli = {
        .protocol          = WOLFCERT_PROTO_EST,
        .server_url        = url,
        .trust_anchors     = tls_cert,
        .trust_anchors_len = tls_cert_len,
        .verify_server     = 1,
    };
    WolfCertKey* cur_key = NULL;
    WolfCertEstResult issued = { 0 };
    int rc;

    REQUIRE(wolfcert_key_from_pem(cli_key, cli_key_len, NULL, &cur_key) == WOLFCERT_OK);
    rc = wolfcert_est_simple_reenroll(&cli, cli_cert, cli_cert_len, cur_key,
                                      not_csr, sizeof(not_csr), &issued);
    wolfcert_key_free(cur_key);
    if (rc != WOLFCERT_ERR_HTTP)
        fprintf(stderr, "non-CSR reenroll rc=%d (%s)\n", rc,
                wolfcert_last_error_message());
    REQUIRE(rc == WOLFCERT_ERR_HTTP);
    REQUIRE(issued.cert_pem.data == NULL);
    REQUIRE(strstr(wolfcert_last_error_message(), "HTTP 400") != NULL);
    return 0;
}

#ifdef HAVE_ECC
/* The GeneralNames of a non-critical SAN extension in der, or NULL. */
static const uint8_t* raw_san(const uint8_t* der, size_t der_len, size_t* len)
{
    static const uint8_t oid[] = { 0x06, 0x03, 0x55, 0x1d, 0x11, 0x04 };
    const uint8_t* p = memmem(der, der_len, oid, sizeof(oid));
    size_t n;

    if (p == NULL || (size_t)(der + der_len - p) < sizeof(oid) + 3)
        return NULL;
    p += sizeof(oid);
    if (p[0] < 0x80) {
        *len = p[0];
        n = 1;
    }
    else if (p[0] == 0x81) {
        *len = p[1];
        n = 2;
    }
    else if (p[0] == 0x82) {
        *len = ((size_t)p[1] << 8) | p[2];
        n = 3;
    }
    else {
        return NULL;
    }
    return (size_t)(der + der_len - p) >= n + *len ? p + n : NULL;
}

/* A CSR carrying cert's raw Subject and SAN, with the SAN marked critical. */
static int csr_with_critical_san(const WolfCertBuffer* cert_pem,
                                 uint8_t* out, size_t out_cap)
{
    WC_RNG rng;
    ecc_key key;
    Cert req;
    uint8_t der[4096];
    const uint8_t* san;
    size_t san_len = 0;
    int der_len;
    int len = -1;

    der_len = wc_CertPemToDer(cert_pem->data, (int)cert_pem->len, der,
                              (int)sizeof(der), CERT_TYPE);
    if (der_len <= 0)
        return -1;
    san = raw_san(der, (size_t)der_len, &san_len);
    if (san == NULL || san_len > sizeof(req.altNames) || wc_InitRng(&rng) != 0)
        return -1;
    if (wc_ecc_init(&key) == 0) {
        if (wc_ecc_make_key(&rng, 32, &key) == 0 && wc_InitCert(&req) == 0 &&
            wc_SetSubjectRaw(&req, der, der_len) == 0) {
            memcpy(req.altNames, san, san_len);
            req.altNamesSz = (int)san_len;
            req.altNamesCrit = 1;
            req.version = 0;
            req.sigType = CTC_SHA256wECDSA;
            len = wc_MakeCertReq_ex(&req, out, (word32)out_cap, ECC_TYPE, &key);
            if (len > 0)
                len = wc_SignCert_ex(req.bodySz, req.sigType, out,
                                     (word32)out_cap, ECC_TYPE, &key, &rng);
        }
        wc_ecc_free(&key);
    }
    wc_FreeRng(&rng);
    return len;
}
#endif

/* A software key of each type re-enrolls; its DER reaches TLS untyped. */
static int reenroll_key_type(const WolfCertServerCfg* cli, WolfCertKeyType type,
                             int param)
{
    const WolfCertCertMeta meta = { .subject_dn = "CN=reenroll-type,O=wolfSSL" };
    WolfCertKeyCfg kcfg = { .type = type, .param = param,
                            .dev_id = INVALID_DEVID };
    WolfCertKey* key = NULL;
    WolfCertBuffer csr = { 0 };
    WolfCertEstResult cert = { 0 };
    WolfCertEstResult renewed = { 0 };
    int rc;

    REQUIRE(wolfcert_key_generate(&kcfg, &key) == WOLFCERT_OK);
    REQUIRE(wolfcert_csr_build(key, &meta, &csr) == WOLFCERT_OK);
    REQUIRE(wolfcert_est_simple_enroll(cli, csr.data, csr.len, &cert) ==
            WOLFCERT_OK);
    REQUIRE(cert.status == WOLFCERT_EST_STATUS_SUCCESS);
    rc = wolfcert_est_simple_reenroll(cli, cert.cert_pem.data,
                                      cert.cert_pem.len, key, csr.data,
                                      csr.len, &renewed);
    if (rc != WOLFCERT_OK)
        fprintf(stderr, "key type %d reenroll rc=%d (%s)\n", (int)type, rc,
                wolfcert_last_error_message());
    REQUIRE(rc == WOLFCERT_OK);
    REQUIRE(renewed.status == WOLFCERT_EST_STATUS_SUCCESS);

    wolfcert_est_result_free(&renewed);
    wolfcert_est_result_free(&cert);
    wolfcert_buffer_free(&csr);
    wolfcert_key_free(key);
    return 0;
}

/* Reenroll of a multi-RDN, multi-SAN cert the server CA issued succeeds; a
 * changed dNSName or a critical SAN (ECC builds) gets 400. */
static int test_reenroll_server_issued(const uint8_t* tls_cert, size_t tls_cert_len,
                                       const uint8_t* tls_key, size_t tls_key_len,
                                       const uint8_t* cli_cert, size_t cli_cert_len,
                                       const uint8_t* cli_key, size_t cli_key_len)
{
    static const char* const dns[] = { "a.example", "b.example", "c.example" };
    static const char* const dns2[] = { "a.example", "b.example", "d.example" };
    static const char* const ip[] = { "127.0.0.1", "10.0.0.7" };
    static const char* const email[] = { "dev@example.com" };
    const WolfCertCertMeta meta = {
        .subject_dn = "CN=multi-san,O=wolfSSL,OU=EST",
        .san_dns = dns,     .san_dns_len = 3,
        .san_ip = ip,       .san_ip_len = 2,
        .san_email = email, .san_email_len = 1,
    };
    const WolfCertCertMeta meta2 = {
        .subject_dn = "CN=multi-san,O=wolfSSL,OU=EST",
        .san_dns = dns2,    .san_dns_len = 3,
        .san_ip = ip,       .san_ip_len = 2,
        .san_email = email, .san_email_len = 1,
    };
    WolfCertKeyCfg kcfg = { .type = TEST_ENROLL_KEY_TYPE, .param = TEST_ENROLL_KEY_PARAM,
                            .dev_id = INVALID_DEVID };
    WolfCertServerCfgSrv cfg = {
        .protocol              = WOLFCERT_PROTO_EST,
        .bind_host             = "127.0.0.1",
        .bind_port             = 0,
        .tls_cert_pem          = tls_cert, .tls_cert_pem_len       = tls_cert_len,
        .tls_key_pem           = tls_key,  .tls_key_pem_len        = tls_key_len,
        .tls_client_ca_pem     = cli_cert, .tls_client_ca_pem_len  = cli_cert_len,
    };
    WolfCertServer* srv = NULL;
    const WolfCertBuffer* ca_der = &test_ca()->cert;
    WolfCertBuffer csr = { 0 };
    WolfCertEstResult issued = { 0 };
    WolfCertEstResult renewed = { 0 };
    WolfCertEstResult san_changed = { 0 };
    WolfCertKey* k1 = NULL;
    WolfCertKey* k2 = NULL;
    uint8_t* bundle = NULL;
    size_t bundle_cap;
    pthread_t tid;
    char url[128];
    int pem_len;
    int rc;
#ifdef HAVE_ECC
    uint8_t crit_csr[4096];
    WolfCertEstResult refused = { 0 };
    int crit_len;
#endif

    test_ca_set(&cfg);
    bundle_cap = cli_cert_len + ca_der->len * 2 + 256;
    bundle = (uint8_t*)malloc(bundle_cap);
    REQUIRE(bundle != NULL);
    memcpy(bundle, cli_cert, cli_cert_len);
    pem_len = wc_DerToPem(ca_der->data, (word32)ca_der->len, bundle + cli_cert_len,
                          (word32)(bundle_cap - cli_cert_len), CERT_TYPE);
    REQUIRE(pem_len > 0);
    cfg.tls_client_ca_pem     = bundle;
    cfg.tls_client_ca_pem_len = cli_cert_len + (size_t)pem_len;

    REQUIRE(wolfcert_server_start(&cfg, &srv) == WOLFCERT_OK);
    REQUIRE(pthread_create(&tid, NULL, server_thread, srv) == 0);
    snprintf(url, sizeof(url), "https://127.0.0.1:%u/.well-known/est",
             wolfcert_server_port(srv));

    WolfCertServerCfg cli = {
        .protocol          = WOLFCERT_PROTO_EST,
        .server_url        = url,
        .trust_anchors     = tls_cert,
        .trust_anchors_len = tls_cert_len,
        .verify_server     = 1,
        .client_cert       = cli_cert,
        .client_cert_len   = cli_cert_len,
        .client_key        = cli_key,
        .client_key_len    = cli_key_len,
    };

    REQUIRE(wolfcert_key_generate(&kcfg, &k1) == WOLFCERT_OK);
    REQUIRE(wolfcert_csr_build(k1, &meta, &csr) == WOLFCERT_OK);
    rc = wolfcert_est_simple_enroll(&cli, csr.data, csr.len, &issued);
    wolfcert_buffer_free(&csr);
    REQUIRE(rc == WOLFCERT_OK && issued.status == WOLFCERT_EST_STATUS_SUCCESS);

    REQUIRE(wolfcert_key_generate(&kcfg, &k2) == WOLFCERT_OK);
    REQUIRE(wolfcert_csr_build(k2, &meta, &csr) == WOLFCERT_OK);
    rc = wolfcert_est_simple_reenroll(&cli, issued.cert_pem.data, issued.cert_pem.len, k1,
                                      csr.data, csr.len, &renewed);
    if (rc != WOLFCERT_OK)
        fprintf(stderr, "reenroll of a server-issued cert rc=%d (%s)\n", rc,
                wolfcert_strerror(rc));
    REQUIRE(rc == WOLFCERT_OK && renewed.status == WOLFCERT_EST_STATUS_SUCCESS);
    REQUIRE(memmem(renewed.cert_pem.data, renewed.cert_pem.len,
                   "BEGIN CERTIFICATE", 17) != NULL);

    /* Same Subject and SAN shape, one dNSName changed. */
    wolfcert_buffer_free(&csr);
    REQUIRE(wolfcert_csr_build(k2, &meta2, &csr) == WOLFCERT_OK);
    rc = wolfcert_est_simple_reenroll(&cli, issued.cert_pem.data, issued.cert_pem.len, k1,
                                      csr.data, csr.len, &san_changed);
    REQUIRE(rc == WOLFCERT_ERR_HTTP);
    REQUIRE(strstr(wolfcert_last_error_message(), "HTTP 400") != NULL);
    REQUIRE(san_changed.cert_pem.data == NULL);

#ifdef HAVE_ECC
    crit_len = csr_with_critical_san(&issued.cert_pem, crit_csr, sizeof(crit_csr));
    REQUIRE(crit_len > 0);
    rc = wolfcert_est_simple_reenroll(&cli, issued.cert_pem.data, issued.cert_pem.len, k1,
                                      crit_csr, (size_t)crit_len, &refused);
    REQUIRE(rc == WOLFCERT_ERR_HTTP);
    REQUIRE(strstr(wolfcert_last_error_message(), "HTTP 400") != NULL);
    REQUIRE(refused.cert_pem.data == NULL);
#endif

    static const struct { WolfCertKeyType type; int param; } types[] = {
#ifdef WOLFCERT_HAVE_RSA
        { WOLFCERT_KEY_RSA, 2048 },
#endif
#ifdef WOLFCERT_HAVE_ECC
        { WOLFCERT_KEY_ECC, 384 },
#endif
#ifdef WOLFCERT_HAVE_ED25519
        { WOLFCERT_KEY_ED25519, 0 },
#endif
#ifdef WOLFCERT_HAVE_ED448
        { WOLFCERT_KEY_ED448, 0 },
#endif
#ifdef WOLFCERT_HAVE_MLDSA
#ifndef WOLFSSL_NO_ML_DSA_44
        { WOLFCERT_KEY_MLDSA44, 0 },
#endif
#ifndef WOLFSSL_NO_ML_DSA_65
        { WOLFCERT_KEY_MLDSA65, 0 },
#endif
#ifndef WOLFSSL_NO_ML_DSA_87
        { WOLFCERT_KEY_MLDSA87, 0 },
#endif
#endif
    };
    for (size_t i = 0; i < sizeof(types) / sizeof(types[0]); i++)
        REQUIRE(reenroll_key_type(&cli, types[i].type, types[i].param) == 0);

    wolfcert_server_stop(srv);
    pthread_join(tid, NULL);
    wolfcert_server_free(srv);
    wolfcert_est_result_free(&renewed);
    wolfcert_est_result_free(&issued);
    wolfcert_buffer_free(&csr);
    wolfcert_key_free(k2);
    wolfcert_key_free(k1);
    free(bundle);
    return 0;
}

/* The approval gate runs after the identity check, so a mismatched reenroll
 * gets its 400 on the first POST rather than a 202. A matching one is parked
 * and issued on its re-POST. */
static int test_reenroll_under_approval(const uint8_t* tls_cert, size_t tls_cert_len,
                                        const uint8_t* tls_key, size_t tls_key_len,
                                        const uint8_t* cli_cert, size_t cli_cert_len,
                                        const uint8_t* cli_key, size_t cli_key_len)
{
    const WolfCertCertMeta meta = { .subject_dn = "CN=someone-else" };
    const WolfCertCertMeta same = { .subject_dn = "CN=factory-bootstrap" };
    const WolfCertCertMeta none = { 0 };
    WolfCertKeyCfg kcfg = { .type = TEST_ENROLL_KEY_TYPE, .param = TEST_ENROLL_KEY_PARAM,
                            .dev_id = INVALID_DEVID };
    WolfCertServerCfgSrv cfg = {
        .protocol              = WOLFCERT_PROTO_EST,
        .bind_host             = "127.0.0.1",
        .bind_port             = 0,
        TEST_CA_CFG,
        .tls_cert_pem          = tls_cert, .tls_cert_pem_len       = tls_cert_len,
        .tls_key_pem           = tls_key,  .tls_key_pem_len        = tls_key_len,
        .tls_client_ca_pem     = cli_cert, .tls_client_ca_pem_len  = cli_cert_len,
        .est_require_approval  = 1,
    };
    WolfCertServer* srv = NULL;
    WolfCertKey* cur_key = NULL;
    WolfCertKey* dk = NULL;
    WolfCertBuffer csr = { 0 };
    WolfCertEstResult issued = { 0 };
    WolfCertClient* client = NULL;
    WolfCertKey* nk = NULL;
    WolfCertBuffer cert = { 0 };
    pthread_t tid;
    char url[128];
    int rc;

    REQUIRE(wolfcert_server_start(&cfg, &srv) == WOLFCERT_OK);
    REQUIRE(pthread_create(&tid, NULL, server_thread, srv) == 0);
    snprintf(url, sizeof(url), "https://127.0.0.1:%u/.well-known/est",
             wolfcert_server_port(srv));

    WolfCertServerCfg cli = {
        .protocol          = WOLFCERT_PROTO_EST,
        .server_url        = url,
        .trust_anchors     = tls_cert,
        .trust_anchors_len = tls_cert_len,
        .verify_server     = 1,
    };

    REQUIRE(wolfcert_key_from_pem(cli_key, cli_key_len, NULL, &cur_key) == WOLFCERT_OK);
    REQUIRE(wolfcert_key_generate(&kcfg, &dk) == WOLFCERT_OK);
    REQUIRE(wolfcert_csr_build(dk, &meta, &csr) == WOLFCERT_OK);
    rc = wolfcert_est_simple_reenroll(&cli, cli_cert, cli_cert_len, cur_key,
                                      csr.data, csr.len, &issued);
    if (rc != WOLFCERT_ERR_HTTP)
        fprintf(stderr, "mismatched reenroll under approval rc=%d (%s)\n", rc,
                wolfcert_last_error_message());
    REQUIRE(rc == WOLFCERT_ERR_HTTP);
    REQUIRE(issued.cert_pem.data == NULL);
    REQUIRE(strstr(wolfcert_last_error_message(), "HTTP 400") != NULL);
    wolfcert_buffer_free(&csr);

    REQUIRE(wolfcert_csr_build(dk, &same, &csr) == WOLFCERT_OK);
    REQUIRE(wolfcert_est_simple_reenroll(&cli, cli_cert, cli_cert_len, cur_key,
                                         csr.data, csr.len, &issued) == WOLFCERT_OK);
    REQUIRE(issued.status == WOLFCERT_EST_STATUS_PENDING);
    REQUIRE(issued.retry_after_sec == 1);
    REQUIRE(issued.cert_pem.data == NULL);
    REQUIRE(wolfcert_est_simple_reenroll(&cli, cli_cert, cli_cert_len, cur_key,
                                         csr.data, csr.len, &issued) == WOLFCERT_OK);
    REQUIRE(issued.status == WOLFCERT_EST_STATUS_SUCCESS);
    REQUIRE(memmem(issued.cert_pem.data, issued.cert_pem.len,
                   "BEGIN CERTIFICATE", 17) != NULL);
    wolfcert_est_result_free(&issued);

    /* The client API reports the 202 as WOLFCERT_ERR_PENDING. */
    REQUIRE(wolfcert_client_new(&client) == WOLFCERT_OK);
    REQUIRE(wolfcert_client_reenroll(client, &cli, cli_cert, cli_cert_len,
                                     cur_key, &kcfg, &none, &nk, &cert)
            == WOLFCERT_ERR_PENDING);
    REQUIRE(nk == NULL && cert.data == NULL);
    wolfcert_client_free(client);

    wolfcert_server_stop(srv);
    pthread_join(tid, NULL);
    wolfcert_server_free(srv);
    wolfcert_buffer_free(&csr);
    wolfcert_key_free(dk);
    wolfcert_key_free(cur_key);
    return 0;
}

/* tls_client_trust_issued: anonymous enroll still works, the issued cert
 * renews over mTLS, and a cert from another CA is refused. */
static int test_reenroll_trust_issued(const uint8_t* tls_cert, size_t tls_cert_len,
                                      const uint8_t* tls_key, size_t tls_key_len,
                                      const uint8_t* cli_cert, size_t cli_cert_len,
                                      const uint8_t* cli_key, size_t cli_key_len)
{
    WolfCertKeyCfg kcfg = { .type = TEST_ENROLL_KEY_TYPE, .param = TEST_ENROLL_KEY_PARAM,
                            .dev_id = INVALID_DEVID };
    WolfCertCertMeta meta = { .subject_dn = "CN=trust-issued" };
    WolfCertServerCfgSrv cfg = {
        .protocol                   = WOLFCERT_PROTO_EST,
        .bind_host                  = "127.0.0.1",
        .bind_port                  = 0,
        TEST_CA_CFG,
        .tls_cert_pem = tls_cert, .tls_cert_pem_len = tls_cert_len,
        .tls_key_pem  = tls_key,  .tls_key_pem_len  = tls_key_len,
        .est_allow_anonymous_enroll = 1,
        .tls_client_trust_issued    = 1,
    };
    WolfCertServer* srv = NULL;
    WolfCertKey* k1 = NULL;
    WolfCertKey* k2 = NULL;
    WolfCertKey* foreign = NULL;
    WolfCertBuffer ca_pem = { 0 };
    WolfCertBuffer csr = { 0 };
    WolfCertEstResult issued = { 0 };
    WolfCertEstResult renewed = { 0 };
    WolfCertEstResult refused = { 0 };
    static const char anon_req[] =
        "POST /.well-known/est/simplereenroll HTTP/1.1\r\n"
        "Host: 127.0.0.1\r\nContent-Type: application/pkcs10\r\n"
        "Content-Length: 4\r\nConnection: close\r\n\r\nAAAA";
    TestTlsConn conn;
    char resp[1024];
    size_t resp_len = 0;
    pthread_t tid;
    char url[128];
    int rc;

    REQUIRE(wolfcert_server_start(&cfg, &srv) == WOLFCERT_OK);
    REQUIRE(pthread_create(&tid, NULL, server_thread, srv) == 0);
    snprintf(url, sizeof(url), "https://127.0.0.1:%u/.well-known/est",
             wolfcert_server_port(srv));

    WolfCertServerCfg cli = {
        .protocol          = WOLFCERT_PROTO_EST,
        .server_url        = url,
        .trust_anchors     = tls_cert,
        .trust_anchors_len = tls_cert_len,
        .verify_server     = 1,
    };
    REQUIRE(wolfcert_est_get_cacerts(&cli, WOLFCERT_ENCODING_PEM, &ca_pem) == WOLFCERT_OK);

    REQUIRE(wolfcert_key_generate(&kcfg, &k1) == WOLFCERT_OK);
    REQUIRE(wolfcert_csr_build(k1, &meta, &csr) == WOLFCERT_OK);
    REQUIRE(wolfcert_est_simple_enroll(&cli, csr.data, csr.len, &issued) ==
            WOLFCERT_OK);
    wolfcert_buffer_free(&csr);

    REQUIRE(wolfcert_key_generate(&kcfg, &k2) == WOLFCERT_OK);
    REQUIRE(wolfcert_csr_build(k2, &meta, &csr) == WOLFCERT_OK);
    rc = wolfcert_est_simple_reenroll(&cli, issued.cert_pem.data, issued.cert_pem.len, k1,
                                      csr.data, csr.len, &renewed);
    wolfcert_buffer_free(&csr);
    REQUIRE(rc == WOLFCERT_OK);
    REQUIRE(memmem(renewed.cert_pem.data, renewed.cert_pem.len, "BEGIN CERTIFICATE", 17) != NULL);

    REQUIRE(wolfcert_key_from_pem(cli_key, cli_key_len, NULL, &foreign) ==
            WOLFCERT_OK);
    meta.subject_dn = "CN=factory-bootstrap";
    REQUIRE(wolfcert_csr_build(foreign, &meta, &csr) == WOLFCERT_OK);
    rc = wolfcert_est_simple_reenroll(&cli, cli_cert, cli_cert_len, foreign,
                                      csr.data, csr.len, &refused);
    /* The handshake refuses it, so no HTTP answer comes. */
    REQUIRE(rc != WOLFCERT_OK && rc != WOLFCERT_ERR_HTTP &&
            rc != WOLFCERT_ERR_AUTH);
    REQUIRE(refused.cert_pem.data == NULL);

    /* Without a client certificate there is nothing to renew. */
    REQUIRE(test_tls_connect(&conn, wolfcert_server_port(srv), tls_cert,
                             tls_cert_len) == 0);
    REQUIRE(test_tls_write(&conn, anon_req, sizeof(anon_req) - 1) == 0);
    while (resp_len < sizeof(resp) - 1) {
        int n = test_tls_read(&conn, resp + resp_len,
                              sizeof(resp) - 1 - resp_len);
        if (n <= 0)
            break;
        resp_len += (size_t)n;
    }
    test_tls_close(&conn);
    resp[resp_len] = '\0';
    REQUIRE(strncmp(resp, "HTTP/1.1 403", 12) == 0);

    wolfcert_server_stop(srv);
    pthread_join(tid, NULL);
    wolfcert_server_free(srv);
    srv = NULL;
    wolfcert_buffer_free(&csr);

#ifdef WOLFCERT_HAVE_SCEP
    cfg.protocol = WOLFCERT_PROTO_SCEP;
    REQUIRE(wolfcert_server_start(&cfg, &srv) == WOLFCERT_ERR_BAD_ARG);
    REQUIRE(srv == NULL);
    cfg.protocol = WOLFCERT_PROTO_EST;
#endif

    /* With no other authenticator the server only renews, from a kept CA. */
    cfg.est_allow_anonymous_enroll = 0;
    cfg.ca_cert     = NULL;
    cfg.ca_cert_len = 0;
    cfg.ca_key      = NULL;
    cfg.ca_key_len  = 0;
    REQUIRE(wolfcert_server_start(&cfg, &srv) == WOLFCERT_ERR_BAD_ARG);
    REQUIRE(srv == NULL);
    test_ca_set(&cfg);
    REQUIRE(wolfcert_server_start(&cfg, &srv) == WOLFCERT_OK);
    REQUIRE(pthread_create(&tid, NULL, server_thread, srv) == 0);
    snprintf(url, sizeof(url), "https://127.0.0.1:%u/.well-known/est",
             wolfcert_server_port(srv));
    meta.subject_dn = "CN=trust-issued";
    REQUIRE(wolfcert_csr_build(k2, &meta, &csr) == WOLFCERT_OK);
    wolfcert_clear_error();
    rc = wolfcert_est_simple_enroll(&cli, csr.data, csr.len, &refused);
    REQUIRE(rc == WOLFCERT_ERR_AUTH);
    REQUIRE(strstr(wolfcert_last_error_message(), "HTTP 403") != NULL);
    REQUIRE(refused.cert_pem.data == NULL);
    wolfcert_est_result_free(&issued);
    rc = wolfcert_est_simple_reenroll(&cli, renewed.cert_pem.data, renewed.cert_pem.len, k2,
                                      csr.data, csr.len, &issued);
    REQUIRE(rc == WOLFCERT_OK);
    REQUIRE(memmem(issued.cert_pem.data, issued.cert_pem.len, "BEGIN CERTIFICATE", 17) != NULL);

    wolfcert_server_stop(srv);
    pthread_join(tid, NULL);
    wolfcert_server_free(srv);
    wolfcert_buffer_free(&csr);
    wolfcert_est_result_free(&renewed);
    wolfcert_est_result_free(&issued);
    wolfcert_buffer_free(&ca_pem);
    wolfcert_key_free(foreign);
    wolfcert_key_free(k2);
    wolfcert_key_free(k1);
    return 0;
}
/* Without ECC the test server offers no TLS 1.2 suite: it loads no DH. */
#if !defined(WOLFSSL_NO_TLS12) && defined(HAVE_ECC)
/* A TLS 1.2 session resumed from one authenticated by cert/key carries no
 * peer certificate; write req on it and return the response's status line. */
static int resumed_status(uint16_t port, const uint8_t* ca, size_t ca_len,
                          const WolfCertBuffer* cert, const WolfCertBuffer* key,
                          const char* req, char* status, size_t status_sz)
{
    TestTlsConn c;
    WOLFSSL_SESSION* sess = NULL;
    char resp[512];
    int n;

    REQUIRE(test_tls_setup(&c, port, ca, ca_len) == 0);
    REQUIRE(wolfSSL_SetVersion(c.ssl, WOLFSSL_TLSV1_2) == WOLFSSL_SUCCESS);
    REQUIRE(wolfSSL_use_certificate_buffer(c.ssl, cert->data, (long)cert->len,
                                           WOLFSSL_FILETYPE_PEM) ==
            WOLFSSL_SUCCESS);
    REQUIRE(wolfSSL_use_PrivateKey_buffer(c.ssl, key->data, (long)key->len,
                                          WOLFSSL_FILETYPE_PEM) ==
            WOLFSSL_SUCCESS);
    REQUIRE(wolfSSL_connect(c.ssl) == WOLFSSL_SUCCESS);
    sess = wolfSSL_get1_session(c.ssl);
    test_tls_close(&c);
    REQUIRE(sess != NULL);

    REQUIRE(test_tls_setup(&c, port, ca, ca_len) == 0);
    REQUIRE(wolfSSL_SetVersion(c.ssl, WOLFSSL_TLSV1_2) == WOLFSSL_SUCCESS);
    REQUIRE(wolfSSL_set_session(c.ssl, sess) == WOLFSSL_SUCCESS);
    REQUIRE(wolfSSL_connect(c.ssl) == WOLFSSL_SUCCESS);
    wolfSSL_SESSION_free(sess);
    REQUIRE(wolfSSL_session_reused(c.ssl) == 1);
    REQUIRE(test_tls_write(&c, req, strlen(req)) == 0);
    n = test_tls_read(&c, resp, sizeof(resp) - 1);
    test_tls_close(&c);
    REQUIRE(n > 0);
    resp[n] = '\0';
    snprintf(status, status_sz, "%.*s", (int)strcspn(resp, "\r"), resp);
    return 0;
}
#endif

/* tls_client_trust_issued next to a client CA that is another wolfCert CA,
 * with the same subject: a certificate from either CA verifies, and one this
 * server issued renews but does not enroll. */
static int test_trust_issued_with_client_ca(const uint8_t* tls_cert,
                                            size_t tls_cert_len,
                                            const uint8_t* tls_key,
                                            size_t tls_key_len)
{
    WolfCertKeyCfg kcfg = { .type = TEST_ENROLL_KEY_TYPE, .param = TEST_ENROLL_KEY_PARAM,
                            .dev_id = INVALID_DEVID };
    WolfCertCertMeta meta = { .subject_dn = "CN=bootstrap" };
    WolfCertServerCfgSrv cfg = {
        .protocol                   = WOLFCERT_PROTO_EST,
        .bind_host                  = "127.0.0.1",
        .bind_port                  = 0,
        .tls_cert_pem = tls_cert, .tls_cert_pem_len = tls_cert_len,
        .tls_key_pem  = tls_key,  .tls_key_pem_len  = tls_key_len,
        .est_allow_anonymous_enroll = 1,
    };
    WolfCertServer* srv = NULL;
    WolfCertKey* kb = NULL;
    WolfCertKey* k1 = NULL;
    WolfCertKey* k2 = NULL;
    WolfCertBuffer other_ca = { 0 };
    WolfCertBuffer none = { 0 };
    WolfCertEstResult boot = { 0 };
    WolfCertEstResult issued = { 0 };
    WolfCertEstResult renewed = { 0 };
    WolfCertEstResult refused = { 0 };
    WolfCertBuffer csr = { 0 };
    WolfCertBuffer boot_key = { 0 };
    WolfCertBuffer k1_pem = { 0 };
    char status[64];
    pthread_t tid;
    char url[128];
    int rc;

    /* A second CA, as another wolfcert-server would generate it. */
    REQUIRE(wolfcert_server_start(&cfg, &srv) == WOLFCERT_OK);
    REQUIRE(pthread_create(&tid, NULL, server_thread, srv) == 0);
    snprintf(url, sizeof(url), "https://127.0.0.1:%u/.well-known/est",
             wolfcert_server_port(srv));
    WolfCertServerCfg cli = {
        .protocol          = WOLFCERT_PROTO_EST,
        .server_url        = url,
        .trust_anchors     = tls_cert,
        .trust_anchors_len = tls_cert_len,
        .verify_server     = 1,
    };
    REQUIRE(wolfcert_est_get_cacerts(&cli, WOLFCERT_ENCODING_PEM,
                                     &other_ca) == WOLFCERT_OK);
    REQUIRE(wolfcert_key_generate(&kcfg, &kb) == WOLFCERT_OK);
    REQUIRE(wolfcert_csr_build(kb, &meta, &csr) == WOLFCERT_OK);
    REQUIRE(wolfcert_est_simple_enroll(&cli, csr.data, csr.len, &boot) ==
            WOLFCERT_OK);
    wolfcert_buffer_free(&csr);
    REQUIRE(wolfcert_key_to_pem(kb, &boot_key) == WOLFCERT_OK);
    wolfcert_server_stop(srv);
    pthread_join(tid, NULL);
    wolfcert_server_free(srv);
    srv = NULL;

    test_ca_set(&cfg);
    cfg.est_allow_anonymous_enroll = 0;
    cfg.tls_client_ca_pem          = other_ca.data;
    cfg.tls_client_ca_pem_len      = other_ca.len;
    cfg.tls_client_trust_issued    = 1;
    REQUIRE(wolfcert_server_start(&cfg, &srv) == WOLFCERT_OK);
    REQUIRE(pthread_create(&tid, NULL, server_thread, srv) == 0);
    snprintf(url, sizeof(url), "https://127.0.0.1:%u/.well-known/est",
             wolfcert_server_port(srv));

    /* The client CA still demands a certificate, so no HTTP answer comes. */
    rc = wolfcert_est_get_cacerts(&cli, WOLFCERT_ENCODING_PEM, &none);
    REQUIRE(rc != WOLFCERT_OK && rc != WOLFCERT_ERR_HTTP &&
            rc != WOLFCERT_ERR_AUTH);

    cli.client_cert     = boot.cert_pem.data;
    cli.client_cert_len = boot.cert_pem.len;
    cli.client_key      = boot_key.data;
    cli.client_key_len  = boot_key.len;
    meta.subject_dn = "CN=issued-here";
    REQUIRE(wolfcert_key_generate(&kcfg, &k1) == WOLFCERT_OK);
    REQUIRE(wolfcert_csr_build(k1, &meta, &csr) == WOLFCERT_OK);
    REQUIRE(wolfcert_est_simple_enroll(&cli, csr.data, csr.len, &issued) ==
            WOLFCERT_OK);

    /* A certificate this server issued does not authenticate an enroll. */
    REQUIRE(wolfcert_key_to_pem(k1, &k1_pem) == WOLFCERT_OK);
    cli.client_cert     = issued.cert_pem.data;
    cli.client_cert_len = issued.cert_pem.len;
    cli.client_key      = k1_pem.data;
    cli.client_key_len  = k1_pem.len;
    wolfcert_clear_error();
    rc = wolfcert_est_simple_enroll(&cli, csr.data, csr.len, &refused);
    wolfcert_buffer_free(&csr);
    REQUIRE(rc == WOLFCERT_ERR_AUTH);
    REQUIRE(strstr(wolfcert_last_error_message(), "HTTP 403") != NULL);
    REQUIRE(refused.cert_pem.data == NULL);

    REQUIRE(wolfcert_key_generate(&kcfg, &k2) == WOLFCERT_OK);
    REQUIRE(wolfcert_csr_build(k2, &meta, &csr) == WOLFCERT_OK);
    rc = wolfcert_est_simple_reenroll(&cli, issued.cert_pem.data, issued.cert_pem.len, k1,
                                      csr.data, csr.len, &renewed);
    REQUIRE(rc == WOLFCERT_OK);
    REQUIRE(memmem(renewed.cert_pem.data, renewed.cert_pem.len, "BEGIN CERTIFICATE", 17) != NULL);

#if !defined(WOLFSSL_NO_TLS12) && defined(HAVE_ECC)
    /* A resumed session cannot enroll: 403 when SESSION_CERTS keeps its
     * certificate, 500 when there is none to check. */
    REQUIRE(resumed_status(wolfcert_server_port(srv), tls_cert, tls_cert_len,
                           &issued.cert_pem, &k1_pem,
                           "POST /.well-known/est/simpleenroll HTTP/1.1\r\n"
                           "Host: 127.0.0.1\r\n"
                           "Content-Type: application/pkcs10\r\n"
                           "Content-Length: 4\r\nConnection: close\r\n"
                           "\r\nAAAA", status, sizeof(status)) == 0);
    REQUIRE(strcmp(status, "HTTP/1.1 500 Server Error") == 0 ||
            strncmp(status, "HTTP/1.1 403", 12) == 0);
#endif

    /* With Basic, a certificate issued here no longer blocks an enroll. */
    WolfCertEstResult with_basic = { 0 };
    wolfcert_server_stop(srv);
    pthread_join(tid, NULL);
    wolfcert_server_free(srv);
    srv = NULL;
    cfg.http_basic_user = "alice";
    cfg.http_basic_pass = "secret";
    REQUIRE(wolfcert_server_start(&cfg, &srv) == WOLFCERT_OK);
    REQUIRE(pthread_create(&tid, NULL, server_thread, srv) == 0);
    snprintf(url, sizeof(url), "https://127.0.0.1:%u/.well-known/est",
             wolfcert_server_port(srv));
    cli.proto_opts.est.username = "alice";
    cli.proto_opts.est.password = "secret";
    rc = wolfcert_est_simple_enroll(&cli, csr.data, csr.len, &with_basic);
    REQUIRE(rc == WOLFCERT_OK);
    REQUIRE(with_basic.status == WOLFCERT_EST_STATUS_SUCCESS);
    wolfcert_est_result_free(&with_basic);

    wolfcert_server_stop(srv);
    pthread_join(tid, NULL);
    wolfcert_server_free(srv);
    wolfcert_buffer_free(&csr);
    wolfcert_est_result_free(&renewed);
    wolfcert_est_result_free(&issued);
    wolfcert_est_result_free(&boot);
    wolfcert_buffer_free(&other_ca);
    wolfcert_buffer_free(&k1_pem);
    wolfcert_buffer_free(&boot_key);
    wolfcert_key_free(k2);
    wolfcert_key_free(k1);
    wolfcert_key_free(kb);
    return 0;
}

/* A pinned self-signed client certificate still enrolls next to
 * tls_client_trust_issued. */
static int test_trust_issued_pinned_self_signed(const uint8_t* tls_cert,
                                                size_t tls_cert_len,
                                                const uint8_t* tls_key,
                                                size_t tls_key_len,
                                                const uint8_t* cli_cert,
                                                size_t cli_cert_len,
                                                const uint8_t* cli_key,
                                                size_t cli_key_len)
{
    WolfCertKeyCfg kcfg = { .type = TEST_ENROLL_KEY_TYPE, .param = TEST_ENROLL_KEY_PARAM,
                            .dev_id = INVALID_DEVID };
    WolfCertCertMeta meta = { .subject_dn = "CN=pinned" };
    WolfCertServerCfgSrv cfg = {
        .protocol                = WOLFCERT_PROTO_EST,
        .bind_host               = "127.0.0.1",
        .bind_port               = 0,
        TEST_CA_CFG,
        .tls_cert_pem = tls_cert, .tls_cert_pem_len = tls_cert_len,
        .tls_key_pem  = tls_key,  .tls_key_pem_len  = tls_key_len,
        .tls_client_ca_pem       = cli_cert,
        .tls_client_ca_pem_len   = cli_cert_len,
        .tls_client_trust_issued = 1,
    };
    WolfCertServer* srv = NULL;
    WolfCertKey* k = NULL;
    WolfCertBuffer csr = { 0 };
    WolfCertEstResult issued = { 0 };
    pthread_t tid;
    char url[128];
    int rc;

    REQUIRE(wolfcert_server_start(&cfg, &srv) == WOLFCERT_OK);
    REQUIRE(pthread_create(&tid, NULL, server_thread, srv) == 0);
    snprintf(url, sizeof(url), "https://127.0.0.1:%u/.well-known/est",
             wolfcert_server_port(srv));
    WolfCertServerCfg cli = {
        .protocol          = WOLFCERT_PROTO_EST,
        .server_url        = url,
        .trust_anchors     = tls_cert,
        .trust_anchors_len = tls_cert_len,
        .verify_server     = 1,
        .client_cert       = cli_cert,
        .client_cert_len   = cli_cert_len,
        .client_key        = cli_key,
        .client_key_len    = cli_key_len,
    };
    REQUIRE(wolfcert_key_generate(&kcfg, &k) == WOLFCERT_OK);
    REQUIRE(wolfcert_csr_build(k, &meta, &csr) == WOLFCERT_OK);
    rc = wolfcert_est_simple_enroll(&cli, csr.data, csr.len, &issued);

    wolfcert_server_stop(srv);
    pthread_join(tid, NULL);
    wolfcert_server_free(srv);
    REQUIRE(rc == WOLFCERT_OK);
    wolfcert_est_result_free(&issued);
    wolfcert_buffer_free(&csr);
    wolfcert_key_free(k);
    return 0;
}
#endif /* KEEP_PEER_CERT */

#ifndef KEEP_PEER_CERT
/* The mTLS handshake demanded a client cert this build cannot read: 500. */
static int test_reenroll_needs_peer_cert(const char* url,
                                         const uint8_t* tls_cert, size_t tls_cert_len,
                                         const uint8_t* cli_cert, size_t cli_cert_len,
                                         const uint8_t* cli_key, size_t cli_key_len)
{
    WolfCertKeyCfg kcfg = { .type = TEST_ENROLL_KEY_TYPE, .param = TEST_ENROLL_KEY_PARAM,
                            .dev_id = INVALID_DEVID };
    WolfCertCertMeta meta = { .subject_dn = "CN=factory-bootstrap" };
    WolfCertServerCfg cli = {
        .protocol          = WOLFCERT_PROTO_EST,
        .server_url        = url,
        .trust_anchors     = tls_cert,
        .trust_anchors_len = tls_cert_len,
        .verify_server     = 1,
    };
    WolfCertKey* cur_key = NULL;
    WolfCertKey* dk = NULL;
    WolfCertBuffer csr = { 0 };
    WolfCertEstResult issued = { 0 };
    int rc;

    REQUIRE(wolfcert_key_from_pem(cli_key, cli_key_len, NULL, &cur_key) == WOLFCERT_OK);
    REQUIRE(wolfcert_key_generate(&kcfg, &dk) == WOLFCERT_OK);
    REQUIRE(wolfcert_csr_build(dk, &meta, &csr) == WOLFCERT_OK);
    rc = wolfcert_est_simple_reenroll(&cli, cli_cert, cli_cert_len, cur_key,
                                      csr.data, csr.len, &issued);
    wolfcert_buffer_free(&csr);
    wolfcert_key_free(dk);
    wolfcert_key_free(cur_key);
    REQUIRE(rc == WOLFCERT_ERR_HTTP);
    REQUIRE(strstr(wolfcert_last_error_message(), "HTTP 500") != NULL);
    REQUIRE(issued.cert_pem.data == NULL);
    return 0;
}

/* tls_client_trust_issued cannot work without the peer certificate. */
static int test_trust_issued_needs_peer_cert(const uint8_t* tls_cert,
                                             size_t tls_cert_len,
                                             const uint8_t* tls_key,
                                             size_t tls_key_len)
{
    WolfCertServerCfgSrv cfg = {
        .protocol                = WOLFCERT_PROTO_EST,
        .bind_host               = "127.0.0.1",
        .tls_cert_pem = tls_cert, .tls_cert_pem_len = tls_cert_len,
        .tls_key_pem  = tls_key,  .tls_key_pem_len  = tls_key_len,
        .tls_client_trust_issued = 1,
    };
    WolfCertServer* srv = NULL;

    REQUIRE(wolfcert_server_start(&cfg, &srv) == WOLFCERT_ERR_UNSUPPORTED);
    REQUIRE(srv == NULL);
    return 0;
}
#endif

int main(void)
{
    REQUIRE(wolfcert_init(NULL) == WOLFCERT_OK);

    /* Server identity (CN=127.0.0.1 with IP SAN). */
    uint8_t* tls_cert = NULL;
    size_t tls_cert_len = 0;
    uint8_t* tls_key  = NULL;
    size_t tls_key_len  = 0;
    REQUIRE(mint_self_id("127.0.0.1", 0,
                        &tls_cert, &tls_cert_len, &tls_key, &tls_key_len) == 0);

    /* Self-signed, so it is both the server's client CA and the client cert. */
    uint8_t* cli_cert = NULL;
    size_t cli_cert_len = 0;
    uint8_t* cli_key  = NULL;
    size_t cli_key_len  = 0;
    REQUIRE(mint_self_id("factory-bootstrap", 1,
                        &cli_cert, &cli_cert_len, &cli_key, &cli_key_len) == 0);

    WolfCertServerCfgSrv cfg = {
        .protocol              = WOLFCERT_PROTO_EST,
        .bind_host             = "127.0.0.1",
        .bind_port             = 0,
        TEST_CA_CFG,
        .tls_cert_pem          = tls_cert, .tls_cert_pem_len       = tls_cert_len,
        .tls_key_pem           = tls_key,  .tls_key_pem_len        = tls_key_len,
        .tls_client_ca_pem     = cli_cert, .tls_client_ca_pem_len  = cli_cert_len,
    };
    WolfCertServer* srv = NULL;
    REQUIRE(wolfcert_server_start(&cfg, &srv) == WOLFCERT_OK);
    pthread_t tid;
    REQUIRE(pthread_create(&tid, NULL, server_thread, srv) == 0);

    char url[128];
    snprintf(url, sizeof(url), "https://127.0.0.1:%u/.well-known/est",
             wolfcert_server_port(srv));

    /* Without a client identity the handshake fails. */
    {
        WolfCertServerCfg cli = {
            .protocol          = WOLFCERT_PROTO_EST,
            .server_url        = url,
            .trust_anchors = tls_cert, .trust_anchors_len = tls_cert_len,
            .verify_server     = 1,
        };
        WolfCertBuffer ca_pem = { 0 };
        int rc = wolfcert_est_get_cacerts(&cli, WOLFCERT_ENCODING_PEM, &ca_pem);
        REQUIRE(rc != WOLFCERT_OK);
        if (rc == WOLFCERT_OK)
            wolfcert_buffer_free(&ca_pem);

        /* A session without a client cert refuses reenroll before sending. */
        static const uint8_t csr[] = { 0x30, 0x03, 0x02, 0x01, 0x00 };
        WolfCertEstSession* ns = NULL;
        WolfCertEstResult nr = { 0 };
        REQUIRE(wolfcert_est_session_open(&cli, &ns) == WOLFCERT_OK);
        REQUIRE(wolfcert_est_session_simple_reenroll(ns, csr, sizeof(csr), &nr)
                == WOLFCERT_ERR_BAD_ARG);
        wolfcert_est_session_close(ns);
    }

    {
        WolfCertServerCfg cli = {
            .protocol          = WOLFCERT_PROTO_EST,
            .server_url        = url,
            .trust_anchors     = tls_cert,
            .trust_anchors_len = tls_cert_len,
            .verify_server     = 1,
            .client_cert       = cli_cert,
            .client_cert_len   = cli_cert_len,
            .client_key        = cli_key,
            .client_key_len    = cli_key_len,
        };

        WolfCertBuffer ca_pem = { 0 };
        REQUIRE(wolfcert_est_get_cacerts(&cli, WOLFCERT_ENCODING_PEM,
                                         &ca_pem) == WOLFCERT_OK);
        REQUIRE(ca_pem.len > 0);
        wolfcert_buffer_free(&ca_pem);

        WolfCertKeyCfg kcfg = { .type = TEST_ENROLL_KEY_TYPE, .param = TEST_ENROLL_KEY_PARAM,
                                .dev_id = INVALID_DEVID };
        WolfCertKey* dk = NULL;
        REQUIRE(wolfcert_key_generate(&kcfg, &dk) == WOLFCERT_OK);
        WolfCertCertMeta meta = { .subject_dn = "CN=mtls-est-client" };
        WolfCertBuffer csr = { 0 };
        REQUIRE(wolfcert_csr_build(dk, &meta, &csr) == WOLFCERT_OK);

        WolfCertEstResult issued = { 0 };
        int rc = wolfcert_est_simple_enroll(&cli, csr.data, csr.len, &issued);
        if (rc != WOLFCERT_OK)
            fprintf(stderr, "mtls enroll rc=%d (%s)\n", rc, wolfcert_strerror(rc));
        REQUIRE(rc == WOLFCERT_OK && issued.status == WOLFCERT_EST_STATUS_SUCCESS);
        REQUIRE(memmem(issued.cert_pem.data, issued.cert_pem.len,
                       "BEGIN CERTIFICATE", 17) != NULL);

        wolfcert_buffer_free(&csr);
        wolfcert_est_result_free(&issued);
        wolfcert_key_free(dk);
    }

#ifdef KEEP_PEER_CERT
    REQUIRE(test_reenroll_ignores_cfg_identity(url, tls_cert, tls_cert_len,
                                               cli_cert, cli_cert_len,
                                               cli_key, cli_key_len) == 0);
    REQUIRE(test_reenroll_rejects_identity_change(url, tls_cert, tls_cert_len,
                                                  cli_cert, cli_cert_len,
                                                  cli_key, cli_key_len) == 0);
    REQUIRE(test_reenroll_rejects_non_csr(url, tls_cert, tls_cert_len,
                                          cli_cert, cli_cert_len,
                                          cli_key, cli_key_len) == 0);
#else
    REQUIRE(test_reenroll_needs_peer_cert(url, tls_cert, tls_cert_len,
                                          cli_cert, cli_cert_len,
                                          cli_key, cli_key_len) == 0);
    REQUIRE(test_trust_issued_needs_peer_cert(tls_cert, tls_cert_len,
                                              tls_key, tls_key_len) == 0);
    printf("skip reenroll cases: wolfSSL built without KEEP_PEER_CERT\n");
#endif

    wolfcert_server_stop(srv);
    pthread_join(tid, NULL);
    wolfcert_server_free(srv);

#ifdef KEEP_PEER_CERT
    REQUIRE(test_reenroll_server_issued(tls_cert, tls_cert_len,
                                        tls_key, tls_key_len,
                                        cli_cert, cli_cert_len,
                                        cli_key, cli_key_len) == 0);
    REQUIRE(test_reenroll_under_approval(tls_cert, tls_cert_len,
                                         tls_key, tls_key_len,
                                         cli_cert, cli_cert_len,
                                         cli_key, cli_key_len) == 0);
    REQUIRE(test_reenroll_trust_issued(tls_cert, tls_cert_len,
                                       tls_key, tls_key_len,
                                       cli_cert, cli_cert_len,
                                       cli_key, cli_key_len) == 0);
    REQUIRE(test_trust_issued_with_client_ca(tls_cert, tls_cert_len,
                                             tls_key, tls_key_len) == 0);
    REQUIRE(test_trust_issued_pinned_self_signed(tls_cert, tls_cert_len,
                                                 tls_key, tls_key_len,
                                                 cli_cert, cli_cert_len,
                                                 cli_key, cli_key_len) == 0);
#endif

    free(tls_cert);
    free(tls_key);
    free(cli_cert);
    free(cli_key);
    test_ca_close();
    wolfcert_cleanup();
    printf("OK\n");
    return 0;
}
