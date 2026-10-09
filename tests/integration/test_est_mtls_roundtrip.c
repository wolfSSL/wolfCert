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
    WolfCertBuffer issued = { 0 };
    WolfCertBuffer ca_pem = { 0 };
    WolfCertKeyCfg kcfg = { .type = TEST_ENROLL_KEY_TYPE, .param = TEST_ENROLL_KEY_PARAM,
                            .dev_id = WOLFCERT_DEVID_SOFTWARE };
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
    rc = wolfcert_est_get_cacerts(&cli, &ca_pem);
    wolfcert_buffer_free(&ca_pem);
    REQUIRE(rc != WOLFCERT_OK);

    REQUIRE(wolfcert_key_from_pem(cli_key, cli_key_len, NULL, &cur_key) == WOLFCERT_OK);
    REQUIRE(wolfcert_key_generate(&kcfg, &dk) == WOLFCERT_OK);
    REQUIRE(wolfcert_csr_build(dk, &meta, &csr) == WOLFCERT_OK);

    rc = wolfcert_est_simple_reenroll(&cli, cli_cert, cli_cert_len, cur_key,
                                      csr.data, csr.len, &issued);
    if (rc != WOLFCERT_OK)
        fprintf(stderr, "mtls reenroll rc=%d (%s)\n", rc, wolfcert_strerror(rc));
    REQUIRE(rc == WOLFCERT_OK);
    REQUIRE(memmem(issued.data, issued.len, "BEGIN CERTIFICATE", 17) != NULL);

    wolfcert_buffer_free(&issued);
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
                            .dev_id = WOLFCERT_DEVID_SOFTWARE };
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
        WolfCertBuffer issued = { 0 };
        int rc;

        REQUIRE(wolfcert_csr_build(dk, &metas[i], &csr) == WOLFCERT_OK);
        rc = wolfcert_est_simple_reenroll(&cli, cli_cert, cli_cert_len, cur_key,
                                          csr.data, csr.len, &issued);
        wolfcert_buffer_free(&csr);
        if (rc == WOLFCERT_OK)
            fprintf(stderr, "reenroll with changed identity %zu was issued\n", i);
        REQUIRE(rc == WOLFCERT_ERR_HTTP);
        REQUIRE(issued.data == NULL);
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
    WolfCertBuffer issued = { 0 };
    int rc;

    REQUIRE(wolfcert_key_from_pem(cli_key, cli_key_len, NULL, &cur_key) == WOLFCERT_OK);
    rc = wolfcert_est_simple_reenroll(&cli, cli_cert, cli_cert_len, cur_key,
                                      not_csr, sizeof(not_csr), &issued);
    wolfcert_key_free(cur_key);
    if (rc != WOLFCERT_ERR_HTTP)
        fprintf(stderr, "non-CSR reenroll rc=%d (%s)\n", rc,
                wolfcert_last_error_message());
    REQUIRE(rc == WOLFCERT_ERR_HTTP);
    REQUIRE(issued.data == NULL);
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
                            .dev_id = WOLFCERT_DEVID_SOFTWARE };
    WolfCertServerCfgSrv cfg = {
        .protocol              = WOLFCERT_PROTO_EST,
        .bind_host             = "127.0.0.1",
        .bind_port             = 0,
        .tls_cert_pem          = tls_cert, .tls_cert_pem_len       = tls_cert_len,
        .tls_key_pem           = tls_key,  .tls_key_pem_len        = tls_key_len,
        .tls_client_ca_pem     = cli_cert, .tls_client_ca_pem_len  = cli_cert_len,
    };
    WolfCertStoreOps* store = wolfcert_store_memory_open(NULL);
    WolfCertServer* srv = NULL;
    WolfCertBuffer ca_der = { 0 };
    WolfCertBuffer csr = { 0 };
    WolfCertBuffer issued = { 0 };
    WolfCertBuffer renewed = { 0 };
    WolfCertBuffer san_changed = { 0 };
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
    WolfCertBuffer refused = { 0 };
    int crit_len;
#endif

    /* The first start mints the CA into the store; the second adopts it. */
    REQUIRE(store != NULL);
    cfg.ca_store = store;
    REQUIRE(wolfcert_server_start(&cfg, &srv) == WOLFCERT_OK);
    wolfcert_server_free(srv);
    srv = NULL;
    REQUIRE(store->read(store->ctx, "ca.cert.der", &ca_der) == WOLFCERT_OK);

    bundle_cap = cli_cert_len + ca_der.len * 2 + 256;
    bundle = (uint8_t*)malloc(bundle_cap);
    REQUIRE(bundle != NULL);
    memcpy(bundle, cli_cert, cli_cert_len);
    pem_len = wc_DerToPem(ca_der.data, (word32)ca_der.len, bundle + cli_cert_len,
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
    REQUIRE(rc == WOLFCERT_OK);

    REQUIRE(wolfcert_key_generate(&kcfg, &k2) == WOLFCERT_OK);
    REQUIRE(wolfcert_csr_build(k2, &meta, &csr) == WOLFCERT_OK);
    rc = wolfcert_est_simple_reenroll(&cli, issued.data, issued.len, k1,
                                      csr.data, csr.len, &renewed);
    if (rc != WOLFCERT_OK)
        fprintf(stderr, "reenroll of a server-issued cert rc=%d (%s)\n", rc,
                wolfcert_strerror(rc));
    REQUIRE(rc == WOLFCERT_OK);
    REQUIRE(memmem(renewed.data, renewed.len, "BEGIN CERTIFICATE", 17) != NULL);

    /* Same Subject and SAN shape, one dNSName changed. */
    wolfcert_buffer_free(&csr);
    REQUIRE(wolfcert_csr_build(k2, &meta2, &csr) == WOLFCERT_OK);
    rc = wolfcert_est_simple_reenroll(&cli, issued.data, issued.len, k1,
                                      csr.data, csr.len, &san_changed);
    REQUIRE(rc == WOLFCERT_ERR_HTTP);
    REQUIRE(strstr(wolfcert_last_error_message(), "HTTP 400") != NULL);
    REQUIRE(san_changed.data == NULL);

#ifdef HAVE_ECC
    crit_len = csr_with_critical_san(&issued, crit_csr, sizeof(crit_csr));
    REQUIRE(crit_len > 0);
    rc = wolfcert_est_simple_reenroll(&cli, issued.data, issued.len, k1,
                                      crit_csr, (size_t)crit_len, &refused);
    REQUIRE(rc == WOLFCERT_ERR_HTTP);
    REQUIRE(strstr(wolfcert_last_error_message(), "HTTP 400") != NULL);
    REQUIRE(refused.data == NULL);
#endif

    wolfcert_server_stop(srv);
    pthread_join(tid, NULL);
    wolfcert_server_free(srv);
    wolfcert_store_memory_close(store);
    wolfcert_buffer_free(&renewed);
    wolfcert_buffer_free(&issued);
    wolfcert_buffer_free(&csr);
    wolfcert_buffer_free(&ca_der);
    wolfcert_key_free(k2);
    wolfcert_key_free(k1);
    free(bundle);
    return 0;
}

/* The approval gate runs after the identity check, so a mismatched reenroll
 * gets its 400 on the first POST rather than a 202. */
static int test_reenroll_mismatch_not_parked(const uint8_t* tls_cert, size_t tls_cert_len,
                                             const uint8_t* tls_key, size_t tls_key_len,
                                             const uint8_t* cli_cert, size_t cli_cert_len,
                                             const uint8_t* cli_key, size_t cli_key_len)
{
    const WolfCertCertMeta meta = { .subject_dn = "CN=someone-else" };
    WolfCertKeyCfg kcfg = { .type = TEST_ENROLL_KEY_TYPE, .param = TEST_ENROLL_KEY_PARAM,
                            .dev_id = WOLFCERT_DEVID_SOFTWARE };
    WolfCertServerCfgSrv cfg = {
        .protocol              = WOLFCERT_PROTO_EST,
        .bind_host             = "127.0.0.1",
        .bind_port             = 0,
        .ca_store              = test_ca_store(),
        .tls_cert_pem          = tls_cert, .tls_cert_pem_len       = tls_cert_len,
        .tls_key_pem           = tls_key,  .tls_key_pem_len        = tls_key_len,
        .tls_client_ca_pem     = cli_cert, .tls_client_ca_pem_len  = cli_cert_len,
        .est_require_approval  = 1,
    };
    WolfCertServer* srv = NULL;
    WolfCertKey* cur_key = NULL;
    WolfCertKey* dk = NULL;
    WolfCertBuffer csr = { 0 };
    WolfCertBuffer issued = { 0 };
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
    REQUIRE(issued.data == NULL);
    REQUIRE(strstr(wolfcert_last_error_message(), "HTTP 400") != NULL);

    wolfcert_server_stop(srv);
    pthread_join(tid, NULL);
    wolfcert_server_free(srv);
    wolfcert_buffer_free(&csr);
    wolfcert_key_free(dk);
    wolfcert_key_free(cur_key);
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
                            .dev_id = WOLFCERT_DEVID_SOFTWARE };
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
    WolfCertBuffer issued = { 0 };
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
    REQUIRE(issued.data == NULL);
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
        .ca_store              = test_ca_store(),
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
        int rc = wolfcert_est_get_cacerts(&cli, &ca_pem);
        REQUIRE(rc != WOLFCERT_OK);
        if (rc == WOLFCERT_OK)
            wolfcert_buffer_free(&ca_pem);
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
        REQUIRE(wolfcert_est_get_cacerts(&cli, &ca_pem) == WOLFCERT_OK);
        REQUIRE(ca_pem.len > 0);
        wolfcert_buffer_free(&ca_pem);

        WolfCertKeyCfg kcfg = { .type = TEST_ENROLL_KEY_TYPE, .param = TEST_ENROLL_KEY_PARAM,
                                .dev_id = WOLFCERT_DEVID_SOFTWARE };
        WolfCertKey* dk = NULL;
        REQUIRE(wolfcert_key_generate(&kcfg, &dk) == WOLFCERT_OK);
        WolfCertCertMeta meta = { .subject_dn = "CN=mtls-est-client" };
        WolfCertBuffer csr = { 0 };
        REQUIRE(wolfcert_csr_build(dk, &meta, &csr) == WOLFCERT_OK);

        WolfCertBuffer issued = { 0 };
        int rc = wolfcert_est_simple_enroll(&cli, csr.data, csr.len, &issued);
        if (rc != WOLFCERT_OK)
            fprintf(stderr, "mtls enroll rc=%d (%s)\n", rc, wolfcert_strerror(rc));
        REQUIRE(rc == WOLFCERT_OK);
        REQUIRE(memmem(issued.data, issued.len, "BEGIN CERTIFICATE", 17) != NULL);

        wolfcert_buffer_free(&csr);
        wolfcert_buffer_free(&issued);
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
    REQUIRE(test_reenroll_mismatch_not_parked(tls_cert, tls_cert_len,
                                              tls_key, tls_key_len,
                                              cli_cert, cli_cert_len,
                                              cli_key, cli_key_len) == 0);
#endif

    free(tls_cert);
    free(tls_key);
    free(cli_cert);
    free(cli_key);
    test_ca_store_close();
    wolfcert_cleanup();
    printf("OK\n");
    return 0;
}
