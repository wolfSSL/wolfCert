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
#include <wolfcert/server.h>
#include "internal.h"
#include "../test_static_mem.h"
#include "../integration/tls_test_util.h"

#include <wolfssl/options.h>
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

/* The CA store is protocol-agnostic; the listener just needs a protocol that
 * was compiled in, and SCEP is absent from any NO_RSA build. EST has no
 * plaintext mode, so that variant carries a throwaway server identity. */
#if defined(WOLFCERT_HAVE_EST)
    #define CA_STORE_PROTO WOLFCERT_PROTO_EST
    #define CA_STORE_NEEDS_TLS 1
#else
    #define CA_STORE_PROTO WOLFCERT_PROTO_SCEP
    #define CA_STORE_NEEDS_TLS 0
#endif

#if CA_STORE_NEEDS_TLS
static uint8_t* srv_cert_pem;
static size_t   srv_cert_pem_len;
static uint8_t* srv_key_pem;
static size_t   srv_key_pem_len;
#endif

static void ca_store_cfg(WolfCertServerCfgSrv* cfg, WolfCertStoreOps* store)
{
    memset(cfg, 0, sizeof(*cfg));
    cfg->protocol     = CA_STORE_PROTO;
#if CA_STORE_NEEDS_TLS
    cfg->tls_cert_pem     = srv_cert_pem;
    cfg->tls_cert_pem_len = srv_cert_pem_len;
    cfg->tls_key_pem      = srv_key_pem;
    cfg->tls_key_pem_len  = srv_key_pem_len;
#endif
    cfg->bind_host    = "127.0.0.1";
    cfg->ca_store     = store;
    cfg->ca_key_type  = CA_KEY_TYPE;
    cfg->ca_key_param = CA_KEY_PARAM;
}

/* Stub backend: every read reports the configured error, every write the
 * configured error, so a start can be driven down one failure path at a time. */
typedef struct {
    int read_rc;
    int write_rc;
} StubCtx;

static int stub_read(void* ctx_, const char* key, WolfCertBuffer* out)
{
    (void)key;
    (void)out;
    return ((StubCtx*)ctx_)->read_rc;
}

static int stub_write(void* ctx_, const char* key, const uint8_t* data,
                      size_t len, int sensitive)
{
    (void)key;
    (void)data;
    (void)len;
    (void)sensitive;
    return ((StubCtx*)ctx_)->write_rc;
}

static int stub_remove(void* ctx_, const char* key)
{
    (void)ctx_;
    (void)key;
    return WOLFCERT_OK;
}

static void stub_store(WolfCertStoreOps* ops, StubCtx* ctx)
{
    memset(ops, 0, sizeof(*ops));
    ops->read   = stub_read;
    ops->write  = stub_write;
    ops->remove = stub_remove;
    ops->ctx    = ctx;
}

static int test_corrupt_ca_rejected(void)
{
    WolfCertStoreOps* store = wolfcert_store_memory_open(NULL);
    REQUIRE(store != NULL);

    const uint8_t junk[] = { 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA };
    REQUIRE(store->write(store->ctx, "ca.cert.der", junk, sizeof(junk), 0) == WOLFCERT_OK);
    REQUIRE(store->write(store->ctx, "ca.key.der", junk, sizeof(junk), 1) == WOLFCERT_OK);

    WolfCertServerCfgSrv cfg;
    WolfCertServer* srv = NULL;

    ca_store_cfg(&cfg, store);
    REQUIRE(wolfcert_server_start(&cfg, &srv) == WOLFCERT_ERR_PARSE);
    REQUIRE(srv == NULL);

    wolfcert_store_memory_close(store);
    return 0;
}

static int test_load_io_error_rejected(void)
{
    StubCtx ctx = { WOLFCERT_ERR_IO, WOLFCERT_OK };
    WolfCertStoreOps store;
    WolfCertServerCfgSrv cfg;
    WolfCertServer* srv = NULL;

    stub_store(&store, &ctx);
    ca_store_cfg(&cfg, &store);
    REQUIRE(wolfcert_server_start(&cfg, &srv) == WOLFCERT_ERR_IO);
    REQUIRE(srv == NULL);
    return 0;
}

static int test_save_failure_rejected(void)
{
    StubCtx ctx = { WOLFCERT_ERR_NOT_FOUND, WOLFCERT_ERR_IO };
    WolfCertStoreOps store;
    WolfCertServerCfgSrv cfg;
    WolfCertServer* srv = NULL;

    stub_store(&store, &ctx);
    ca_store_cfg(&cfg, &store);
    REQUIRE(wolfcert_server_start(&cfg, &srv) == WOLFCERT_ERR_IO);
    REQUIRE(srv == NULL);
    return 0;
}

/* Stub backend whose two CA reads fail differently, so the precedence between
 * an absent half and a genuinely failing read can be driven either way. */
typedef struct {
    int cert_rc;
    int key_rc;
} SplitCtx;

static int split_read(void* ctx_, const char* key, WolfCertBuffer* out)
{
    SplitCtx* ctx = (SplitCtx*)ctx_;

    (void)out;
    return strcmp(key, "ca.cert.der") == 0 ? ctx->cert_rc : ctx->key_rc;
}

/* A read that failed for a reason other than absence must be reported as
 * itself: calling the store "incomplete" hides an actionable I/O or memory
 * failure behind a parse error. */
static int mixed_read_failure(int cert_rc, int key_rc, int want)
{
    SplitCtx ctx = { cert_rc, key_rc };
    WolfCertStoreOps store;
    WolfCertServerCfgSrv cfg;
    WolfCertServer* srv = NULL;

    memset(&store, 0, sizeof(store));
    store.read   = split_read;
    store.write  = stub_write;
    store.remove = stub_remove;
    store.ctx    = &ctx;

    ca_store_cfg(&cfg, &store);
    REQUIRE(wolfcert_server_start(&cfg, &srv) == want);
    REQUIRE(srv == NULL);
    return 0;
}

static int test_mixed_read_failure(void)
{
    if (mixed_read_failure(WOLFCERT_ERR_NOT_FOUND, WOLFCERT_ERR_IO,
                           WOLFCERT_ERR_IO))
        return 1;
    if (mixed_read_failure(WOLFCERT_ERR_IO, WOLFCERT_ERR_NOT_FOUND,
                           WOLFCERT_ERR_IO))
        return 1;
    if (mixed_read_failure(WOLFCERT_ERR_NOT_FOUND, WOLFCERT_ERR_MEMORY,
                           WOLFCERT_ERR_MEMORY))
        return 1;

    /* Both absent is still an empty store, which bootstraps rather than
     * failing; one absent beside one good read is still incomplete. */
    return mixed_read_failure(WOLFCERT_ERR_NOT_FOUND, WOLFCERT_OK,
                              WOLFCERT_ERR_PARSE);
}

/* Backend that forwards to a real store but fails the nth write, so a
 * bootstrap can be interrupted between the certificate and the key. */
typedef struct {
    WolfCertStoreOps* inner;
    int               writes;
    int               fail_at;
} FlakyCtx;

static int flaky_read(void* ctx_, const char* key, WolfCertBuffer* out)
{
    WolfCertStoreOps* in = ((FlakyCtx*)ctx_)->inner;

    return in->read(in->ctx, key, out);
}

static int flaky_write(void* ctx_, const char* key, const uint8_t* data,
                       size_t len, int sensitive)
{
    FlakyCtx* ctx = (FlakyCtx*)ctx_;

    if (++ctx->writes == ctx->fail_at)
        return WOLFCERT_ERR_IO;

    return ctx->inner->write(ctx->inner->ctx, key, data, len, sensitive);
}

static int flaky_remove(void* ctx_, const char* key)
{
    WolfCertStoreOps* in = ((FlakyCtx*)ctx_)->inner;

    return in->remove(in->ctx, key);
}

static int failing_remove(void* ctx_, const char* key)
{
    (void)ctx_;
    (void)key;
    return WOLFCERT_ERR_IO;
}

/* A key write that fails once the certificate has landed must take the
 * certificate with it: a cert-only store is rejected by every later load. */
static int test_save_rollback(void)
{
    WolfCertStoreOps* mem = wolfcert_store_memory_open(NULL);
    FlakyCtx fctx;
    WolfCertStoreOps store;
    WolfCertServerCfgSrv cfg;
    WolfCertServer* srv = NULL;
    WolfCertBuffer left = { 0 };

    REQUIRE(mem != NULL);

    memset(&fctx, 0, sizeof(fctx));
    fctx.inner   = mem;
    fctx.fail_at = 2;

    memset(&store, 0, sizeof(store));
    store.read   = flaky_read;
    store.write  = flaky_write;
    store.remove = flaky_remove;
    store.ctx    = &fctx;

    ca_store_cfg(&cfg, &store);
    REQUIRE(wolfcert_server_start(&cfg, &srv) == WOLFCERT_ERR_IO);
    REQUIRE(srv == NULL);
    REQUIRE(mem->read(mem->ctx, "ca.cert.der", &left) == WOLFCERT_ERR_NOT_FOUND);

    /* The store is still empty, so the next start bootstraps normally. */
    fctx.fail_at = 0;
    REQUIRE(wolfcert_server_start(&cfg, &srv) == WOLFCERT_OK);
    wolfcert_server_free(srv);
    REQUIRE(mem->read(mem->ctx, "ca.cert.der", &left) == WOLFCERT_OK);

    wolfcert_buffer_free(&left);
    wolfcert_store_memory_close(mem);
    return 0;
}

/* A rollback the store cannot perform must not be reported as a plain write
 * failure: the certificate stays behind and poisons every later start, so the
 * diagnostic has to say so. */
static int rollback_unavailable(int have_remove)
{
    WolfCertStoreOps* mem = wolfcert_store_memory_open(NULL);
    FlakyCtx fctx;
    WolfCertStoreOps store;
    WolfCertServerCfgSrv cfg;
    WolfCertServer* srv = NULL;
    WolfCertBuffer left = { 0 };

    REQUIRE(mem != NULL);

    memset(&fctx, 0, sizeof(fctx));
    fctx.inner   = mem;
    fctx.fail_at = 2;

    memset(&store, 0, sizeof(store));
    store.read   = flaky_read;
    store.write  = flaky_write;
    store.remove = have_remove ? failing_remove : NULL;
    store.ctx    = &fctx;

    ca_store_cfg(&cfg, &store);
    REQUIRE(wolfcert_server_start(&cfg, &srv) == WOLFCERT_ERR_IO);
    REQUIRE(srv == NULL);
    REQUIRE(strstr(wolfcert_last_error_message(), "rolled back") != NULL);

    /* The certificate really is still there, and the next start refuses it. */
    REQUIRE(mem->read(mem->ctx, "ca.cert.der", &left) == WOLFCERT_OK);
    wolfcert_buffer_free(&left);

    fctx.fail_at = 0;
    REQUIRE(wolfcert_server_start(&cfg, &srv) == WOLFCERT_ERR_PARSE);
    REQUIRE(srv == NULL);

    wolfcert_store_memory_close(mem);
    return 0;
}

static int test_rollback_unavailable(void)
{
    if (rollback_unavailable(0))
        return 1;

    return rollback_unavailable(1);
}

/* A store holding one half of the pair is damaged, not empty: starting
 * against it must fail rather than mint a CA over the surviving half. */
static int partial_store_rejected(const char* present)
{
    WolfCertStoreOps* store = wolfcert_store_memory_open(NULL);
    const uint8_t stored[] = { 0x30, 0x03, 0x02, 0x01, 0x01 };
    WolfCertBuffer left = { 0 };
    WolfCertServerCfgSrv cfg;
    WolfCertServer* srv = NULL;

    REQUIRE(store != NULL);
    REQUIRE(store->write(store->ctx, present, stored, sizeof(stored), 0)
            == WOLFCERT_OK);

    ca_store_cfg(&cfg, store);
    REQUIRE(wolfcert_server_start(&cfg, &srv) == WOLFCERT_ERR_PARSE);
    REQUIRE(srv == NULL);

    /* The survivor is still exactly what was stored. */
    REQUIRE(store->read(store->ctx, present, &left) == WOLFCERT_OK);
    REQUIRE(left.len == sizeof(stored));
    REQUIRE(memcmp(left.data, stored, left.len) == 0);

    wolfcert_buffer_free(&left);
    wolfcert_store_memory_close(store);
    return 0;
}

static int test_partial_store_rejected(void)
{
    if (partial_store_rejected("ca.cert.der"))
        return 1;

    return partial_store_rejected("ca.key.der");
}

static int test_ca_persists_across_starts(void)
{
    WolfCertStoreOps* store = wolfcert_store_memory_open(NULL);
    REQUIRE(store != NULL);

    WolfCertServerCfgSrv cfg;
    WolfCertServer* srv = NULL;
    WolfCertBuffer first = { 0 };
    WolfCertBuffer second = { 0 };

    ca_store_cfg(&cfg, store);
    REQUIRE(wolfcert_server_start(&cfg, &srv) == WOLFCERT_OK);
    wolfcert_server_free(srv);
    srv = NULL;
    REQUIRE(store->read(store->ctx, "ca.cert.der", &first) == WOLFCERT_OK);

    REQUIRE(wolfcert_server_start(&cfg, &srv) == WOLFCERT_OK);
    wolfcert_server_free(srv);
    REQUIRE(store->read(store->ctx, "ca.cert.der", &second) == WOLFCERT_OK);

    REQUIRE(first.len == second.len);
    REQUIRE(memcmp(first.data, second.data, first.len) == 0);

    wolfcert_buffer_free(&first);
    wolfcert_buffer_free(&second);
    wolfcert_store_memory_close(store);
    return 0;
}

/* Fill `store` with a freshly generated CA of `type` by letting a server start
 * against it, then hand back copies of the stored pair. */
/* Every compiled key type, so each algorithm's certificate-to-key check is
 * exercised on both a legitimate reload and a mismatched pair. */
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

static int ca_key_param(WolfCertKeyType t)
{
    if (t == WOLFCERT_KEY_RSA)
        return 2048;
    if (t == WOLFCERT_KEY_ECC)
        return 256;
    return 0;
}

/* Reload the stored CA and have it issue one certificate, then verify that
 * certificate against the CA. A pub_check that leaves the key's public half
 * unset passes the pair check and still signs garbage, so asserting the
 * reload alone would miss it. */
static int reloaded_ca_signs(WolfCertStoreOps* store, WolfCertKeyType ca_type)
{
    /* Any compiled algorithm serves as the leaf; the first entry always is. */
    WolfCertKeyCfg kcfg = { .type = CA_KEY_TYPES[0],
                            .param = ca_key_param(CA_KEY_TYPES[0]),
                            .dev_id = WOLFCERT_DEVID_SOFTWARE };
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

    REQUIRE(wolfcert_ca_load(&ca, store, NULL) == WOLFCERT_OK);
    rc = wolfcert_ca_issue(&ca, csr.data, csr.len, &issued, &issued_len);
    wolfcert_buffer_free(&csr);
    REQUIRE(rc == WOLFCERT_OK);

    (void)ca_type;
#ifdef WOLFSSL_NO_MALLOC
    /* A WOLFSSL_NO_MALLOC wolfSSL never copies an RSA public key onto the CA
     * Signer, so its chain verify fails BAD_FUNC_ARG. Assert the issue half
     * only, until that lands upstream and the declared wolfSSL floor clears
     * it. */
    if (ca_type == WOLFCERT_KEY_RSA) {
        WOLFCERT_XFREE(issued, ca.heap);
        wolfcert_ca_free(&ca);
        return 0;
    }
#endif

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

static int test_every_alg_reloads(void)
{
    size_t i;

    for (i = 0; i < sizeof(CA_KEY_TYPES) / sizeof(CA_KEY_TYPES[0]); ++i) {
        WolfCertStoreOps* store = wolfcert_store_memory_open(NULL);
        WolfCertServerCfgSrv cfg;
        WolfCertServer* srv = NULL;

        REQUIRE(store != NULL);
        ca_store_cfg(&cfg, store);
        cfg.ca_key_type  = CA_KEY_TYPES[i];
        cfg.ca_key_param = ca_key_param(CA_KEY_TYPES[i]);
        REQUIRE(wolfcert_server_start(&cfg, &srv) == WOLFCERT_OK);
        wolfcert_server_free(srv);
        srv = NULL;

        /* Second start reloads the saved pair through the pair check. */
        REQUIRE(wolfcert_server_start(&cfg, &srv) == WOLFCERT_OK);
        wolfcert_server_free(srv);

        if (reloaded_ca_signs(store, CA_KEY_TYPES[i]))
            return 1;

        wolfcert_store_memory_close(store);
    }
    return 0;
}

static int generate_ca_into(WolfCertStoreOps* store, WolfCertKeyType type,
                            WolfCertBuffer* cert, WolfCertBuffer* key)
{
    WolfCertServerCfgSrv cfg;
    WolfCertServer* srv = NULL;

    ca_store_cfg(&cfg, store);
    cfg.ca_key_type  = type;
    cfg.ca_key_param = ca_key_param(type);
    REQUIRE(wolfcert_server_start(&cfg, &srv) == WOLFCERT_OK);
    wolfcert_server_free(srv);

    REQUIRE(store->read(store->ctx, "ca.cert.der", cert) == WOLFCERT_OK);
    REQUIRE(store->read(store->ctx, "ca.key.der", key) == WOLFCERT_OK);
    return 0;
}

static int mismatched_ca_rejected(WolfCertKeyType type)
{
    WolfCertStoreOps* src_a = wolfcert_store_memory_open(NULL);
    WolfCertStoreOps* src_b = wolfcert_store_memory_open(NULL);
    WolfCertStoreOps* mixed = wolfcert_store_memory_open(NULL);
    WolfCertBuffer cert_a = { 0 };
    WolfCertBuffer key_a  = { 0 };
    WolfCertBuffer cert_b = { 0 };
    WolfCertBuffer key_b  = { 0 };
    WolfCertServerCfgSrv cfg;
    WolfCertServer* srv = NULL;

    REQUIRE(src_a != NULL);
    REQUIRE(src_b != NULL);
    REQUIRE(mixed != NULL);

    if (generate_ca_into(src_a, type, &cert_a, &key_a))
        return 1;
    if (generate_ca_into(src_b, type, &cert_b, &key_b))
        return 1;
    REQUIRE(key_a.len != key_b.len || memcmp(key_a.data, key_b.data, key_a.len) != 0);

    REQUIRE(mixed->write(mixed->ctx, "ca.cert.der", cert_a.data, cert_a.len, 0)
            == WOLFCERT_OK);
    REQUIRE(mixed->write(mixed->ctx, "ca.key.der", key_b.data, key_b.len, 1)
            == WOLFCERT_OK);

    ca_store_cfg(&cfg, mixed);
    cfg.ca_key_type  = type;
    cfg.ca_key_param = ca_key_param(type);
    REQUIRE(wolfcert_server_start(&cfg, &srv) == WOLFCERT_ERR_PARSE);
    REQUIRE(srv == NULL);

    wolfcert_buffer_free(&cert_a);
    wolfcert_buffer_free(&key_a);
    wolfcert_buffer_free(&cert_b);
    wolfcert_buffer_free(&key_b);
    wolfcert_store_memory_close(src_a);
    wolfcert_store_memory_close(src_b);
    wolfcert_store_memory_close(mixed);
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

/* RFC 8894 section 2.1.2 MUST: the CA signs certificates and, for SCEP, both
 * signs CertReps and decrypts the pkcsPKIEnvelope, so its certificate must
 * assert those usages rather than omitting the extension. RFC 5280 section
 * 4.2.1.9 MUST: basicConstraints is present and critical on such a CA. */
static int ca_key_usage_set(WolfCertKeyType type)
{
    WolfCertStoreOps* store = wolfcert_store_memory_open(NULL);
    WolfCertBuffer cert = { 0 };
    WolfCertBuffer key  = { 0 };
    DecodedCert dc;
    int rc = 0;

    REQUIRE(store != NULL);

    if (generate_ca_into(store, type, &cert, &key))
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
    /* keyEncipherment belongs to the RSA CA alone: it decrypts the SCEP
     * pkcsPKIEnvelope, which no other key type is used for. */
    else if (((dc.extKeyUsage & KEYUSE_KEY_ENCIPHER) != 0) !=
            (type == WOLFCERT_KEY_RSA)) {
        rc = 1;
    }

    wc_FreeDecodedCert(&dc);
    wolfcert_buffer_free(&cert);
    wolfcert_buffer_free(&key);
    wolfcert_store_memory_close(store);

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
    WolfCertStoreOps* src   = wolfcert_store_memory_open(NULL);
    WolfCertStoreOps* mixed = wolfcert_store_memory_open(NULL);
    WolfCertBuffer cert = { 0 };
    WolfCertBuffer key  = { 0 };
    const uint8_t junk[] = { 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA };
    WolfCertServerCfgSrv cfg;
    WolfCertServer* srv = NULL;

    REQUIRE(src != NULL);
    REQUIRE(mixed != NULL);

    if (generate_ca_into(src, CA_KEY_TYPE, &cert, &key))
        return 1;

    REQUIRE(mixed->write(mixed->ctx, "ca.cert.der", junk, sizeof(junk), 0)
            == WOLFCERT_OK);
    REQUIRE(mixed->write(mixed->ctx, "ca.key.der", key.data, key.len, 1)
            == WOLFCERT_OK);

    ca_store_cfg(&cfg, mixed);
    REQUIRE(wolfcert_server_start(&cfg, &srv) == WOLFCERT_ERR_PARSE);
    REQUIRE(srv == NULL);

    wolfcert_buffer_free(&cert);
    wolfcert_buffer_free(&key);
    wolfcert_store_memory_close(src);
    wolfcert_store_memory_close(mixed);
    return 0;
}

#ifdef WOLFCERT_HAVE_ECC
/* A self-signed certificate with no CA:TRUE, plus the key that signed it: a
 * self-consistent pair that is still unusable as a CA. */
static int make_leaf_pair(WolfCertBuffer* cert_out, WolfCertBuffer* key_out)
{
    WolfCertKeyCfg kcfg = { .type = WOLFCERT_KEY_ECC, .param = 256,
                            .dev_id = WOLFCERT_DEVID_SOFTWARE };
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
    cert.isCA       = 0;
    cert.selfSigned = 1;
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
    WolfCertStoreOps* store = wolfcert_store_memory_open(NULL);
    WolfCertBuffer cert = { 0 };
    WolfCertBuffer key  = { 0 };
    WolfCertServerCfgSrv cfg;
    WolfCertServer* srv = NULL;

    REQUIRE(store != NULL);
    if (make_leaf_pair(&cert, &key))
        return 1;

    REQUIRE(store->write(store->ctx, "ca.cert.der", cert.data, cert.len, 0)
            == WOLFCERT_OK);
    REQUIRE(store->write(store->ctx, "ca.key.der", key.data, key.len, 1)
            == WOLFCERT_OK);

    ca_store_cfg(&cfg, store);
    REQUIRE(wolfcert_server_start(&cfg, &srv) == WOLFCERT_ERR_PARSE);
    REQUIRE(srv == NULL);

    wolfcert_buffer_free(&cert);
    wolfcert_buffer_free(&key);
    wolfcert_store_memory_close(store);
    return 0;
}
#endif /* WOLFCERT_HAVE_ECC */

int main(void)
{
    REQUIRE(test_static_mem_init() == 0);
    REQUIRE(wolfcert_init(NULL) == WOLFCERT_OK);

#if CA_STORE_NEEDS_TLS
    REQUIRE(gen_server_identity(&srv_cert_pem, &srv_cert_pem_len,
                                &srv_key_pem, &srv_key_pem_len) == 0);
#endif

    if (test_corrupt_ca_rejected())
        return 1;
    if (test_load_io_error_rejected())
        return 1;
    if (test_save_failure_rejected())
        return 1;
    if (test_save_rollback())
        return 1;
    if (test_rollback_unavailable())
        return 1;
    if (test_mixed_read_failure())
        return 1;
    if (test_partial_store_rejected())
        return 1;
    if (test_ca_persists_across_starts())
        return 1;
    if (test_every_alg_reloads())
        return 1;
    if (test_mismatched_ca_rejected())
        return 1;
    if (test_corrupt_ca_cert_rejected())
        return 1;
#ifdef WOLFCERT_HAVE_ECC
    if (test_leaf_ca_rejected())
        return 1;
#endif
    if (test_ca_key_usage())
        return 1;

#if CA_STORE_NEEDS_TLS
    free(srv_cert_pem);
    free(srv_key_pem);
#endif
    wolfcert_cleanup();
    printf("OK\n");
    return 0;
}
