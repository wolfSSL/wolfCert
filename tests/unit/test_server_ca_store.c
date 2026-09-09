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

#ifdef WOLFCERT_HAVE_ECC
    #define CA_KEY_TYPE   WOLFCERT_KEY_ECC
    #define CA_KEY_PARAM  256
#else
    #define CA_KEY_TYPE   0
    #define CA_KEY_PARAM  0
#endif

static void ca_store_cfg(WolfCertServerCfgSrv* cfg, WolfCertStoreOps* store)
{
    memset(cfg, 0, sizeof(*cfg));
    cfg->protocol     = WOLFCERT_PROTO_SCEP;
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

int main(void)
{
    REQUIRE(test_static_mem_init() == 0);
    REQUIRE(wolfcert_init(NULL) == WOLFCERT_OK);

    if (test_corrupt_ca_rejected())
        return 1;
    if (test_load_io_error_rejected())
        return 1;
    if (test_save_failure_rejected())
        return 1;
    if (test_save_rollback())
        return 1;
    if (test_partial_store_rejected())
        return 1;
    if (test_ca_persists_across_starts())
        return 1;

    wolfcert_cleanup();
    printf("OK\n");
    return 0;
}
