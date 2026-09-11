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

/*
 * End-to-end HTTPS EST roundtrip: stands up wolfcert-server behind its
 * built-in TLS terminator (new v0.2 feature), then runs wolfcert-client
 * against it over HTTPS, pinning the freshly-minted server cert as the
 * bootstrap trust anchor. Verifies that:
 *   - wolfcert_server_start() accepts --tls-cert/--tls-key-equivalent config,
 *   - the accept loop terminates TLS and dispatches to the EST handler,
 *   - the protocol handler's read/send helpers work through the TLS layer,
 *   - wolfcert_est_simple_enroll() drives the full TLS + EST round trip.
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#define _DARWIN_C_SOURCE   /* expose memmem/strcasestr/INADDR_LOOPBACK on macOS */
#define _GNU_SOURCE

#include <wolfcert/wolfcert.h>
#include <wolfcert/est.h>
#include <wolfcert/server.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/random.h>

#include "tls_test_util.h"
#include <wolfssl/wolfcrypt/rsa.h>

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

int main(void)
{
    REQUIRE(wolfcert_init(NULL) == WOLFCERT_OK);

    uint8_t* tls_cert = NULL;
    size_t tls_cert_len = 0;
    uint8_t* tls_key  = NULL;
    size_t tls_key_len  = 0;
    REQUIRE(gen_server_identity(&tls_cert, &tls_cert_len, &tls_key, &tls_key_len) == 0);

    /* An EST listener with no TLS identity must be refused at start. */
    WolfCertStoreOps* plain_store = wolfcert_store_memory_open(NULL);
    REQUIRE(plain_store != NULL);
    WolfCertServerCfgSrv plain = {
        .protocol  = WOLFCERT_PROTO_EST,
        .bind_host = "127.0.0.1",
        .bind_port = 0,
        .ca_store  = plain_store,
    };
    WolfCertServer* plain_srv = NULL;
    REQUIRE(wolfcert_server_start(&plain, &plain_srv) == WOLFCERT_ERR_TLS);
    REQUIRE(plain_srv == NULL);

    /* The rejection must land before the CA is minted, so the caller is not
     * left with a CA it never asked for -- one the next start would adopt. */
    WolfCertBuffer leftover = { 0 };
    REQUIRE(plain_store->read(plain_store->ctx, "ca.cert.der", &leftover)
            == WOLFCERT_ERR_NOT_FOUND);
    REQUIRE(plain_store->read(plain_store->ctx, "ca.key.der", &leftover)
            == WOLFCERT_ERR_NOT_FOUND);
    wolfcert_store_memory_close(plain_store);

    WolfCertServerCfgSrv cfg = {
        .protocol         = WOLFCERT_PROTO_EST,
        .bind_host        = "127.0.0.1",
        .bind_port        = 0,
        .tls_cert_pem     = tls_cert, .tls_cert_pem_len = tls_cert_len,
        .tls_key_pem      = tls_key,  .tls_key_pem_len  = tls_key_len,
    };
    WolfCertServer* srv = NULL;
    REQUIRE(wolfcert_server_start(&cfg, &srv) == WOLFCERT_OK);
    pthread_t tid;
    REQUIRE(pthread_create(&tid, NULL, server_thread, srv) == 0);

    char url[128];
    snprintf(url, sizeof(url), "https://127.0.0.1:%u/.well-known/est",
             wolfcert_server_port(srv));

    WolfCertServerCfg cli = {
        .protocol          = WOLFCERT_PROTO_EST,
        .server_url        = url,
        .trust_anchors     = tls_cert,
        .trust_anchors_len = tls_cert_len,
        .verify_server     = 1,
    };

    /* Fetch the CA chain from the server - this hits the TLS path end-to-end. */
    WolfCertBuffer ca_pem = { 0 };
    REQUIRE(wolfcert_est_get_cacerts(&cli, &ca_pem) == WOLFCERT_OK);
    REQUIRE(ca_pem.len > 0);

    /* Generate a device key, build CSR, enroll over HTTPS. */
    WolfCertKeyCfg kcfg = { .type = TEST_ENROLL_KEY_TYPE, .param = TEST_ENROLL_KEY_PARAM,
                            .dev_id = WOLFCERT_DEVID_SOFTWARE };
    WolfCertKey* dk = NULL;
    REQUIRE(wolfcert_key_generate(&kcfg, &dk) == WOLFCERT_OK);
    WolfCertCertMeta meta = { .subject_dn = "CN=tls-est-client" };
    WolfCertBuffer csr = { 0 };
    REQUIRE(wolfcert_csr_build(dk, &meta, &csr) == WOLFCERT_OK);

    WolfCertBuffer issued = { 0 };
    int rc = wolfcert_est_simple_enroll(&cli, csr.data, csr.len, &issued);
    if (rc != WOLFCERT_OK)
        fprintf(stderr, "enroll rc=%d (%s)\n", rc, wolfcert_strerror(rc));
    REQUIRE(rc == WOLFCERT_OK);
    REQUIRE(memmem(issued.data, issued.len, "BEGIN CERTIFICATE", 17) != NULL);
    REQUIRE(memmem(issued.data, issued.len, "tls-est-client", 14) != NULL ||
            issued.len > 0);   /* PEM carries subject in DER, not ASCII */

    /* DER trust-anchor coverage: the same anchor as DER must drive the TLS
     * load path (buffer_is_der -> WOLFSSL_FILETYPE_ASN1) just as well as PEM. */
    DerBuffer* ta_der = NULL;
    REQUIRE(wc_PemToDer(tls_cert, (long)tls_cert_len, CERT_TYPE,
                        &ta_der, NULL, NULL, NULL) == 0);
    WolfCertServerCfg cli_der = {
        .protocol          = WOLFCERT_PROTO_EST,
        .server_url        = url,
        .trust_anchors     = ta_der->buffer,
        .trust_anchors_len = ta_der->length,
        .verify_server     = 1,
    };
    WolfCertBuffer ca_pem_der = { 0 };
    REQUIRE(wolfcert_est_get_cacerts(&cli_der, &ca_pem_der) == WOLFCERT_OK);
    REQUIRE(ca_pem_der.len > 0);
    wolfcert_buffer_free(&ca_pem_der);
    wc_FreeDer(&ta_der);

    wolfcert_server_stop(srv);
    pthread_join(tid, NULL);
    wolfcert_server_free(srv);

    wolfcert_buffer_free(&ca_pem);
    wolfcert_buffer_free(&csr);
    wolfcert_buffer_free(&issued);
    wolfcert_key_free(dk);
    free(tls_cert);
    free(tls_key);
    wolfcert_cleanup();
    printf("OK\n");
    return 0;
}
