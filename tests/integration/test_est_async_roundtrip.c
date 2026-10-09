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

/* Non-blocking EST session driven through a poll(2) loop: /cacerts and
 * /simpleenroll under TLS 1.3 PHA, then against a Basic-only server. */

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


static void* server_thread(void* arg)
{
    wolfcert_server_run((WolfCertServer*)arg);
    return NULL;
}

/* Wait on the session fd in the direction a WANT_* return asked for. */
static int wait_io(WolfCertEstSession* s, int rc)
{
    struct pollfd p = { .fd = wolfcert_est_session_fd(s),
        .events = (rc == WOLFCERT_ERR_WANT_WRITE) ? POLLOUT : POLLIN };
    return poll(&p, 1, 5000) > 0 ? 0 : -1;
}

static int pump_get_cacerts(WolfCertEstSession* s, WolfCertBuffer* out)
{
    for (;;) {
        int rc = wolfcert_est_session_get_cacerts_nb(s, out);
        if (rc == WOLFCERT_OK)
            return 0;
        if (rc == WOLFCERT_ERR_WANT_READ || rc == WOLFCERT_ERR_WANT_WRITE) {
            if (wait_io(s, rc) != 0)
                return -1;
            continue;
        }
        fprintf(stderr, "cacerts rc=%d (%s)\n", rc, wolfcert_strerror(rc));
        return -1;
    }
}

/* Returns the terminal rc. */
static int pump_simple_enroll(WolfCertEstSession* s,
                              const uint8_t* csr, size_t csr_len,
                              WolfCertBuffer* out)
{
    for (;;) {
        int rc = wolfcert_est_session_simple_enroll_nb(s, csr, csr_len, out);
        if (rc == WOLFCERT_ERR_WANT_READ || rc == WOLFCERT_ERR_WANT_WRITE) {
            if (wait_io(s, rc) != 0)
                return WOLFCERT_ERR_IO;
            continue;
        }
        if (rc != WOLFCERT_OK)
            fprintf(stderr, "enroll rc=%d (%s) last=%s\n",
                    rc, wolfcert_strerror(rc), wolfcert_last_error_message());
        return rc;
    }
}

static int pump_simple_enroll_ex(WolfCertEstSession* s,
                                 const uint8_t* csr, size_t csr_len,
                                 WolfCertEstResult* out)
{
    for (;;) {
        int rc = wolfcert_est_session_simple_enroll_nb_ex(s, csr, csr_len, out);
        if (rc != WOLFCERT_ERR_WANT_READ && rc != WOLFCERT_ERR_WANT_WRITE)
            return rc;
        if (wait_io(s, rc) != 0)
            return WOLFCERT_ERR_IO;
    }
}

int main(void)
{
    REQUIRE(wolfcert_init(NULL) == WOLFCERT_OK);

    uint8_t* tls_cert = NULL;
    size_t tls_cert_len = 0;
    uint8_t* tls_key  = NULL;
    size_t tls_key_len  = 0;
    REQUIRE(mint_self_id("127.0.0.1", 0,
                        &tls_cert, &tls_cert_len, &tls_key, &tls_key_len) == 0);
    uint8_t* cli_cert = NULL;
    size_t cli_cert_len = 0;
    uint8_t* cli_key  = NULL;
    size_t cli_key_len  = 0;
    REQUIRE(mint_self_id("async-bootstrap", 1,
                        &cli_cert, &cli_cert_len, &cli_key, &cli_key_len) == 0);

    WolfCertKeyCfg kcfg = { .type = TEST_ENROLL_KEY_TYPE, .param = TEST_ENROLL_KEY_PARAM,
                            .dev_id = WOLFCERT_DEVID_SOFTWARE };
    WolfCertKey* dk = NULL;
    REQUIRE(wolfcert_key_generate(&kcfg, &dk) == WOLFCERT_OK);
    WolfCertCertMeta meta = { .subject_dn = "CN=async-enrollee" };
    WolfCertBuffer csr = { 0 };
    REQUIRE(wolfcert_csr_build(dk, &meta, &csr) == WOLFCERT_OK);

    WolfCertServerCfgSrv cfg = {
        .protocol                = WOLFCERT_PROTO_EST,
        .bind_host               = "127.0.0.1",
        .bind_port               = 0,
        .ca_store                = test_ca_store(),
        .tls_cert_pem            = tls_cert, .tls_cert_pem_len       = tls_cert_len,
        .tls_key_pem             = tls_key,  .tls_key_pem_len        = tls_key_len,
        .tls_client_ca_pem       = cli_cert, .tls_client_ca_pem_len  = cli_cert_len,
        .tls_post_handshake_auth = 1,
    };
    WolfCertServer* srv = NULL;
    int start_rc = wolfcert_server_start(&cfg, &srv);
    int pha_skipped = (start_rc == WOLFCERT_ERR_UNSUPPORTED);
    if (pha_skipped) {
        printf("SKIP PHA: %s\n", wolfcert_last_error_message());
    }
    else {
        REQUIRE(start_rc == WOLFCERT_OK);
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
            .client_cert       = cli_cert,
            .client_cert_len   = cli_cert_len,
            .client_key        = cli_key,
            .client_key_len    = cli_key_len,
            .proto_opts.est    = { .allow_post_handshake_auth = 1 },
        };
        WolfCertEstSession* es = NULL;
        REQUIRE(wolfcert_est_session_open_async(&cli, &es) == WOLFCERT_OK);
        REQUIRE(wolfcert_est_session_fd(es) >= 0);

        WolfCertBuffer ca_pem = { 0 };
        REQUIRE(pump_get_cacerts(es, &ca_pem) == 0);
        REQUIRE(ca_pem.len > 0);

        /* The server sends a PHA CertificateRequest mid-call. */
        WolfCertBuffer issued = { 0 };
        REQUIRE(pump_simple_enroll(es, csr.data, csr.len, &issued) == 0);
        REQUIRE(memmem(issued.data, issued.len, "BEGIN CERTIFICATE", 17) != NULL);

        wolfcert_buffer_free(&ca_pem);
        wolfcert_buffer_free(&issued);
        wolfcert_est_session_close(es);

        wolfcert_server_stop(srv);
        pthread_join(tid, NULL);
        wolfcert_server_free(srv);
    }

    /* Basic-only server: cacerts and enroll on one async session as alice. */
    WolfCertServerCfgSrv bcfg = {
        .protocol        = WOLFCERT_PROTO_EST,
        .bind_host       = "127.0.0.1",
        .bind_port       = 0,
        .ca_store        = test_ca_store(),
        .http_basic_user = "alice",
        .http_basic_pass = "hunter2",
        .tls_cert_pem    = tls_cert, .tls_cert_pem_len = tls_cert_len,
        .tls_key_pem     = tls_key,  .tls_key_pem_len  = tls_key_len,
    };
    WolfCertServer* bsrv = NULL;
    REQUIRE(wolfcert_server_start(&bcfg, &bsrv) == WOLFCERT_OK);
    pthread_t btid;
    REQUIRE(pthread_create(&btid, NULL, server_thread, bsrv) == 0);

    char burl[128];
    snprintf(burl, sizeof(burl), "https://127.0.0.1:%u/.well-known/est",
             wolfcert_server_port(bsrv));

    WolfCertServerCfg bcli = {
        .protocol          = WOLFCERT_PROTO_EST,
        .server_url        = burl,
        .proto_opts.est    = { .username = "alice", .password = "hunter2" },
        .trust_anchors     = tls_cert,
        .trust_anchors_len = tls_cert_len,
        .verify_server     = 1,
    };
    WolfCertEstSession* bes = NULL;
    REQUIRE(wolfcert_est_session_open_async(&bcli, &bes) == WOLFCERT_OK);

    WolfCertBuffer bca = { 0 }, bissued = { 0 };
    REQUIRE(pump_get_cacerts(bes, &bca) == 0);
    REQUIRE(bca.len > 0);
    REQUIRE(pump_simple_enroll(bes, csr.data, csr.len, &bissued) == 0);
    REQUIRE(memmem(bissued.data, bissued.len, "BEGIN CERTIFICATE", 17) != NULL);

    wolfcert_buffer_free(&bca);
    wolfcert_buffer_free(&bissued);
    wolfcert_est_session_close(bes);

    /* A wrong password fails both enroll forms, one session each. */
    WolfCertServerCfg wcli = bcli;
    wcli.proto_opts.est.password = "wrong";
    bes = NULL;
    REQUIRE(wolfcert_est_session_open_async(&wcli, &bes) == WOLFCERT_OK);

    WolfCertEstResult wr = { 0 };
    REQUIRE(pump_simple_enroll_ex(bes, csr.data, csr.len, &wr)
            == WOLFCERT_ERR_AUTH);
    REQUIRE(wr.status == WOLFCERT_EST_STATUS_FAILURE);
    REQUIRE(wr.cert_pem.data == NULL);
    wolfcert_est_result_free(&wr);

    /* The failed enroll no longer counts as in flight. */
    REQUIRE(wolfcert_est_session_get_cacerts_nb(bes, &bca)
            != WOLFCERT_ERR_BAD_ARG);
    wolfcert_buffer_free(&bca);
    wolfcert_est_session_close(bes);

    bes = NULL;
    REQUIRE(wolfcert_est_session_open_async(&wcli, &bes) == WOLFCERT_OK);
    REQUIRE(pump_simple_enroll(bes, csr.data, csr.len, &bissued)
            == WOLFCERT_ERR_AUTH);
    REQUIRE(bissued.data == NULL);
    wolfcert_est_session_close(bes);

    wolfcert_server_stop(bsrv);
    pthread_join(btid, NULL);
    wolfcert_server_free(bsrv);

    wolfcert_buffer_free(&csr);
    wolfcert_key_free(dk);

    free(tls_cert);
    free(tls_key);
    free(cli_cert);
    free(cli_key);
    test_ca_store_close();
    wolfcert_cleanup();
    if (pha_skipped)
        return 77;
    printf("OK\n");
    return 0;
}
