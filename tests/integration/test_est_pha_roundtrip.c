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

/* TLS 1.3 post-handshake auth over the keep-alive EST session. Reenroll over
 * PHA uses a raw TLS client, since sessions have no reenroll call. */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#define _DARWIN_C_SOURCE   /* expose memmem/strcasestr/INADDR_LOOPBACK on macOS */
#define _GNU_SOURCE

#include <wolfcert/wolfcert.h>
#include <wolfcert/est.h>
#include <wolfcert/server.h>

#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/coding.h>
#include <wolfssl/wolfcrypt/random.h>

#include "tls_test_util.h"
#include <wolfssl/wolfcrypt/rsa.h>

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#define REQUIRE(cond) \
    do {                                                                    \
        if (!(cond)) {                                                      \
            fprintf(stderr, "FAIL %s:%d %s\n", __FILE__, __LINE__, #cond);  \
            return 1;                                                       \
        }                                                                   \
    } while (0)


static void* server_thread(void* arg) { wolfcert_server_run((WolfCertServer*)arg); return NULL; }

#ifdef WOLFSSL_POST_HANDSHAKE_AUTH
/* POST a renewal CSR for cli_cert over a PHA connection and expect a 200. */
static int pha_reenroll(uint16_t port, const uint8_t* tls_cert, size_t tls_cert_len,
                        const uint8_t* cli_cert, size_t cli_cert_len,
                        const uint8_t* cli_key, size_t cli_key_len)
{
    WolfCertKeyCfg kcfg = { .type = TEST_ENROLL_KEY_TYPE, .param = TEST_ENROLL_KEY_PARAM,
                            .dev_id = WOLFCERT_DEVID_SOFTWARE };
    WolfCertCertMeta meta = { .subject_dn = "CN=factory-bootstrap" };
    WolfCertKey* dk = NULL;
    WolfCertBuffer csr = { 0 };
    TestTlsConn c;
    char req[4096];
    byte b64[3072];
    word32 b64_len = sizeof(b64);
    char resp[64] = { 0 };
    int n;

    REQUIRE(wolfcert_key_generate(&kcfg, &dk) == WOLFCERT_OK);
    REQUIRE(wolfcert_csr_build(dk, &meta, &csr) == WOLFCERT_OK);
    wolfcert_key_free(dk);
    REQUIRE(Base64_Encode_NoNl(csr.data, (word32)csr.len, b64, &b64_len) == 0);
    wolfcert_buffer_free(&csr);
    n = snprintf(req, sizeof(req),
                 "POST /.well-known/est/simplereenroll HTTP/1.1\r\n"
                 "Host: 127.0.0.1\r\nContent-Type: application/pkcs10\r\n"
                 "Content-Length: %u\r\nConnection: close\r\n\r\n%.*s",
                 (unsigned)b64_len, (int)b64_len, (const char*)b64);
    REQUIRE(n > 0 && (size_t)n < sizeof(req));

    /* wolfSSL unloads an SSL-level identity after the handshake, so it goes
     * on the CTX. */
    REQUIRE(test_tls_setup(&c, port, tls_cert, tls_cert_len) == 0);
    REQUIRE(wolfSSL_CTX_use_certificate_buffer(c.ctx, cli_cert, (long)cli_cert_len,
                                               WOLFSSL_FILETYPE_PEM) == WOLFSSL_SUCCESS);
    REQUIRE(wolfSSL_CTX_use_PrivateKey_buffer(c.ctx, cli_key, (long)cli_key_len,
                                              WOLFSSL_FILETYPE_PEM) == WOLFSSL_SUCCESS);
    wolfSSL_free(c.ssl);
    c.ssl = wolfSSL_new(c.ctx);
    REQUIRE(c.ssl != NULL && wolfSSL_set_fd(c.ssl, c.fd) == WOLFSSL_SUCCESS);
    REQUIRE(wolfSSL_allow_post_handshake_auth(c.ssl) == 0);
    REQUIRE(wolfSSL_connect(c.ssl) == WOLFSSL_SUCCESS);
    REQUIRE(test_tls_write(&c, req, (size_t)n) == 0);
    REQUIRE(test_tls_read(&c, resp, sizeof(resp) - 1) > 0);
    test_tls_close(&c);
    if (strncmp(resp, "HTTP/1.1 200", 12) != 0)
        fprintf(stderr, "pha reenroll: %s\n", resp);
    REQUIRE(strncmp(resp, "HTTP/1.1 200", 12) == 0);
    return 0;
}
#endif

#ifdef WOLFSSL_POST_HANDSHAKE_AUTH
static int discard_send(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
    (void)ssl;
    (void)buf;
    (void)ctx;
    return sz;
}
#endif

/* /cacerts must succeed and /simpleenroll must be refused. */
static int expect_enroll_refused(const WolfCertServerCfg* cli, const char* cn)
{
    WolfCertEstSession* s = NULL;
    REQUIRE(wolfcert_est_session_open(cli, &s) == WOLFCERT_OK);

    WolfCertBuffer ca_pem = { 0 };
    REQUIRE(wolfcert_est_session_get_cacerts(s, &ca_pem) == WOLFCERT_OK);
    REQUIRE(ca_pem.len > 0);
    wolfcert_buffer_free(&ca_pem);

    WolfCertKeyCfg kcfg = { .type = TEST_ENROLL_KEY_TYPE, .param = TEST_ENROLL_KEY_PARAM,
                            .dev_id = WOLFCERT_DEVID_SOFTWARE };
    WolfCertKey* dk = NULL;
    REQUIRE(wolfcert_key_generate(&kcfg, &dk) == WOLFCERT_OK);
    WolfCertCertMeta meta = { .subject_dn = cn };
    WolfCertBuffer csr = { 0 };
    REQUIRE(wolfcert_csr_build(dk, &meta, &csr) == WOLFCERT_OK);

    WolfCertBuffer issued = { 0 };
    int rc = wolfcert_est_session_simple_enroll(s, csr.data, csr.len, &issued);
    REQUIRE(rc == WOLFCERT_ERR_AUTH);
    wolfcert_buffer_free(&csr);
    wolfcert_buffer_free(&issued);
    wolfcert_key_free(dk);
    wolfcert_est_session_close(s);
    return 0;
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

    /* Self-signed, so it is both the server's client CA and the client cert. */
    uint8_t* cli_cert = NULL;
    size_t cli_cert_len = 0;
    uint8_t* cli_key  = NULL;
    size_t cli_key_len  = 0;
    REQUIRE(mint_self_id("factory-bootstrap", 1,
                        &cli_cert, &cli_cert_len, &cli_key, &cli_key_len) == 0);

    WolfCertServerCfgSrv cfg = {
        .protocol                = WOLFCERT_PROTO_EST,
        .bind_host               = "127.0.0.1",
        .bind_port               = 0,
        .ca_store                = test_ca_store(),
        .tls_cert_pem            = tls_cert,
        .tls_cert_pem_len        = tls_cert_len,
        .tls_key_pem             = tls_key,
        .tls_key_pem_len         = tls_key_len,
        .tls_client_ca_pem       = cli_cert,
        .tls_client_ca_pem_len   = cli_cert_len,
        .tls_post_handshake_auth = 1,
    };
    WolfCertServer* srv = NULL;
    WolfCertServerCfgSrv bad = cfg;
    bad.tls_client_ca_pem = NULL;
    bad.tls_client_ca_pem_len = 0;
    bad.est_allow_anonymous_enroll = 1;
    REQUIRE(wolfcert_server_start(&bad, &srv) == WOLFCERT_ERR_BAD_ARG);
    REQUIRE(srv == NULL);
#ifdef WOLFCERT_HAVE_SCEP
    /* SCEP never requests the certificate, so PHA would drop mTLS there. */
    bad = cfg;
    bad.protocol = WOLFCERT_PROTO_SCEP;
    REQUIRE(wolfcert_server_start(&bad, &srv) == WOLFCERT_ERR_BAD_ARG);
    REQUIRE(srv == NULL);
#endif

    int start_rc = wolfcert_server_start(&cfg, &srv);
    if (start_rc == WOLFCERT_ERR_UNSUPPORTED) {
        printf("SKIP: %s\n", wolfcert_last_error_message());
        free(tls_cert);
        free(tls_key);
        free(cli_cert);
        free(cli_key);
        test_ca_store_close();
        wolfcert_cleanup();
        return 77;
    }
    REQUIRE(start_rc == WOLFCERT_OK);
    pthread_t tid;
    REQUIRE(pthread_create(&tid, NULL, server_thread, srv) == 0);

    char url[128];
    snprintf(url, sizeof(url), "https://127.0.0.1:%u/.well-known/est",
             wolfcert_server_port(srv));

    /* Client identity and PHA opt-in. */
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
            .proto_opts.est    = { .allow_post_handshake_auth = 1 },
        };
        WolfCertEstSession* s = NULL;
        REQUIRE(wolfcert_est_session_open(&cli, &s) == WOLFCERT_OK);

        /* /cacerts on the anonymous leg of the TLS connection. */
        WolfCertBuffer ca_pem = { 0 };
        REQUIRE(wolfcert_est_session_get_cacerts(s, &ca_pem) == WOLFCERT_OK);
        REQUIRE(ca_pem.len > 0);

        /* /simpleenroll triggers the server's CertificateRequest. */
        WolfCertKeyCfg kcfg = { .type = TEST_ENROLL_KEY_TYPE, .param = TEST_ENROLL_KEY_PARAM,
                                .dev_id = WOLFCERT_DEVID_SOFTWARE };
        WolfCertKey* dk = NULL;
        REQUIRE(wolfcert_key_generate(&kcfg, &dk) == WOLFCERT_OK);
        WolfCertCertMeta meta = { .subject_dn = "CN=pha-enrollee" };
        WolfCertBuffer csr = { 0 };
        REQUIRE(wolfcert_csr_build(dk, &meta, &csr) == WOLFCERT_OK);

        WolfCertBuffer issued = { 0 };
        int rc = wolfcert_est_session_simple_enroll(s, csr.data, csr.len, &issued);
        if (rc != WOLFCERT_OK)
            fprintf(stderr, "pha enroll rc=%d (%s) last=%s\n",
                    rc, wolfcert_strerror(rc), wolfcert_last_error_message());
        REQUIRE(rc == WOLFCERT_OK);
        REQUIRE(memmem(issued.data, issued.len, "BEGIN CERTIFICATE", 17) != NULL);
        wolfcert_buffer_free(&issued);

        /* A second enroll reuses the cert the connection already holds. */
        REQUIRE(wolfcert_est_session_simple_enroll(s, csr.data, csr.len,
                                                   &issued) == WOLFCERT_OK);
        REQUIRE(memmem(issued.data, issued.len, "BEGIN CERTIFICATE", 17) != NULL);

        wolfcert_buffer_free(&ca_pem);
        wolfcert_buffer_free(&csr);
        wolfcert_buffer_free(&issued);
        wolfcert_key_free(dk);
        wolfcert_est_session_close(s);
    }

    /* No client identity to answer the CertificateRequest. */
    {
        WolfCertServerCfg cli = {
            .protocol          = WOLFCERT_PROTO_EST,
            .server_url        = url,
            .trust_anchors     = tls_cert,
            .trust_anchors_len = tls_cert_len,
            .verify_server     = 1,
            .proto_opts.est    = { .allow_post_handshake_auth = 1 },
        };
        REQUIRE(expect_enroll_refused(&cli, "CN=pha-negative") == 0);
    }

    /* Client identity without the PHA opt-in. */
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
        REQUIRE(expect_enroll_refused(&cli, "CN=pha-no-opt-in") == 0);
    }

#ifdef WOLFSSL_POST_HANDSHAKE_AUTH
    /* Reenroll over PHA with a CSR for cli_cert's own subject gets 200. */
    REQUIRE(pha_reenroll(wolfcert_server_port(srv), tls_cert, tls_cert_len,
                         cli_cert, cli_cert_len, cli_key, cli_key_len) == 0);

    /* A client that never answers the CertificateRequest gets a 403. */
    {
        static const char req[] =
            "POST /.well-known/est/simpleenroll HTTP/1.1\r\n"
            "Host: 127.0.0.1\r\n"
            "Content-Type: application/pkcs10\r\n"
            "Content-Length: 1\r\n"
            "\r\n"
            "x";
        struct timeval tv = { .tv_sec = 15, .tv_usec = 0 };
        TestTlsConn c;
        char resp[64] = { 0 };

        REQUIRE(test_tls_setup(&c, wolfcert_server_port(srv),
                               tls_cert, tls_cert_len) == 0);
        /* Bounds the read in case the server never stops waiting. */
        REQUIRE(setsockopt(c.fd, SOL_SOCKET, SO_RCVTIMEO, &tv,
                           sizeof(tv)) == 0);
        REQUIRE(wolfSSL_allow_post_handshake_auth(c.ssl) == 0);
        REQUIRE(wolfSSL_connect(c.ssl) == WOLFSSL_SUCCESS);
        REQUIRE(test_tls_write(&c, req, sizeof(req) - 1) == 0);
        /* Drop the reply wolfSSL_read() sends to the CertificateRequest. */
        wolfSSL_SSLSetIOSend(c.ssl, discard_send);
        REQUIRE(test_tls_read(&c, resp, sizeof(resp) - 1) > 0);
        REQUIRE(strncmp(resp, "HTTP/1.1 403", 12) == 0);
        test_tls_close(&c);
    }
#endif

/* The test server loads no DH parameters, so TLS 1.2 needs ECDHE. */
#if !defined(WOLFSSL_NO_TLS12) && defined(HAVE_ECC)
    /* A TLS 1.2 client, without PHA, still reaches /cacerts. */
    {
        static const char req[] =
            "GET /.well-known/est/cacerts HTTP/1.1\r\n"
            "Host: 127.0.0.1\r\n"
            "Connection: close\r\n"
            "\r\n";
        TestTlsConn c;
        char resp[64] = { 0 };

        REQUIRE(test_tls_setup(&c, wolfcert_server_port(srv),
                               tls_cert, tls_cert_len) == 0);
        REQUIRE(wolfSSL_SetVersion(c.ssl, WOLFSSL_TLSV1_2) == WOLFSSL_SUCCESS);
        REQUIRE(wolfSSL_connect(c.ssl) == WOLFSSL_SUCCESS);
        REQUIRE(test_tls_write(&c, req, sizeof(req) - 1) == 0);
        REQUIRE(test_tls_read(&c, resp, sizeof(resp) - 1) > 0);
        REQUIRE(strncmp(resp, "HTTP/1.1 200", 12) == 0);
        test_tls_close(&c);
    }
#endif

    wolfcert_server_stop(srv);
    pthread_join(tid, NULL);
    wolfcert_server_free(srv);

    free(tls_cert);
    free(tls_key);
    free(cli_cert);
    free(cli_key);
    test_ca_store_close();
    wolfcert_cleanup();
    printf("OK\n");
    return 0;
}
