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

/* EST 202 Accepted + Retry-After (RFC 7030 section 4.2.3) through the
 * one-shot, session and non-blocking enroll calls. */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#define _DARWIN_C_SOURCE   /* expose memmem/strcasestr/INADDR_LOOPBACK on macOS */
#define _GNU_SOURCE

#include <wolfcert/wolfcert.h>
#include <wolfcert/est.h>
#include <wolfcert/server.h>

#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/coding.h>

#include "tls_test_util.h"

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

/* Server TLS trust anchor, pinned by the client. */
static const uint8_t* g_ca = NULL;
static size_t         g_ca_len = 0;

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

/* Returns the terminal rc, WOLFCERT_ERR_PENDING included. */
static int pump_enroll_nb(WolfCertEstSession* s, const uint8_t* csr,
                          size_t csr_len, WolfCertBuffer* out)
{
    for (;;) {
        int rc = wolfcert_est_session_simple_enroll_nb(s, csr, csr_len, out);
        if (rc != WOLFCERT_ERR_WANT_READ && rc != WOLFCERT_ERR_WANT_WRITE)
            return rc;
        if (wait_io(s, rc) != 0)
            return WOLFCERT_ERR_IO;
    }
}

static int pump_enroll_nb_ex(WolfCertEstSession* s, const uint8_t* csr,
                             size_t csr_len, WolfCertEstResult* out)
{
    for (;;) {
        int rc = wolfcert_est_session_simple_enroll_nb_ex(s, csr, csr_len, out);
        if (rc != WOLFCERT_ERR_WANT_READ && rc != WOLFCERT_ERR_WANT_WRITE)
            return rc;
        if (wait_io(s, rc) != 0)
            return WOLFCERT_ERR_IO;
    }
}

static int pump_cacerts_nb(WolfCertEstSession* s, WolfCertBuffer* out)
{
    for (;;) {
        int rc = wolfcert_est_session_get_cacerts_nb(s, out);
        if (rc != WOLFCERT_ERR_WANT_READ && rc != WOLFCERT_ERR_WANT_WRITE)
            return rc;
        if (wait_io(s, rc) != 0)
            return WOLFCERT_ERR_IO;
    }
}

/* A distinct subject per sub-test gives each its own pending-queue entry. */
static int make_csr(const char* subject, WolfCertKey** out_key,
                    WolfCertBuffer* out_csr)
{
    WolfCertKeyCfg kcfg = { .type = TEST_ENROLL_KEY_TYPE, .param = TEST_ENROLL_KEY_PARAM,
                            .dev_id = WOLFCERT_DEVID_SOFTWARE };
    if (wolfcert_key_generate(&kcfg, out_key) != WOLFCERT_OK)
        return 1;
    WolfCertCertMeta meta = { .subject_dn = subject };
    return wolfcert_csr_build(*out_key, &meta, out_csr) == WOLFCERT_OK ? 0 : 1;
}

/* POST a base64 CSR body as given and return the response status code. */
static int post_enroll_raw(uint16_t port, const byte* b64, word32 b64_len)
{
    TestTlsConn c;
    char hdr[256];
    char resp[64] = { 0 };
    int n;

    n = snprintf(hdr, sizeof(hdr),
                 "POST /.well-known/est/simpleenroll HTTP/1.1\r\n"
                 "Host: 127.0.0.1\r\nContent-Type: application/pkcs10\r\n"
                 "Content-Length: %u\r\nConnection: close\r\n\r\n",
                 (unsigned)b64_len);
    if (n <= 0 || (size_t)n >= sizeof(hdr) ||
            test_tls_connect(&c, port, g_ca, g_ca_len) != 0)
        return -1;
    if (test_tls_write(&c, hdr, (size_t)n) != 0 ||
            test_tls_write(&c, b64, b64_len) != 0 ||
            test_tls_read(&c, resp, sizeof(resp) - 1) < 12) {
        test_tls_close(&c);
        return -1;
    }
    test_tls_close(&c);
    return atoi(resp + 9);
}

static int pending_path(WolfCertServer* s)
{
    char url[128];
    snprintf(url, sizeof(url), "https://127.0.0.1:%u/.well-known/est",
             wolfcert_server_port(s));
    WolfCertServerCfg cli = { .protocol = WOLFCERT_PROTO_EST,
                              .server_url = url,
                              .trust_anchors = g_ca,
                              .trust_anchors_len = g_ca_len,
                              .verify_server = 1 };

    WolfCertBuffer ca_pem = { 0 };
    REQUIRE(wolfcert_est_get_cacerts(&cli, &ca_pem) == WOLFCERT_OK);

    /* _ex reports PENDING with the Retry-After hint, then SUCCESS. */
    WolfCertKey* dk_ex = NULL;
    WolfCertBuffer csr_ex = { 0 };
    REQUIRE(make_csr("CN=device-est-pending-ex", &dk_ex, &csr_ex) == 0);

    WolfCertEstResult r1 = { 0 };
    int rc = wolfcert_est_simple_enroll_ex(&cli, csr_ex.data, csr_ex.len, &r1);
    REQUIRE(rc == WOLFCERT_OK);
    REQUIRE(r1.status == WOLFCERT_EST_STATUS_PENDING);
    REQUIRE(r1.retry_after_sec == 1);
    REQUIRE(r1.cert_pem.data == NULL);
    wolfcert_est_result_free(&r1);

    WolfCertEstResult r2 = { 0 };
    rc = wolfcert_est_simple_enroll_ex(&cli, csr_ex.data, csr_ex.len, &r2);
    REQUIRE(rc == WOLFCERT_OK);
    REQUIRE(r2.status == WOLFCERT_EST_STATUS_SUCCESS);
    REQUIRE(r2.cert_pem.data != NULL);
    REQUIRE(memmem(r2.cert_pem.data, r2.cert_pem.len,
                   "BEGIN CERTIFICATE", 17) != NULL);

    WOLFSSL_CERT_MANAGER* cm = wolfSSL_CertManagerNew();
    REQUIRE(cm != NULL);
    REQUIRE(wolfSSL_CertManagerLoadCABuffer(cm, ca_pem.data, (long)ca_pem.len,
                                            WOLFSSL_FILETYPE_PEM)
            == WOLFSSL_SUCCESS);
    DerBuffer* issued_der = NULL;
    REQUIRE(wc_PemToDer(r2.cert_pem.data, (long)r2.cert_pem.len, CERT_TYPE,
                        &issued_der, NULL, NULL, NULL) == 0);
    REQUIRE(wolfSSL_CertManagerVerifyBuffer(cm, issued_der->buffer,
                                            (long)issued_der->length,
                                            WOLFSSL_FILETYPE_ASN1)
            == WOLFSSL_SUCCESS);
    wc_FreeDer(&issued_der);
    wolfSSL_CertManagerFree(cm);

    wolfcert_est_result_free(&r2);

    /* A non-PKCS#10 body and a CSR with a flipped signature bit each get
     * FAILURE on the first POST. */
    static const uint8_t not_a_csr[] = "this is not a PKCS#10 request";
    WolfCertEstResult bad = { 0 };
    rc = wolfcert_est_simple_enroll_ex(&cli, not_a_csr, sizeof(not_a_csr),
                                       &bad);
    REQUIRE(rc == WOLFCERT_ERR_HTTP);
    REQUIRE(bad.status == WOLFCERT_EST_STATUS_FAILURE);
    wolfcert_est_result_free(&bad);

    csr_ex.data[csr_ex.len - 1] ^= 0x01;
    rc = wolfcert_est_simple_enroll_ex(&cli, csr_ex.data, csr_ex.len, &bad);
    REQUIRE(rc == WOLFCERT_ERR_HTTP);
    REQUIRE(bad.status == WOLFCERT_EST_STATUS_FAILURE);
    wolfcert_est_result_free(&bad);

    /* The queue matches the decoded CSR, whatever the base64 line wrapping. */
    WolfCertKey* dk_wrap = NULL;
    WolfCertBuffer csr_wrap = { 0 };
    byte b64[4096];
    word32 b64_len = sizeof(b64);
    REQUIRE(make_csr("CN=device-est-pending-rewrap", &dk_wrap, &csr_wrap) == 0);
    REQUIRE(Base64_Encode(csr_wrap.data, (word32)csr_wrap.len, b64,
                          &b64_len) == 0);
    REQUIRE(memchr(b64, '\n', b64_len - 1) != NULL);
    REQUIRE(post_enroll_raw(wolfcert_server_port(s), b64, b64_len) == 202);
    b64_len = sizeof(b64);
    REQUIRE(Base64_Encode_NoNl(csr_wrap.data, (word32)csr_wrap.len, b64,
                               &b64_len) == 0);
    REQUIRE(post_enroll_raw(wolfcert_server_port(s), b64, b64_len) == 200);
    wolfcert_buffer_free(&csr_wrap);
    wolfcert_key_free(dk_wrap);

    wolfcert_buffer_free(&csr_ex);
    wolfcert_key_free(dk_ex);

    /* wolfcert_est_simple_enroll: ERR_PENDING first, the cert on the retry. */
    WolfCertKey* dk_leg = NULL;
    WolfCertBuffer csr_leg = { 0 };
    REQUIRE(make_csr("CN=device-est-pending-legacy", &dk_leg, &csr_leg) == 0);

    WolfCertBuffer legacy_out = { 0 };
    int legacy_rc = wolfcert_est_simple_enroll(&cli, csr_leg.data, csr_leg.len,
                                               &legacy_out);
    REQUIRE(legacy_rc == WOLFCERT_ERR_PENDING);
    REQUIRE(legacy_out.data == NULL);

    legacy_rc = wolfcert_est_simple_enroll(&cli, csr_leg.data, csr_leg.len,
                                           &legacy_out);
    REQUIRE(legacy_rc == WOLFCERT_OK);
    REQUIRE(legacy_out.data != NULL);
    REQUIRE(memmem(legacy_out.data, legacy_out.len,
                   "BEGIN CERTIFICATE", 17) != NULL);
    wolfcert_buffer_free(&legacy_out);

    wolfcert_buffer_free(&csr_leg);
    wolfcert_key_free(dk_leg);

    /* Session enroll: ERR_PENDING first, the cert on the retry. */
    WolfCertKey* dk_sess = NULL;
    WolfCertBuffer csr_sess = { 0 };
    REQUIRE(make_csr("CN=device-est-pending-session", &dk_sess, &csr_sess) == 0);

    WolfCertEstSession* sess = NULL;
    REQUIRE(wolfcert_est_session_open(&cli, &sess) == WOLFCERT_OK);

    WolfCertBuffer sess_out = { 0 };
    int sess_rc = wolfcert_est_session_simple_enroll(sess, csr_sess.data,
                                                     csr_sess.len, &sess_out);
    REQUIRE(sess_rc == WOLFCERT_ERR_PENDING);
    REQUIRE(sess_out.data == NULL);

    sess_rc = wolfcert_est_session_simple_enroll(sess, csr_sess.data,
                                                 csr_sess.len, &sess_out);
    REQUIRE(sess_rc == WOLFCERT_OK);
    REQUIRE(sess_out.data != NULL);
    REQUIRE(memmem(sess_out.data, sess_out.len,
                   "BEGIN CERTIFICATE", 17) != NULL);
    wolfcert_buffer_free(&sess_out);

    wolfcert_est_session_close(sess);
    wolfcert_buffer_free(&csr_sess);
    wolfcert_key_free(dk_sess);

    /* Non-blocking session enroll, retried on the same connection. */
    WolfCertKey* dk_async = NULL;
    WolfCertBuffer csr_async = { 0 };
    REQUIRE(make_csr("CN=device-est-pending-async", &dk_async, &csr_async) == 0);

    WolfCertEstSession* asess = NULL;
    REQUIRE(wolfcert_est_session_open_async(&cli, &asess) == WOLFCERT_OK);

    WolfCertBuffer async_out = { 0 };
    int async_rc = pump_enroll_nb(asess, csr_async.data, csr_async.len,
                                  &async_out);
    REQUIRE(async_rc == WOLFCERT_ERR_PENDING);
    REQUIRE(async_out.data == NULL);

    async_rc = pump_enroll_nb(asess, csr_async.data, csr_async.len, &async_out);
    REQUIRE(async_rc == WOLFCERT_OK);
    REQUIRE(async_out.data != NULL);
    REQUIRE(memmem(async_out.data, async_out.len,
                   "BEGIN CERTIFICATE", 17) != NULL);
    wolfcert_buffer_free(&async_out);

    wolfcert_est_session_close(asess);
    wolfcert_buffer_free(&csr_async);
    wolfcert_key_free(dk_async);

    /* Session _ex carries the Retry-After hint. */
    WolfCertKey* dk_sex = NULL;
    WolfCertBuffer csr_sex = { 0 };
    REQUIRE(make_csr("CN=device-est-pending-session-ex", &dk_sex, &csr_sex) == 0);

    WolfCertEstSession* xsess = NULL;
    REQUIRE(wolfcert_est_session_open(&cli, &xsess) == WOLFCERT_OK);

    /* A missing CSR is refused on a live session, which stays usable. */
    WolfCertEstResult sr1 = { 0 };
    REQUIRE(wolfcert_est_session_simple_enroll_ex(xsess, NULL, csr_sex.len,
                                                  &sr1) == WOLFCERT_ERR_BAD_ARG);
    REQUIRE(wolfcert_est_session_simple_enroll_ex(xsess, csr_sex.data, 0,
                                                  &sr1) == WOLFCERT_ERR_BAD_ARG);
    REQUIRE(sr1.status == WOLFCERT_EST_STATUS_UNSET);

    rc = wolfcert_est_session_simple_enroll_ex(xsess, csr_sex.data,
                                               csr_sex.len, &sr1);
    REQUIRE(rc == WOLFCERT_OK);
    REQUIRE(sr1.status == WOLFCERT_EST_STATUS_PENDING);
    REQUIRE(sr1.retry_after_sec == 1);
    REQUIRE(sr1.cert_pem.data == NULL);
    wolfcert_est_result_free(&sr1);

    WolfCertEstResult sr2 = { 0 };
    rc = wolfcert_est_session_simple_enroll_ex(xsess, csr_sex.data,
                                               csr_sex.len, &sr2);
    REQUIRE(rc == WOLFCERT_OK);
    REQUIRE(sr2.status == WOLFCERT_EST_STATUS_SUCCESS);
    REQUIRE(sr2.cert_pem.data != NULL);
    REQUIRE(memmem(sr2.cert_pem.data, sr2.cert_pem.len,
                   "BEGIN CERTIFICATE", 17) != NULL);
    wolfcert_est_result_free(&sr2);

    /* A failed _nb enroll on a blocking session leaves no request in flight. */
    WolfCertEstResult sr3 = { 0 };
    REQUIRE(wolfcert_est_session_simple_enroll_nb_ex(xsess, csr_sex.data,
                                                     csr_sex.len, &sr3)
            == WOLFCERT_ERR_BAD_ARG);
    REQUIRE(sr3.status == WOLFCERT_EST_STATUS_UNSET);
    REQUIRE(sr3.cert_pem.data == NULL);

    WolfCertBuffer sess_ca = { 0 };
    REQUIRE(wolfcert_est_session_get_cacerts(xsess, &sess_ca) == WOLFCERT_OK);
    REQUIRE(sess_ca.len > 0);
    wolfcert_buffer_free(&sess_ca);

    wolfcert_est_session_close(xsess);
    wolfcert_buffer_free(&csr_sex);
    wolfcert_key_free(dk_sex);

    /* Non-blocking session _ex: PENDING, retry_after_sec 1, then SUCCESS. */
    WolfCertKey* dk_nex = NULL;
    WolfCertBuffer csr_nex = { 0 };
    REQUIRE(make_csr("CN=device-est-pending-async-ex", &dk_nex, &csr_nex) == 0);

    WolfCertEstSession* nsess = NULL;
    REQUIRE(wolfcert_est_session_open_async(&cli, &nsess) == WOLFCERT_OK);

    WolfCertEstResult nr1 = { 0 };
    rc = pump_enroll_nb_ex(nsess, csr_nex.data, csr_nex.len, &nr1);
    REQUIRE(rc == WOLFCERT_OK);
    REQUIRE(nr1.status == WOLFCERT_EST_STATUS_PENDING);
    REQUIRE(nr1.retry_after_sec == 1);
    REQUIRE(nr1.cert_pem.data == NULL);
    wolfcert_est_result_free(&nr1);

    WolfCertEstResult nr2 = { 0 };
    rc = pump_enroll_nb_ex(nsess, csr_nex.data, csr_nex.len, &nr2);
    REQUIRE(rc == WOLFCERT_OK);
    REQUIRE(nr2.status == WOLFCERT_EST_STATUS_SUCCESS);
    REQUIRE(nr2.cert_pem.data != NULL);
    REQUIRE(memmem(nr2.cert_pem.data, nr2.cert_pem.len,
                   "BEGIN CERTIFICATE", 17) != NULL);
    wolfcert_est_result_free(&nr2);

    wolfcert_est_session_close(nsess);
    wolfcert_buffer_free(&csr_nex);
    wolfcert_key_free(dk_nex);

    /* The black-hole listener never answers, so a started request stays in
     * flight. */
    uint16_t bh_port = 0;
    int bh_fd = black_hole_listener(&bh_port);
    REQUIRE(bh_fd >= 0);
    char bh_url[128];
    snprintf(bh_url, sizeof(bh_url), "https://127.0.0.1:%u/.well-known/est",
             bh_port);
    WolfCertServerCfg bh_cli = cli;
    bh_cli.server_url = bh_url;

    WolfCertKey* dk_mix = NULL;
    WolfCertBuffer csr_mix = { 0 };
    REQUIRE(make_csr("CN=device-est-pending-mixed", &dk_mix, &csr_mix) == 0);

    /* With /cacerts in flight, an enroll or a /cacerts call with a different
     * output buffer gets BAD_ARG. */
    WolfCertEstSession* msess = NULL;
    REQUIRE(wolfcert_est_session_open_async(&bh_cli, &msess) == WOLFCERT_OK);
    WolfCertBuffer mix_ca = { 0 };
    rc = wolfcert_est_session_get_cacerts_nb(msess, &mix_ca);
    REQUIRE(rc == WOLFCERT_ERR_WANT_READ || rc == WOLFCERT_ERR_WANT_WRITE);

    WolfCertEstResult mr = { 0 };
    REQUIRE(wolfcert_est_session_simple_enroll_nb_ex(msess, csr_mix.data,
                                                     csr_mix.len, &mr)
            == WOLFCERT_ERR_BAD_ARG);
    REQUIRE(mr.status == WOLFCERT_EST_STATUS_UNSET);
    REQUIRE(mr.cert_pem.data == NULL);
    WolfCertBuffer other_ca = { 0 };
    REQUIRE(wolfcert_est_session_get_cacerts_nb(msess, &other_ca)
            == WOLFCERT_ERR_BAD_ARG);

    /* Blocking session requests are refused as well. */
    REQUIRE(wolfcert_est_session_simple_enroll_ex(msess, csr_mix.data,
                                                  csr_mix.len, &mr)
            == WOLFCERT_ERR_BAD_ARG);
    REQUIRE(mr.status == WOLFCERT_EST_STATUS_UNSET);
    REQUIRE(wolfcert_est_session_simple_enroll(msess, csr_mix.data,
                                               csr_mix.len, &other_ca)
            == WOLFCERT_ERR_BAD_ARG);
    REQUIRE(wolfcert_est_session_get_cacerts(msess, &other_ca)
            == WOLFCERT_ERR_BAD_ARG);
    REQUIRE(other_ca.data == NULL);

    /* The refused calls left the /cacerts request in flight. */
    rc = wolfcert_est_session_get_cacerts_nb(msess, &mix_ca);
    REQUIRE(rc == WOLFCERT_ERR_WANT_READ || rc == WOLFCERT_ERR_WANT_WRITE);
    REQUIRE(mix_ca.data == NULL);
    wolfcert_est_session_close(msess);

    /* With an enroll in flight, /cacerts or an enroll with a different output
     * gets BAD_ARG. */
    msess = NULL;
    REQUIRE(wolfcert_est_session_open_async(&bh_cli, &msess) == WOLFCERT_OK);

    /* A missing CSR is refused without starting a request. */
    REQUIRE(wolfcert_est_session_simple_enroll_nb_ex(msess, NULL, csr_mix.len,
                                                     &mr) == WOLFCERT_ERR_BAD_ARG);
    REQUIRE(wolfcert_est_session_simple_enroll_nb_ex(msess, csr_mix.data, 0,
                                                     &mr) == WOLFCERT_ERR_BAD_ARG);
    REQUIRE(mr.status == WOLFCERT_EST_STATUS_UNSET);

    /* *out comes back zeroed on a WANT_* return. */
    memset(&mr, 0xA5, sizeof(mr));
    rc = wolfcert_est_session_simple_enroll_nb_ex(msess, csr_mix.data,
                                                  csr_mix.len, &mr);
    REQUIRE(rc == WOLFCERT_ERR_WANT_READ || rc == WOLFCERT_ERR_WANT_WRITE);
    REQUIRE(mr.status == WOLFCERT_EST_STATUS_UNSET);
    REQUIRE(mr.cert_pem.data == NULL && mr.cert_pem.len == 0);
    REQUIRE(mr.retry_after_sec == 0 && mr.heap == NULL);

    REQUIRE(wolfcert_est_session_get_cacerts_nb(msess, &mix_ca)
            == WOLFCERT_ERR_BAD_ARG);
    REQUIRE(mix_ca.data == NULL);
    WolfCertEstResult other_r = { 0 };
    REQUIRE(wolfcert_est_session_simple_enroll_nb_ex(msess, csr_mix.data,
                                                     csr_mix.len, &other_r)
            == WOLFCERT_ERR_BAD_ARG);
    WolfCertBuffer other_pem = { 0 };
    REQUIRE(wolfcert_est_session_simple_enroll_nb(msess, csr_mix.data,
                                                  csr_mix.len, &other_pem)
            == WOLFCERT_ERR_BAD_ARG);
    REQUIRE(other_pem.data == NULL);

    rc = wolfcert_est_session_simple_enroll_nb_ex(msess, csr_mix.data,
                                                  csr_mix.len, &mr);
    REQUIRE(rc == WOLFCERT_ERR_WANT_READ || rc == WOLFCERT_ERR_WANT_WRITE);
    wolfcert_est_session_close(msess);
    close(bh_fd);

    /* A finished enroll frees the session for /cacerts. */
    msess = NULL;
    REQUIRE(wolfcert_est_session_open_async(&cli, &msess) == WOLFCERT_OK);
    REQUIRE(pump_enroll_nb_ex(msess, csr_mix.data, csr_mix.len, &mr)
            == WOLFCERT_OK);
    REQUIRE(mr.status == WOLFCERT_EST_STATUS_PENDING);
    wolfcert_est_result_free(&mr);

    REQUIRE(pump_cacerts_nb(msess, &mix_ca) == WOLFCERT_OK);
    REQUIRE(mix_ca.len > 0);
    wolfcert_buffer_free(&mix_ca);

    wolfcert_est_session_close(msess);
    wolfcert_buffer_free(&csr_mix);
    wolfcert_key_free(dk_mix);

    wolfcert_buffer_free(&ca_pem);
    return 0;
}

int main(void)
{
    REQUIRE(wolfcert_init(NULL) == WOLFCERT_OK);

    uint8_t *tls_cert = NULL, *tls_key = NULL;
    size_t tls_cert_len = 0, tls_key_len = 0;
    REQUIRE(gen_server_identity(&tls_cert, &tls_cert_len,
                                &tls_key, &tls_key_len) == 0);
    g_ca = tls_cert;
    g_ca_len = tls_cert_len;

    WolfCertServerCfgSrv cfg = {
        .protocol               = WOLFCERT_PROTO_EST,
        .bind_host              = "127.0.0.1", .bind_port = 0,
        .ca_store               = test_ca_store(),
        .est_require_approval   = 1,
        .est_retry_after_sec    = 1,
        .tls_cert_pem           = tls_cert, .tls_cert_pem_len = tls_cert_len,
        .tls_key_pem            = tls_key,  .tls_key_pem_len  = tls_key_len,
        .est_allow_anonymous_enroll = 1,
    };
    WolfCertServer* s = NULL;
    REQUIRE(wolfcert_server_start(&cfg, &s) == WOLFCERT_OK);
    pthread_t t;
    REQUIRE(pthread_create(&t, NULL, server_thread, s) == 0);
    int rc = pending_path(s);
    wolfcert_server_stop(s);
    pthread_join(t, NULL);
    wolfcert_server_free(s);

    free(tls_cert);
    free(tls_key);
    test_ca_store_close();
    wolfcert_cleanup();
    if (rc != 0)
        return rc;
    printf("OK\n");
    return 0;
}
