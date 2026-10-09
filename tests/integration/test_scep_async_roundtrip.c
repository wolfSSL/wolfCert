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
 * SCEP sessions against the in-tree server: non-blocking calls pumped through
 * poll(2), the blocking session wrappers, and the session guards.
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#define _DARWIN_C_SOURCE   /* expose memmem on macOS */
#define _GNU_SOURCE

#include <wolfcert/wolfcert.h>
#include <wolfcert/scep.h>
#include <wolfcert/server.h>

#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/asn_public.h>

#include "tls_test_util.h"

#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define REQUIRE(cond) \
    do {                                                                    \
        if (!(cond)) {                                                      \
            fprintf(stderr, "FAIL %s:%d %s\n", __FILE__, __LINE__, #cond);  \
            return 1;                                                       \
        }                                                                   \
    } while (0)

/* REQUIRE that sets ret = 1 and jumps to the local `cleanup:` label. */
#define REQUIRE_CLEAN(cond) \
    do {                                                                    \
        if (!(cond)) {                                                      \
            fprintf(stderr, "FAIL %s:%d %s\n", __FILE__, __LINE__, #cond);  \
            ret = 1; goto cleanup;                                          \
        }                                                                   \
    } while (0)

static void* server_thread(void* arg)
{
    wolfcert_server_run((WolfCertServer*)arg);
    return NULL;
}

/* 1 if *r is UNSET with no buffers, fail_info -1 and no heap. */
static int result_is_defined(const WolfCertScepResult* r)
{
    return r->status == WOLFCERT_SCEP_STATUS_UNSET &&
           r->cert_pem.data == NULL && r->cert_pem.len == 0 &&
           r->transaction_id == NULL && r->transaction_id_len == 0 &&
           r->fail_info == -1 && r->heap == NULL;
}

/* Nonzero if a poisoned result was rejected and cleared. An undefined *r is
 * zeroed so cleanup does not free the poison. */
static int poisoned_call_rejected(int rc, WolfCertScepResult* r)
{
    if (!result_is_defined(r)) {
        memset(r, 0, sizeof(*r));
        return 0;
    }
    return rc == WOLFCERT_ERR_BAD_ARG;
}

/* Generous enough for a loaded CI host. */
#define SCEP_ASYNC_POLL_TIMEOUT_MS 30000

/* Returns 0 once fd is ready for the direction rc asks for, else -1. POLLHUP
 * is not fatal since a peer that closed may still have a full reply queued. */
static int wait_ready(int fd, int rc)
{
    struct pollfd p = {
        .fd = fd,
        .events = (rc == WOLFCERT_ERR_WANT_WRITE) ? POLLOUT : POLLIN,
    };
    int n = poll(&p, 1, SCEP_ASYNC_POLL_TIMEOUT_MS);
    if (n > 0) {
        if ((p.revents & (POLLERR | POLLNVAL)) != 0) {
            fprintf(stderr, "wait_ready: fd error, revents=0x%x\n", p.revents);
            return -1;
        }
        return 0;
    }
    fprintf(stderr, "wait_ready: %s\n",
            n == 0 ? "timed out" : strerror(errno));
    return -1;
}

static int pump_pkcs_req(WolfCertScepSession* s, const WolfCertScepCaps* caps,
                         const uint8_t* ca_der, size_t ca_len,
                         const WolfCertKey* key,
                         const uint8_t* csr, size_t csr_len,
                         WolfCertScepResult* out)
{
    int fd = wolfcert_scep_session_fd(s);
    for (;;) {
        int rc = wolfcert_scep_session_pkcs_req_nb(s, caps, ca_der, ca_len,
                    ca_der, ca_len, key, csr, csr_len, out);
        if (rc == WOLFCERT_OK)
            return 0;
        if (rc == WOLFCERT_ERR_WANT_READ || rc == WOLFCERT_ERR_WANT_WRITE) {
            if (wait_ready(fd, rc) != 0)
                return -1;
            continue;
        }
        fprintf(stderr, "pkcs_req rc=%d (%s)\n", rc, wolfcert_strerror(rc));
        return -1;
    }
}

static int pump_get_cert_initial(WolfCertScepSession* s, const WolfCertScepCaps* caps,
                                 const uint8_t* ca_der, size_t ca_len,
                                 const WolfCertKey* key,
                                 const uint8_t* csr, size_t csr_len,
                                 const uint8_t* tid, size_t tid_len,
                                 WolfCertScepResult* out)
{
    int fd = wolfcert_scep_session_fd(s);
    for (;;) {
        int rc = wolfcert_scep_session_get_cert_initial_nb(s, caps, ca_der, ca_len,
                    ca_der, ca_len, NULL, 0, key, csr, csr_len, tid, tid_len, out);
        if (rc == WOLFCERT_OK)
            return 0;
        if (rc == WOLFCERT_ERR_WANT_READ || rc == WOLFCERT_ERR_WANT_WRITE) {
            if (wait_ready(fd, rc) != 0)
                return -1;
            continue;
        }
        fprintf(stderr, "get_cert_initial rc=%d (%s)\n", rc, wolfcert_strerror(rc));
        return -1;
    }
}

static int pump_renewal_req(WolfCertScepSession* s, const WolfCertScepCaps* caps,
                            const uint8_t* ca_der, size_t ca_len,
                            const uint8_t* cur_cert, size_t cur_cert_len,
                            const WolfCertKey* key,
                            const uint8_t* csr, size_t csr_len,
                            WolfCertScepResult* out)
{
    int fd = wolfcert_scep_session_fd(s);
    for (;;) {
        int rc = wolfcert_scep_session_renewal_req_nb(s, caps, ca_der, ca_len,
                    ca_der, ca_len, cur_cert, cur_cert_len, key, csr, csr_len, out);
        if (rc == WOLFCERT_OK)
            return 0;
        if (rc == WOLFCERT_ERR_WANT_READ || rc == WOLFCERT_ERR_WANT_WRITE) {
            if (wait_ready(fd, rc) != 0)
                return -1;
            continue;
        }
        fprintf(stderr, "renewal_req rc=%d (%s)\n", rc, wolfcert_strerror(rc));
        return -1;
    }
}

/* Fetch caps + CA cert (blocking one-shots), generate a fresh key + CSR. */
static int bootstrap(const WolfCertServerCfg* cli, const char* cn,
                     WolfCertScepCaps* caps, WolfCertBuffer* ca_pem,
                     DerBuffer** ca_der, WolfCertKey** key, WolfCertBuffer* csr)
{
    if (wolfcert_scep_get_ca_caps(cli, caps) != WOLFCERT_OK)
        return -1;
    if (wolfcert_scep_get_ca_cert(cli, ca_pem) != WOLFCERT_OK)
        return -1;
    if (wc_PemToDer(ca_pem->data, (long)ca_pem->len, CERT_TYPE,
                    ca_der, NULL, NULL, NULL) != 0) {
        wolfcert_buffer_free(ca_pem);
        return -1;
    }

    WolfCertKeyCfg kcfg = { .type = WOLFCERT_KEY_RSA, .param = 2048,
                            .dev_id = WOLFCERT_DEVID_SOFTWARE };
    if (wolfcert_key_generate(&kcfg, key) != WOLFCERT_OK) {
        wc_FreeDer(ca_der);
        wolfcert_buffer_free(ca_pem);
        return -1;
    }
    WolfCertCertMeta meta = { .subject_dn = cn };
    if (wolfcert_csr_build(*key, &meta, csr) != WOLFCERT_OK) {
        wolfcert_key_free(*key);
        *key = NULL;
        wc_FreeDer(ca_der);
        wolfcert_buffer_free(ca_pem);
        return -1;
    }
    return 0;
}

/* Scenario A: async PKCSReq, then blocking enroll and RenewalReq. */
static int async_enroll_path(WolfCertServer* s)
{
    char url[128];
    WolfCertServerCfg cli;
    WolfCertScepCaps caps = { 0 };
    WolfCertBuffer ca_pem = { 0 };
    DerBuffer* ca_der = NULL;
    WolfCertKey* dk = NULL;
    WolfCertBuffer csr = { 0 };
    WolfCertScepSession* sess = NULL;
    WolfCertScepResult r = { 0 };
    WolfCertScepSession* bsess = NULL;
    WolfCertKeyCfg kcfg2 = { .type = WOLFCERT_KEY_RSA, .param = 2048,
                             .dev_id = WOLFCERT_DEVID_SOFTWARE };
    WolfCertKey* dk2 = NULL;
    WolfCertCertMeta meta2 = { .subject_dn = "CN=sync-scep-1" };
    WolfCertBuffer csr2 = { 0 };
    WolfCertScepResult rb = { 0 };
    DerBuffer* rb_der = NULL;
    WolfCertScepResult rbr = { 0 };
    int ret = 1;

    snprintf(url, sizeof(url), "http://127.0.0.1:%u/scep", wolfcert_server_port(s));
    cli = (WolfCertServerCfg){ .protocol = WOLFCERT_PROTO_SCEP, .server_url = url };

    REQUIRE_CLEAN(bootstrap(&cli, "CN=async-scep-1", &caps, &ca_pem, &ca_der,
                            &dk, &csr) == 0);

    REQUIRE_CLEAN(wolfcert_scep_session_open_async(&cli, &sess) == WOLFCERT_OK);
    REQUIRE_CLEAN(wolfcert_scep_session_fd(sess) >= 0);

    REQUIRE_CLEAN(pump_pkcs_req(sess, &caps, ca_der->buffer, ca_der->length,
                               dk, csr.data, csr.len, &r) == 0);
    REQUIRE_CLEAN(r.status == WOLFCERT_SCEP_STATUS_SUCCESS);
    REQUIRE_CLEAN(memmem(r.cert_pem.data, r.cert_pem.len, "BEGIN CERTIFICATE", 17) != NULL);

    /* The single-threaded test server serves one connection at a time. */
    wolfcert_scep_session_close(sess);
    sess = NULL;

    REQUIRE_CLEAN(wolfcert_scep_session_open(&cli, &bsess) == WOLFCERT_OK);
    REQUIRE_CLEAN(wolfcert_key_generate(&kcfg2, &dk2) == WOLFCERT_OK);
    REQUIRE_CLEAN(wolfcert_csr_build(dk2, &meta2, &csr2) == WOLFCERT_OK);
    REQUIRE_CLEAN(wolfcert_scep_session_pkcs_req_ex(bsess, &caps,
                ca_der->buffer, ca_der->length, ca_der->buffer, ca_der->length,
                dk2, csr2.data, csr2.len, &rb) == WOLFCERT_OK);
    REQUIRE_CLEAN(rb.status == WOLFCERT_SCEP_STATUS_SUCCESS);

    /* RenewalReq on the same keep-alive connection. */
    REQUIRE_CLEAN(wc_PemToDer(rb.cert_pem.data, (long)rb.cert_pem.len, CERT_TYPE,
                        &rb_der, NULL, NULL, NULL) == 0);
    REQUIRE_CLEAN(wolfcert_scep_session_renewal_req_ex(bsess, &caps,
                ca_der->buffer, ca_der->length, ca_der->buffer, ca_der->length,
                rb_der->buffer, rb_der->length, dk2, csr2.data, csr2.len, &rbr)
            == WOLFCERT_OK);
    REQUIRE_CLEAN(rbr.status == WOLFCERT_SCEP_STATUS_SUCCESS);

    ret = 0;
cleanup:
    if (sess != NULL)
        wolfcert_scep_session_close(sess);
    if (bsess != NULL)
        wolfcert_scep_session_close(bsess);
    wolfcert_scep_result_free(&r);
    wolfcert_scep_result_free(&rb);
    wolfcert_scep_result_free(&rbr);
    if (rb_der != NULL)
        wc_FreeDer(&rb_der);
    wolfcert_buffer_free(&csr2);
    if (dk2 != NULL)
        wolfcert_key_free(dk2);
    if (ca_der != NULL)
        wc_FreeDer(&ca_der);
    wolfcert_buffer_free(&ca_pem);
    wolfcert_buffer_free(&csr);
    if (dk != NULL)
        wolfcert_key_free(dk);
    return ret;
}

/* Scenario B: async PENDING, then async GetCertInitial on one session. */
static int async_poll_path(WolfCertServer* s)
{
    char url[128];
    WolfCertServerCfg cli;
    WolfCertScepCaps caps = { 0 };
    WolfCertBuffer ca_pem = { 0 };
    DerBuffer* ca_der = NULL;
    WolfCertKey* dk = NULL;
    WolfCertBuffer csr = { 0 };
    WolfCertScepSession* sess = NULL;
    WolfCertScepResult r1 = { 0 };
    WolfCertScepResult r2 = { 0 };
    int ret = 1;

    snprintf(url, sizeof(url), "http://127.0.0.1:%u/scep", wolfcert_server_port(s));
    cli = (WolfCertServerCfg){ .protocol = WOLFCERT_PROTO_SCEP, .server_url = url };

    REQUIRE_CLEAN(bootstrap(&cli, "CN=async-scep-poll", &caps, &ca_pem, &ca_der,
                            &dk, &csr) == 0);

    REQUIRE_CLEAN(wolfcert_scep_session_open_async(&cli, &sess) == WOLFCERT_OK);

    /* First round trip: PENDING with a transactionID. */
    REQUIRE_CLEAN(pump_pkcs_req(sess, &caps, ca_der->buffer, ca_der->length,
                          dk, csr.data, csr.len, &r1) == 0);
    REQUIRE_CLEAN(r1.status == WOLFCERT_SCEP_STATUS_PENDING);
    REQUIRE_CLEAN(r1.transaction_id != NULL && r1.transaction_id_len > 0);

    /* Second round trip on the same connection: poll -> SUCCESS. */
    REQUIRE_CLEAN(pump_get_cert_initial(sess, &caps, ca_der->buffer, ca_der->length,
                                  dk, csr.data, csr.len,
                                  r1.transaction_id, r1.transaction_id_len, &r2) == 0);
    REQUIRE_CLEAN(r2.status == WOLFCERT_SCEP_STATUS_SUCCESS);
    REQUIRE_CLEAN(memmem(r2.cert_pem.data, r2.cert_pem.len, "BEGIN CERTIFICATE", 17) != NULL);

    ret = 0;
cleanup:
    if (sess != NULL)
        wolfcert_scep_session_close(sess);
    wolfcert_scep_result_free(&r1);
    wolfcert_scep_result_free(&r2);
    if (ca_der != NULL)
        wc_FreeDer(&ca_der);
    wolfcert_buffer_free(&ca_pem);
    wolfcert_buffer_free(&csr);
    if (dk != NULL)
        wolfcert_key_free(dk);
    return ret;
}

/* Scenario C: async enroll, then async RenewalReq on the same session. */
static int async_renewal_path(WolfCertServer* s)
{
    char url[128];
    WolfCertServerCfg cli;
    WolfCertScepCaps caps = { 0 };
    WolfCertBuffer ca_pem = { 0 };
    DerBuffer* ca_der = NULL;
    WolfCertKey* dk = NULL;
    WolfCertBuffer csr = { 0 };
    WolfCertScepSession* sess = NULL;
    WolfCertScepResult r1 = { 0 };
    DerBuffer* cur_der = NULL;
    WolfCertScepResult r2 = { 0 };
    int ret = 1;

    snprintf(url, sizeof(url), "http://127.0.0.1:%u/scep", wolfcert_server_port(s));
    cli = (WolfCertServerCfg){ .protocol = WOLFCERT_PROTO_SCEP, .server_url = url };

    REQUIRE_CLEAN(bootstrap(&cli, "CN=async-scep-renew", &caps, &ca_pem, &ca_der,
                            &dk, &csr) == 0);

    REQUIRE_CLEAN(wolfcert_scep_session_open_async(&cli, &sess) == WOLFCERT_OK);

    /* First round trip: enroll to obtain the cert to renew. */
    REQUIRE_CLEAN(pump_pkcs_req(sess, &caps, ca_der->buffer, ca_der->length,
                          dk, csr.data, csr.len, &r1) == 0);
    REQUIRE_CLEAN(r1.status == WOLFCERT_SCEP_STATUS_SUCCESS);

    REQUIRE_CLEAN(wc_PemToDer(r1.cert_pem.data, (long)r1.cert_pem.len, CERT_TYPE,
                        &cur_der, NULL, NULL, NULL) == 0);

    /* Second round trip: RenewalReq signed by the cert just issued. */
    REQUIRE_CLEAN(pump_renewal_req(sess, &caps, ca_der->buffer, ca_der->length,
                             cur_der->buffer, cur_der->length,
                             dk, csr.data, csr.len, &r2) == 0);
    REQUIRE_CLEAN(r2.status == WOLFCERT_SCEP_STATUS_SUCCESS);
    REQUIRE_CLEAN(memmem(r2.cert_pem.data, r2.cert_pem.len, "BEGIN CERTIFICATE", 17) != NULL);

    ret = 0;
cleanup:
    if (sess != NULL)
        wolfcert_scep_session_close(sess);
    wolfcert_scep_result_free(&r1);
    wolfcert_scep_result_free(&r2);
    if (cur_der != NULL)
        wc_FreeDer(&cur_der);
    if (ca_der != NULL)
        wc_FreeDer(&ca_der);
    wolfcert_buffer_free(&ca_pem);
    wolfcert_buffer_free(&csr);
    if (dk != NULL)
        wolfcert_key_free(dk);
    return ret;
}

/* Scenario D: _nb on a blocking session, _ex on an async one, and a second
 * call mid-request with another result pointer or operation all get BAD_ARG. */
static int async_guard_path(WolfCertServer* s)
{
    char real_url[128];
    char bh_url[128];
    WolfCertServerCfg cli_real;
    WolfCertServerCfg cli;
    WolfCertScepCaps caps = { 0 };
    WolfCertBuffer ca_pem = { 0 };
    DerBuffer* ca_der = NULL;
    WolfCertKey* dk = NULL;
    WolfCertBuffer csr = { 0 };
    WolfCertScepSession* bsess = NULL;
    WolfCertScepSession* asess = NULL;
    WolfCertScepResult rbad = { 0 };
    WolfCertScepResult r1 = { 0 };
    WolfCertScepResult r2 = { 0 };
    uint16_t bh_port = 0;
    int bh_fd = -1;
    int rc = 0;
    int ret = 1;

    snprintf(real_url, sizeof(real_url), "http://127.0.0.1:%u/scep",
             wolfcert_server_port(s));
    cli_real = (WolfCertServerCfg){ .protocol = WOLFCERT_PROTO_SCEP,
                                    .server_url = real_url };
    REQUIRE_CLEAN(bootstrap(&cli_real, "CN=async-scep-guard", &caps, &ca_pem,
                            &ca_der, &dk, &csr) == 0);

    /* A request to the black hole stays in flight regardless of host speed. */
    bh_fd = black_hole_listener(&bh_port);
    REQUIRE_CLEAN(bh_fd >= 0);
    snprintf(bh_url, sizeof(bh_url), "http://127.0.0.1:%u/scep", (unsigned)bh_port);
    cli = (WolfCertServerCfg){ .protocol = WOLFCERT_PROTO_SCEP, .server_url = bh_url };

    /* Mode guard: an _nb call on a blocking session is rejected. */
    REQUIRE_CLEAN(wolfcert_scep_session_open(&cli, &bsess) == WOLFCERT_OK);
    REQUIRE_CLEAN(wolfcert_scep_session_pkcs_req_nb(bsess, &caps,
                ca_der->buffer, ca_der->length, ca_der->buffer, ca_der->length,
                dk, csr.data, csr.len, &rbad) == WOLFCERT_ERR_BAD_ARG);
    wolfcert_scep_session_close(bsess);
    bsess = NULL;

    /* Mode guard: an _ex call on an async session is rejected. */
    REQUIRE_CLEAN(wolfcert_scep_session_open_async(&cli, &asess) == WOLFCERT_OK);
    REQUIRE_CLEAN(wolfcert_scep_session_pkcs_req_ex(asess, &caps,
                ca_der->buffer, ca_der->length, ca_der->buffer, ca_der->length,
                dk, csr.data, csr.len, &rbad) == WOLFCERT_ERR_BAD_ARG);

    /* Leave a PKCSReq to the black hole in flight for the guard checks. */
    rc = wolfcert_scep_session_pkcs_req_nb(asess, &caps,
                ca_der->buffer, ca_der->length, ca_der->buffer, ca_der->length,
                dk, csr.data, csr.len, &r1);
    REQUIRE_CLEAN(rc == WOLFCERT_ERR_WANT_READ || rc == WOLFCERT_ERR_WANT_WRITE);

    /* out-pointer guard: resuming with a different result pointer is rejected,
     * and the poisoned result still comes back defined. */
    memset(&r2, 0xA5, sizeof(r2));
    REQUIRE_CLEAN(poisoned_call_rejected(
                wolfcert_scep_session_pkcs_req_nb(asess, &caps,
                ca_der->buffer, ca_der->length, ca_der->buffer, ca_der->length,
                dk, csr.data, csr.len, &r2), &r2));

    /* in_op guard: a different operation while one is in flight is rejected. */
    memset(&r2, 0xA5, sizeof(r2));
    REQUIRE_CLEAN(poisoned_call_rejected(
                wolfcert_scep_session_renewal_req_nb(asess, &caps,
                ca_der->buffer, ca_der->length, ca_der->buffer, ca_der->length,
                ca_der->buffer, ca_der->length, dk, csr.data, csr.len, &r2),
            &r2));

    memset(&r2, 0xA5, sizeof(r2));
    REQUIRE_CLEAN(poisoned_call_rejected(
                wolfcert_scep_session_get_cert_initial_nb(asess, &caps,
                ca_der->buffer, ca_der->length, ca_der->buffer, ca_der->length,
                NULL, 0, dk, csr.data, csr.len, csr.data, csr.len, &r2),
            &r2));

    /* A resume on the session's own result leaves it intact; fail_info 42 is
     * a sentinel that a clear would reset. */
    r1.fail_info = 42;
    rc = wolfcert_scep_session_pkcs_req_nb(asess, &caps,
                ca_der->buffer, ca_der->length, ca_der->buffer, ca_der->length,
                dk, csr.data, csr.len, &r1);
    REQUIRE_CLEAN(rc == WOLFCERT_ERR_WANT_READ || rc == WOLFCERT_ERR_WANT_WRITE);
    REQUIRE_CLEAN(r1.fail_info == 42);

    /* An _ex call rejected on an async session leaves the result intact. */
    REQUIRE_CLEAN(wolfcert_scep_session_pkcs_req_ex(asess, &caps,
                ca_der->buffer, ca_der->length, ca_der->buffer, ca_der->length,
                dk, csr.data, csr.len, &r1) == WOLFCERT_ERR_BAD_ARG);
    REQUIRE_CLEAN(r1.fail_info == 42);

    ret = 0;
cleanup:
    if (bsess != NULL)
        wolfcert_scep_session_close(bsess);
    if (asess != NULL)
        wolfcert_scep_session_close(asess);
    if (bh_fd >= 0)
        close(bh_fd);
    wolfcert_scep_result_free(&r1);
    wolfcert_scep_result_free(&r2);
    wolfcert_scep_result_free(&rbad);
    if (ca_der != NULL)
        wc_FreeDer(&ca_der);
    wolfcert_buffer_free(&ca_pem);
    wolfcert_buffer_free(&csr);
    if (dk != NULL)
        wolfcert_key_free(dk);
    return ret;
}

/* Scenario E: blocking PENDING then GetCertInitial; a 200-byte transactionID
 * gets badCertId and one containing '_' gets WOLFCERT_ERR_BAD_ARG. */
static int blocking_poll_path(WolfCertServer* s)
{
    char url[128];
    WolfCertServerCfg cli;
    WolfCertScepCaps caps = { 0 };
    WolfCertBuffer ca_pem = { 0 };
    DerBuffer* ca_der = NULL;
    WolfCertKey* dk = NULL;
    WolfCertBuffer csr = { 0 };
    WolfCertScepSession* sess = NULL;
    WolfCertScepResult r1 = { 0 };
    WolfCertScepResult r2 = { 0 };
    WolfCertScepResult r3 = { 0 };
    WolfCertScepResult r4 = { 0 };
    uint8_t long_tid[200];
    int ret = 1;

    snprintf(url, sizeof(url), "http://127.0.0.1:%u/scep", wolfcert_server_port(s));
    cli = (WolfCertServerCfg){ .protocol = WOLFCERT_PROTO_SCEP, .server_url = url };

    REQUIRE_CLEAN(bootstrap(&cli, "CN=sync-scep-poll", &caps, &ca_pem, &ca_der,
                            &dk, &csr) == 0);

    REQUIRE_CLEAN(wolfcert_scep_session_open(&cli, &sess) == WOLFCERT_OK);

    REQUIRE_CLEAN(wolfcert_scep_session_pkcs_req_ex(sess, &caps,
                ca_der->buffer, ca_der->length, ca_der->buffer, ca_der->length,
                dk, csr.data, csr.len, &r1) == WOLFCERT_OK);
    REQUIRE_CLEAN(r1.status == WOLFCERT_SCEP_STATUS_PENDING);
    REQUIRE_CLEAN(r1.transaction_id != NULL && r1.transaction_id_len > 0);

    REQUIRE_CLEAN(wolfcert_scep_session_get_cert_initial_ex(sess, &caps,
                ca_der->buffer, ca_der->length, ca_der->buffer, ca_der->length,
                NULL, 0, dk, csr.data, csr.len,
                r1.transaction_id, r1.transaction_id_len, &r2) == WOLFCERT_OK);
    REQUIRE_CLEAN(r2.status == WOLFCERT_SCEP_STATUS_SUCCESS);
    REQUIRE_CLEAN(memmem(r2.cert_pem.data, r2.cert_pem.len, "BEGIN CERTIFICATE", 17) != NULL);

    memset(long_tid, 'A', sizeof(long_tid));
    REQUIRE_CLEAN(wolfcert_scep_session_get_cert_initial_ex(sess, &caps,
                ca_der->buffer, ca_der->length, ca_der->buffer, ca_der->length,
                NULL, 0, dk, csr.data, csr.len,
                long_tid, sizeof(long_tid), &r3) == WOLFCERT_OK);
    REQUIRE_CLEAN(r3.status == WOLFCERT_SCEP_STATUS_FAILURE);
    REQUIRE_CLEAN(r3.fail_info == 4);

    long_tid[1] = '_';
    REQUIRE_CLEAN(wolfcert_scep_session_get_cert_initial_ex(sess, &caps,
                ca_der->buffer, ca_der->length, ca_der->buffer, ca_der->length,
                NULL, 0, dk, csr.data, csr.len,
                long_tid, sizeof(long_tid), &r4) == WOLFCERT_ERR_BAD_ARG);

    ret = 0;
cleanup:
    if (sess != NULL)
        wolfcert_scep_session_close(sess);
    wolfcert_scep_result_free(&r1);
    wolfcert_scep_result_free(&r2);
    wolfcert_scep_result_free(&r3);
    wolfcert_scep_result_free(&r4);
    if (ca_der != NULL)
        wc_FreeDer(&ca_der);
    wolfcert_buffer_free(&ca_pem);
    wolfcert_buffer_free(&csr);
    if (dk != NULL)
        wolfcert_key_free(dk);
    return ret;
}

/* Scenario F: a session over the base64 GET transport (RFC 8894 4.1). */
static int session_get_transport_path(WolfCertServer* s)
{
    char url[128];
    WolfCertServerCfg cli;
    WolfCertScepCaps caps = { 0 };
    WolfCertBuffer ca_pem = { 0 };
    DerBuffer* ca_der = NULL;
    WolfCertKey* dk = NULL;
    WolfCertBuffer csr = { 0 };
    WolfCertScepSession* sess = NULL;
    WolfCertScepResult r = { 0 };
    int ret = 1;

    snprintf(url, sizeof(url), "http://127.0.0.1:%u/scep", wolfcert_server_port(s));
    cli = (WolfCertServerCfg){ .protocol = WOLFCERT_PROTO_SCEP, .server_url = url };

    REQUIRE_CLEAN(bootstrap(&cli, "CN=sync-scep-get", &caps, &ca_pem, &ca_der,
                            &dk, &csr) == 0);

    caps.post_pki_operation = 0;   /* force the base64 GET transport */

    REQUIRE_CLEAN(wolfcert_scep_session_open(&cli, &sess) == WOLFCERT_OK);

    REQUIRE_CLEAN(wolfcert_scep_session_pkcs_req_ex(sess, &caps,
                ca_der->buffer, ca_der->length, ca_der->buffer, ca_der->length,
                dk, csr.data, csr.len, &r) == WOLFCERT_OK);
    REQUIRE_CLEAN(r.status == WOLFCERT_SCEP_STATUS_SUCCESS);
    REQUIRE_CLEAN(memmem(r.cert_pem.data, r.cert_pem.len, "BEGIN CERTIFICATE", 17) != NULL);

    ret = 0;
cleanup:
    if (sess != NULL)
        wolfcert_scep_session_close(sess);
    wolfcert_scep_result_free(&r);
    if (ca_der != NULL)
        wc_FreeDer(&ca_der);
    wolfcert_buffer_free(&ca_pem);
    wolfcert_buffer_free(&csr);
    if (dk != NULL)
        wolfcert_key_free(dk);
    return ret;
}

/* Scenario G: https:// without verify_server is refused at session open. */
static int tls_guard_path(void)
{
    WolfCertServerCfg cli = { .protocol = WOLFCERT_PROTO_SCEP,
                              .server_url = "https://127.0.0.1:8443/scep",
                              .verify_server = 0 };
    WolfCertScepSession* sess = NULL;

    REQUIRE(wolfcert_scep_session_open(&cli, &sess) == WOLFCERT_ERR_TLS);
    REQUIRE(sess == NULL);
    REQUIRE(wolfcert_scep_session_open_async(&cli, &sess) == WOLFCERT_ERR_TLS);
    REQUIRE(sess == NULL);

    /* NULL-input contract of the session accessors. */
    REQUIRE(wolfcert_scep_session_fd(NULL) == -1);
    wolfcert_scep_session_close(NULL);   /* no-op, must not crash */

    /* NULL srv / server_url are rejected by both opens. */
    REQUIRE(wolfcert_scep_session_open(NULL, &sess) == WOLFCERT_ERR_BAD_ARG);
    REQUIRE(wolfcert_scep_session_open_async(NULL, &sess) == WOLFCERT_ERR_BAD_ARG);
    WolfCertServerCfg no_url = { .protocol = WOLFCERT_PROTO_SCEP, .server_url = NULL };
    REQUIRE(wolfcert_scep_session_open(&no_url, &sess) == WOLFCERT_ERR_BAD_ARG);
    return 0;
}

#ifdef WOLFCERT_HAVE_ED25519
/* Scenario H: each session request rejects a non-RSA signer (RFC 8894). */
static int non_rsa_reject_path(WolfCertServer* s)
{
    char url[128];
    WolfCertServerCfg cli;
    WolfCertScepCaps caps = { 0 };
    WolfCertBuffer ca_pem = { 0 };
    DerBuffer* ca_der = NULL;
    WolfCertKey* dk = NULL;
    WolfCertBuffer csr = { 0 };
    WolfCertKeyCfg ecfg = { .type = WOLFCERT_KEY_ED25519, .param = 0,
                            .dev_id = WOLFCERT_DEVID_SOFTWARE };
    WolfCertKey* ek = NULL;
    WolfCertScepSession* sess = NULL;
    WolfCertScepResult r = { 0 };
    int ret = 1;

    snprintf(url, sizeof(url), "http://127.0.0.1:%u/scep", wolfcert_server_port(s));
    cli = (WolfCertServerCfg){ .protocol = WOLFCERT_PROTO_SCEP, .server_url = url };
    REQUIRE_CLEAN(bootstrap(&cli, "CN=nonrsa", &caps, &ca_pem, &ca_der, &dk, &csr) == 0);
    REQUIRE_CLEAN(wolfcert_key_generate(&ecfg, &ek) == WOLFCERT_OK);
    REQUIRE_CLEAN(wolfcert_scep_session_open(&cli, &sess) == WOLFCERT_OK);

    REQUIRE_CLEAN(wolfcert_scep_session_pkcs_req_ex(sess, &caps,
                ca_der->buffer, ca_der->length, ca_der->buffer, ca_der->length,
                ek, csr.data, csr.len, &r) == WOLFCERT_ERR_UNSUPPORTED);
    REQUIRE_CLEAN(wolfcert_scep_session_renewal_req_ex(sess, &caps,
                ca_der->buffer, ca_der->length, ca_der->buffer, ca_der->length,
                ca_der->buffer, ca_der->length, ek, csr.data, csr.len, &r)
            == WOLFCERT_ERR_UNSUPPORTED);
    REQUIRE_CLEAN(wolfcert_scep_session_get_cert_initial_ex(sess, &caps,
                ca_der->buffer, ca_der->length, ca_der->buffer, ca_der->length,
                NULL, 0, ek, csr.data, csr.len, csr.data, csr.len, &r)
            == WOLFCERT_ERR_UNSUPPORTED);

    ret = 0;
cleanup:
    if (sess != NULL)
        wolfcert_scep_session_close(sess);
    wolfcert_scep_result_free(&r);
    if (ek != NULL)
        wolfcert_key_free(ek);
    if (ca_der != NULL)
        wc_FreeDer(&ca_der);
    wolfcert_buffer_free(&ca_pem);
    wolfcert_buffer_free(&csr);
    if (dk != NULL)
        wolfcert_key_free(dk);
    return ret;
}
#endif /* WOLFCERT_HAVE_ED25519 */

/* Scenario I: session GetCertInitial with a caller-supplied signer_cert. */
static int blocking_renewal_poll_path(WolfCertServer* s)
{
    char url[128];
    WolfCertServerCfg cli;
    WolfCertScepCaps caps = { 0 };
    WolfCertBuffer ca_pem = { 0 };
    DerBuffer* ca_der = NULL;
    WolfCertKey* dk = NULL;
    WolfCertBuffer csr = { 0 };
    WolfCertScepSession* sess = NULL;
    WolfCertScepResult r1 = { 0 };
    WolfCertScepResult r2 = { 0 };
    DerBuffer* issued_der = NULL;
    WolfCertScepResult r3 = { 0 };
    WolfCertScepResult r4 = { 0 };
    int ret = 1;

    snprintf(url, sizeof(url), "http://127.0.0.1:%u/scep", wolfcert_server_port(s));
    cli = (WolfCertServerCfg){ .protocol = WOLFCERT_PROTO_SCEP, .server_url = url };
    REQUIRE_CLEAN(bootstrap(&cli, "CN=sync-renew-poll", &caps, &ca_pem, &ca_der,
                            &dk, &csr) == 0);
    REQUIRE_CLEAN(wolfcert_scep_session_open(&cli, &sess) == WOLFCERT_OK);

    /* Enroll -> PENDING, then poll (signer_cert NULL) -> issued cert. */
    REQUIRE_CLEAN(wolfcert_scep_session_pkcs_req_ex(sess, &caps,
                ca_der->buffer, ca_der->length, ca_der->buffer, ca_der->length,
                dk, csr.data, csr.len, &r1) == WOLFCERT_OK);
    REQUIRE_CLEAN(r1.status == WOLFCERT_SCEP_STATUS_PENDING);
    REQUIRE_CLEAN(wolfcert_scep_session_get_cert_initial_ex(sess, &caps,
                ca_der->buffer, ca_der->length, ca_der->buffer, ca_der->length,
                NULL, 0, dk, csr.data, csr.len,
                r1.transaction_id, r1.transaction_id_len, &r2) == WOLFCERT_OK);
    REQUIRE_CLEAN(r2.status == WOLFCERT_SCEP_STATUS_SUCCESS);
    REQUIRE_CLEAN(wc_PemToDer(r2.cert_pem.data, (long)r2.cert_pem.len, CERT_TYPE,
                        &issued_der, NULL, NULL, NULL) == 0);

    /* Renew -> PENDING, then poll with the issued cert as signer_cert. */
    REQUIRE_CLEAN(wolfcert_scep_session_renewal_req_ex(sess, &caps,
                ca_der->buffer, ca_der->length, ca_der->buffer, ca_der->length,
                issued_der->buffer, issued_der->length, dk, csr.data, csr.len, &r3)
            == WOLFCERT_OK);
    REQUIRE_CLEAN(r3.status == WOLFCERT_SCEP_STATUS_PENDING);
    REQUIRE_CLEAN(wolfcert_scep_session_get_cert_initial_ex(sess, &caps,
                ca_der->buffer, ca_der->length, ca_der->buffer, ca_der->length,
                issued_der->buffer, issued_der->length, dk, csr.data, csr.len,
                r3.transaction_id, r3.transaction_id_len, &r4) == WOLFCERT_OK);
    REQUIRE_CLEAN(r4.status == WOLFCERT_SCEP_STATUS_SUCCESS);
    REQUIRE_CLEAN(memmem(r4.cert_pem.data, r4.cert_pem.len, "BEGIN CERTIFICATE", 17) != NULL);

    ret = 0;
cleanup:
    if (sess != NULL)
        wolfcert_scep_session_close(sess);
    wolfcert_scep_result_free(&r1);
    wolfcert_scep_result_free(&r2);
    wolfcert_scep_result_free(&r3);
    wolfcert_scep_result_free(&r4);
    if (issued_der != NULL)
        wc_FreeDer(&issued_der);
    if (ca_der != NULL)
        wc_FreeDer(&ca_der);
    wolfcert_buffer_free(&ca_pem);
    wolfcert_buffer_free(&csr);
    if (dk != NULL)
        wolfcert_key_free(dk);
    return ret;
}

/* Answers one connection with HTTP 500. Polls first so join() cannot hang
 * when no client connects. */
static void* stub_500_thread(void* arg)
{
    int lfd = *(int*)arg;
    struct pollfd p = { .fd = lfd, .events = POLLIN };
    int cfd;
    if (poll(&p, 1, SCEP_ASYNC_POLL_TIMEOUT_MS) <= 0 ||
            (p.revents & (POLLERR | POLLNVAL)) != 0)
        return NULL;
    cfd = accept(lfd, NULL, NULL);
    if (cfd >= 0) {
        static const char resp[] =
            "HTTP/1.1 500 Internal Server Error\r\n"
            "Content-Length: 0\r\nConnection: close\r\n\r\n";
        char buf[2048];
        (void)recv(cfd, buf, sizeof(buf), 0);
        (void)send(cfd, resp, sizeof(resp) - 1, 0);
        while (recv(cfd, buf, sizeof(buf), MSG_DONTWAIT) > 0)
            ;                                          /* drain for a clean close */
        close(cfd);
    }
    return NULL;
}

/* Scenario J: a non-200 reply surfaces WOLFCERT_ERR_HTTP. */
static int non_200_path(WolfCertServer* s)
{
    char real_url[128];
    char stub_url[128];
    WolfCertServerCfg cli_real;
    WolfCertServerCfg cli;
    WolfCertScepCaps caps = { 0 };
    WolfCertBuffer ca_pem = { 0 };
    DerBuffer* ca_der = NULL;
    WolfCertKey* dk = NULL;
    WolfCertBuffer csr = { 0 };
    WolfCertScepSession* sess = NULL;
    WolfCertScepResult r = { 0 };
    uint16_t port = 0;
    int lfd = -1;
    pthread_t stub;
    int stub_started = 0;
    int ret = 1;

    snprintf(real_url, sizeof(real_url), "http://127.0.0.1:%u/scep",
             wolfcert_server_port(s));
    cli_real = (WolfCertServerCfg){ .protocol = WOLFCERT_PROTO_SCEP,
                                    .server_url = real_url };
    REQUIRE_CLEAN(bootstrap(&cli_real, "CN=sync-500", &caps, &ca_pem, &ca_der,
                            &dk, &csr) == 0);

    lfd = black_hole_listener(&port);   /* the stub accepts on it */
    REQUIRE_CLEAN(lfd >= 0);
    REQUIRE_CLEAN(pthread_create(&stub, NULL, stub_500_thread, &lfd) == 0);
    stub_started = 1;
    snprintf(stub_url, sizeof(stub_url), "http://127.0.0.1:%u/scep", (unsigned)port);
    cli = (WolfCertServerCfg){ .protocol = WOLFCERT_PROTO_SCEP, .server_url = stub_url };

    REQUIRE_CLEAN(wolfcert_scep_session_open(&cli, &sess) == WOLFCERT_OK);
    REQUIRE_CLEAN(wolfcert_scep_session_pkcs_req_ex(sess, &caps,
                ca_der->buffer, ca_der->length, ca_der->buffer, ca_der->length,
                dk, csr.data, csr.len, &r) == WOLFCERT_ERR_HTTP);

    ret = 0;
cleanup:
    if (sess != NULL)
        wolfcert_scep_session_close(sess);
    if (stub_started)
        pthread_join(stub, NULL);
    if (lfd >= 0)
        close(lfd);
    wolfcert_scep_result_free(&r);
    if (ca_der != NULL)
        wc_FreeDer(&ca_der);
    wolfcert_buffer_free(&ca_pem);
    wolfcert_buffer_free(&csr);
    if (dk != NULL)
        wolfcert_key_free(dk);
    return ret;
}

/* Scenario K: argument checks of the session request calls. */
static int negative_args_path(WolfCertServer* s)
{
    char url[128];
    WolfCertServerCfg cli;
    WolfCertScepCaps caps = { 0 };
    WolfCertBuffer ca_pem = { 0 };
    DerBuffer* ca_der = NULL;
    WolfCertKey* dk = NULL;
    WolfCertBuffer csr = { 0 };
    WolfCertScepSession* sess = NULL;
    WolfCertScepResult r = { 0 };
    const uint8_t* ca = NULL;
    size_t ca_len = 0;
    int ret = 1;

    snprintf(url, sizeof(url), "http://127.0.0.1:%u/scep", wolfcert_server_port(s));
    cli = (WolfCertServerCfg){ .protocol = WOLFCERT_PROTO_SCEP, .server_url = url };
    REQUIRE_CLEAN(bootstrap(&cli, "CN=negargs", &caps, &ca_pem, &ca_der, &dk, &csr) == 0);
    REQUIRE_CLEAN(wolfcert_scep_session_open(&cli, &sess) == WOLFCERT_OK);
    ca = ca_der->buffer;
    ca_len = ca_der->length;

    /* PKCSReq: NULL session, NULL out, NULL/zero required arg, NULL caps. */
    REQUIRE_CLEAN(wolfcert_scep_session_pkcs_req_ex(NULL, &caps, ca, ca_len,
                ca, ca_len, dk, csr.data, csr.len, &r) == WOLFCERT_ERR_BAD_ARG);
    REQUIRE_CLEAN(wolfcert_scep_session_pkcs_req_ex(sess, &caps, ca, ca_len,
                ca, ca_len, dk, csr.data, csr.len, NULL) == WOLFCERT_ERR_BAD_ARG);
    REQUIRE_CLEAN(wolfcert_scep_session_pkcs_req_ex(sess, &caps, NULL, ca_len,
                ca, ca_len, dk, csr.data, csr.len, &r) == WOLFCERT_ERR_BAD_ARG);
    REQUIRE_CLEAN(wolfcert_scep_session_pkcs_req_ex(sess, &caps, ca, 0,
                ca, ca_len, dk, csr.data, csr.len, &r) == WOLFCERT_ERR_BAD_ARG);
    REQUIRE_CLEAN(wolfcert_scep_session_pkcs_req_ex(sess, NULL, ca, ca_len,
                ca, ca_len, dk, csr.data, csr.len, &r) == WOLFCERT_ERR_BAD_ARG);

    /* RenewalReq: a NULL op-specific required arg (current_cert). */
    REQUIRE_CLEAN(wolfcert_scep_session_renewal_req_ex(sess, &caps, ca, ca_len,
                ca, ca_len, NULL, 0, dk, csr.data, csr.len, &r) == WOLFCERT_ERR_BAD_ARG);

    /* GetCertInitial: a NULL transactionID. */
    REQUIRE_CLEAN(wolfcert_scep_session_get_cert_initial_ex(sess, &caps, ca, ca_len,
                ca, ca_len, NULL, 0, dk, csr.data, csr.len, NULL, 0, &r)
            == WOLFCERT_ERR_BAD_ARG);

    /* Mode guard: _nb on a blocking session is rejected. */
    REQUIRE_CLEAN(wolfcert_scep_session_renewal_req_nb(sess, &caps, ca, ca_len,
                ca, ca_len, ca, ca_len, dk, csr.data, csr.len, &r) == WOLFCERT_ERR_BAD_ARG);
    REQUIRE_CLEAN(wolfcert_scep_session_get_cert_initial_nb(sess, &caps, ca, ca_len,
                ca, ca_len, NULL, 0, dk, csr.data, csr.len, csr.data, csr.len, &r)
            == WOLFCERT_ERR_BAD_ARG);

    ret = 0;
cleanup:
    if (sess != NULL)
        wolfcert_scep_session_close(sess);
    wolfcert_scep_result_free(&r);
    if (ca_der != NULL)
        wc_FreeDer(&ca_der);
    wolfcert_buffer_free(&ca_pem);
    wolfcert_buffer_free(&csr);
    if (dk != NULL)
        wolfcert_key_free(dk);
    return ret;
}

int main(void)
{
    REQUIRE(wolfcert_init(NULL) == WOLFCERT_OK);

    /* Scenario A: auto-approve server. */
    WolfCertServerCfgSrv cfg = { .protocol = WOLFCERT_PROTO_SCEP,
                                 .bind_host = "127.0.0.1", .bind_port = 0,
                                 .ca_store = test_ca_store() };
    WolfCertServer* s1 = NULL;
    REQUIRE(wolfcert_server_start(&cfg, &s1) == WOLFCERT_OK);
    pthread_t t1;
    REQUIRE(pthread_create(&t1, NULL, server_thread, s1) == 0);
    int rc = async_enroll_path(s1);
    wolfcert_server_stop(s1);
    pthread_join(t1, NULL);
    wolfcert_server_free(s1);
    if (rc != 0)
        return rc;

    /* Scenario B: approval-required server (PENDING -> poll). */
    WolfCertServerCfgSrv cfg_pending = { .protocol = WOLFCERT_PROTO_SCEP,
                                         .bind_host = "127.0.0.1", .bind_port = 0,
                                         .ca_store = test_ca_store(),
                                         .scep_require_approval = 1 };
    WolfCertServer* s2 = NULL;
    REQUIRE(wolfcert_server_start(&cfg_pending, &s2) == WOLFCERT_OK);
    pthread_t t2;
    REQUIRE(pthread_create(&t2, NULL, server_thread, s2) == 0);
    rc = async_poll_path(s2);
    wolfcert_server_stop(s2);
    pthread_join(t2, NULL);
    wolfcert_server_free(s2);
    if (rc != 0)
        return rc;

    /* Scenario C: auto-approve server, async enroll -> async RenewalReq. */
    WolfCertServerCfgSrv cfg_renew = { .protocol = WOLFCERT_PROTO_SCEP,
                                       .bind_host = "127.0.0.1", .bind_port = 0,
                                       .ca_store = test_ca_store() };
    WolfCertServer* s3 = NULL;
    REQUIRE(wolfcert_server_start(&cfg_renew, &s3) == WOLFCERT_OK);
    pthread_t t3;
    REQUIRE(pthread_create(&t3, NULL, server_thread, s3) == 0);
    rc = async_renewal_path(s3);
    wolfcert_server_stop(s3);
    pthread_join(t3, NULL);
    wolfcert_server_free(s3);
    if (rc != 0)
        return rc;

    /* Scenario D: auto-approve server, session misuse guards. */
    WolfCertServerCfgSrv cfg_guard = { .protocol = WOLFCERT_PROTO_SCEP,
                                       .bind_host = "127.0.0.1", .bind_port = 0,
                                       .ca_store = test_ca_store() };
    WolfCertServer* s4 = NULL;
    REQUIRE(wolfcert_server_start(&cfg_guard, &s4) == WOLFCERT_OK);
    pthread_t t4;
    REQUIRE(pthread_create(&t4, NULL, server_thread, s4) == 0);
    rc = async_guard_path(s4);
    wolfcert_server_stop(s4);
    pthread_join(t4, NULL);
    wolfcert_server_free(s4);
    if (rc != 0)
        return rc;

    /* Scenario E: approval-required server, blocking PENDING -> poll. */
    WolfCertServerCfgSrv cfg_bpoll = { .protocol = WOLFCERT_PROTO_SCEP,
                                       .bind_host = "127.0.0.1", .bind_port = 0,
                                       .ca_store = test_ca_store(),
                                       .scep_require_approval = 1 };
    WolfCertServer* s5 = NULL;
    REQUIRE(wolfcert_server_start(&cfg_bpoll, &s5) == WOLFCERT_OK);
    pthread_t t5;
    REQUIRE(pthread_create(&t5, NULL, server_thread, s5) == 0);
    rc = blocking_poll_path(s5);
    wolfcert_server_stop(s5);
    pthread_join(t5, NULL);
    wolfcert_server_free(s5);
    if (rc != 0)
        return rc;

    /* Scenario F: auto-approve server, session over base64 GET. */
    WolfCertServerCfgSrv cfg_get = { .protocol = WOLFCERT_PROTO_SCEP,
                                     .bind_host = "127.0.0.1", .bind_port = 0,
                                     .ca_store = test_ca_store() };
    WolfCertServer* s6 = NULL;
    REQUIRE(wolfcert_server_start(&cfg_get, &s6) == WOLFCERT_OK);
    pthread_t t6;
    REQUIRE(pthread_create(&t6, NULL, server_thread, s6) == 0);
    rc = session_get_transport_path(s6);
    wolfcert_server_stop(s6);
    pthread_join(t6, NULL);
    wolfcert_server_free(s6);
    if (rc != 0)
        return rc;

    /* Scenario G: TLS transport guard (no server needed). */
    if (tls_guard_path())
        return 1;

#ifdef WOLFCERT_HAVE_ED25519
    /* Scenario H: auto-approve server, non-RSA signer rejection. */
    WolfCertServerCfgSrv cfg_nonrsa = { .protocol = WOLFCERT_PROTO_SCEP,
                                        .bind_host = "127.0.0.1", .bind_port = 0,
                                        .ca_store = test_ca_store() };
    WolfCertServer* s7 = NULL;
    REQUIRE(wolfcert_server_start(&cfg_nonrsa, &s7) == WOLFCERT_OK);
    pthread_t t7;
    REQUIRE(pthread_create(&t7, NULL, server_thread, s7) == 0);
    rc = non_rsa_reject_path(s7);
    wolfcert_server_stop(s7);
    pthread_join(t7, NULL);
    wolfcert_server_free(s7);
    if (rc != 0)
        return rc;
#endif

    /* Scenario I: approval-required server, renewal poll with signer_cert. */
    WolfCertServerCfgSrv cfg_rpoll = { .protocol = WOLFCERT_PROTO_SCEP,
                                       .bind_host = "127.0.0.1", .bind_port = 0,
                                       .ca_store = test_ca_store(),
                                       .scep_require_approval = 1 };
    WolfCertServer* s8 = NULL;
    REQUIRE(wolfcert_server_start(&cfg_rpoll, &s8) == WOLFCERT_OK);
    pthread_t t8;
    REQUIRE(pthread_create(&t8, NULL, server_thread, s8) == 0);
    rc = blocking_renewal_poll_path(s8);
    wolfcert_server_stop(s8);
    pthread_join(t8, NULL);
    wolfcert_server_free(s8);
    if (rc != 0)
        return rc;

    /* Scenario J: auto-approve server for bootstrap, then the 500 stub. */
    WolfCertServerCfgSrv cfg_500 = { .protocol = WOLFCERT_PROTO_SCEP,
                                     .bind_host = "127.0.0.1", .bind_port = 0,
                                     .ca_store = test_ca_store() };
    WolfCertServer* s9 = NULL;
    REQUIRE(wolfcert_server_start(&cfg_500, &s9) == WOLFCERT_OK);
    pthread_t t9;
    REQUIRE(pthread_create(&t9, NULL, server_thread, s9) == 0);
    rc = non_200_path(s9);
    wolfcert_server_stop(s9);
    pthread_join(t9, NULL);
    wolfcert_server_free(s9);
    if (rc != 0)
        return rc;

    /* Scenario K: auto-approve server, argument-validation guards. */
    WolfCertServerCfgSrv cfg_neg = { .protocol = WOLFCERT_PROTO_SCEP,
                                     .bind_host = "127.0.0.1", .bind_port = 0,
                                     .ca_store = test_ca_store() };
    WolfCertServer* s10 = NULL;
    REQUIRE(wolfcert_server_start(&cfg_neg, &s10) == WOLFCERT_OK);
    pthread_t t10;
    REQUIRE(pthread_create(&t10, NULL, server_thread, s10) == 0);
    rc = negative_args_path(s10);
    wolfcert_server_stop(s10);
    pthread_join(t10, NULL);
    wolfcert_server_free(s10);
    if (rc != 0)
        return rc;

    test_ca_store_close();
    wolfcert_cleanup();
    printf("OK\n");
    return 0;
}
