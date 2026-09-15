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
 * End-to-end non-blocking SCEP session driven through a real poll(2) loop.
 * Exercises:
 *   - wolfcert_scep_session_open_async over plaintext HTTP,
 *   - wolfcert_scep_session_pkcs_req_nb (direct enrollment -> SUCCESS),
 *   - a PENDING enrollment followed by wolfcert_scep_session_get_cert_initial_nb
 *     on the same keep-alive connection (-> SUCCESS),
 * all pumped through poll() between WOLFCERT_ERR_WANT_READ / _WANT_WRITE
 * returns. The async counterpart to test_scep_roundtrip / test_scep_poll_roundtrip.
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#define _DARWIN_C_SOURCE   /* expose memmem on macOS */
#define _GNU_SOURCE

#include <wolfcert/wolfcert.h>
#include <wolfcert/scep.h>
#include <wolfcert/server.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/asn_public.h>

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

/* Like REQUIRE but jumps to a function-local `cleanup:` label (setting ret=1)
 * so a scenario holding open sessions/allocations releases them on failure. */
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

/* wolfcert/scep.h: an entry point defines *out before any other argument check,
 * so a rejected call still hands back something safe to free. */
static int result_is_defined(const WolfCertScepResult* r)
{
    return r->status == WOLFCERT_SCEP_STATUS_UNSET &&
           r->cert_pem.data == NULL && r->cert_pem.len == 0 &&
           r->transaction_id == NULL && r->transaction_id_len == 0 &&
           r->fail_info == -1;
}

/* Generous poll ceiling so a legitimately slow WANT_READ/WANT_WRITE wait on a
 * loaded CI host is not mistaken for a hang. */
#define SCEP_ASYNC_POLL_TIMEOUT_MS 30000

/* poll() until the session's fd is ready for the direction it asked for.
 * Returns 0 on ready, -1 on timeout or poll error - both are fatal for the pump
 * but are logged distinctly so a timeout is not confused with a syscall error.
 *
 * A positive poll() return does not mean the fd is healthy: POLLERR and
 * POLLNVAL are reported in revents regardless of what was requested, and
 * looping on them would spin instead of failing, so treat them as fatal.
 * POLLHUP is deliberately not fatal - a peer that closed after sending a
 * complete response still has readable data, and letting the pump read it
 * surfaces either the response or a clean EOF error from the session. */
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

/* Scenario A: an auto-approving server issues immediately over an async
 * PKCSReq, then a blocking session runs enroll + RenewalReq to completion.
 * Every allocation is released through the single cleanup: label so a REQUIRE
 * failure cannot leak the open sessions or buffers. */
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

    /* Close the async session before opening the blocking one: the single-
     * threaded test server serves one connection at a time. */
    wolfcert_scep_session_close(sess);
    sess = NULL;

    REQUIRE_CLEAN(wolfcert_scep_session_open(&cli, &bsess) == WOLFCERT_OK);
    REQUIRE_CLEAN(wolfcert_key_generate(&kcfg2, &dk2) == WOLFCERT_OK);
    REQUIRE_CLEAN(wolfcert_csr_build(dk2, &meta2, &csr2) == WOLFCERT_OK);
    REQUIRE_CLEAN(wolfcert_scep_session_pkcs_req_ex(bsess, &caps,
                ca_der->buffer, ca_der->length, ca_der->buffer, ca_der->length,
                dk2, csr2.data, csr2.len, &rb) == WOLFCERT_OK);
    REQUIRE_CLEAN(rb.status == WOLFCERT_SCEP_STATUS_SUCCESS);

    /* Blocking-session RenewalReq on the same keep-alive connection, covering
     * wolfcert_scep_session_renewal_req_ex. */
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

/* Scenario B: an approval-required server returns PENDING, then issues on the
 * follow-up GetCertInitial - both round trips async on one keep-alive session. */
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

/* Scenario C: async enroll, then an async RenewalReq re-using the same
 * keep-alive session. current_cert/current_key sign the renewal pkiMessage;
 * the auto-approving server issues immediately. Covers
 * wolfcert_scep_session_renewal_req_nb. */
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

    /* First round trip: an initial enrollment to obtain the cert we then renew. */
    REQUIRE_CLEAN(pump_pkcs_req(sess, &caps, ca_der->buffer, ca_der->length,
                          dk, csr.data, csr.len, &r1) == 0);
    REQUIRE_CLEAN(r1.status == WOLFCERT_SCEP_STATUS_SUCCESS);

    REQUIRE_CLEAN(wc_PemToDer(r1.cert_pem.data, (long)r1.cert_pem.len, CERT_TYPE,
                        &cur_der, NULL, NULL, NULL) == 0);

    /* Second round trip on the same connection: RenewalReq signed by the cert
     * just issued (the CSR carries the - here unchanged - public key). */
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

/* Open a loopback listener that completes the TCP handshake (via the kernel
 * backlog) but never accepts, reads, or answers, so a non-blocking HTTP request
 * sent to it is guaranteed to stay in WOLFCERT_ERR_WANT_READ. Returns the
 * listening fd (>= 0) and writes the bound port to *out_port, or -1 on error. */
static int black_hole_listener(uint16_t* out_port)
{
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port        = 0;   /* ephemeral */
    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) != 0 ||
            listen(fd, 16) != 0 ||
            getsockname(fd, (struct sockaddr*)&addr, &addr_len) != 0) {
        close(fd);
        return -1;
    }

    *out_port = ntohs(addr.sin_port);
    return fd;
}

/* Scenario D: session misuse guards. Covers (1) the mode guards that reject an
 * _ex call on an async session and an _nb call on a blocking session, and (2)
 * the in_op guard that rejects starting a different operation while one is
 * already in flight. The in-flight state is held deterministically by pointing
 * the guard sessions at a black-hole listener (accepts the connect, never
 * answers) instead of the real server, so the first non-blocking pump always
 * returns WANT_* regardless of host speed. */
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

    /* Real server: fetch caps + CA and generate a valid key/CSR so the
     * pkiMessage the in-flight guard builds is well-formed. */
    snprintf(real_url, sizeof(real_url), "http://127.0.0.1:%u/scep",
             wolfcert_server_port(s));
    cli_real = (WolfCertServerCfg){ .protocol = WOLFCERT_PROTO_SCEP,
                                    .server_url = real_url };
    REQUIRE_CLEAN(bootstrap(&cli_real, "CN=async-scep-guard", &caps, &ca_pem,
                            &ca_der, &dk, &csr) == 0);

    /* Point the guard sessions at a black hole so a non-blocking request stays
     * in flight deterministically (see black_hole_listener). */
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

    /* in_op guard: begin a PKCSReq against the black hole and leave it in
     * flight, then attempt a different operation on the same session. The peer
     * completes the TCP connect but never answers, so the first pump always
     * returns WANT_* with the request in flight - the in-flight state is
     * independent of host speed, closing the timing hole a real server would
     * open by occasionally replying before the client's first read. */
    rc = wolfcert_scep_session_pkcs_req_nb(asess, &caps,
                ca_der->buffer, ca_der->length, ca_der->buffer, ca_der->length,
                dk, csr.data, csr.len, &r1);
    REQUIRE_CLEAN(rc == WOLFCERT_ERR_WANT_READ || rc == WOLFCERT_ERR_WANT_WRITE);

    /* out-pointer guard: resuming the in-flight PKCSReq (same operation) with a
     * different WolfCertScepResult* than the one captured at begin is rejected,
     * rather than writing the eventual result to the wrong object. The rejected
     * object must still come back defined - wolfcert/scep.h promises a caller
     * can free the result on any outcome - so poison it first. */
    memset(&r2, 0xA5, sizeof(r2));
    REQUIRE_CLEAN(wolfcert_scep_session_pkcs_req_nb(asess, &caps,
                ca_der->buffer, ca_der->length, ca_der->buffer, ca_der->length,
                dk, csr.data, csr.len, &r2) == WOLFCERT_ERR_BAD_ARG);
    REQUIRE_CLEAN(result_is_defined(&r2));

    /* in_op guard: a different operation while one is in flight is rejected. */
    memset(&r2, 0xA5, sizeof(r2));
    REQUIRE_CLEAN(wolfcert_scep_session_renewal_req_nb(asess, &caps,
                ca_der->buffer, ca_der->length, ca_der->buffer, ca_der->length,
                ca_der->buffer, ca_der->length, dk, csr.data, csr.len, &r2)
            == WOLFCERT_ERR_BAD_ARG);
    REQUIRE_CLEAN(result_is_defined(&r2));

    memset(&r2, 0xA5, sizeof(r2));
    REQUIRE_CLEAN(wolfcert_scep_session_get_cert_initial_nb(asess, &caps,
                ca_der->buffer, ca_der->length, ca_der->buffer, ca_der->length,
                NULL, 0, dk, csr.data, csr.len, csr.data, csr.len, &r2)
            == WOLFCERT_ERR_BAD_ARG);
    REQUIRE_CLEAN(result_is_defined(&r2));

    /* The complement: the session's own in-flight result is NOT cleared by a
     * rejected resume, because it belongs to the request still running. */
    REQUIRE_CLEAN(r1.heap != NULL || r1.fail_info == -1);

    ret = 0;
cleanup:
    if (bsess != NULL)
        wolfcert_scep_session_close(bsess);
    if (asess != NULL)
        wolfcert_scep_session_close(asess);   /* resets any in-flight PKCSReq cleanly */
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

/* Scenario E: the blocking mirror of scenario B. A blocking session drives
 * PKCSReq -> PENDING then GetCertInitial -> SUCCESS on one keep-alive
 * connection, covering wolfcert_scep_session_get_cert_initial_ex. Also checks
 * that a transactionID far longer than the generated 32-hex one is carried
 * rather than rejected, since the client imposes no length bound of its own. */
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

    /* A 200-byte transactionID reaches the server intact: the round trip
     * completes and the server answers FAILURE/badCertId for the unknown
     * transaction, rather than the client refusing the argument. */
    memset(long_tid, 0x11, sizeof(long_tid));
    REQUIRE_CLEAN(wolfcert_scep_session_get_cert_initial_ex(sess, &caps,
                ca_der->buffer, ca_der->length, ca_der->buffer, ca_der->length,
                NULL, 0, dk, csr.data, csr.len,
                long_tid, sizeof(long_tid), &r3) == WOLFCERT_OK);
    REQUIRE_CLEAN(r3.status == WOLFCERT_SCEP_STATUS_FAILURE);
    REQUIRE_CLEAN(r3.fail_info == 4);

    ret = 0;
cleanup:
    if (sess != NULL)
        wolfcert_scep_session_close(sess);
    wolfcert_scep_result_free(&r1);
    wolfcert_scep_result_free(&r2);
    wolfcert_scep_result_free(&r3);
    if (ca_der != NULL)
        wc_FreeDer(&ca_der);
    wolfcert_buffer_free(&ca_pem);
    wolfcert_buffer_free(&csr);
    if (dk != NULL)
        wolfcert_key_free(dk);
    return ret;
}

/* Scenario F: force the base64 HTTP GET PKIOperation transport (RFC 8894 4.1)
 * over a session by clearing post_pki_operation in the caps, covering the
 * session's use_post==0 wiring in scep_session_begin (the in-tree server
 * otherwise always advertises POSTPKIOperation). Blocking for brevity. */
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

/* Scenario G: the TLS transport guard. An https:// SCEP session with
 * verify_server unset is refused before any connect; plaintext http:// (used by
 * every other scenario) is accepted. Needs no server - the guard fires during
 * URL parsing in session open. */
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
/* Scenario H: SCEP is RSA-only (RFC 8894); each session begin helper rejects a
 * non-RSA signer with WOLFCERT_ERR_UNSUPPORTED before any network I/O. */
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

/* Scenario I: the non-NULL signer_cert branch of session GetCertInitial. On an
 * approval-required server: enroll -> PENDING -> poll (signer_cert NULL, the
 * derive branch) yields a cert; renew that cert -> PENDING -> poll passing the
 * issued cert as signer_cert (the non-derive branch) -> SUCCESS. */
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

    /* Renew -> PENDING, then poll passing the issued cert as signer_cert
     * (the non-NULL / non-derive branch) -> SUCCESS. */
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

/* A listener thread that accepts one connection and answers HTTP 500, so a
 * session request against it returns WOLFCERT_ERR_HTTP. Polls first so it can
 * never block join() indefinitely if no client shows up. */
static void* stub_500_thread(void* arg)
{
    int lfd = *(int*)arg;
    struct pollfd p = { .fd = lfd, .events = POLLIN };
    int cfd;
    /* As in wait_ready: poll() can report readiness and an error event in the
     * same call, so a positive return alone does not mean accept() will work. */
    if (poll(&p, 1, SCEP_ASYNC_POLL_TIMEOUT_MS) <= 0 ||
            (p.revents & (POLLERR | POLLNVAL)) != 0)
        return NULL;
    cfd = accept(lfd, NULL, NULL);
    if (cfd >= 0) {
        static const char resp[] =
            "HTTP/1.1 500 Internal Server Error\r\n"
            "Content-Length: 0\r\nConnection: close\r\n\r\n";
        char buf[2048];
        (void)recv(cfd, buf, sizeof(buf), 0);         /* read the request head  */
        (void)send(cfd, resp, sizeof(resp) - 1, 0);   /* answer 500             */
        while (recv(cfd, buf, sizeof(buf), MSG_DONTWAIT) > 0)
            ;                                          /* drain for a clean close */
        close(cfd);
    }
    return NULL;
}

/* Scenario J: a session whose HTTP peer answers a non-200 status surfaces
 * WOLFCERT_ERR_HTTP. bootstrap runs against the real server; the enrolling
 * request goes to the 500 stub. */
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

    lfd = black_hole_listener(&port);   /* just need a listening socket to accept on */
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

/* Scenario K: argument-validation guards of the session request APIs. NULL
 * pointers, zero lengths and a NULL caps all return WOLFCERT_ERR_BAD_ARG before
 * any network I/O; also covers the renewal / get_cert_initial mode guards
 * (Scenario D covers pkcs_req). NULL srv and the accessor NULL-safety are
 * covered in tls_guard_path; Scenario E covers an over-long transactionID,
 * which is carried rather than rejected. */
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

    /* Mode-guard sibling coverage: _nb on a blocking session is rejected. */
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
                                 .bind_host = "127.0.0.1", .bind_port = 0 };
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
                                       .bind_host = "127.0.0.1", .bind_port = 0 };
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
                                       .bind_host = "127.0.0.1", .bind_port = 0 };
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

    /* Scenario E: approval-required server, blocking PENDING -> GetCertInitial. */
    WolfCertServerCfgSrv cfg_bpoll = { .protocol = WOLFCERT_PROTO_SCEP,
                                       .bind_host = "127.0.0.1", .bind_port = 0,
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

    /* Scenario F: auto-approve server, session over the base64 GET transport. */
    WolfCertServerCfgSrv cfg_get = { .protocol = WOLFCERT_PROTO_SCEP,
                                     .bind_host = "127.0.0.1", .bind_port = 0 };
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
                                        .bind_host = "127.0.0.1", .bind_port = 0 };
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

    /* Scenario I: approval-required server, renewal PENDING -> poll with a
     * caller-supplied signer_cert. */
    WolfCertServerCfgSrv cfg_rpoll = { .protocol = WOLFCERT_PROTO_SCEP,
                                       .bind_host = "127.0.0.1", .bind_port = 0,
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

    /* Scenario J: auto-approve server for bootstrap; enrolling request hits a
     * 500 stub -> WOLFCERT_ERR_HTTP. */
    WolfCertServerCfgSrv cfg_500 = { .protocol = WOLFCERT_PROTO_SCEP,
                                     .bind_host = "127.0.0.1", .bind_port = 0 };
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
                                     .bind_host = "127.0.0.1", .bind_port = 0 };
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

    wolfcert_cleanup();
    printf("OK\n");
    return 0;
}
