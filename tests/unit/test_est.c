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
 * End-to-end test of the EST client module against a single-shot loopback
 * HTTP responder.
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#define _DARWIN_C_SOURCE   /* expose memmem/strcasestr/INADDR_LOOPBACK on macOS */
#define _GNU_SOURCE

#include <wolfcert/wolfcert.h>
#include "../test_static_mem.h"
#include "internal.h"

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/random.h>

#include "../integration/tls_test_util.h"

#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define REQUIRE(cond) \
    do {                                                                    \
        if (!(cond)) {                                                      \
            fprintf(stderr, "FAIL %s:%d %s\n", __FILE__, __LINE__, #cond);  \
            return 1;                                                       \
        }                                                                   \
    } while (0)

static int make_test_ca(uint8_t* out, size_t cap, size_t* out_len)
{
    test_signkey key;
    WC_RNG rng;
    Cert cert;
    int sz;

    if (wc_InitRng(&rng) != 0)
        return -1;
    if (test_signkey_make(&key, &rng) != 0) {
        wc_FreeRng(&rng);
        return -1;
    }

    wc_InitCert(&cert);
    strcpy(cert.subject.commonName, "wolfCert Test CA");
    strcpy(cert.subject.org,        "wolfCert");
    strcpy(cert.subject.country,    "US");
    cert.isCA       = 1;
    cert.sigType    = TEST_CERT_SIGTYPE;
    cert.selfSigned = 1;
    sz = test_sign_selfcert(&cert, out, (int)cap, &key, &rng);
    if (sz <= 0)
        goto fail;
    *out_len = (size_t)sz;
    test_signkey_free(&key);
    wc_FreeRng(&rng);
    return 0;
fail:
    test_signkey_free(&key);
    wc_FreeRng(&rng);
    return -1;
}

/* EST is TLS-only (RFC 7030), so the mock responder terminates TLS using a
 * self-signed identity the client pins as its trust anchor. */
struct srv_ctx { int listen_fd; uint8_t* body; size_t len; WOLFSSL_CTX* ctx;
                 char request[8192]; size_t request_len;
                 int post_missing_ctenc; };

/* Bind a loopback listener and report the ephemeral port it landed on.
 * Callers run this before spawning the responder thread, so the port never
 * has to travel back across the thread boundary. */
static int listen_loopback(int* port)
{
    int ls = socket(AF_INET, SOCK_STREAM, 0);
    if (ls < 0)
        return -1;
    int yes = 1;
    setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    struct sockaddr_in sa = { .sin_family = AF_INET, .sin_port = htons(0),
                              .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    if (bind(ls, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
        close(ls);
        return -1;
    }
    if (listen(ls, 2) < 0) {
        close(ls);
        return -1;
    }
    socklen_t slen = sizeof(sa);
    if (getsockname(ls, (struct sockaddr*)&sa, &slen) < 0) {
        close(ls);
        return -1;
    }
    *port = ntohs(sa.sin_port);
    return ls;
}

static void tls_write_all(WOLFSSL* ssl, const void* buf, int len)
{
    const uint8_t* p = buf;
    int n = 0;
    while (n < len) {
        int r = wolfSSL_write(ssl, p + n, len - n);
        if (r <= 0)
            break;
        n += r;
    }
}

static void handle_conn(int cs, struct srv_ctx* sc)
{
    WOLFSSL* ssl = wolfSSL_new(sc->ctx);
    if (ssl == NULL) {
        close(cs);
        return;
    }
    wolfSSL_set_fd(ssl, cs);
    if (wolfSSL_accept(ssl) != WOLFSSL_SUCCESS) {
        wolfSSL_free(ssl);
        close(cs);
        return;
    }

    /* Read the request headers, then drain the body. The canned response is
     * the same regardless of the request, but we must still consume the whole
     * request before responding + closing: a POST /simpleenroll carries the
     * CSR, and shutting the connection while the client is still writing that
     * body races the client's send and intermittently fails the enroll. */
    char buf[8192];
    int n = 0;
    char* hdr_end = NULL;
    while (n < (int)sizeof(buf) - 1) {
        int r = wolfSSL_read(ssl, buf + n, (int)sizeof(buf) - 1 - n);
        if (r <= 0)
            break;
        n += r;
        buf[n] = '\0';
        hdr_end = strstr(buf, "\r\n\r\n");
        if (hdr_end != NULL)
            break;
    }

    if (hdr_end != NULL) {
        int  header_len = (int)(hdr_end - buf) + 4;
        long content_length = 0;
        char* cl = strcasestr(buf, "Content-Length:");
        if (cl != NULL && cl < hdr_end)
            content_length = strtol(cl + 15, NULL, 10);

        while ((long)(n - header_len) < content_length &&
               n < (int)sizeof(buf) - 1) {
            int r = wolfSSL_read(ssl, buf + n, (int)sizeof(buf) - 1 - n);
            if (r <= 0)
                break;
            n += r;
        }
    }

    /* Record the raw request so a test can inspect which headers the
     * client emitted on the wire. The last connection wins. */
    if (n > 0) {
        size_t cap = sizeof(sc->request) - 1;
        size_t cpy = (size_t)n < cap ? (size_t)n : cap;
        memcpy(sc->request, buf, cpy);
        sc->request[cpy] = '\0';
        sc->request_len = cpy;

        /* Every base64 enrollment POST must advertise the encoding. Count
         * any POST that does not, so a regression in either session enroll
         * variant is caught, not only the last request captured above. */
        if (strncmp(sc->request, "POST", 4) == 0 &&
            strstr(sc->request, "Content-Transfer-Encoding: base64") == NULL)
            ++sc->post_missing_ctenc;
    }

    char hdr[256];
    int hn = snprintf(hdr, sizeof(hdr),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/pkcs7-mime; smime-type=certs-only\r\n"
        "Content-Transfer-Encoding: base64\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n\r\n", sc->len);
    tls_write_all(ssl, hdr, hn);
    tls_write_all(ssl, sc->body, (int)sc->len);
    wolfSSL_shutdown(ssl);
    wolfSSL_free(ssl);
    close(cs);
}

static void* srv_thread(void* arg)
{
    struct srv_ctx* sc = (struct srv_ctx*)arg;

    for (int i = 0; i < 5; ++i) {
        int cs = accept(sc->listen_fd, NULL, NULL);
        if (cs < 0)
            break;
        handle_conn(cs, sc);
    }
    close(sc->listen_fd);
    return NULL;
}

/* wolfcert_oid_to_dotted must decode the first two arcs correctly even when
 * the leading byte is >= 120 (node1 == 2, node2 >= 40), not just for the
 * common OIDs whose first byte is < 80. */
static int test_oid_to_dotted(void)
{
    char out[128];

    const uint8_t high[] = { 0x78, 0x03 };   /* 40*2 + 40 = 120 -> 2.40.3 */
    wolfcert_oid_to_dotted(high, sizeof(high), out, sizeof(out));
    REQUIRE(strcmp(out, "2.40.3") == 0);

    const uint8_t low[] = { 0x2A, 0x03 };    /* 40*1 + 2 = 42 -> 1.2.3 */
    wolfcert_oid_to_dotted(low, sizeof(low), out, sizeof(out));
    REQUIRE(strcmp(out, "1.2.3") == 0);

    /* An empty OID must still leave a valid, empty C string. */
    memset(out, 'x', sizeof(out));
    wolfcert_oid_to_dotted(NULL, 0, out, sizeof(out));
    REQUIRE(out[0] == '\0');

    return 0;
}

/* wolfcert_hex_encode writes exactly 2 * in_len characters in the requested
 * case and touches nothing beyond them (callers such as url_encode and the SCEP
 * transactionID builders rely on both properties). */
static int test_hex_encode(void)
{
    const uint8_t in[] = { 0x00, 0x0f, 0xa5, 0xff };
    char out[16];

    memset(out, 'x', sizeof(out));
    wolfcert_hex_encode(in, sizeof(in), 0, out);
    REQUIRE(memcmp(out, "000fa5ff", 8) == 0);
    REQUIRE(out[8] == 'x');                  /* no NUL terminator, no overrun */

    memset(out, 'x', sizeof(out));
    wolfcert_hex_encode(in, sizeof(in), 1, out);
    REQUIRE(memcmp(out, "000FA5FF", 8) == 0);
    REQUIRE(out[8] == 'x');

    /* Single-byte encoding, the shape url_encode uses per escaped byte. */
    memset(out, 'x', sizeof(out));
    wolfcert_hex_encode(in + 2, 1, 1, out);
    REQUIRE(memcmp(out, "A5", 2) == 0);
    REQUIRE(out[2] == 'x');

    /* Zero length and NULL input must leave the buffer alone. */
    wolfcert_hex_encode(in, 0, 1, out);
    wolfcert_hex_encode(NULL, sizeof(in), 1, out);
    REQUIRE(out[0] == 'A' && out[1] == '5' && out[2] == 'x');

    return 0;
}

/* RFC 7030 mandates that an EST client authenticate the server. In this
 * transport verify_server is the only switch that turns on peer verification,
 * so any config that leaves it at its zero default must be refused - with or
 * without a pinned trust anchor - before an HTTP Basic credential or a CSR
 * crosses the wire, rather than silently completing a VERIFY_NONE handshake. */
static int test_est_require_server_auth(void)
{
    static const uint8_t dummy_ta[]  = { 0x30, 0x03, 0x02, 0x01, 0x00 };
    static const uint8_t dummy_csr[] = { 0x30, 0x03, 0x02, 0x01, 0x00 };
    WolfCertServerCfg srv = {
        .protocol      = WOLFCERT_PROTO_EST,
        .server_url    = "https://127.0.0.1:1/.well-known/est",
        .verify_server = 0
    };
    WolfCertBuffer out = { 0 };
    WolfCertEstSession* sess = NULL;
    WolfCertKeyCfg kcfg = { .type = TEST_ENROLL_KEY_TYPE, .param = TEST_ENROLL_KEY_PARAM,
                            .dev_id = WOLFCERT_DEVID_SOFTWARE };
    WolfCertKey* rk = NULL;

    /* verify_server off, no trust anchor: every entry point must be rejected
     * at the TLS gate, before the transport is dialed, so the assertion is
     * the gate's own WOLFCERT_ERR_TLS rather than a downstream connect
     * failure. The enroll path is the one that actually transmits the Basic
     * credentials and the CSR, so it is asserted directly; the gate fires
     * before the CSR bytes are parsed, so a placeholder CSR is fine. */
    REQUIRE(wolfcert_est_get_cacerts(&srv, &out) == WOLFCERT_ERR_TLS);
    REQUIRE(wolfcert_est_get_csr_attrs(&srv, &out) == WOLFCERT_ERR_TLS);
    REQUIRE(wolfcert_est_simple_enroll(&srv, dummy_csr, sizeof(dummy_csr),
                                       &out) == WOLFCERT_ERR_TLS);

    /* Reenroll shares the same gate, but it fires inside post_enroll_ex after
     * the current key is serialized to PEM, so it needs a real key to reach
     * the gate rather than tripping an earlier argument check. */
    REQUIRE(wolfcert_key_generate(&kcfg, &rk) == WOLFCERT_OK);
    REQUIRE(wolfcert_est_simple_reenroll(&srv, dummy_csr, sizeof(dummy_csr), rk,
                                         dummy_csr, sizeof(dummy_csr), &out)
            == WOLFCERT_ERR_TLS);
    wolfcert_key_free(rk);

    REQUIRE(wolfcert_est_session_open(&srv, &sess) == WOLFCERT_ERR_TLS);
    REQUIRE(sess == NULL);

    /* A pinned trust anchor is not enough: verify_server alone drives peer
     * verification, so verify_server=0 stays refused even with a trust anchor.
     * The gate must not be fooled into treating a loaded-but-unenforced trust
     * anchor as server authentication. */
    srv.trust_anchors     = dummy_ta;
    srv.trust_anchors_len = sizeof(dummy_ta);
    REQUIRE(wolfcert_est_get_cacerts(&srv, &out) == WOLFCERT_ERR_TLS);
    REQUIRE(wolfcert_est_session_open(&srv, &sess) == WOLFCERT_ERR_TLS);

    /* An authenticated config (verify_server on) passes the gate and reaches
     * the transport, failing only because nothing is listening on port 1,
     * which surfaces as WOLFCERT_ERR_IO - proving the gate does not
     * over-refuse a legitimate request. */
    srv.verify_server = 1;
    REQUIRE(wolfcert_est_get_cacerts(&srv, &out) == WOLFCERT_ERR_IO);
    REQUIRE(wolfcert_est_session_open(&srv, &sess) == WOLFCERT_ERR_IO);

    return 0;
}

/* WolfCertServerCfg.protocol discriminates the proto_opts union, so an EST
 * entry point handed a SCEP config must refuse it rather than read the wrong
 * arm. The overlay is actively dangerous: proto_opts.scep.txid_mode and
 * .content_cipher share storage with proto_opts.est.password, so reading the
 * EST arm here would hand basic_auth_header a pointer fabricated from two
 * enum values. Every rejection happens before any network access. */
static int test_est_rejects_scep_cfg(void)
{
    static const uint8_t dummy_csr[] = { 0x30, 0x03, 0x02, 0x01, 0x00 };
    WolfCertServerCfg srv = {
        .protocol      = WOLFCERT_PROTO_SCEP,
        .server_url    = "https://127.0.0.1:1/scep",
        .verify_server = 1,
        .proto_opts.scep = {
            .ca_id          = "RolloverCA",
            .txid_mode      = WOLFCERT_SCEP_TXID_PUBKEY_HASH,
            .content_cipher = WOLFCERT_SCEP_CIPHER_AES256
        }
    };
    WolfCertBuffer out = { 0 };
    WolfCertEstSession* sess = NULL;
    WolfCertKeyCfg kcfg = { .type = TEST_ENROLL_KEY_TYPE, .param = TEST_ENROLL_KEY_PARAM,
                            .dev_id = WOLFCERT_DEVID_SOFTWARE };
    WolfCertKey* rk = NULL;

    REQUIRE(wolfcert_est_get_cacerts(&srv, &out) == WOLFCERT_ERR_BAD_ARG);
    REQUIRE(wolfcert_est_get_csr_attrs(&srv, &out) == WOLFCERT_ERR_BAD_ARG);
    REQUIRE(wolfcert_est_simple_enroll(&srv, dummy_csr, sizeof(dummy_csr),
                                       &out) == WOLFCERT_ERR_BAD_ARG);

    REQUIRE(wolfcert_key_generate(&kcfg, &rk) == WOLFCERT_OK);
    REQUIRE(wolfcert_est_simple_reenroll(&srv, dummy_csr, sizeof(dummy_csr), rk,
                                         dummy_csr, sizeof(dummy_csr), &out)
            == WOLFCERT_ERR_BAD_ARG);
    wolfcert_key_free(rk);

    /* Both session-open paths gate on the discriminator too, before they copy
     * the credentials out of the union. */
    REQUIRE(wolfcert_est_session_open(&srv, &sess) == WOLFCERT_ERR_BAD_ARG);
    REQUIRE(sess == NULL);
    REQUIRE(wolfcert_est_session_open_async(&srv, &sess) == WOLFCERT_ERR_BAD_ARG);
    REQUIRE(sess == NULL);

    /* An unset discriminator is refused for the same reason: nothing says
     * which arm of the union the caller populated. */
    srv.protocol = (WolfCertProtocol)0;
    REQUIRE(wolfcert_est_get_cacerts(&srv, &out) == WOLFCERT_ERR_BAD_ARG);
    REQUIRE(wolfcert_est_session_open(&srv, &sess) == WOLFCERT_ERR_BAD_ARG);

    return 0;
}

/* The built-in transport would fail this dial too, so only the count proves
 * srv.transport reached the HTTP layer. */
static int g_cfg_tr_connects;

static int cfg_tr_connect(void* ctx, const char* h, int p, int t, void** o)
{
    (void)ctx; (void)h; (void)p; (void)t; (void)o;
    ++g_cfg_tr_connects;
    return WOLFCERT_ERR_IO;
}

static int cfg_tr_read(void* ctx, void* c, uint8_t* b, size_t n, int t)
{
    (void)ctx; (void)c; (void)b; (void)n; (void)t;
    return WOLFCERT_ERR_IO;
}

static int cfg_tr_write(void* ctx, void* c, const uint8_t* b, size_t n, int t)
{
    (void)ctx; (void)c; (void)b; (void)n; (void)t;
    return WOLFCERT_ERR_IO;
}

static int cfg_tr_disconnect(void* ctx, void* c)
{
    (void)ctx; (void)c;
    return WOLFCERT_OK;
}

static int test_est_uses_cfg_transport(void)
{
    static const WolfCertTransport tr = { cfg_tr_connect, cfg_tr_read,
                                          cfg_tr_write, cfg_tr_disconnect,
                                          NULL };
    WolfCertServerCfg srv = {
        .protocol      = WOLFCERT_PROTO_EST,
        .server_url    = "https://127.0.0.1:1/.well-known/est",
        .verify_server = 1,
        .transport     = &tr
    };
    WolfCertBuffer out = { 0 };

    g_cfg_tr_connects = 0;
    REQUIRE(wolfcert_est_get_cacerts(&srv, &out) != WOLFCERT_OK);
    REQUIRE(g_cfg_tr_connects == 1);
    return 0;
}

/* Drive a non-blocking session enroll to completion, poll()ing on the
 * session fd between WANT_READ / WANT_WRITE returns. */
static int pump_simple_enroll(WolfCertEstSession* s,
                              const uint8_t* csr, size_t csr_len,
                              WolfCertBuffer* out)
{
    int fd = wolfcert_est_session_fd(s);
    for (;;) {
        int rc = wolfcert_est_session_simple_enroll_nb(s, csr, csr_len, out);
        if (rc == WOLFCERT_OK)
            return 0;
        if (rc == WOLFCERT_ERR_WANT_READ || rc == WOLFCERT_ERR_WANT_WRITE) {
            struct pollfd p = {
                .fd = fd,
                .events = (rc == WOLFCERT_ERR_WANT_WRITE) ? POLLOUT : POLLIN,
            };
            if (poll(&p, 1, 5000) <= 0)
                return -1;
            continue;
        }
        return -1;
    }
}

int main(void)
{
    /* The mock TLS responder may wolfSSL_write() after the client has read its
     * response and closed the connection ("Connection: close"); don't die on
     * the resulting SIGPIPE. */
    signal(SIGPIPE, SIG_IGN);

    REQUIRE(test_static_mem_init() == 0);
    REQUIRE(wolfcert_init(NULL) == WOLFCERT_OK);

    if (test_oid_to_dotted())
        return 1;

    if (test_hex_encode())
        return 1;

    if (test_est_require_server_auth())
        return 1;

    if (test_est_rejects_scep_cfg())
        return 1;

    if (test_est_uses_cfg_transport())
        return 1;

    uint8_t ca_der[4096];
    size_t ca_len = 0;
    REQUIRE(make_test_ca(ca_der, sizeof(ca_der), &ca_len) == 0);

    const uint8_t* certs_arr[1] = { ca_der };
    size_t certs_sz[1] = { ca_len };
    WolfCertBuffer p7 = { 0 };
    REQUIRE(wolfcert_pkcs7_build_certs_only(certs_arr, certs_sz, 1, &p7, NULL) == WOLFCERT_OK);

    WolfCertBuffer b64 = { 0 };
    REQUIRE(wolfcert_base64_encode(p7.data, p7.len, &b64, NULL) == WOLFCERT_OK);
    wolfcert_buffer_free(&p7);

    /* EST runs over TLS (RFC 7030): give the mock responder a self-signed
     * identity and pin it as the client trust anchor. */
    uint8_t *tls_cert = NULL, *tls_key = NULL;
    size_t tls_cert_len = 0, tls_key_len = 0;
    REQUIRE(gen_server_identity(&tls_cert, &tls_cert_len,
                                &tls_key, &tls_key_len) == 0);
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(wolfSSLv23_server_method());
    REQUIRE(ctx != NULL);
    REQUIRE(wolfSSL_CTX_use_certificate_buffer(ctx, tls_cert, (long)tls_cert_len,
            WOLFSSL_FILETYPE_PEM) == WOLFSSL_SUCCESS);
    REQUIRE(wolfSSL_CTX_use_PrivateKey_buffer(ctx, tls_key, (long)tls_key_len,
            WOLFSSL_FILETYPE_PEM) == WOLFSSL_SUCCESS);

    struct srv_ctx sc = { .body = b64.data, .len = b64.len, .ctx = ctx };
    pthread_t tid;
    int port = 0;
    sc.listen_fd = listen_loopback(&port);
    REQUIRE(sc.listen_fd >= 0);
    REQUIRE(pthread_create(&tid, NULL, srv_thread, &sc) == 0);

    char url[128];
    snprintf(url, sizeof(url), "https://127.0.0.1:%d/.well-known/est", port);
    WolfCertServerCfg srv = { .protocol = WOLFCERT_PROTO_EST, .server_url = url,
                              .trust_anchors = tls_cert,
                              .trust_anchors_len = tls_cert_len,
                              .verify_server = 1 };

    WolfCertBuffer ca_pem = { 0 };
    REQUIRE(wolfcert_est_get_cacerts(&srv, &ca_pem) == WOLFCERT_OK);
    REQUIRE(memmem(ca_pem.data, ca_pem.len, "BEGIN CERTIFICATE", 17) != NULL);
    wolfcert_buffer_free(&ca_pem);

    WolfCertKeyCfg kcfg = { .type = TEST_ENROLL_KEY_TYPE, .param = TEST_ENROLL_KEY_PARAM,
                            .dev_id = WOLFCERT_DEVID_SOFTWARE };
    WolfCertKey* dk = NULL;
    REQUIRE(wolfcert_key_generate(&kcfg, &dk) == WOLFCERT_OK);
    WolfCertCertMeta meta = { .subject_dn = "CN=device-99" };
    WolfCertBuffer csr = { 0 };
    REQUIRE(wolfcert_csr_build(dk, &meta, &csr) == WOLFCERT_OK);

    WolfCertBuffer enrolled = { 0 };
    REQUIRE(wolfcert_est_simple_enroll(&srv, csr.data, csr.len, &enrolled) == WOLFCERT_OK);
    REQUIRE(memmem(enrolled.data, enrolled.len, "BEGIN CERTIFICATE", 17) != NULL);
    wolfcert_buffer_free(&enrolled);

    WolfCertBuffer reenrolled = { 0 };
    REQUIRE(wolfcert_est_simple_reenroll(&srv, ca_der, ca_len, dk,
                                         csr.data, csr.len, &reenrolled) == WOLFCERT_OK);
    wolfcert_buffer_free(&reenrolled);

    /* The session-based enroll base64-encodes the CSR too, so it must
     * emit Content-Transfer-Encoding: base64 like the one-shot path
     * (RFC 7030 section 4.2.1). */
    WolfCertEstSession* sess = NULL;
    REQUIRE(wolfcert_est_session_open(&srv, &sess) == WOLFCERT_OK);
    WolfCertBuffer sess_enrolled = { 0 };
    REQUIRE(wolfcert_est_session_simple_enroll(sess, csr.data, csr.len,
                                               &sess_enrolled) == WOLFCERT_OK);
    REQUIRE(memmem(sess_enrolled.data, sess_enrolled.len,
                   "BEGIN CERTIFICATE", 17) != NULL);
    wolfcert_buffer_free(&sess_enrolled);
    wolfcert_est_session_close(sess);

    /* Same requirement for the non-blocking session enroll, which shares the
     * base64 body path: drive it through a poll loop and confirm its request
     * carries the header too. */
    WolfCertEstSession* sess_nb = NULL;
    REQUIRE(wolfcert_est_session_open_async(&srv, &sess_nb) == WOLFCERT_OK);
    WolfCertBuffer sess_nb_enrolled = { 0 };
    REQUIRE(pump_simple_enroll(sess_nb, csr.data, csr.len,
                               &sess_nb_enrolled) == 0);
    REQUIRE(memmem(sess_nb_enrolled.data, sess_nb_enrolled.len,
                   "BEGIN CERTIFICATE", 17) != NULL);
    wolfcert_buffer_free(&sess_nb_enrolled);
    wolfcert_est_session_close(sess_nb);

    wolfcert_buffer_free(&csr);
    wolfcert_key_free(dk);
    wolfcert_buffer_free(&b64);
    pthread_join(tid, NULL);

    /* sc.request holds the last connection, the non-blocking enroll;
     * post_missing_ctenc catches any POST enrollment, the blocking session
     * variant included, that dropped the header. */
    REQUIRE(strstr(sc.request, "Content-Transfer-Encoding: base64") != NULL);
    REQUIRE(sc.post_missing_ctenc == 0);
    wolfSSL_CTX_free(ctx);
    free(tls_cert);
    free(tls_key);
    wolfcert_cleanup();
    printf("OK\n");
    return 0;
}
