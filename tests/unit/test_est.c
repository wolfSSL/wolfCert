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

/* EST client module against a single-shot loopback TLS responder. */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#define _DARWIN_C_SOURCE   /* expose memmem/strcasestr/INADDR_LOOPBACK on macOS */
#define _GNU_SOURCE

#include <wolfcert/wolfcert.h>
#include "../test_static_mem.h"
#include "internal.h"

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

#ifndef WOLFCERT_HAVE_BUILTIN_TRANSPORT
int main(void)
{
    return 77;
}
#else

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

struct srv_ctx { int listen_fd; uint8_t* body; size_t len; WOLFSSL_CTX* ctx;
                 char request[8192]; size_t request_len;
                 int post_missing_ctenc; };

/* Returns a bound loopback listener and its ephemeral port. */
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

    /* Closing before the CSR body is fully read races the client's send and
     * fails the enroll intermittently, so drain the request first. */
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

    /* The last connection's raw request is kept for the tests. */
    if (n > 0) {
        size_t cap = sizeof(sc->request) - 1;
        size_t cpy = (size_t)n < cap ? (size_t)n : cap;
        memcpy(sc->request, buf, cpy);
        sc->request[cpy] = '\0';
        sc->request_len = cpy;

        /* Counts each enrollment POST lacking the base64 CTE header. */
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

/* A first byte >= 120 decodes to arc 2 with a second arc >= 40. */
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

/* verify_server = 0 gets ERR_TLS from the EST one-shots and session_open,
 * also with a trust anchor set; verify_server = 1 gets IO from the dial. */
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

    /* Each call gets ERR_TLS, even simple_enroll with a placeholder CSR. */
    REQUIRE(wolfcert_est_get_cacerts(&srv, &out) == WOLFCERT_ERR_TLS);
    REQUIRE(wolfcert_est_get_csr_attrs(&srv, &out) == WOLFCERT_ERR_TLS);
    REQUIRE(wolfcert_est_simple_enroll(&srv, dummy_csr, sizeof(dummy_csr),
                                       &out) == WOLFCERT_ERR_TLS);

    /* Reenroll with a generated key so verify_server = 0 is what fails it. */
    REQUIRE(wolfcert_key_generate(&kcfg, &rk) == WOLFCERT_OK);
    REQUIRE(wolfcert_est_simple_reenroll(&srv, dummy_csr, sizeof(dummy_csr), rk,
                                         dummy_csr, sizeof(dummy_csr), &out)
            == WOLFCERT_ERR_TLS);
    wolfcert_key_free(rk);

    REQUIRE(wolfcert_est_session_open(&srv, &sess) == WOLFCERT_ERR_TLS);
    REQUIRE(sess == NULL);

    /* A pinned trust anchor alone does not count as server authentication. */
    srv.trust_anchors     = dummy_ta;
    srv.trust_anchors_len = sizeof(dummy_ta);
    REQUIRE(wolfcert_est_get_cacerts(&srv, &out) == WOLFCERT_ERR_TLS);
    REQUIRE(wolfcert_est_session_open(&srv, &sess) == WOLFCERT_ERR_TLS);

    /* With verify_server on, the dial to port 1 fails with WOLFCERT_ERR_IO. */
    srv.verify_server = 1;
    REQUIRE(wolfcert_est_get_cacerts(&srv, &out) == WOLFCERT_ERR_IO);
    REQUIRE(wolfcert_est_session_open(&srv, &sess) == WOLFCERT_ERR_IO);

    return 0;
}

/* A SCEP config gets BAD_ARG from the EST one-shots and both session opens. */
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

    REQUIRE(wolfcert_est_session_open(&srv, &sess) == WOLFCERT_ERR_BAD_ARG);
    REQUIRE(sess == NULL);
    REQUIRE(wolfcert_est_session_open_async(&srv, &sess) == WOLFCERT_ERR_BAD_ARG);
    REQUIRE(sess == NULL);

    /* protocol = 0 is refused too. */
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

static int est_result_defined(const char* what, int rc, const WolfCertEstResult* r)
{
    if (rc != WOLFCERT_ERR_BAD_ARG) {
        fprintf(stderr, "FAIL %s: expected BAD_ARG, got %d\n", what, rc);
        return 1;
    }
    if (r->status != WOLFCERT_EST_STATUS_UNSET || r->cert_pem.data != NULL ||
            r->cert_pem.len != 0 || r->retry_after_sec != 0 || r->heap != NULL) {
        fprintf(stderr, "FAIL %s: result left indeterminate\n", what);
        return 1;
    }
    return 0;
}

static int test_est_result_defined_on_early_return(void)
{
    WolfCertEstResult r;
    uint8_t           blob[4] = { 1, 2, 3, 4 };
    WolfCertKey*      key = NULL;
#ifdef WOLFCERT_HAVE_RSA
    WolfCertKeyCfg    kcfg = { .type = WOLFCERT_KEY_RSA, .param = 2048,
                               .dev_id = WOLFCERT_DEVID_SOFTWARE };
#else
    WolfCertKeyCfg    kcfg = { .type = WOLFCERT_KEY_ECC, .param = 256,
                               .dev_id = WOLFCERT_DEVID_SOFTWARE };
#endif

    REQUIRE(wolfcert_key_generate(&kcfg, &key) == WOLFCERT_OK);

    memset(&r, 0xA5, sizeof(r));
    if (est_result_defined("simple_enroll_ex",
            wolfcert_est_simple_enroll_ex(NULL, blob, sizeof(blob), &r), &r)) {
        wolfcert_key_free(key);
        return 1;
    }
    wolfcert_est_result_free(&r);

    memset(&r, 0xA5, sizeof(r));
    if (est_result_defined("simple_reenroll_ex",
            wolfcert_est_simple_reenroll_ex(NULL, blob, sizeof(blob), key,
                                            blob, sizeof(blob), &r), &r)) {
        wolfcert_key_free(key);
        return 1;
    }
    wolfcert_est_result_free(&r);

    memset(&r, 0xA5, sizeof(r));
    if (est_result_defined("session_simple_enroll_ex",
            wolfcert_est_session_simple_enroll_ex(NULL, blob, sizeof(blob),
                                                  &r), &r)) {
        wolfcert_key_free(key);
        return 1;
    }
    wolfcert_est_result_free(&r);

    memset(&r, 0xA5, sizeof(r));
    if (est_result_defined("session_simple_enroll_nb_ex",
            wolfcert_est_session_simple_enroll_nb_ex(NULL, blob, sizeof(blob),
                                                     &r), &r)) {
        wolfcert_key_free(key);
        return 1;
    }
    wolfcert_est_result_free(&r);

    if (wolfcert_est_session_simple_enroll_ex(NULL, blob, sizeof(blob), NULL)
            != WOLFCERT_ERR_BAD_ARG ||
        wolfcert_est_session_simple_enroll_nb_ex(NULL, blob, sizeof(blob), NULL)
            != WOLFCERT_ERR_BAD_ARG) {
        fprintf(stderr, "FAIL session enroll _ex: NULL out not rejected\n");
        wolfcert_key_free(key);
        return 1;
    }

    wolfcert_key_free(key);
    return 0;
}

static int test_est_uses_cfg_transport(void)
{
    WolfCertTransport tr = { cfg_tr_connect, cfg_tr_read,
                             cfg_tr_write, cfg_tr_disconnect, NULL };
    WolfCertServerCfg srv = {
        .protocol      = WOLFCERT_PROTO_EST,
        .server_url    = "https://127.0.0.1:1/.well-known/est",
        .verify_server = 1
    };
    WolfCertBuffer out = { 0 };

    srv.transport = tr;
    g_cfg_tr_connects = 0;
    REQUIRE(wolfcert_est_get_cacerts(&srv, &out) != WOLFCERT_OK);
    REQUIRE(g_cfg_tr_connects == 1);
    return 0;
}

/* Drives a non-blocking session enroll, polling the session fd. */
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

/* One request per connection srv_thread() accepts, five in all. */
static int check_empty_body(WOLFSSL_CTX* ctx, const WolfCertServerCfg* tmpl,
                            const uint8_t* csr, size_t csr_len,
                            const uint8_t* cur, size_t cur_len,
                            const WolfCertKey* dk)
{
    struct srv_ctx sc = { .body = NULL, .len = 0, .ctx = ctx };
    WolfCertServerCfg srv = *tmpl;
    WolfCertEstSession* sess = NULL;
    WolfCertBuffer out = { 0 };
    pthread_t tid;
    char url[128];
    int port = 0;

    sc.listen_fd = listen_loopback(&port);
    REQUIRE(sc.listen_fd >= 0);
    REQUIRE(pthread_create(&tid, NULL, srv_thread, &sc) == 0);
    snprintf(url, sizeof(url), "https://127.0.0.1:%d/.well-known/est", port);
    srv.server_url = url;

    REQUIRE(wolfcert_est_get_cacerts(&srv, &out) == WOLFCERT_ERR_HTTP);
    REQUIRE(out.data == NULL);
    REQUIRE(wolfcert_est_simple_enroll(&srv, csr, csr_len, &out)
            == WOLFCERT_ERR_HTTP);
    REQUIRE(out.data == NULL);
    REQUIRE(wolfcert_est_simple_reenroll(&srv, cur, cur_len, dk, csr, csr_len,
                                         &out) == WOLFCERT_ERR_HTTP);
    REQUIRE(out.data == NULL);

    REQUIRE(wolfcert_est_session_open(&srv, &sess) == WOLFCERT_OK);
    REQUIRE(wolfcert_est_session_get_cacerts(sess, &out) == WOLFCERT_ERR_HTTP);
    wolfcert_est_session_close(sess);
    REQUIRE(out.data == NULL);

    sess = NULL;
    REQUIRE(wolfcert_est_session_open(&srv, &sess) == WOLFCERT_OK);
    REQUIRE(wolfcert_est_session_simple_enroll(sess, csr, csr_len, &out)
            == WOLFCERT_ERR_HTTP);
    wolfcert_est_session_close(sess);
    REQUIRE(out.data == NULL);

    pthread_join(tid, NULL);
    return 0;
}

int main(void)
{
    /* The mock responder may write after the client closed the connection. */
    signal(SIGPIPE, SIG_IGN);

    REQUIRE(test_static_mem_init() == 0);
    REQUIRE(wolfcert_init(test_heap_hint()) == WOLFCERT_OK);

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

    if (test_est_result_defined_on_early_return())
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

    /* The mock responder gets a self-signed identity the client pins. */
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

    /* Session enroll sends the base64 CTE header (RFC 7030 section 4.2.1). */
    WolfCertEstSession* sess = NULL;
    REQUIRE(wolfcert_est_session_open(&srv, &sess) == WOLFCERT_OK);
    WolfCertBuffer sess_enrolled = { 0 };
    REQUIRE(wolfcert_est_session_simple_enroll(sess, csr.data, csr.len,
                                               &sess_enrolled) == WOLFCERT_OK);
    REQUIRE(memmem(sess_enrolled.data, sess_enrolled.len,
                   "BEGIN CERTIFICATE", 17) != NULL);
    wolfcert_buffer_free(&sess_enrolled);
    wolfcert_est_session_close(sess);

    /* Non-blocking session enroll also sends the base64 CTE header. */
    WolfCertEstSession* sess_nb = NULL;
    REQUIRE(wolfcert_est_session_open_async(&srv, &sess_nb) == WOLFCERT_OK);
    WolfCertBuffer sess_nb_enrolled = { 0 };
    REQUIRE(pump_simple_enroll(sess_nb, csr.data, csr.len,
                               &sess_nb_enrolled) == 0);
    REQUIRE(memmem(sess_nb_enrolled.data, sess_nb_enrolled.len,
                   "BEGIN CERTIFICATE", 17) != NULL);
    wolfcert_buffer_free(&sess_nb_enrolled);
    wolfcert_est_session_close(sess_nb);

    REQUIRE(check_empty_body(ctx, &srv, csr.data, csr.len, ca_der, ca_len,
                             dk) == 0);

    wolfcert_buffer_free(&csr);
    wolfcert_key_free(dk);
    wolfcert_buffer_free(&b64);
    pthread_join(tid, NULL);

    /* sc.request is the last connection, the non-blocking enroll. */
    REQUIRE(strstr(sc.request, "Content-Transfer-Encoding: base64") != NULL);
    REQUIRE(sc.post_missing_ctenc == 0);
    wolfSSL_CTX_free(ctx);
    free(tls_cert);
    free(tls_key);
    wolfcert_cleanup();
    printf("OK\n");
    return 0;
}

#endif
