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
#include "../test_certs.h"
#include "internal.h"
#if defined(WOLFCERT_HAVE_RSA) && defined(WC_RSA_PSS)
#define USE_CERT_BUFFERS_2048
#include <wolfssl/certs_test.h>
#endif

#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/pkcs7.h>
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

/* A cert for dk's public key, signed by a throwaway key. */
static int make_device_cert(const WolfCertKey* dk, uint8_t* out, size_t cap,
                            size_t* out_len)
{
    test_signkey key;
    WC_RNG rng;
    Cert cert;
    int type;
    int sz;

    switch (dk->type) {
        case WOLFCERT_KEY_RSA:     type = RSA_TYPE;     break;
        case WOLFCERT_KEY_ECC:     type = ECC_TYPE;     break;
        case WOLFCERT_KEY_ED25519: type = ED25519_TYPE; break;
        case WOLFCERT_KEY_ED448:   type = ED448_TYPE;   break;
        default:                   return -1;
    }
    if (wc_InitRng(&rng) != 0)
        return -1;
    if (test_signkey_make(&key, &rng) != 0) {
        wc_FreeRng(&rng);
        return -1;
    }

    wc_InitCert(&cert);
    strcpy(cert.subject.commonName, "device-99");
    strcpy(cert.issuer.commonName,  "wolfCert Test CA");
    cert.sigType = TEST_CERT_SIGTYPE;
    sz = wc_MakeCert_ex(&cert, out, (word32)cap, type, dk->impl, &rng);
    if (sz > 0) {
#if !defined(NO_RSA)
        sz = wc_SignCert(cert.bodySz, cert.sigType, out, (word32)cap, &key,
                         NULL, &rng);
#else
        sz = wc_SignCert(cert.bodySz, cert.sigType, out, (word32)cap, NULL,
                         &key, &rng);
#endif
    }
    test_signkey_free(&key);
    wc_FreeRng(&rng);
    if (sz <= 0)
        return -1;
    *out_len = (size_t)sz;
    return 0;
}

struct srv_ctx { int listen_fd; uint8_t* body; size_t len; WOLFSSL_CTX* ctx;
                 char request[8192]; size_t request_len;
                 int post_missing_ctenc; int status; int conns; };

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
        "HTTP/1.1 %d X\r\n"
        "Content-Type: application/pkcs7-mime; smime-type=certs-only\r\n"
        "Content-Transfer-Encoding: base64\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n\r\n", sc->status ? sc->status : 200,
        sc->len);
    tls_write_all(ssl, hdr, hn);
    tls_write_all(ssl, sc->body, (int)sc->len);
    wolfSSL_shutdown(ssl);
    wolfSSL_free(ssl);
    close(cs);
}

static void* srv_thread(void* arg)
{
    struct srv_ctx* sc = (struct srv_ctx*)arg;

    for (int i = 0; i < (sc->conns ? sc->conns : 5); ++i) {
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
    WolfCertEstResult res = { 0 };
    WolfCertEstSession* sess = NULL;
    WolfCertKeyCfg kcfg = { .type = TEST_ENROLL_KEY_TYPE, .param = TEST_ENROLL_KEY_PARAM,
                            .dev_id = INVALID_DEVID };
    WolfCertKey* rk = NULL;

    /* Each call gets ERR_TLS, even simple_enroll with a placeholder CSR. */
    REQUIRE(wolfcert_est_get_cacerts(&srv, WOLFCERT_ENCODING_PEM,
                                     &out) == WOLFCERT_ERR_TLS);
    REQUIRE(wolfcert_est_get_csr_attrs(&srv, &out) == WOLFCERT_ERR_TLS);
    REQUIRE(wolfcert_est_simple_enroll(&srv, dummy_csr, sizeof(dummy_csr),
                                       &res) == WOLFCERT_ERR_TLS);

    /* Reenroll with a generated key so verify_server = 0 is what fails it. */
    REQUIRE(wolfcert_key_generate(&kcfg, &rk) == WOLFCERT_OK);
    REQUIRE(wolfcert_est_simple_reenroll(&srv, dummy_csr, sizeof(dummy_csr), rk,
                                         dummy_csr, sizeof(dummy_csr), &res)
            == WOLFCERT_ERR_TLS);
    /* An empty current cert is refused before the config is checked. */
    REQUIRE(wolfcert_est_simple_reenroll(&srv, dummy_csr, 0, rk, dummy_csr,
                                         sizeof(dummy_csr), &res)
            == WOLFCERT_ERR_BAD_ARG);
    wolfcert_key_free(rk);

    REQUIRE(wolfcert_est_session_open(&srv, &sess) == WOLFCERT_ERR_TLS);
    REQUIRE(sess == NULL);

    /* A pinned trust anchor alone does not count as server authentication. */
    srv.trust_anchors     = dummy_ta;
    srv.trust_anchors_len = sizeof(dummy_ta);
    REQUIRE(wolfcert_est_get_cacerts(&srv, WOLFCERT_ENCODING_PEM,
                                     &out) == WOLFCERT_ERR_TLS);
    REQUIRE(wolfcert_est_session_open(&srv, &sess) == WOLFCERT_ERR_TLS);

    /* With verify_server on, the dial to port 1 fails with WOLFCERT_ERR_IO. */
    srv.verify_server = 1;
    REQUIRE(wolfcert_est_get_cacerts(&srv, WOLFCERT_ENCODING_PEM,
                                     &out) == WOLFCERT_ERR_IO);
    REQUIRE(wolfcert_est_session_open(&srv, &sess) == WOLFCERT_ERR_IO);

    /* Bad arguments fail before the dial. */
    REQUIRE(wolfcert_est_get_cacerts(&srv, WOLFCERT_ENCODING_PEM,
                                     NULL) == WOLFCERT_ERR_BAD_ARG);
    REQUIRE(wolfcert_est_simple_enroll(&srv, NULL, 0, &res)
            == WOLFCERT_ERR_BAD_ARG);

    return 0;
}

/* An unknown encoding gets BAD_ARG before the dial, with the output cleared. */
static int test_est_rejects_bad_encoding(void)
{
    WolfCertServerCfg srv = {
        .protocol      = WOLFCERT_PROTO_EST,
        .server_url    = "https://127.0.0.1:1/.well-known/est",
        .verify_server = 1
    };
    WolfCertBuffer out;

    memset(&out, 0xA5, sizeof(out));
    REQUIRE(wolfcert_est_get_cacerts(&srv, (WolfCertEncoding)2, &out)
            == WOLFCERT_ERR_BAD_ARG);
    REQUIRE(out.data == NULL && out.len == 0);
    return 0;
}

/* A SCEP config gets BAD_ARG from the EST one-shots and the session open. */
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
    WolfCertEstResult res = { 0 };
    WolfCertEstSession* sess = NULL;
    WolfCertKeyCfg kcfg = { .type = TEST_ENROLL_KEY_TYPE, .param = TEST_ENROLL_KEY_PARAM,
                            .dev_id = INVALID_DEVID };
    WolfCertKey* rk = NULL;

    REQUIRE(wolfcert_est_get_cacerts(&srv, WOLFCERT_ENCODING_PEM,
                                     &out) == WOLFCERT_ERR_BAD_ARG);
    REQUIRE(wolfcert_est_get_csr_attrs(&srv, &out) == WOLFCERT_ERR_BAD_ARG);
    REQUIRE(wolfcert_est_simple_enroll(&srv, dummy_csr, sizeof(dummy_csr),
                                       &res) == WOLFCERT_ERR_BAD_ARG);

    REQUIRE(wolfcert_key_generate(&kcfg, &rk) == WOLFCERT_OK);
    REQUIRE(wolfcert_est_simple_reenroll(&srv, dummy_csr, sizeof(dummy_csr), rk,
                                         dummy_csr, sizeof(dummy_csr), &res)
            == WOLFCERT_ERR_BAD_ARG);
    wolfcert_key_free(rk);

    REQUIRE(wolfcert_est_session_open(&srv, &sess) == WOLFCERT_ERR_BAD_ARG);
    REQUIRE(sess == NULL);

    /* protocol = 0 is refused too. */
    srv.protocol = (WolfCertProtocol)0;
    REQUIRE(wolfcert_est_get_cacerts(&srv, WOLFCERT_ENCODING_PEM,
                                     &out) == WOLFCERT_ERR_BAD_ARG);
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
                               .dev_id = INVALID_DEVID };
#else
    WolfCertKeyCfg    kcfg = { .type = WOLFCERT_KEY_ECC, .param = 256,
                               .dev_id = INVALID_DEVID };
#endif

    REQUIRE(wolfcert_key_generate(&kcfg, &key) == WOLFCERT_OK);

    memset(&r, 0xA5, sizeof(r));
    if (est_result_defined("simple_enroll",
            wolfcert_est_simple_enroll(NULL, blob, sizeof(blob), &r), &r)) {
        wolfcert_key_free(key);
        return 1;
    }
    wolfcert_est_result_free(&r);

    memset(&r, 0xA5, sizeof(r));
    if (est_result_defined("simple_reenroll",
            wolfcert_est_simple_reenroll(NULL, blob, sizeof(blob), key,
                                         blob, sizeof(blob), &r), &r)) {
        wolfcert_key_free(key);
        return 1;
    }
    wolfcert_est_result_free(&r);

    memset(&r, 0xA5, sizeof(r));
    if (est_result_defined("session_simple_enroll",
            wolfcert_est_session_simple_enroll(NULL, blob, sizeof(blob),
                                               &r), &r)) {
        wolfcert_key_free(key);
        return 1;
    }
    wolfcert_est_result_free(&r);

    memset(&r, 0xA5, sizeof(r));
    if (est_result_defined("session_simple_enroll_nb",
            wolfcert_est_session_simple_enroll_nb(NULL, blob, sizeof(blob),
                                                  &r), &r)) {
        wolfcert_key_free(key);
        return 1;
    }
    wolfcert_est_result_free(&r);

    if (wolfcert_est_session_simple_enroll(NULL, blob, sizeof(blob), NULL)
            != WOLFCERT_ERR_BAD_ARG ||
        wolfcert_est_session_simple_enroll_nb(NULL, blob, sizeof(blob), NULL)
            != WOLFCERT_ERR_BAD_ARG) {
        fprintf(stderr, "FAIL session enroll: NULL out not rejected\n");
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
    REQUIRE(wolfcert_est_get_cacerts(&srv, WOLFCERT_ENCODING_PEM,
                                     &out) != WOLFCERT_OK);
    REQUIRE(g_cfg_tr_connects == 1);
    return 0;
}

/* Drives a non-blocking session enroll, polling the session fd. */
static int pump_simple_enroll(WolfCertEstSession* s,
                              const uint8_t* csr, size_t csr_len,
                              WolfCertEstResult* out)
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
    WolfCertEstResult res = { 0 };
    pthread_t tid;
    char url[128];
    int port = 0;

    sc.listen_fd = listen_loopback(&port);
    REQUIRE(sc.listen_fd >= 0);
    REQUIRE(pthread_create(&tid, NULL, srv_thread, &sc) == 0);
    snprintf(url, sizeof(url), "https://127.0.0.1:%d/.well-known/est", port);
    srv.server_url = url;

    REQUIRE(wolfcert_est_get_cacerts(&srv, WOLFCERT_ENCODING_PEM,
                                     &out) == WOLFCERT_ERR_HTTP);
    REQUIRE(out.data == NULL);
    /* A one-shot closes after its request; a session keeps the connection. */
    REQUIRE(strstr(sc.request, "Connection: close\r\n") != NULL);
    REQUIRE(wolfcert_est_simple_enroll(&srv, csr, csr_len, &res)
            == WOLFCERT_ERR_HTTP);
    REQUIRE(res.cert_pem.data == NULL);
    REQUIRE(wolfcert_est_simple_reenroll(&srv, cur, cur_len, dk, csr, csr_len,
                                         &res) == WOLFCERT_ERR_HTTP);
    REQUIRE(res.cert_pem.data == NULL);

    REQUIRE(wolfcert_est_session_open(&srv, &sess) == WOLFCERT_OK);
    REQUIRE(wolfcert_est_session_get_cacerts(sess, WOLFCERT_ENCODING_PEM,
                                             &out) == WOLFCERT_ERR_HTTP);
    wolfcert_est_session_close(sess);
    REQUIRE(out.data == NULL);
    REQUIRE(strstr(sc.request, "Connection: keep-alive\r\n") != NULL);

    sess = NULL;
    REQUIRE(wolfcert_est_session_open(&srv, &sess) == WOLFCERT_OK);
    REQUIRE(wolfcert_est_session_simple_enroll(sess, csr, csr_len, &res)
            == WOLFCERT_ERR_HTTP);
    wolfcert_est_session_close(sess);
    REQUIRE(res.cert_pem.data == NULL);

    pthread_join(tid, NULL);
    return 0;
}

/* An empty /csrattrs reply: a 401 is WOLFCERT_ERR_AUTH, a 500 is not "no CSR
 * attributes", and a 200, 405 or 501 is. Every outcome leaves the output
 * empty. */
static int check_error_status(WOLFSSL_CTX* ctx, const WolfCertServerCfg* tmpl)
{
    static const struct { int status; int rc; } cases[] = {
        { 401, WOLFCERT_ERR_AUTH }, { 500, WOLFCERT_ERR_HTTP },
        { 200, WOLFCERT_OK },       { 405, WOLFCERT_OK },
        { 501, WOLFCERT_OK },
    };
    WolfCertServerCfg srv = *tmpl;
    WolfCertBuffer out;
    struct srv_ctx sc;
    pthread_t tid;
    char url[128];
    int port = 0;
    size_t i;

    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        sc = (struct srv_ctx){ .ctx = ctx, .status = cases[i].status,
                               .conns = 1 };
        sc.listen_fd = listen_loopback(&port);
        REQUIRE(sc.listen_fd >= 0);
        REQUIRE(pthread_create(&tid, NULL, srv_thread, &sc) == 0);
        snprintf(url, sizeof(url), "https://127.0.0.1:%d/.well-known/est",
                 port);
        srv.server_url = url;

        memset(&out, 0xA5, sizeof(out));
        REQUIRE(wolfcert_est_get_csr_attrs(&srv, &out) == cases[i].rc);
        pthread_join(tid, NULL);
        REQUIRE(out.data == NULL && out.len == 0);
    }
    return 0;
}

/* A body that decodes to nothing is (NULL, 0) for /csrattrs and an HTTP
 * error for a certificate request. */
static int check_body_decodes_empty(WOLFSSL_CTX* ctx,
                                    const WolfCertServerCfg* tmpl,
                                    const uint8_t* csr, size_t csr_len)
{
    static uint8_t body[] = "\r\n";
    struct srv_ctx sc = { .body = body, .len = sizeof(body) - 1, .ctx = ctx,
                          .conns = 5 };
    WolfCertServerCfg srv = *tmpl;
    WolfCertCertMeta meta = { 0 };
    WolfCertBuffer attrs = { .data = (uint8_t*)1, .len = 1 };
    WolfCertBuffer certs = { 0 };
    WolfCertEstResult res = { 0 };
    pthread_t tid;
    char url[128];
    int port = 0;

    sc.listen_fd = listen_loopback(&port);
    REQUIRE(sc.listen_fd >= 0);
    REQUIRE(pthread_create(&tid, NULL, srv_thread, &sc) == 0);
    snprintf(url, sizeof(url), "https://127.0.0.1:%d/.well-known/est", port);
    srv.server_url = url;

    REQUIRE(wolfcert_est_get_csr_attrs(&srv, &attrs) == WOLFCERT_OK);
    REQUIRE(attrs.data == NULL && attrs.len == 0);
    REQUIRE(wolfcert_client_fetch_meta(NULL, &srv, &meta) == WOLFCERT_OK);
    REQUIRE(wolfcert_est_get_cacerts(&srv, WOLFCERT_ENCODING_PEM,
                                     &certs) == WOLFCERT_ERR_HTTP);
    REQUIRE(certs.data == NULL);
    REQUIRE(wolfcert_est_get_cacerts(&srv, WOLFCERT_ENCODING_DER,
                                     &certs) == WOLFCERT_ERR_HTTP);
    REQUIRE(certs.data == NULL);
    REQUIRE(wolfcert_est_simple_enroll(&srv, csr, csr_len, &res)
            == WOLFCERT_ERR_HTTP);
    REQUIRE(res.status == WOLFCERT_EST_STATUS_FAILURE);
    REQUIRE(res.cert_pem.data == NULL);
    pthread_join(tid, NULL);
    REQUIRE(meta.subject_dn == NULL && meta.key_usage == NULL);
    return 0;
}

#ifdef WOLFCERT_HAVE_ECC
/* An issued cert with an unknown critical extension still matches. */
static int test_issued_crit_ext(const uint8_t* ca_der, size_t ca_len)
{
    const uint8_t* certs[2] = { ca_der, crit_ext_cert };
    size_t lens[2] = { ca_len, sizeof(crit_ext_cert) };
    WolfCertIssuedMatch m;
    WolfCertBuffer p7 = { 0 };
    WolfCertBuffer pem = { 0 };
    int rc;

    memset(&m, 0, sizeof(m));
    REQUIRE(wolfcert_public_key_hash(crit_ext_cert, sizeof(crit_ext_cert),
                                     CERT_TYPE, &m.key_oid, m.key_hash, NULL)
            == WOLFCERT_OK);

    REQUIRE(wolfcert_pkcs7_build_certs_only(certs, lens, 2, &p7, NULL)
            == WOLFCERT_OK);
    rc = wolfcert_pkcs7_issued_to_pem(p7.data, p7.len, &m, &pem, NULL);
    wolfcert_buffer_free(&p7);
    REQUIRE(rc == WOLFCERT_OK);
    REQUIRE(test_pem_cert_is(&pem, 0, crit_ext_cert, sizeof(crit_ext_cert)));
    wolfcert_buffer_free(&pem);
    return 0;
}
#endif

#if defined(WOLFCERT_HAVE_ECC) && defined(HAVE_COMP_KEY)
/* crit_ext_cert with its SPKI re-encoded as a compressed point; the signature
 * no longer verifies, which the match does not check. */
static int compress_cert_point(uint8_t* out, size_t cap, size_t* out_len)
{
    const uint8_t* in = crit_ext_cert;
    size_t in_len = sizeof(crit_ext_cert);
    uint8_t spki[256], cspki[256];
    word32 spki_len = sizeof(spki), idx = 0;
    ecc_key key;
    size_t off;
    int clen;

    if (wc_GetSubjectPubKeyInfoDerFromCert(in, (word32)in_len, spki,
                                           &spki_len) < 0)
        return -1;
    for (off = 0; off + spki_len <= in_len; off++)
        if (memcmp(in + off, spki, spki_len) == 0)
            break;
    if (off + spki_len > in_len || wc_ecc_init(&key) != 0)
        return -1;
    clen = wc_EccPublicKeyDecode(spki, &idx, &key, spki_len) == 0 ?
           wc_EccPublicKeyToDer_ex(&key, cspki, sizeof(cspki), 1, 1) : -1;
    wc_ecc_free(&key);
    if (clen <= 0 || (word32)clen >= spki_len || in[1] != 0x82 ||
            in[5] != 0x82 || in_len > cap)
        return -1;

    size_t delta = spki_len - (word32)clen;
    memcpy(out, in, off);
    memcpy(out + off, cspki, (size_t)clen);
    memcpy(out + off + (size_t)clen, in + off + spki_len,
           in_len - off - spki_len);
    for (int i = 2; i <= 6; i += 4) {
        size_t l = (((size_t)in[i] << 8) | in[i + 1]) - delta;
        out[i]     = (uint8_t)(l >> 8);
        out[i + 1] = (uint8_t)l;
    }
    *out_len = in_len - delta;
    return 0;
}

/* A reply cert whose SPKI holds the same ECC key compressed still matches. */
static int test_issued_compressed_point(const uint8_t* ca_der, size_t ca_len)
{
    uint8_t comp[sizeof(crit_ext_cert)];
    size_t comp_len = 0;
    WolfCertIssuedMatch m;
    WolfCertBuffer p7 = { 0 };
    WolfCertBuffer pem = { 0 };
    int rc;

    REQUIRE(compress_cert_point(comp, sizeof(comp), &comp_len) == 0);
    const uint8_t* certs[2] = { ca_der, comp };
    size_t lens[2] = { ca_len, comp_len };

    memset(&m, 0, sizeof(m));
    REQUIRE(wolfcert_public_key_hash(crit_ext_cert, sizeof(crit_ext_cert),
                                     CERT_TYPE, &m.key_oid, m.key_hash, NULL)
            == WOLFCERT_OK);
    REQUIRE(wolfcert_pkcs7_build_certs_only(certs, lens, 2, &p7, NULL)
            == WOLFCERT_OK);
    rc = wolfcert_pkcs7_issued_to_pem(p7.data, p7.len, &m, &pem, NULL);
    wolfcert_buffer_free(&p7);
    REQUIRE(rc == WOLFCERT_OK);
    REQUIRE(test_pem_cert_is(&pem, 0, comp, comp_len));
    wolfcert_buffer_free(&pem);
    return 0;
}
#endif

/* A renewal skips the cert being renewed when the CA sends it first, also
 * when current_cert carries a chain after it, in DER or PEM. */
static int check_renewal_chain(WOLFSSL_CTX* ctx, const WolfCertServerCfg* tmpl,
                               const WolfCertKey* dk, const WolfCertBuffer* csr,
                               const uint8_t* ca_der, size_t ca_len)
{
    uint8_t old[4096], fresh[4096], cur[8192];
    size_t old_len = 0, fresh_len = 0;
    WolfCertBuffer p7 = { 0 };
    WolfCertBuffer b64 = { 0 };
    WolfCertServerCfg srv = *tmpl;
    struct srv_ctx sc;
    pthread_t tid;
    char url[128];
    int port = 0;
    int n;

    REQUIRE(make_device_cert(dk, old, sizeof(old), &old_len) == 0);
    REQUIRE(make_device_cert(dk, fresh, sizeof(fresh), &fresh_len) == 0);
    const uint8_t* certs[2] = { old, fresh };
    size_t lens[2] = { old_len, fresh_len };
    REQUIRE(wolfcert_pkcs7_build_certs_only(certs, lens, 2, &p7, NULL)
            == WOLFCERT_OK);
    REQUIRE(wolfcert_base64_encode(p7.data, p7.len, &b64, NULL)
            == WOLFCERT_OK);
    wolfcert_buffer_free(&p7);

    sc = (struct srv_ctx){ .body = b64.data, .len = b64.len, .ctx = ctx,
                           .conns = 2 };
    sc.listen_fd = listen_loopback(&port);
    REQUIRE(sc.listen_fd >= 0);
    REQUIRE(pthread_create(&tid, NULL, srv_thread, &sc) == 0);
    snprintf(url, sizeof(url), "https://127.0.0.1:%d/.well-known/est", port);
    srv.server_url = url;

    for (int pem = 0; pem <= 1; pem++) {
        WolfCertEstResult res = { 0 };

        if (pem) {
            n = wc_DerToPem(old, (word32)old_len, cur, sizeof(cur), CERT_TYPE);
            REQUIRE(n > 0);
            int m = wc_DerToPem(ca_der, (word32)ca_len, cur + n,
                                sizeof(cur) - (size_t)n, CERT_TYPE);
            REQUIRE(m > 0);
            n += m;
        }
        else {
            memcpy(cur, old, old_len);
            memcpy(cur + old_len, ca_der, ca_len);
            n = (int)(old_len + ca_len);
        }
        REQUIRE(wolfcert_est_simple_reenroll(&srv, cur, (size_t)n, dk,
                                             csr->data, csr->len, &res)
                == WOLFCERT_OK);
        REQUIRE(test_pem_cert_is(&res.cert_pem, 0, fresh, fresh_len));
        REQUIRE(test_pem_cert_is(&res.cert_pem, 1, old, old_len));
        wolfcert_est_result_free(&res);
    }
    pthread_join(tid, NULL);
    wolfcert_buffer_free(&b64);
    return 0;
}

/* Rewrites the ECC or RSA SPKI key OID in der to an unknown OID of the same
 * length; -1 when der holds neither. */
static int unknown_key_oid(uint8_t* der, size_t len)
{
    static const uint8_t ecc[] = { 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D,
                                   0x02, 0x01 };
    static const uint8_t rsa[] = { 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7,
                                   0x0D, 0x01, 0x01, 0x01 };

    for (size_t i = 0; i < len; i++) {
        if (i + sizeof(ecc) <= len && memcmp(der + i, ecc, sizeof(ecc)) == 0) {
            der[i + sizeof(ecc) - 1] = 0x7F;
            return 0;
        }
        if (i + sizeof(rsa) <= len && memcmp(der + i, rsa, sizeof(rsa)) == 0) {
            der[i + sizeof(rsa) - 1] = 0x7F;
            return 0;
        }
    }
    return -1;
}

/* A CSR whose key wolfSSL cannot decode still matches the cert that copies
 * its SubjectPublicKeyInfo. */
static int test_issued_raw_spki(const WolfCertKey* dk,
                                const WolfCertBuffer* csr,
                                const uint8_t* ca_der, size_t ca_len)
{
    uint8_t req[4096], cert[4096];
    size_t cert_len = 0;
    WolfCertIssuedMatch m;
    WolfCertBuffer p7 = { 0 };
    WolfCertBuffer pem = { 0 };
    int rc;

    REQUIRE(csr->len <= sizeof(req));
    memcpy(req, csr->data, csr->len);
    REQUIRE(make_device_cert(dk, cert, sizeof(cert), &cert_len) == 0);
    if (unknown_key_oid(req, csr->len) != 0)
        return 0;
    REQUIRE(unknown_key_oid(cert, cert_len) == 0);

    REQUIRE(wolfcert_issued_match_init(&m, req, csr->len, NULL, 0, NULL)
            == WOLFCERT_OK);
    REQUIRE(m.raw_spki);
    const uint8_t* certs[2] = { ca_der, cert };
    size_t lens[2] = { ca_len, cert_len };
    REQUIRE(wolfcert_pkcs7_build_certs_only(certs, lens, 2, &p7, NULL)
            == WOLFCERT_OK);
    rc = wolfcert_pkcs7_issued_to_pem(p7.data, p7.len, &m, &pem, NULL);
    wolfcert_buffer_free(&p7);
    REQUIRE(rc == WOLFCERT_OK);
    REQUIRE(test_pem_cert_is(&pem, 0, cert, cert_len));
    REQUIRE(test_pem_cert_is(&pem, 1, ca_der, ca_len));
    wolfcert_buffer_free(&pem);
    return 0;
}

/* Body offset of the DER TLV at off, with its length in *n; 0 on error. */
static size_t der_body(const uint8_t* d, size_t len, size_t off, size_t* n)
{
    size_t p = off + 2;

    if (off + 2 > len)
        return 0;
    if (d[off + 1] < 0x80) {
        *n = d[off + 1];
    }
    else if (d[off + 1] == 0x81 && off + 3 <= len) {
        *n = d[off + 2];
        p = off + 3;
    }
    else if (d[off + 1] == 0x82 && off + 4 <= len) {
        *n = ((size_t)d[off + 2] << 8) | d[off + 3];
        p = off + 4;
    }
    else {
        return 0;
    }
    return p + *n <= len ? p : 0;
}

/* A device cert wolfSSL will not parse, its outer signature algorithm no
 * longer matching the TBS one, with the SPKI left intact. */
static int unparseable_cert(const WolfCertKey* dk, uint8_t* out, size_t cap,
                            size_t* out_len)
{
    size_t n = 0, tbs, alg, oid;

    if (make_device_cert(dk, out, cap, out_len) != 0)
        return -1;
    tbs = der_body(out, *out_len, 0, &n);
    if (tbs == 0 || der_body(out, *out_len, tbs, &n) == 0)
        return -1;
    alg = der_body(out, *out_len, tbs, &n) + n;
    if ((oid = der_body(out, *out_len, alg, &n)) == 0 ||
            (oid = der_body(out, *out_len, oid, &n)) == 0 || n == 0)
        return -1;
    out[oid + n - 1] ^= 0x01;
    return 0;
}

/* A CSR wolfSSL reads still matches an issued cert it cannot parse, by the
 * SubjectPublicKeyInfo bytes. */
static int test_issued_unparseable_cert(const WolfCertKey* dk,
                                        const WolfCertBuffer* csr,
                                        const uint8_t* ca_der, size_t ca_len)
{
    uint8_t cert[4096];
    uint8_t hash[WC_SHA256_DIGEST_SIZE];
    size_t cert_len = 0;
    word32 oid = 0;
    WolfCertIssuedMatch m;
    WolfCertBuffer p7 = { 0 };
    WolfCertBuffer pem = { 0 };
    int rc;

    REQUIRE(unparseable_cert(dk, cert, sizeof(cert), &cert_len) == 0);
    REQUIRE(wolfcert_public_key_hash(cert, cert_len, CERT_TYPE, &oid, hash,
                                     NULL) == WOLFCERT_ERR_PARSE);
    REQUIRE(wolfcert_issued_match_init(&m, csr->data, csr->len, NULL, 0,
                                       NULL) == WOLFCERT_OK);
    REQUIRE(!m.raw_spki && m.has_spki);

    const uint8_t* certs[2] = { ca_der, cert };
    size_t lens[2] = { ca_len, cert_len };
    REQUIRE(wolfcert_pkcs7_build_certs_only(certs, lens, 2, &p7, NULL)
            == WOLFCERT_OK);
    rc = wolfcert_pkcs7_issued_to_pem(p7.data, p7.len, &m, &pem, NULL);
    wolfcert_buffer_free(&p7);
    REQUIRE(rc == WOLFCERT_OK);
    REQUIRE(test_pem_cert_is(&pem, 0, cert, cert_len));
    wolfcert_buffer_free(&pem);

    /* A reply cert nothing can read is passed over, not fatal; wolfSSL
     * parses only the first. */
    static const uint8_t junk[] = { 0x30, 0x03, 0x02, 0x01, 0x00 };
    REQUIRE(make_device_cert(dk, cert, sizeof(cert), &cert_len) == 0);
    const uint8_t* three[3] = { ca_der, junk, cert };
    size_t three_len[3] = { ca_len, sizeof(junk), cert_len };
    REQUIRE(wolfcert_pkcs7_build_certs_only(three, three_len, 3, &p7, NULL)
            == WOLFCERT_OK);
    rc = wolfcert_pkcs7_issued_to_pem(p7.data, p7.len, &m, &pem, NULL);
    wolfcert_buffer_free(&p7);
    REQUIRE(rc == WOLFCERT_OK);
    REQUIRE(test_pem_cert_is(&pem, 0, cert, cert_len));
    wolfcert_buffer_free(&pem);
    return 0;
}

/* With the issued cert past the slots wolfSSL keeps, the error says so. */
static int test_issued_max_certs(const WolfCertKey* dk,
                                 const WolfCertBuffer* csr,
                                 const uint8_t* ca_der, size_t ca_len)
{
    const uint8_t* certs[MAX_PKCS7_CERTS + 1];
    size_t lens[MAX_PKCS7_CERTS + 1];
    uint8_t dev[4096];
    size_t dev_len = 0;
    WolfCertIssuedMatch m;
    WolfCertBuffer p7 = { 0 };
    WolfCertBuffer pem = { 0 };
    int rc;

    REQUIRE(make_device_cert(dk, dev, sizeof(dev), &dev_len) == 0);
    for (int i = 0; i < MAX_PKCS7_CERTS; i++) {
        certs[i] = ca_der;
        lens[i]  = ca_len;
    }
    certs[MAX_PKCS7_CERTS] = dev;
    lens[MAX_PKCS7_CERTS]  = dev_len;
    REQUIRE(wolfcert_issued_match_init(&m, csr->data, csr->len, NULL, 0,
                                       NULL) == WOLFCERT_OK);
    REQUIRE(wolfcert_pkcs7_build_certs_only(certs, lens, MAX_PKCS7_CERTS + 1,
                                            &p7, NULL) == WOLFCERT_OK);
    wolfcert_clear_error();
    rc = wolfcert_pkcs7_issued_to_pem(p7.data, p7.len, &m, &pem, NULL);
    wolfcert_buffer_free(&p7);
    wolfcert_buffer_free(&pem);
    REQUIRE(rc == WOLFCERT_ERR_PROTOCOL);
    REQUIRE(strstr(wolfcert_last_error_message(), "MAX_PKCS7_CERTS") != NULL);
    return 0;
}

/* A certs-only reply holding no certs is NOT_FOUND, not a key mismatch. */
static int test_issued_empty_reply(const WolfCertBuffer* csr)
{
    static const uint8_t empty_p7[] = {
        0x30, 0x23, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01,
        0x07, 0x02, 0xa0, 0x16, 0x30, 0x14, 0x02, 0x01, 0x01, 0x31, 0x00,
        0x30, 0x0b, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01,
        0x07, 0x01, 0x31, 0x00
    };
    WolfCertIssuedMatch m;
    WolfCertBuffer pem = { 0 };
    int rc;

    REQUIRE(wolfcert_issued_match_init(&m, csr->data, csr->len, NULL, 0,
                                       NULL) == WOLFCERT_OK);
    /* wolfSSL refuses a cert-less bundle with WC_PKCS7_WANT_READ_E today. */
    rc = wolfcert_pkcs7_issued_to_pem(empty_p7, sizeof(empty_p7), &m, &pem,
                                      NULL);
    REQUIRE(rc != WOLFCERT_OK && rc != WOLFCERT_ERR_PROTOCOL);
    REQUIRE(pem.data == NULL);
    return 0;
}

/* A client cert the match cannot hash only loses the tie-break: the enroll
 * still dials, where the old code failed before it. */
static int test_client_hash_tiebreak(WolfCertKey* dk, const WolfCertBuffer* csr)
{
    static const uint8_t bad_cert[] = { 0x30, 0x84, 0xFF, 0xFF, 0xFF, 0xFF };
    WolfCertTransport tr = { cfg_tr_connect, cfg_tr_read,
                             cfg_tr_write, cfg_tr_disconnect, NULL };
    WolfCertServerCfg srv = {
        .protocol        = WOLFCERT_PROTO_EST,
        .server_url      = "https://127.0.0.1:1/.well-known/est",
        .verify_server   = 1,
        .client_cert     = bad_cert,
        .client_cert_len = sizeof(bad_cert),
        .client_key_obj  = dk,
    };
    WolfCertEstSession* sess = NULL;
    WolfCertEstResult res = { 0 };
    int rc;

    srv.transport = tr;
    g_cfg_tr_connects = 0;
    rc = wolfcert_est_simple_enroll(&srv, csr->data, csr->len, &res);
    wolfcert_est_result_free(&res);
    REQUIRE(rc != WOLFCERT_OK && rc != WOLFCERT_ERR_PARSE);
    REQUIRE(g_cfg_tr_connects == 1);

    g_cfg_tr_connects = 0;
    rc = wolfcert_est_session_open(&srv, &sess);
    if (rc == WOLFCERT_OK) {
        rc = wolfcert_est_session_simple_enroll(sess, csr->data, csr->len,
                                                &res);
        wolfcert_est_result_free(&res);
        wolfcert_est_session_close(sess);
    }
    REQUIRE(rc != WOLFCERT_OK && rc != WOLFCERT_ERR_PARSE);
    REQUIRE(g_cfg_tr_connects == 1);
    return 0;
}

#if defined(WOLFCERT_HAVE_RSA) && defined(WC_RSA_PSS)
/* A CSR key certified under the other RSA SPKI OID, rsaEncryption against
 * RSASSA-PSS, still matches. */
static int test_issued_rsa_pss(const uint8_t* ca_der, size_t ca_len)
{
    static const uint8_t rsa[] = { 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7,
                                   0x0D, 0x01, 0x01, 0x01 };
    uint8_t pss[sizeof(server_cert_der_2048)];
    size_t pss_len = sizeof(server_cert_der_2048);
    WolfCertIssuedMatch m;
    WolfCertBuffer p7 = { 0 };
    WolfCertBuffer pem = { 0 };
    word32 oid = 0;
    size_t i;
    int rc;

    memcpy(pss, server_cert_der_2048, pss_len);
    for (i = 0; i + sizeof(rsa) <= pss_len; i++)
        if (memcmp(pss + i, rsa, sizeof(rsa)) == 0)
            break;
    REQUIRE(i + sizeof(rsa) <= pss_len);
    pss[i + sizeof(rsa) - 1] = 0x0A;
    REQUIRE(wolfcert_public_key_hash(pss, pss_len, CERT_TYPE, &oid,
                                     m.key_hash, NULL) == WOLFCERT_OK);
    REQUIRE(oid == RSAPSSk);

    memset(&m, 0, sizeof(m));
    REQUIRE(wolfcert_public_key_hash(server_cert_der_2048,
                                     sizeof(server_cert_der_2048), CERT_TYPE,
                                     &m.key_oid, m.key_hash, NULL)
            == WOLFCERT_OK);
    const uint8_t* certs[2] = { ca_der, pss };
    size_t lens[2] = { ca_len, pss_len };
    REQUIRE(wolfcert_pkcs7_build_certs_only(certs, lens, 2, &p7, NULL)
            == WOLFCERT_OK);
    rc = wolfcert_pkcs7_issued_to_pem(p7.data, p7.len, &m, &pem, NULL);
    wolfcert_buffer_free(&p7);
    REQUIRE(rc == WOLFCERT_OK);
    REQUIRE(test_pem_cert_is(&pem, 0, pss, pss_len));
    wolfcert_buffer_free(&pem);
    return 0;
}
#endif

/* Serve one canned issued-cert reply holding certs on conns connections. */
static int start_canned(WOLFSSL_CTX* ctx, struct srv_ctx* sc, pthread_t* tid,
                        WolfCertBuffer* b64, const uint8_t* const* certs,
                        const size_t* lens, size_t n, int conns,
                        char* url, size_t url_cap)
{
    WolfCertBuffer p7 = { 0 };
    int port = 0;

    REQUIRE(wolfcert_pkcs7_build_certs_only(certs, lens, n, &p7, NULL)
            == WOLFCERT_OK);
    REQUIRE(wolfcert_base64_encode(p7.data, p7.len, b64, NULL)
            == WOLFCERT_OK);
    wolfcert_buffer_free(&p7);
    *sc = (struct srv_ctx){ .body = b64->data, .len = b64->len, .ctx = ctx,
                            .conns = conns };
    sc->listen_fd = listen_loopback(&port);
    REQUIRE(sc->listen_fd >= 0);
    REQUIRE(pthread_create(tid, NULL, srv_thread, sc) == 0);
    snprintf(url, url_cap, "https://127.0.0.1:%d/.well-known/est", port);
    return 0;
}

/* A same-key renewal answered with only the unchanged cert takes that cert. */
static int check_renewal_unchanged(WOLFSSL_CTX* ctx,
                                   const WolfCertServerCfg* tmpl,
                                   const WolfCertKey* dk,
                                   const WolfCertBuffer* csr)
{
    uint8_t old[4096];
    size_t old_len = 0;
    WolfCertBuffer b64 = { 0 };
    WolfCertServerCfg srv = *tmpl;
    WolfCertEstResult res = { 0 };
    struct srv_ctx sc;
    pthread_t tid;
    char url[128];

    REQUIRE(make_device_cert(dk, old, sizeof(old), &old_len) == 0);
    const uint8_t* certs[1] = { old };
    size_t lens[1] = { old_len };
    REQUIRE(start_canned(ctx, &sc, &tid, &b64, certs, lens, 1, 1, url,
                         sizeof(url)) == 0);
    srv.server_url = url;

    REQUIRE(wolfcert_est_simple_reenroll(&srv, old, old_len, dk, csr->data,
                                         csr->len, &res) == WOLFCERT_OK);
    pthread_join(tid, NULL);
    wolfcert_buffer_free(&b64);
    REQUIRE(res.status == WOLFCERT_EST_STATUS_SUCCESS);
    REQUIRE(test_pem_cert_is(&res.cert_pem, 0, old, old_len));
    wolfcert_est_result_free(&res);
    return 0;
}

/* A simpleenroll under a TLS client cert holding the same key skips that
 * cert when the CA sends it first, one-shot and on a session. */
static int check_enroll_skips_client(WOLFSSL_CTX* ctx,
                                     const WolfCertServerCfg* tmpl,
                                     WolfCertKey* dk,
                                     const WolfCertBuffer* csr)
{
    uint8_t old[4096], fresh[4096];
    size_t old_len = 0, fresh_len = 0;
    WolfCertBuffer b64 = { 0 };
    WolfCertServerCfg srv = *tmpl;
    WolfCertEstSession* sess = NULL;
    WolfCertEstResult res = { 0 };
    struct srv_ctx sc;
    pthread_t tid;
    char url[128];

    REQUIRE(make_device_cert(dk, old, sizeof(old), &old_len) == 0);
    REQUIRE(make_device_cert(dk, fresh, sizeof(fresh), &fresh_len) == 0);
    const uint8_t* certs[2] = { old, fresh };
    size_t lens[2] = { old_len, fresh_len };
    REQUIRE(start_canned(ctx, &sc, &tid, &b64, certs, lens, 2, 2, url,
                         sizeof(url)) == 0);
    srv.server_url      = url;
    srv.client_cert     = old;
    srv.client_cert_len = old_len;
    srv.client_key_obj  = dk;

    REQUIRE(wolfcert_est_simple_enroll(&srv, csr->data, csr->len, &res)
            == WOLFCERT_OK);
    REQUIRE(test_pem_cert_is(&res.cert_pem, 0, fresh, fresh_len));
    REQUIRE(test_pem_cert_is(&res.cert_pem, 1, old, old_len));
    wolfcert_est_result_free(&res);

    REQUIRE(wolfcert_est_session_open(&srv, &sess) == WOLFCERT_OK);
    REQUIRE(wolfcert_est_session_simple_enroll(sess, csr->data, csr->len,
                                               &res) == WOLFCERT_OK);
    wolfcert_est_session_close(sess);
    pthread_join(tid, NULL);
    wolfcert_buffer_free(&b64);
    REQUIRE(test_pem_cert_is(&res.cert_pem, 0, fresh, fresh_len));
    wolfcert_est_result_free(&res);
    return 0;
}

/* A simpleenroll reply holding only the TLS client cert is not an issue,
 * though that cert holds the CSR's key. */
static int check_enroll_only_client(WOLFSSL_CTX* ctx,
                                    const WolfCertServerCfg* tmpl,
                                    WolfCertKey* dk,
                                    const WolfCertBuffer* csr)
{
    uint8_t old[4096];
    size_t old_len = 0;
    WolfCertBuffer b64 = { 0 };
    WolfCertServerCfg srv = *tmpl;
    WolfCertEstResult res = { 0 };
    struct srv_ctx sc;
    pthread_t tid;
    char url[128];
    int rc;

    REQUIRE(make_device_cert(dk, old, sizeof(old), &old_len) == 0);
    const uint8_t* certs[1] = { old };
    size_t lens[1] = { old_len };
    REQUIRE(start_canned(ctx, &sc, &tid, &b64, certs, lens, 1, 1, url,
                         sizeof(url)) == 0);
    srv.server_url      = url;
    srv.client_cert     = old;
    srv.client_cert_len = old_len;
    srv.client_key_obj  = dk;

    rc = wolfcert_est_simple_enroll(&srv, csr->data, csr->len, &res);
    pthread_join(tid, NULL);
    wolfcert_buffer_free(&b64);
    REQUIRE(rc == WOLFCERT_ERR_PROTOCOL);
    REQUIRE(res.status == WOLFCERT_EST_STATUS_FAILURE);
    REQUIRE(test_pem_cert_is(&res.cert_pem, 0, old, old_len));
    wolfcert_est_result_free(&res);
    return 0;
}

/* A CSR wolfSSL cannot parse fails before any request is sent, one-shot and
 * on a session. */
static int check_unparseable_csr(WOLFSSL_CTX* ctx,
                                 const WolfCertServerCfg* tmpl)
{
    static const uint8_t not_csr[] = { 0x30, 0x03, 0x02, 0x01, 0x00 };
    struct srv_ctx sc = { .ctx = ctx, .conns = 1 };
    WolfCertServerCfg srv = *tmpl;
    WolfCertEstSession* sess = NULL;
    WolfCertEstResult res = { 0 };
    pthread_t tid;
    char url[128];
    int port = 0;
    int rc;

    /* The one-shot fails before dialing, which to port 1 would give IO. */
    srv.server_url = "https://127.0.0.1:1/.well-known/est";
    rc = wolfcert_est_simple_enroll(&srv, not_csr, sizeof(not_csr), &res);
    REQUIRE(rc == WOLFCERT_ERR_PARSE);
    REQUIRE(res.status == WOLFCERT_EST_STATUS_UNSET);

    sc.listen_fd = listen_loopback(&port);
    REQUIRE(sc.listen_fd >= 0);
    REQUIRE(pthread_create(&tid, NULL, srv_thread, &sc) == 0);
    snprintf(url, sizeof(url), "https://127.0.0.1:%d/.well-known/est", port);
    srv.server_url = url;
    REQUIRE(wolfcert_est_session_open(&srv, &sess) == WOLFCERT_OK);
    REQUIRE(wolfcert_est_session_simple_enroll(sess, not_csr, sizeof(not_csr),
                                               &res) == WOLFCERT_ERR_PARSE);
    REQUIRE(wolfcert_est_session_simple_enroll_nb(sess, not_csr,
                                                  sizeof(not_csr), &res)
            == WOLFCERT_ERR_PARSE);
    wolfcert_est_session_close(sess);
    pthread_join(tid, NULL);
    REQUIRE(sc.request_len == 0);
    return 0;
}

/* An enroll reply without a cert for the CSR's key is a protocol error. */
static int check_no_key_cert(WOLFSSL_CTX* ctx, const WolfCertServerCfg* tmpl,
                             const uint8_t* csr, size_t csr_len,
                             const uint8_t* ca_der, size_t ca_len)
{
    uint8_t tls_der[4096];
    int tls_len = wc_CertPemToDer(tmpl->trust_anchors,
                                  (int)tmpl->trust_anchors_len, tls_der,
                                  sizeof(tls_der), CERT_TYPE);
    const uint8_t* certs[2] = { ca_der, tls_der };
    size_t lens[2] = { ca_len, 0 };
    WolfCertBuffer p7 = { 0 };
    WolfCertBuffer b64 = { 0 };
    WolfCertServerCfg srv = *tmpl;
    WolfCertEstResult res = { 0 };
    struct srv_ctx sc;
    pthread_t tid;
    char url[128];
    int port = 0;
    int rc;

    REQUIRE(tls_len > 0);
    lens[1] = (size_t)tls_len;
    REQUIRE(wolfcert_pkcs7_build_certs_only(certs, lens, 2, &p7, NULL)
            == WOLFCERT_OK);
    REQUIRE(wolfcert_base64_encode(p7.data, p7.len, &b64, NULL)
            == WOLFCERT_OK);
    wolfcert_buffer_free(&p7);

    sc = (struct srv_ctx){ .body = b64.data, .len = b64.len, .ctx = ctx,
                           .conns = 1 };
    sc.listen_fd = listen_loopback(&port);
    REQUIRE(sc.listen_fd >= 0);
    REQUIRE(pthread_create(&tid, NULL, srv_thread, &sc) == 0);
    snprintf(url, sizeof(url), "https://127.0.0.1:%d/.well-known/est", port);
    srv.server_url = url;

    rc = wolfcert_est_simple_enroll(&srv, csr, csr_len, &res);
    pthread_join(tid, NULL);
    wolfcert_buffer_free(&b64);
    REQUIRE(rc == WOLFCERT_ERR_PROTOCOL);
    REQUIRE(res.status == WOLFCERT_EST_STATUS_FAILURE);
    REQUIRE(test_pem_cert_is(&res.cert_pem, 0, ca_der, ca_len));
    REQUIRE(test_pem_cert_is(&res.cert_pem, 1, tls_der, lens[1]));
    wolfcert_est_result_free(&res);
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

    if (test_est_rejects_bad_encoding())
        return 1;

    if (test_est_uses_cfg_transport())
        return 1;

    if (test_est_result_defined_on_early_return())
        return 1;

    uint8_t ca_der[4096];
    size_t ca_len = 0;
    REQUIRE(make_test_ca(ca_der, sizeof(ca_der), &ca_len) == 0);
#ifdef WOLFCERT_HAVE_ECC
    REQUIRE(test_issued_crit_ext(ca_der, ca_len) == 0);
#endif
#if defined(WOLFCERT_HAVE_ECC) && defined(HAVE_COMP_KEY)
    REQUIRE(test_issued_compressed_point(ca_der, ca_len) == 0);
#endif

    WolfCertKeyCfg kcfg = { .type = TEST_ENROLL_KEY_TYPE,
                            .param = TEST_ENROLL_KEY_PARAM,
                            .dev_id = INVALID_DEVID };
    WolfCertKey* dk = NULL;
    REQUIRE(wolfcert_key_generate(&kcfg, &dk) == WOLFCERT_OK);
    WolfCertCertMeta meta = { .subject_dn = "CN=device-99" };
    WolfCertBuffer csr = { 0 };
    REQUIRE(wolfcert_csr_build(dk, &meta, &csr) == WOLFCERT_OK);
    REQUIRE(test_issued_raw_spki(dk, &csr, ca_der, ca_len) == 0);
    REQUIRE(test_issued_unparseable_cert(dk, &csr, ca_der, ca_len) == 0);
    REQUIRE(test_issued_max_certs(dk, &csr, ca_der, ca_len) == 0);
    REQUIRE(test_issued_empty_reply(&csr) == 0);
    REQUIRE(test_client_hash_tiebreak(dk, &csr) == 0);
#if defined(WOLFCERT_HAVE_RSA) && defined(WC_RSA_PSS)
    REQUIRE(test_issued_rsa_pss(ca_der, ca_len) == 0);
#endif

    /* The CA cert comes first, so every enroll result must reorder. */
    uint8_t dev_der[4096];
    size_t dev_len = 0;
    REQUIRE(make_device_cert(dk, dev_der, sizeof(dev_der), &dev_len) == 0);
    const uint8_t* certs_arr[2] = { ca_der, dev_der };
    size_t certs_sz[2] = { ca_len, dev_len };
    WolfCertBuffer p7 = { 0 };
    REQUIRE(wolfcert_pkcs7_build_certs_only(certs_arr, certs_sz, 2, &p7, NULL)
            == WOLFCERT_OK);

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
    REQUIRE(wolfcert_est_get_cacerts(&srv, WOLFCERT_ENCODING_PEM,
                                     &ca_pem) == WOLFCERT_OK);
    /* /cacerts keeps the order it was sent in. */
    REQUIRE(test_pem_cert_is(&ca_pem, 0, ca_der, ca_len));
    wolfcert_buffer_free(&ca_pem);

    WolfCertEstResult enrolled = { 0 };
    REQUIRE(wolfcert_est_simple_enroll(&srv, csr.data, csr.len, &enrolled) == WOLFCERT_OK);
    REQUIRE(test_pem_cert_is(&enrolled.cert_pem, 0, dev_der, dev_len));
    REQUIRE(test_pem_cert_is(&enrolled.cert_pem, 1, ca_der, ca_len));
    wolfcert_est_result_free(&enrolled);

    WolfCertEstResult reenrolled = { 0 };
    REQUIRE(wolfcert_est_simple_reenroll(&srv, ca_der, ca_len, dk,
                                         csr.data, csr.len, &reenrolled) == WOLFCERT_OK
            && reenrolled.status == WOLFCERT_EST_STATUS_SUCCESS);
    REQUIRE(test_pem_cert_is(&reenrolled.cert_pem, 0, dev_der, dev_len));
    wolfcert_est_result_free(&reenrolled);

    /* Session enroll sends the base64 CTE header (RFC 7030 section 4.2.1). */
    WolfCertEstSession* sess = NULL;
    REQUIRE(wolfcert_est_session_open(&srv, &sess) == WOLFCERT_OK);
    WolfCertEstResult sess_enrolled = { 0 };
    REQUIRE(wolfcert_est_session_simple_enroll(sess, csr.data, csr.len,
                                               &sess_enrolled) == WOLFCERT_OK);
    REQUIRE(test_pem_cert_is(&sess_enrolled.cert_pem, 0, dev_der, dev_len));
    wolfcert_est_result_free(&sess_enrolled);
    wolfcert_est_session_close(sess);

    /* Non-blocking session enroll also sends the base64 CTE header. */
    WolfCertEstSession* sess_nb = NULL;
    REQUIRE(wolfcert_est_session_open(&srv, &sess_nb) == WOLFCERT_OK);
    WolfCertEstResult sess_nb_enrolled = { 0 };
    REQUIRE(pump_simple_enroll(sess_nb, csr.data, csr.len,
                               &sess_nb_enrolled) == 0);
    REQUIRE(test_pem_cert_is(&sess_nb_enrolled.cert_pem, 0, dev_der,
                             dev_len));
    wolfcert_est_result_free(&sess_nb_enrolled);
    wolfcert_est_session_close(sess_nb);

    REQUIRE(check_empty_body(ctx, &srv, csr.data, csr.len, ca_der, ca_len,
                             dk) == 0);
    REQUIRE(check_error_status(ctx, &srv) == 0);
    REQUIRE(check_body_decodes_empty(ctx, &srv, csr.data, csr.len) == 0);
    REQUIRE(check_unparseable_csr(ctx, &srv) == 0);
    REQUIRE(check_renewal_chain(ctx, &srv, dk, &csr, ca_der, ca_len) == 0);
    REQUIRE(check_renewal_unchanged(ctx, &srv, dk, &csr) == 0);
    REQUIRE(check_enroll_skips_client(ctx, &srv, dk, &csr) == 0);
    REQUIRE(check_enroll_only_client(ctx, &srv, dk, &csr) == 0);
    REQUIRE(check_no_key_cert(ctx, &srv, csr.data, csr.len, ca_der,
                              ca_len) == 0);

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
