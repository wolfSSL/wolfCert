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

/* Certificate chains over EST: a client cert that chains through an
 * intermediate, and trust anchors as concatenated DER. */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#define _DARWIN_C_SOURCE   /* expose INADDR_LOOPBACK on macOS */

#include <wolfcert/wolfcert.h>
#include <wolfcert/est.h>
#include <wolfcert/server.h>

#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/random.h>

#include "tls_test_util.h"
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/ecc.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
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

#if !defined(NO_RSA)
    #define SIGNKEY_ARGS(k) (k), NULL
#else
    #define SIGNKEY_ARGS(k) NULL, (k)
#endif

typedef struct {
    test_signkey key;
    int          have_key;
    uint8_t      der[4096];
    int          der_len;
    uint8_t      pem[8192];
    int          pem_len;
    uint8_t      key_pem[8192];
    int          key_pem_len;
} Id;

/* Self-signed when issuer is NULL. A leaf gets an iPAddress SAN 127.0.0.1. */
static int mint(Id* id, const char* cn, int is_ca, const Id* issuer,
                WC_RNG* rng)
{
    static const uint8_t san_seq[] = { 0x30, 0x06, 0x87, 0x04, 127, 0, 0, 1 };
    uint8_t kder[4096];
    Cert cert;
    int ks;

    REQUIRE(test_signkey_make(&id->key, rng) == 0);
    id->have_key = 1;

    REQUIRE(wc_InitCert(&cert) == 0);
    strncpy(cert.subject.commonName, cn, CTC_NAME_SIZE - 1);
    cert.sigType = TEST_CERT_SIGTYPE;
    cert.daysValid = 1;
    cert.isCA = is_ca ? 1 : 0;
    if (is_ca) {
        REQUIRE(wc_SetKeyUsage(&cert, TEST_CA_KEY_USAGE) == 0);
    }
    else {
        memcpy(cert.altNames, san_seq, sizeof(san_seq));
        cert.altNamesSz = (int)sizeof(san_seq);
    }

    if (issuer == NULL) {
        cert.selfSigned = 1;
        id->der_len = test_sign_selfcert(&cert, id->der, (int)sizeof(id->der),
                                         &id->key, rng);
    }
    else {
        REQUIRE(wc_SetIssuerBuffer(&cert, issuer->der, issuer->der_len) == 0);
        REQUIRE(wc_MakeCert(&cert, id->der, sizeof(id->der),
                            SIGNKEY_ARGS(&id->key), rng) > 0);
        id->der_len = wc_SignCert(cert.bodySz, cert.sigType, id->der,
                                  sizeof(id->der),
                                  SIGNKEY_ARGS((test_signkey*)&issuer->key),
                                  rng);
    }
    REQUIRE(id->der_len > 0);
    id->pem_len = wc_DerToPem(id->der, (word32)id->der_len, id->pem,
                              sizeof(id->pem), CERT_TYPE);
    REQUIRE(id->pem_len > 0);

    ks = test_signkey_to_der(&id->key, kder, (int)sizeof(kder));
    REQUIRE(ks > 0);
    id->key_pem_len = wc_DerToPem(kder, (word32)ks, id->key_pem,
                                  sizeof(id->key_pem), TEST_KEY_PEM_TYPE);
    REQUIRE(id->key_pem_len > 0);
    return 0;
}

static void id_free(Id* id)
{
    if (id->have_key)
        test_signkey_free(&id->key);
    id->have_key = 0;
}

/* Concatenates parts into buf; returns the total length. */
static size_t cat(uint8_t* buf, size_t cap, const uint8_t* a, size_t a_len,
                  const uint8_t* b, size_t b_len, const uint8_t* c,
                  size_t c_len)
{
    if (a_len + b_len + c_len > cap)
        return 0;
    memcpy(buf, a, a_len);
    memcpy(buf + a_len, b, b_len);
    if (c_len > 0)
        memcpy(buf + a_len + b_len, c, c_len);
    return a_len + b_len + c_len;
}

static int cacerts(WolfCertServerCfg* cli)
{
    WolfCertBuffer ca = { 0 };
    int rc = wolfcert_est_get_cacerts(cli, WOLFCERT_ENCODING_PEM, &ca);

    wolfcert_buffer_free(&ca);
    return rc;
}

static Id g_root, g_int, g_srv, g_cli, g_other;

static uint8_t g_long[65536];
static uint8_t g_csr[4096];
static int g_csr_len;
static uint8_t g_v1[4096];
static int g_v1_len;

/* A self-signed v1 certificate: g_root's key, no version tag, no extensions. */
static int make_v1(WC_RNG* rng)
{
    static const uint8_t ver[] = { 0xA0, 0x03, 0x02, 0x01, 0x02 };
    uint8_t tbs[4096];
    size_t idx;
    size_t body_len;
    size_t hdr = 2;
    int n;
    Cert cert;

    REQUIRE(wc_InitCert(&cert) == 0);
    strncpy(cert.subject.commonName, "Legacy v1", CTC_NAME_SIZE - 1);
    cert.issuer = cert.subject;
    cert.sigType = TEST_CERT_SIGTYPE;
    cert.daysValid = 1;
    REQUIRE(wc_MakeCert(&cert, tbs, sizeof(tbs), SIGNKEY_ARGS(&g_root.key),
                        rng) > 0);
    REQUIRE(tbs[0] == 0x30 && tbs[1] >= 0x81 && tbs[1] <= 0x82);
    if (tbs[1] == 0x81) {
        idx = 3;
        body_len = tbs[2];
    }
    else {
        idx = 4;
        body_len = (size_t)tbs[2] << 8 | tbs[3];
    }
    body_len -= sizeof(ver);
    REQUIRE(memcmp(tbs + idx, ver, sizeof(ver)) == 0);
    g_v1[0] = 0x30;
    if (body_len < 0x80) {
        g_v1[1] = (uint8_t)body_len;
    }
    else if (body_len < 0x100) {
        g_v1[1] = 0x81;
        g_v1[2] = (uint8_t)body_len;
        hdr = 3;
    }
    else {
        g_v1[1] = 0x82;
        g_v1[2] = (uint8_t)(body_len >> 8);
        g_v1[3] = (uint8_t)body_len;
        hdr = 4;
    }
    memcpy(g_v1 + hdr, tbs + idx + sizeof(ver), body_len);
    n = wc_SignCert((int)(hdr + body_len), cert.sigType, g_v1, sizeof(g_v1),
                    SIGNKEY_ARGS(&g_root.key), rng);
    REQUIRE(n > 0);
    g_v1_len = n;
    return 0;
}

/* A PKCS#10 request signed with g_cli's key. */
static int make_csr(WC_RNG* rng)
{
    Cert req;

    REQUIRE(wc_InitCert(&req) == 0);
    strncpy(req.subject.commonName, "chain-device", CTC_NAME_SIZE - 1);
    req.sigType = TEST_CERT_SIGTYPE;
    REQUIRE(wc_MakeCertReq(&req, g_csr, sizeof(g_csr),
                           SIGNKEY_ARGS(&g_cli.key)) > 0);
    g_csr_len = wc_SignCert(req.bodySz, req.sigType, g_csr, sizeof(g_csr),
                            SIGNKEY_ARGS(&g_cli.key), rng);
    REQUIRE(g_csr_len > 0);
    return 0;
}

static int failed_with(const char* what)
{
    return strstr(wolfcert_last_error_message(), what) != NULL;
}

static int test_client_chain(const char* url)
{
    static const uint8_t trailer[] = { '\n', 0xFF, 0x00 };
    static const uint8_t nl[] = { '\n' };
    uint8_t chain[16384];
    uint8_t kder[4096];
    size_t chain_len;
    int ks;
    int i;
    WolfCertServerCfg cli = {
        .protocol          = WOLFCERT_PROTO_EST,
        .server_url        = url,
        .trust_anchors     = g_int.pem,
        .trust_anchors_len = (size_t)g_int.pem_len,
        .verify_server     = 1,
        .client_cert       = g_cli.pem,
        .client_cert_len   = (size_t)g_cli.pem_len,
        .client_key        = g_cli.key_pem,
        .client_key_len    = (size_t)g_cli.key_pem_len,
        .timeout_ms        = 30000,
    };

    /* The server trusts only the root, so the leaf alone is refused. */
    REQUIRE(cacerts(&cli) != WOLFCERT_OK);

    chain_len = cat(chain, sizeof(chain), g_cli.pem, (size_t)g_cli.pem_len,
                    g_int.pem, (size_t)g_int.pem_len, NULL, 0);
    cli.client_cert = chain;
    cli.client_cert_len = chain_len;
    REQUIRE(cacerts(&cli) == WOLFCERT_OK);

    chain_len = cat(chain, sizeof(chain), g_cli.der, (size_t)g_cli.der_len,
                    g_int.der, (size_t)g_int.der_len, trailer,
                    sizeof(trailer));
    cli.client_cert_len = chain_len;
    REQUIRE(cacerts(&cli) == WOLFCERT_OK);

    chain_len = cat(chain, sizeof(chain), g_cli.der, (size_t)g_cli.der_len,
                    g_int.der, (size_t)g_int.der_len, g_cli.key_pem,
                    (size_t)g_cli.key_pem_len);
    cli.client_cert_len = chain_len;
    REQUIRE(cacerts(&cli) == WOLFCERT_OK);

    chain_len = cat(chain, sizeof(chain), g_cli.der, (size_t)g_cli.der_len,
                    nl, sizeof(nl), g_int.der, (size_t)g_int.der_len);
    cli.client_cert_len = chain_len;
    REQUIRE(cacerts(&cli) == WOLFCERT_ERR_TLS);
    REQUIRE(failed_with("filler between certificates"));

    chain_len = cat(chain, sizeof(chain), g_cli.der, (size_t)g_cli.der_len,
                    g_int.der, (size_t)g_int.der_len, g_csr,
                    (size_t)g_csr_len);
    cli.client_cert_len = chain_len;
    REQUIRE(cacerts(&cli) == WOLFCERT_OK);

    /* A key after the chain is dropped; test_sends_only_chain counts. */
    ks = test_signkey_to_der(&g_cli.key, kder, (int)sizeof(kder));
    REQUIRE(ks > 0);
    chain_len = cat(chain, sizeof(chain), g_cli.der, (size_t)g_cli.der_len,
                    g_int.der, (size_t)g_int.der_len, nl, sizeof(nl));
    REQUIRE(chain_len > 0 && chain_len + (size_t)ks <= sizeof(chain));
    memcpy(chain + chain_len, kder, (size_t)ks);
    chain_len += (size_t)ks;
    cli.client_cert_len = chain_len;
    REQUIRE(cacerts(&cli) == WOLFCERT_OK);

    /* More intermediates than any MAX_CHAIN_DEPTH a build would set. */
    memcpy(g_long, g_cli.der, (size_t)g_cli.der_len);
    chain_len = (size_t)g_cli.der_len;
    for (i = 0; i < 20; i++) {
        REQUIRE(chain_len + (size_t)g_int.der_len <= sizeof(g_long));
        memcpy(g_long + chain_len, g_int.der, (size_t)g_int.der_len);
        chain_len += (size_t)g_int.der_len;
    }
    cli.client_cert = g_long;
    cli.client_cert_len = chain_len;
    REQUIRE(cacerts(&cli) == WOLFCERT_ERR_TLS);
    REQUIRE(failed_with("MAX_CHAIN_DEPTH"));
    return 0;
}

static int test_der_anchors(const char* url)
{
    static const uint8_t junk[] = { 0x30, 0x03, 0x02, 0x01, 0x00 };
    static const uint8_t pad[] = { 0xFF, 0xFF, '\r', '\n' };
    static const uint8_t v1_shape[] = { 0x30, 0x12, 0x30, 0x0B, 0x02, 0x01,
                                        0x01, 0x30, 0x02, 0x06, 0x00, 0x30,
                                        0x00, 0x30, 0x00, 0x30, 0x00, 0x03,
                                        0x01, 0x00 };
    uint8_t chain[16384];
    uint8_t ta[16384];
    WolfCertServerCfg cli = {
        .protocol          = WOLFCERT_PROTO_EST,
        .server_url        = url,
        .verify_server     = 1,
        .client_key        = g_cli.key_pem,
        .client_key_len    = (size_t)g_cli.key_pem_len,
        .timeout_ms        = 30000,
    };

    cli.client_cert = chain;
    cli.client_cert_len = cat(chain, sizeof(chain), g_cli.pem,
                              (size_t)g_cli.pem_len, g_int.pem,
                              (size_t)g_int.pem_len, NULL, 0);
    cli.trust_anchors = ta;

    cli.trust_anchors_len = cat(ta, sizeof(ta), g_other.der,
                                (size_t)g_other.der_len, g_int.der,
                                (size_t)g_int.der_len, NULL, 0);
    REQUIRE(cacerts(&cli) == WOLFCERT_OK);

    /* The server's issuer comes second, after filler. */
    cli.trust_anchors_len = cat(ta, sizeof(ta), g_root.der,
                                (size_t)g_root.der_len, pad, sizeof(pad),
                                g_int.der, (size_t)g_int.der_len);
    REQUIRE(cacerts(&cli) == WOLFCERT_OK);

    /* A certificate wolfSSL refuses is skipped. */
    cli.trust_anchors_len = cat(ta, sizeof(ta), v1_shape, sizeof(v1_shape),
                                g_int.der, (size_t)g_int.der_len, NULL, 0);
    REQUIRE(cacerts(&cli) == WOLFCERT_OK);

    memcpy(ta, v1_shape, sizeof(v1_shape));
    cli.trust_anchors_len = sizeof(v1_shape);
    REQUIRE(cacerts(&cli) == WOLFCERT_ERR_TLS);
    REQUIRE(wolfcert_last_wolfssl_err() < 0);

    /* A SEQUENCE that is not a certificate ends the bundle. */
    cli.trust_anchors_len = cat(ta, sizeof(ta), junk, sizeof(junk), g_int.der,
                                (size_t)g_int.der_len, NULL, 0);
    REQUIRE(cacerts(&cli) == WOLFCERT_ERR_TLS);
    REQUIRE(failed_with("no certificate"));

    cli.trust_anchors_len = cat(ta, sizeof(ta), g_int.der,
                                (size_t)g_int.der_len, g_csr,
                                (size_t)g_csr_len, NULL, 0);
    REQUIRE(cacerts(&cli) == WOLFCERT_OK);

    /* A cut certificate after the last whole one is dropped. */
    cli.trust_anchors_len = cat(ta, sizeof(ta), g_int.der,
                                (size_t)g_int.der_len, g_root.der,
                                (size_t)g_root.der_len - 1, NULL, 0);
    REQUIRE(cacerts(&cli) == WOLFCERT_OK);

    /* Only the unrelated CA loads. */
    cli.trust_anchors_len = cat(ta, sizeof(ta), g_other.der,
                                (size_t)g_other.der_len, pad, sizeof(pad), NULL, 0);
    REQUIRE(cacerts(&cli) == WOLFCERT_ERR_TLS_UNTRUSTED);
    return 0;
}

#ifdef KEEP_PEER_CERT
static int reenroll_with(const char* url, const uint8_t* cur, size_t cur_len)
{
    WolfCertServerCfg cli = {
        .protocol          = WOLFCERT_PROTO_EST,
        .server_url        = url,
        .trust_anchors     = g_int.pem,
        .trust_anchors_len = (size_t)g_int.pem_len,
        .verify_server     = 1,
        .timeout_ms        = 30000,
    };
    WolfCertCertMeta meta = { 0 };
    WolfCertKey* cur_key = NULL;
    WolfCertKey* out_key = NULL;
    WolfCertBuffer out = { 0 };
    int rc;

    REQUIRE(wolfcert_key_from_pem(g_cli.key_pem, (size_t)g_cli.key_pem_len,
                                  NULL, &cur_key) == WOLFCERT_OK);
    rc = wolfcert_client_reenroll(NULL, &cli, cur, cur_len, cur_key, NULL,
                                  &meta, &out_key, &out);
    if (rc != WOLFCERT_OK)
        fprintf(stderr, "chain reenroll rc=%d (%s): %s\n", rc,
                wolfcert_strerror(rc), wolfcert_last_error_message());
    wolfcert_buffer_free(&out);
    wolfcert_key_free(out_key);
    wolfcert_key_free(cur_key);
    REQUIRE(rc == WOLFCERT_OK);
    return 0;
}

static int test_reenroll_chain(const char* url)
{
    uint8_t chain[16384];
    size_t chain_len;

    chain_len = cat(chain, sizeof(chain), g_cli.pem, (size_t)g_cli.pem_len,
                    g_int.pem, (size_t)g_int.pem_len, NULL, 0);
    REQUIRE(reenroll_with(url, chain, chain_len) == 0);

    chain_len = cat(chain, sizeof(chain), g_cli.der, (size_t)g_cli.der_len,
                    g_int.der, (size_t)g_int.der_len, NULL, 0);
    REQUIRE(reenroll_with(url, chain, chain_len) == 0);
    return 0;
}
#endif

/* A server with no client CA, so every client cert reaches verify_cb. */
typedef struct {
    wolfSSL_Atomic_Int port;
    wolfSSL_Atomic_Int accepted;
    int peer_certs;
    int handshake_ok;
} CountSrv;

static int g_peer_certs;

static int count_cb(int preverify, WOLFSSL_X509_STORE_CTX* store)
{
    (void)preverify;
    if (store->totalCerts > g_peer_certs)
        g_peer_certs = store->totalCerts;
    return 1;
}

static void* count_srv_thread(void* arg)
{
    static const char reply[] =
        "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n"
        "Connection: close\r\n\r\n";
    CountSrv* cs = (CountSrv*)arg;
    struct sockaddr_in sa;
    socklen_t slen = sizeof(sa);
    WOLFSSL_CTX* ctx;
    WOLFSSL* ssl = NULL;
    char req[2048];
    int ls;
    int fd = -1;
    int yes = 1;

    ctx = wolfSSL_CTX_new(wolfTLS_server_method());
    if (ctx == NULL)
        return NULL;
    if (wolfSSL_CTX_use_certificate_buffer(ctx, g_srv.pem, g_srv.pem_len,
            WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS ||
        wolfSSL_CTX_use_PrivateKey_buffer(ctx, g_srv.key_pem, g_srv.key_pem_len,
            WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS) {
        wolfSSL_CTX_free(ctx);
        return NULL;
    }
    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER |
                           WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT, count_cb);

    ls = socket(AF_INET, SOCK_STREAM, 0);
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (ls < 0 ||
            setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) != 0 ||
            bind(ls, (struct sockaddr*)&sa, sizeof(sa)) != 0 ||
            listen(ls, 1) != 0 ||
            getsockname(ls, (struct sockaddr*)&sa, &slen) != 0) {
        if (ls >= 0)
            close(ls);
        wolfSSL_CTX_free(ctx);
        WOLFSSL_ATOMIC_STORE(cs->port, -1);
        return NULL;
    }
    WOLFSSL_ATOMIC_STORE(cs->port, ntohs(sa.sin_port));

    fd = accept(ls, NULL, NULL);
    WOLFSSL_ATOMIC_STORE(cs->accepted, 1);
    close(ls);
    if (fd >= 0)
        ssl = wolfSSL_new(ctx);
    if (ssl != NULL && wolfSSL_set_fd(ssl, fd) == WOLFSSL_SUCCESS &&
            wolfSSL_accept(ssl) == WOLFSSL_SUCCESS) {
        cs->handshake_ok = 1;
        if (wolfSSL_read(ssl, req, sizeof(req)) > 0)
            (void)wolfSSL_write(ssl, reply, (int)sizeof(reply) - 1);
    }
    cs->peer_certs = g_peer_certs;
    if (ssl != NULL) {
        wolfSSL_shutdown(ssl);
        wolfSSL_free(ssl);
    }
    if (fd >= 0)
        close(fd);
    wolfSSL_CTX_free(ctx);
    return NULL;
}

static void unblock_srv(int port)
{
    struct sockaddr_in sa = { .sin_family = AF_INET,
                              .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    int fd = socket(AF_INET, SOCK_STREAM, 0);

    if (fd < 0)
        return;
    sa.sin_port = htons((uint16_t)port);
    (void)connect(fd, (struct sockaddr*)&sa, sizeof(sa));
    close(fd);
}

/* Certificates the server received when the client presents client_cert,
 * or -1 if the handshake failed. */
static int certs_sent(const uint8_t* client_cert, size_t client_cert_len)
{
    static CountSrv cs;
    uint8_t ta[16384];
    pthread_t tid;
    char url[128];
    int port;
    int i;
    WolfCertServerCfg cli = {
        .protocol          = WOLFCERT_PROTO_EST,
        .verify_server     = 1,
        .client_key        = g_cli.key_pem,
        .client_key_len    = (size_t)g_cli.key_pem_len,
        .timeout_ms        = 30000,
    };

    memset(&cs, 0, sizeof(cs));
    g_peer_certs = 0;
    REQUIRE(pthread_create(&tid, NULL, count_srv_thread, &cs) == 0);
    for (i = 0; i < 500 && (port = WOLFSSL_ATOMIC_LOAD(cs.port)) == 0; ++i)
        test_sleep_ms(10);
    if (port == 0)
        pthread_detach(tid);
    if (port < 0)
        pthread_join(tid, NULL);
    if (port <= 0)
        return -1;
    snprintf(url, sizeof(url), "https://127.0.0.1:%d/.well-known/est", port);

    cli.server_url = url;
    cli.client_cert = client_cert;
    cli.client_cert_len = client_cert_len;
    cli.trust_anchors = ta;
    cli.trust_anchors_len = cat(ta, sizeof(ta), g_root.der,
                                (size_t)g_root.der_len, g_int.der,
                                (size_t)g_int.der_len, g_other.der,
                                (size_t)g_other.der_len);
    (void)cacerts(&cli);
    if (!WOLFSSL_ATOMIC_LOAD(cs.accepted))
        unblock_srv(port);
    pthread_join(tid, NULL);
    return cs.handshake_ok ? cs.peer_certs : -1;
}

/* The client sends its leaf and whole intermediates only: no trust anchor,
 * no key, no cut certificate. */
static int test_sends_only_chain(void)
{
    uint8_t chain[16384];
    uint8_t kder[4096];
    size_t chain_len;
    int ks;

    chain_len = cat(chain, sizeof(chain), g_cli.der, (size_t)g_cli.der_len,
                    g_int.der, (size_t)g_int.der_len, NULL, 0);
    REQUIRE(certs_sent(chain, chain_len) == 2);

    ks = test_signkey_to_der(&g_cli.key, kder, (int)sizeof(kder));
    REQUIRE(ks > 0);
    chain_len = cat(chain, sizeof(chain), g_cli.der, (size_t)g_cli.der_len,
                    g_int.der, (size_t)g_int.der_len, kder, (size_t)ks);
    REQUIRE(certs_sent(chain, chain_len) == 2);

    REQUIRE(certs_sent(chain, (size_t)g_cli.der_len + 100) == 1);

    /* A request ends the chain, so the intermediate after one is not sent. */
    chain_len = cat(chain, sizeof(chain), g_cli.der, (size_t)g_cli.der_len,
                    g_csr, (size_t)g_csr_len, g_int.der,
                    (size_t)g_int.der_len);
    REQUIRE(certs_sent(chain, chain_len) == 1);

    chain_len = cat(chain, sizeof(chain), g_cli.der, (size_t)g_cli.der_len,
                    g_int.der, (size_t)g_int.der_len, g_v1, (size_t)g_v1_len);
    REQUIRE(certs_sent(chain, chain_len) == 3);
    return 0;
}

static void* server_thread(void* arg)
{
    wolfcert_server_run((WolfCertServer*)arg);
    return NULL;
}

int main(void)
{
    WolfCertServer* srv = NULL;
    pthread_t tid;
    char url[128];
    WC_RNG rng;
    int failed = 0;

    if (wolfcert_init(NULL) != WOLFCERT_OK)
        return 1;
    REQUIRE(wc_InitRng(&rng) == 0);
    REQUIRE(mint(&g_root, "Chain Root", 1, NULL, &rng) == 0);
    REQUIRE(mint(&g_int, "Chain Intermediate", 1, &g_root, &rng) == 0);
    REQUIRE(mint(&g_srv, "127.0.0.1", 0, &g_int, &rng) == 0);
    REQUIRE(mint(&g_cli, "chain-device", 0, &g_int, &rng) == 0);
    REQUIRE(mint(&g_other, "Unrelated CA", 1, NULL, &rng) == 0);
    REQUIRE(make_csr(&rng) == 0);
    REQUIRE(make_v1(&rng) == 0);
    wc_FreeRng(&rng);

    WolfCertServerCfgSrv cfg = {
        .protocol              = WOLFCERT_PROTO_EST,
        .bind_host             = "127.0.0.1",
        .bind_port             = 0,
        .tls_cert_pem          = g_srv.pem,
        .tls_cert_pem_len      = (size_t)g_srv.pem_len,
        .tls_key_pem           = g_srv.key_pem,
        .tls_key_pem_len       = (size_t)g_srv.key_pem_len,
        .tls_client_ca_pem     = g_root.pem,
        .tls_client_ca_pem_len = (size_t)g_root.pem_len,
        TEST_CA_CFG,
    };
    REQUIRE(wolfcert_server_start(&cfg, &srv) == WOLFCERT_OK);
    REQUIRE(pthread_create(&tid, NULL, server_thread, srv) == 0);
    snprintf(url, sizeof(url), "https://127.0.0.1:%u/.well-known/est",
             wolfcert_server_port(srv));

    failed = test_client_chain(url) || test_der_anchors(url);
#ifdef KEEP_PEER_CERT
    failed = failed || test_reenroll_chain(url);
#endif

    wolfcert_server_stop(srv);
    pthread_join(tid, NULL);
    wolfcert_server_free(srv);

    failed = failed || test_sends_only_chain();

    id_free(&g_root);
    id_free(&g_int);
    id_free(&g_srv);
    id_free(&g_cli);
    id_free(&g_other);
    test_ca_close();
    wolfcert_cleanup();
    if (failed)
        return 1;
    printf("OK\n");
    return 0;
}

#endif /* WOLFCERT_HAVE_BUILTIN_TRANSPORT */
