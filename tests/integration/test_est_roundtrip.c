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

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#define _GNU_SOURCE

#include <wolfcert/wolfcert.h>
#include <wolfcert/server.h>

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/asn_public.h>

#include "tls_test_util.h"

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

static void* server_thread(void* arg)
{
    wolfcert_server_run((WolfCertServer*)arg);
    return NULL;
}

/* Pluggable-transport coverage: a WolfCertTransport whose connect counts
 * invocations and opens through wolfcert_posix_connect, with the byte path
 * over plain blocking sockets. */
static int g_connect_calls = 0;

static int counting_connect(void* ctx, const char* host, int port,
                            int timeout_ms, void** conn)
{
    int fd;

    (void)ctx;
    ++g_connect_calls;
    fd = wolfcert_posix_connect(host, port, timeout_ms, NULL);
    if (fd < 0)
        return WOLFCERT_ERR_IO;

    *conn = (void*)(intptr_t)fd;
    return WOLFCERT_OK;
}

static int counting_read(void* ctx, void* conn, uint8_t* buf, size_t len,
                         int timeout_ms)
{
    ssize_t n;

    (void)ctx;
    (void)timeout_ms;
    n = recv((int)(intptr_t)conn, buf, len, 0);
    if (n > 0)
        return (int)n;
    if (n == 0)
        return WOLFCERT_ERR_CONN_CLOSED;

    return WOLFCERT_ERR_IO;
}

static int counting_write(void* ctx, void* conn, const uint8_t* buf,
                          size_t len, int timeout_ms)
{
    ssize_t n;

    (void)ctx;
    (void)timeout_ms;
    n = send((int)(intptr_t)conn, buf, len, 0);

    return (n > 0) ? (int)n : WOLFCERT_ERR_IO;
}

static int counting_disconnect(void* ctx, void* conn)
{
    (void)ctx;
    (void)close((int)(intptr_t)conn);
    return WOLFCERT_OK;
}

static int enroll_one(const WolfCertServerCfg* client_cfg,
                      WolfCertKeyType kt, int param,
                      const WolfCertBuffer* ca_pem)
{
    WolfCertKeyCfg kcfg = { .type = kt, .param = param,
                            .dev_id = WOLFCERT_DEVID_SOFTWARE };
    WolfCertKey* dk = NULL;
    REQUIRE(wolfcert_key_generate(&kcfg, &dk) == WOLFCERT_OK);

    const char* dns[] = { "device-7.local" };
    WolfCertCertMeta meta = { .subject_dn = "CN=device-7,O=Acme",
                              .san_dns = dns, .san_dns_len = 1 };
    WolfCertBuffer csr = { 0 };
    REQUIRE(wolfcert_csr_build(dk, &meta, &csr) == WOLFCERT_OK);

    WolfCertBuffer issued = { 0 };
    REQUIRE(wolfcert_est_simple_enroll(client_cfg, csr.data, csr.len, &issued)
            == WOLFCERT_OK);

    DerBuffer* issued_der = NULL;
    REQUIRE(wc_PemToDer(issued.data, (long)issued.len, CERT_TYPE,
                        &issued_der, NULL, NULL, NULL) == 0);
    WOLFSSL_CERT_MANAGER* cm = wolfSSL_CertManagerNew();
    REQUIRE(cm != NULL);
    REQUIRE(wolfSSL_CertManagerLoadCABuffer(cm, ca_pem->data, (long)ca_pem->len,
                                            WOLFSSL_FILETYPE_PEM)
            == WOLFSSL_SUCCESS);
    REQUIRE(wolfSSL_CertManagerVerifyBuffer(cm, issued_der->buffer,
                                            (long)issued_der->length,
                                            WOLFSSL_FILETYPE_ASN1)
            == WOLFSSL_SUCCESS);
    wolfSSL_CertManagerFree(cm);
    wc_FreeDer(&issued_der);

    wolfcert_buffer_free(&csr);
    wolfcert_buffer_free(&issued);
    wolfcert_key_free(dk);
    return 0;
}

static int has_alt(const DNS_entry* list, int type, const char* val, int len)
{
    for (const DNS_entry* e = list; e != NULL; e = e->next) {
        if (e->type == type && e->len == len &&
            memcmp(e->name, val, (size_t)len) == 0)
            return 1;
    }
    return 0;
}

/* Regression: a CSR carrying DNS + IP + rfc822 (email) SANs must round-trip
 * into the issued certificate. wolfSSL splits parsed alt names by type --
 * rfc822Name lands in DecodedCert.altEmailNames, not altNames -- so the CA
 * must recombine the lists when re-emitting. This previously dropped the
 * email SAN from the issued cert entirely. */
static int enroll_check_san(const WolfCertServerCfg* client_cfg)
{
    WolfCertKeyCfg kcfg = { .type = TEST_ENROLL_KEY_TYPE, .param = TEST_ENROLL_KEY_PARAM,
                            .dev_id = WOLFCERT_DEVID_SOFTWARE };
    WolfCertKey* dk = NULL;
    REQUIRE(wolfcert_key_generate(&kcfg, &dk) == WOLFCERT_OK);

    const char* dns[]    = { "device-san.local" };
    const char* ips[]    = { "10.20.30.40" };
    const char* emails[] = { "dev-san@example.com" };
    WolfCertCertMeta meta = { .subject_dn   = "CN=device-san",
                              .san_dns      = dns,    .san_dns_len   = 1,
                              .san_ip       = ips,    .san_ip_len    = 1,
                              .san_email    = emails, .san_email_len = 1 };
    WolfCertBuffer csr = { 0 };
    REQUIRE(wolfcert_csr_build(dk, &meta, &csr) == WOLFCERT_OK);

    WolfCertBuffer issued = { 0 };
    REQUIRE(wolfcert_est_simple_enroll(client_cfg, csr.data, csr.len, &issued)
            == WOLFCERT_OK);

    DerBuffer* der = NULL;
    REQUIRE(wc_PemToDer(issued.data, (long)issued.len, CERT_TYPE, &der,
                        NULL, NULL, NULL) == 0);

    DecodedCert dc;
    wc_InitDecodedCert(&dc, der->buffer, der->length, NULL);
    REQUIRE(wc_ParseCert(&dc, CERT_TYPE, NO_VERIFY, NULL) == 0);

    /* DNS + IP travel in altNames. */
    const byte ip[] = { 10, 20, 30, 40 };
    REQUIRE(has_alt(dc.altNames, ASN_DNS_TYPE, "device-san.local",
                    (int)strlen("device-san.local")));
    REQUIRE(has_alt(dc.altNames, ASN_IP_TYPE, (const char*)ip, (int)sizeof(ip)));
    /* The regression guard: email lands in altEmailNames, must still survive. */
    REQUIRE(has_alt(dc.altEmailNames, ASN_RFC822_TYPE, "dev-san@example.com",
                    (int)strlen("dev-san@example.com")));

    wc_FreeDecodedCert(&dc);
    wc_FreeDer(&der);
    wolfcert_buffer_free(&csr);
    wolfcert_buffer_free(&issued);
    wolfcert_key_free(dk);
    return 0;
}

static int rdn_is(const char* p, int len, const char* want)
{
    return p != NULL && len == (int)strlen(want) &&
           memcmp(p, want, (size_t)len) == 0;
}

/* Regression: every subject RDN the CSR builder accepts must survive into the
 * issued certificate. The CA rebuilds the subject field by field, so a name
 * component it has no copy for is dropped without any error. givenName is
 * absent below because wolfSSL's decoder never reports it back. */
static int enroll_check_subject_rdns(const WolfCertServerCfg* client_cfg)
{
    WolfCertKeyCfg kcfg = { .type = TEST_ENROLL_KEY_TYPE, .param = TEST_ENROLL_KEY_PARAM,
                            .dev_id = WOLFCERT_DEVID_SOFTWARE };
    WolfCertKey* dk = NULL;
    REQUIRE(wolfcert_key_generate(&kcfg, &dk) == WOLFCERT_OK);

    WolfCertCertMeta meta = {
        .subject_dn = "CN=device-rdn,O=Acme,OU=Devices,C=US,ST=Washington,"
                      "L=Seattle,SN=Doe,"
                      "emailAddress=jane@example.com,serialNumber=SRL-42,"
                      "UID=factory-1,postalCode=98109"
#ifdef WOLFSSL_CERT_EXT
                      ",businessCategory=Manufacturing"
#endif
    };
    WolfCertBuffer csr = { 0 };
    REQUIRE(wolfcert_csr_build(dk, &meta, &csr) == WOLFCERT_OK);

    WolfCertBuffer issued = { 0 };
    REQUIRE(wolfcert_est_simple_enroll(client_cfg, csr.data, csr.len, &issued)
            == WOLFCERT_OK);

    DerBuffer* der = NULL;
    REQUIRE(wc_PemToDer(issued.data, (long)issued.len, CERT_TYPE, &der,
                        NULL, NULL, NULL) == 0);

    DecodedCert dc;
    wc_InitDecodedCert(&dc, der->buffer, der->length, NULL);
    REQUIRE(wc_ParseCert(&dc, CERT_TYPE, NO_VERIFY, NULL) == 0);

    REQUIRE(rdn_is(dc.subjectCN, dc.subjectCNLen, "device-rdn"));
    REQUIRE(rdn_is(dc.subjectO,  dc.subjectOLen,  "Acme"));
    REQUIRE(rdn_is(dc.subjectOU, dc.subjectOULen, "Devices"));
    REQUIRE(rdn_is(dc.subjectC,  dc.subjectCLen,  "US"));
    REQUIRE(rdn_is(dc.subjectST, dc.subjectSTLen, "Washington"));
    REQUIRE(rdn_is(dc.subjectL,  dc.subjectLLen,  "Seattle"));
    /* The guard: everything below was dropped by the issuer. */
    REQUIRE(rdn_is(dc.subjectSN,  dc.subjectSNLen,  "Doe"));
    REQUIRE(rdn_is(dc.subjectEmail, dc.subjectEmailLen, "jane@example.com"));
    REQUIRE(rdn_is(dc.subjectSND, dc.subjectSNDLen, "SRL-42"));
    REQUIRE(rdn_is(dc.subjectUID, dc.subjectUIDLen, "factory-1"));
    REQUIRE(rdn_is(dc.subjectPC,  dc.subjectPCLen,  "98109"));
#ifdef WOLFSSL_CERT_EXT
    REQUIRE(rdn_is(dc.subjectBC,  dc.subjectBCLen,  "Manufacturing"));
#endif

    wc_FreeDecodedCert(&dc);
    wc_FreeDer(&der);
    wolfcert_buffer_free(&csr);
    wolfcert_buffer_free(&issued);
    wolfcert_key_free(dk);
    return 0;
}

/* HTTP Basic (RFC 7030 section 3.2.3) must authenticate a keep-alive session
 * too, not just the one-shot calls: the credentials have to ride every request
 * on the connection. Enrolls with the good credentials from `client_cfg`, then
 * repeats with a wrong password and requires a rejection - so a session that
 * silently dropped the Authorization header cannot pass both halves. */
static int session_basic_auth(const WolfCertServerCfg* client_cfg)
{
    WolfCertKeyCfg kcfg = { .type = TEST_ENROLL_KEY_TYPE, .param = TEST_ENROLL_KEY_PARAM,
                            .dev_id = WOLFCERT_DEVID_SOFTWARE };
    WolfCertKey* dk = NULL;
    REQUIRE(wolfcert_key_generate(&kcfg, &dk) == WOLFCERT_OK);
    WolfCertCertMeta meta = { .subject_dn = "CN=session-basic-auth" };
    WolfCertBuffer csr = { 0 };
    REQUIRE(wolfcert_csr_build(dk, &meta, &csr) == WOLFCERT_OK);

    WolfCertEstSession* s = NULL;
    REQUIRE(wolfcert_est_session_open(client_cfg, &s) == WOLFCERT_OK);

    WolfCertBuffer ca_pem = { 0 }, issued = { 0 };
    REQUIRE(wolfcert_est_session_get_cacerts(s, &ca_pem) == WOLFCERT_OK);
    REQUIRE(ca_pem.len > 0);
    REQUIRE(wolfcert_est_session_simple_enroll(s, csr.data, csr.len, &issued)
            == WOLFCERT_OK);

    DerBuffer* issued_der = NULL;
    REQUIRE(wc_PemToDer(issued.data, (long)issued.len, CERT_TYPE,
                        &issued_der, NULL, NULL, NULL) == 0);
    wc_FreeDer(&issued_der);

    wolfcert_buffer_free(&ca_pem);
    wolfcert_buffer_free(&issued);
    wolfcert_est_session_close(s);

    /* Same session shape, wrong password: the server must reject the enroll. */
    WolfCertServerCfg bad_cfg = *client_cfg;
    bad_cfg.proto_opts.est.password = "wrong";

    WolfCertEstSession* bs = NULL;
    REQUIRE(wolfcert_est_session_open(&bad_cfg, &bs) == WOLFCERT_OK);

    WolfCertBuffer bad_out = { 0 };
    REQUIRE(wolfcert_est_session_simple_enroll(bs, csr.data, csr.len, &bad_out)
            == WOLFCERT_ERR_AUTH);
    REQUIRE(bad_out.data == NULL);
    wolfcert_est_session_close(bs);

    wolfcert_buffer_free(&csr);
    wolfcert_key_free(dk);
    return 0;
}

int main(void)
{
    REQUIRE(wolfcert_init(NULL) == WOLFCERT_OK);

    /* EST runs over TLS (RFC 7030): stand the server up behind a freshly
     * minted self-signed identity and pin it as the client trust anchor. */
    uint8_t *tls_cert = NULL, *tls_key = NULL;
    size_t tls_cert_len = 0, tls_key_len = 0;
    REQUIRE(gen_server_identity(&tls_cert, &tls_cert_len,
                                &tls_key, &tls_key_len) == 0);

    WolfCertServerCfgSrv cfg = {
        .protocol        = WOLFCERT_PROTO_EST,
        .bind_host       = "127.0.0.1",
        .bind_port       = 0,
        .http_basic_user = "alice",
        .http_basic_pass = "hunter2",
        .tls_cert_pem    = tls_cert, .tls_cert_pem_len = tls_cert_len,
        .tls_key_pem     = tls_key,  .tls_key_pem_len  = tls_key_len,
    };
    WolfCertServer* s = NULL;
    REQUIRE(wolfcert_server_start(&cfg, &s) == WOLFCERT_OK);

    pthread_t tid;
    REQUIRE(pthread_create(&tid, NULL, server_thread, s) == 0);

    char url[128];
    snprintf(url, sizeof(url), "https://127.0.0.1:%u/.well-known/est",
             wolfcert_server_port(s));
    WolfCertServerCfg client_cfg = { .protocol = WOLFCERT_PROTO_EST,
                                     .server_url = url,
                                     .proto_opts.est = { .username = "alice",
                                                         .password = "hunter2" },
                                     .trust_anchors = tls_cert,
                                     .trust_anchors_len = tls_cert_len,
                                     .verify_server = 1 };

    WolfCertTransport counting_transport = {
        counting_connect, counting_read, counting_write, counting_disconnect,
        NULL
    };

    client_cfg.transport = counting_transport;

    WolfCertBuffer ca_pem = { 0 };
    REQUIRE(wolfcert_est_get_cacerts(&client_cfg, &ca_pem) == WOLFCERT_OK);

    /* get_ca DER path: get_ca unpacks the PKCS#7 internally, so for the
     * single-cert test CA the DER result is that cert's raw DER and loads
     * directly as ASN.1. */
    WolfCertClient* client = NULL;
    REQUIRE(wolfcert_client_new(&client) == WOLFCERT_OK);
    WolfCertBuffer ca_der = { 0 };
    REQUIRE(wolfcert_client_get_ca(client, &client_cfg, WOLFCERT_ENCODING_DER, &ca_der)
            == WOLFCERT_OK);
    REQUIRE(ca_der.len > 0 && ca_der.data[0] == 0x30);
    WOLFSSL_CERT_MANAGER* ca_cm = wolfSSL_CertManagerNew();
    REQUIRE(ca_cm != NULL);
    REQUIRE(wolfSSL_CertManagerLoadCABuffer(ca_cm, ca_der.data, (long)ca_der.len,
                                            WOLFSSL_FILETYPE_ASN1) == WOLFSSL_SUCCESS);
    wolfSSL_CertManagerFree(ca_cm);
    wolfcert_buffer_free(&ca_der);
    wolfcert_client_free(client);

    /* One round-trip per key type: a supported default always, Ed25519/Ed448
     * when enabled. */
    if (enroll_one(&client_cfg, TEST_ENROLL_KEY_TYPE, TEST_ENROLL_KEY_PARAM,
                   &ca_pem))
        return 1;
#ifdef WOLFCERT_HAVE_ED25519
    if (enroll_one(&client_cfg, WOLFCERT_KEY_ED25519, 0, &ca_pem))
        return 1;
#endif
#ifdef WOLFCERT_HAVE_ED448
    if (enroll_one(&client_cfg, WOLFCERT_KEY_ED448, 0, &ca_pem))
        return 1;
#endif

    /* SAN round-trip incl. rfc822 (email) regression guard. */
    if (enroll_check_san(&client_cfg))
        return 1;

    /* Full subject-RDN round-trip guard. */
    if (enroll_check_subject_rdns(&client_cfg))
        return 1;

    /* Keep-alive session against the same Basic-auth-protected server. */
    if (session_basic_auth(&client_cfg))
        return 1;

    /* Proof-of-possession: a CSR whose self-signature does not validate must
     * be rejected. Build a valid CSR, corrupt a byte of its trailing
     * signature value (DER structure stays intact so it still parses), and
     * confirm the server refuses to issue. Credentials are still valid here,
     * so a rejection can only come from the PoP check. */
    WolfCertKeyCfg pop_kcfg = { .type = TEST_ENROLL_KEY_TYPE, .param = TEST_ENROLL_KEY_PARAM,
                                .dev_id = WOLFCERT_DEVID_SOFTWARE };
    WolfCertKey* pop_dk = NULL;
    REQUIRE(wolfcert_key_generate(&pop_kcfg, &pop_dk) == WOLFCERT_OK);
    WolfCertCertMeta pop_meta = { .subject_dn = "CN=pop-tamper" };
    WolfCertBuffer pop_csr = { 0 };
    REQUIRE(wolfcert_csr_build(pop_dk, &pop_meta, &pop_csr) == WOLFCERT_OK);
    REQUIRE(pop_csr.len > 0);
    pop_csr.data[pop_csr.len - 1] ^= 0x01;

    WolfCertBuffer pop_out = { 0 };
    REQUIRE(wolfcert_est_simple_enroll(&client_cfg, pop_csr.data, pop_csr.len,
                                       &pop_out) != WOLFCERT_OK);
    REQUIRE(pop_out.data == NULL);

    wolfcert_buffer_free(&pop_csr);
    wolfcert_key_free(pop_dk);

    /* Auth failure path - needs a CSR to send. */
    WolfCertKeyCfg kcfg = { .type = TEST_ENROLL_KEY_TYPE, .param = TEST_ENROLL_KEY_PARAM,
                            .dev_id = WOLFCERT_DEVID_SOFTWARE };
    WolfCertKey* dk = NULL;
    REQUIRE(wolfcert_key_generate(&kcfg, &dk) == WOLFCERT_OK);
    WolfCertCertMeta meta = { .subject_dn = "CN=auth-fail" };
    WolfCertBuffer csr = { 0 };
    REQUIRE(wolfcert_csr_build(dk, &meta, &csr) == WOLFCERT_OK);

    client_cfg.proto_opts.est.username = "bad";
    client_cfg.proto_opts.est.password = "wrong";
    WolfCertBuffer bad = { 0 };
    REQUIRE(wolfcert_est_simple_enroll(&client_cfg, csr.data, csr.len, &bad)
            == WOLFCERT_ERR_AUTH);

    wolfcert_buffer_free(&csr);
    wolfcert_key_free(dk);

    /* Basic-auth must be a full-length exact match. A credential whose base64
     * carries the correct token as a prefix plus trailing bytes must be
     * rejected, not accepted by a prefix-only comparison. This server's
     * "alice:hunter" is 12 bytes, so its base64 has no padding and the base64
     * of the longer "alice:hunterABC" extends it cleanly. */
    WolfCertServerCfgSrv acfg = {
        .protocol        = WOLFCERT_PROTO_EST,
        .bind_host       = "127.0.0.1", .bind_port = 0,
        .http_basic_user = "alice", .http_basic_pass = "hunter",
        .tls_cert_pem    = tls_cert, .tls_cert_pem_len = tls_cert_len,
        .tls_key_pem     = tls_key,  .tls_key_pem_len  = tls_key_len,
    };
    WolfCertServer* as = NULL;
    REQUIRE(wolfcert_server_start(&acfg, &as) == WOLFCERT_OK);
    pthread_t atid;
    REQUIRE(pthread_create(&atid, NULL, server_thread, as) == 0);

    char aurl[128];
    snprintf(aurl, sizeof(aurl), "https://127.0.0.1:%u/.well-known/est",
             wolfcert_server_port(as));
    WolfCertServerCfg acli = { .protocol = WOLFCERT_PROTO_EST, .server_url = aurl,
                               .trust_anchors = tls_cert,
                               .trust_anchors_len = tls_cert_len,
                               .verify_server = 1,
                               .proto_opts.est = { .username = "alice",
                                                   .password = "hunter" } };

    WolfCertKeyCfg akcfg = { .type = TEST_ENROLL_KEY_TYPE, .param = TEST_ENROLL_KEY_PARAM,
                             .dev_id = WOLFCERT_DEVID_SOFTWARE };
    WolfCertKey* adk = NULL;
    REQUIRE(wolfcert_key_generate(&akcfg, &adk) == WOLFCERT_OK);
    WolfCertCertMeta ameta = { .subject_dn = "CN=auth-exact" };
    WolfCertBuffer acsr = { 0 };
    REQUIRE(wolfcert_csr_build(adk, &ameta, &acsr) == WOLFCERT_OK);

    /* Exact credentials still enroll. */
    WolfCertBuffer aok = { 0 };
    REQUIRE(wolfcert_est_simple_enroll(&acli, acsr.data, acsr.len, &aok)
            == WOLFCERT_OK);
    wolfcert_buffer_free(&aok);

    /* Correct token prefix plus trailing bytes must be rejected. */
    acli.proto_opts.est.password = "hunterABC";
    WolfCertBuffer abad = { 0 };
    REQUIRE(wolfcert_est_simple_enroll(&acli, acsr.data, acsr.len, &abad)
            == WOLFCERT_ERR_AUTH);

    wolfcert_buffer_free(&acsr);
    wolfcert_key_free(adk);
    wolfcert_server_stop(as);
    pthread_join(atid, NULL);
    wolfcert_server_free(as);

    /* The pluggable transport must have been used for every request above. */
    REQUIRE(g_connect_calls > 0);

    wolfcert_server_stop(s);
    pthread_join(tid, NULL);
    wolfcert_server_free(s);

    wolfcert_buffer_free(&ca_pem);
    free(tls_cert);
    free(tls_key);
    wolfcert_cleanup();
    printf("OK (%d transport connects)\n", g_connect_calls);
    return 0;
}
