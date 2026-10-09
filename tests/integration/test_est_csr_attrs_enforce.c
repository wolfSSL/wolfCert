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

/* A CSR without the bare-OID challengePassword gets 400, and one that ignores a
 * P-384 Attribute-only policy enrolls; plus error-reply checks. */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#define _DARWIN_C_SOURCE   /* expose INADDR_LOOPBACK on macOS */
#define _GNU_SOURCE

#include <wolfcert/wolfcert.h>
#include <wolfcert/est.h>
#include <wolfcert/keygen.h>
#include <wolfcert/csr.h>
#include <wolfcert/client.h>
#include <wolfcert/server.h>

#include "tls_test_util.h"

#include <wolfssl/wolfcrypt/coding.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>   /* struct timeval for SO_RCVTIMEO */
#include <unistd.h>

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

static const uint8_t OID_CHALLENGE_PASSWORD[] = {
    0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x07
};
static const uint8_t OID_EC_PUBLIC_KEY[] = {
    0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01
};
static const uint8_t OID_SECP384R1[] = { 0x2B, 0x81, 0x04, 0x00, 0x22 };

/* Build a minimal CsrAttrs DER: one bare OID (challengePassword). */
static int build_policy(WolfCertBuffer* out)
{
    WolfCertCsrAttrItem items[1] = {
        { .kind = WOLFCERT_CSRATTR_BARE_OID,
          .oid = OID_CHALLENGE_PASSWORD,
          .oid_len = sizeof(OID_CHALLENGE_PASSWORD) },
    };
    return wolfcert_csr_attrs_build(items, 1, out);
}

/* Policy with only an Attribute-with-values item (id-ecPublicKey, P-384). */
static int build_values_only_policy(WolfCertBuffer* out)
{
    uint8_t curve_tlv[16];
    curve_tlv[0] = 0x06;
    curve_tlv[1] = (uint8_t)sizeof(OID_SECP384R1);
    memcpy(&curve_tlv[2], OID_SECP384R1, sizeof(OID_SECP384R1));
    size_t curve_tlv_len = 2 + sizeof(OID_SECP384R1);

    WolfCertCsrAttrItem items[1] = {
        { .kind = WOLFCERT_CSRATTR_ATTRIBUTE,
          .oid = OID_EC_PUBLIC_KEY,
          .oid_len = sizeof(OID_EC_PUBLIC_KEY),
          .values_der = curve_tlv, .values_len = curve_tlv_len },
    };
    return wolfcert_csr_attrs_build(items, 1, out);
}

static int enroll_with_challenge(WolfCertServer* s)
{
    char url[128];
    snprintf(url, sizeof(url), "https://127.0.0.1:%u/.well-known/est",
             wolfcert_server_port(s));
    WolfCertServerCfg srv = { .protocol = WOLFCERT_PROTO_EST,
                              .server_url = url,
                              .trust_anchors = g_ca,
                              .trust_anchors_len = g_ca_len,
                              .verify_server = 1 };

    WolfCertClient* cli = NULL;
    REQUIRE(wolfcert_client_new(&cli) == WOLFCERT_OK);

    WolfCertKeyCfg  key_cfg = { .type = TEST_ENROLL_KEY_TYPE, .param = TEST_ENROLL_KEY_PARAM,
                                .dev_id = WOLFCERT_DEVID_SOFTWARE };
    WolfCertCertMeta meta = {
        .subject_dn = "CN=enforce-ok",
        .challenge_password = "hunter2",
    };

    WolfCertKey* key = NULL;
    WolfCertBuffer cert_pem = { 0 };
    int rc = wolfcert_client_enroll(cli, &srv, &key_cfg, &meta,
                                    &key, &cert_pem);
    REQUIRE(rc == WOLFCERT_OK);
    REQUIRE(cert_pem.len > 0);

    wolfcert_buffer_free(&cert_pem);
    wolfcert_key_free(key);
    wolfcert_client_free(cli);
    return 0;
}

static int enroll_without_challenge(WolfCertServer* s)
{
    char url[128];
    snprintf(url, sizeof(url), "https://127.0.0.1:%u/.well-known/est",
             wolfcert_server_port(s));
    WolfCertServerCfg srv = { .protocol = WOLFCERT_PROTO_EST,
                              .server_url = url,
                              .trust_anchors = g_ca,
                              .trust_anchors_len = g_ca_len,
                              .verify_server = 1 };

    WolfCertClient* cli = NULL;
    REQUIRE(wolfcert_client_new(&cli) == WOLFCERT_OK);

    WolfCertKeyCfg  key_cfg = { .type = TEST_ENROLL_KEY_TYPE, .param = TEST_ENROLL_KEY_PARAM,
                                .dev_id = WOLFCERT_DEVID_SOFTWARE };
    WolfCertCertMeta meta = {
        .subject_dn = "CN=enforce-reject",
    };

    WolfCertKey* key = NULL;
    WolfCertBuffer cert_pem = { 0 };
    int rc = wolfcert_client_enroll(cli, &srv, &key_cfg, &meta,
                                    &key, &cert_pem);
    REQUIRE(rc == WOLFCERT_ERR_HTTP);
    REQUIRE(cert_pem.len == 0);

    wolfcert_buffer_free(&cert_pem);
    if (key != NULL)
        wolfcert_key_free(key);
    wolfcert_client_free(cli);
    return 0;
}

/* Send req over TLS and read the whole response. Returns bytes read, or -1. */
static int send_and_read_all(uint16_t port, const void* req, size_t req_len,
                             char* resp, size_t cap)
{
    struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };
    TestTlsConn c;
    size_t n = 0;

    if (test_tls_connect(&c, port, g_ca, g_ca_len) != 0)
        return -1;

    setsockopt(c.fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    if (test_tls_write(&c, req, req_len) != 0) {
        test_tls_close(&c);
        return -1;
    }

    while (n + 1 < cap) {
        int r = test_tls_read(&c, resp + n, cap - 1 - n);
        if (r <= 0)
            break;
        n += (size_t)r;
    }
    resp[n] = '\0';
    test_tls_close(&c);
    return (int)n;
}

/* The enforcement 400 body names the missing OID in dotted form. */
static int reject_body_names_missing_oid(uint16_t port)
{
    /* OID_CHALLENGE_PASSWORD in dotted form. */
    static const char EXPECT_OID[] = "1.2.840.113549.1.9.7";
    WolfCertKeyCfg key_cfg = { .type = TEST_ENROLL_KEY_TYPE, .param = TEST_ENROLL_KEY_PARAM,
                               .dev_id = WOLFCERT_DEVID_SOFTWARE };
    WolfCertCertMeta meta = { .subject_dn = "CN=raw-enforce" };
    WolfCertKey* key = NULL;
    WolfCertBuffer csr_der = { 0 };
    byte b64[2048];
    word32 b64_len = sizeof(b64);
    char req[4096];
    char resp[1024] = { 0 };
    int rl, n;

    REQUIRE(wolfcert_key_generate(&key_cfg, &key) == WOLFCERT_OK);
    REQUIRE(wolfcert_csr_build(key, &meta, &csr_der) == WOLFCERT_OK);

    /* Base64_Encode inserts newlines, which the server's decoder tolerates. */
    REQUIRE(Base64_Encode(csr_der.data, (word32)csr_der.len, b64, &b64_len) == 0);

    rl = snprintf(req, sizeof(req),
        "POST /.well-known/est/simpleenroll HTTP/1.1\r\n"
        "Host: 127.0.0.1\r\n"
        "Content-Type: application/pkcs10\r\n"
        "Content-Transfer-Encoding: base64\r\n"
        "Content-Length: %u\r\n"
        "Connection: close\r\n"
        "\r\n"
        "%.*s",
        (unsigned)b64_len, (int)b64_len, (const char*)b64);
    REQUIRE(rl > 0 && (size_t)rl < sizeof(req));

    n = send_and_read_all(port, req, (size_t)rl, resp, sizeof(resp));

    wolfcert_buffer_free(&csr_der);
    wolfcert_key_free(key);

    REQUIRE(n > 0);
    REQUIRE(strstr(resp, "400") != NULL);
    REQUIRE(strstr(resp, EXPECT_OID) != NULL);
    return 0;
}

/* Error responses carry a text/plain body (RFC 7030 section 4.2.3). */
static int reject_bodies_are_plaintext(uint16_t port)
{
    static const char* const reqs[] = {
        "GET /.well-known/est/nosuchop HTTP/1.1\r\n"
        "Host: 127.0.0.1\r\n"
        "Connection: close\r\n"
        "\r\n",
        "POST /.well-known/est/simpleenroll HTTP/1.1\r\n"
        "Host: 127.0.0.1\r\n"
        "Content-Type: application/pkcs10\r\n"
        "Content-Length: 0\r\n"
        "Connection: close\r\n"
        "\r\n"
    };
    char resp[1024];
    size_t i;

    for (i = 0; i < sizeof(reqs) / sizeof(reqs[0]); ++i) {
        const char* body;
        int n = send_and_read_all(port, reqs[i], strlen(reqs[i]),
                                  resp, sizeof(resp));
        REQUIRE(n > 0);
        REQUIRE(strstr(resp, i == 0 ? " 404 " : " 400 ") != NULL);
        REQUIRE(strstr(resp, "Content-Type: text/plain\r\n") != NULL);
        body = strstr(resp, "\r\n\r\n");
        REQUIRE(body != NULL && body[4] != '\0');
    }
    return 0;
}

/* RFC 9110: a 204 carries no Content-Length, a 401 carries a challenge, and a
 * missing client certificate is a 403 since HTTP auth cannot supply one. */
static int bare_status_headers(uint16_t port)
{
    static const char get_attrs[] =
        "GET /.well-known/est/csrattrs HTTP/1.1\r\n"
        "Host: 127.0.0.1\r\n"
        "Connection: close\r\n"
        "\r\n";
    static const char enroll_noauth[] =
        "POST /.well-known/est/simpleenroll HTTP/1.1\r\n"
        "Host: 127.0.0.1\r\n"
        "Content-Type: application/pkcs10\r\n"
        "Content-Length: 4\r\n"
        "Connection: close\r\n"
        "\r\n"
        "AAAA";
    static const char reenroll_nocert[] =
        "POST /.well-known/est/simplereenroll HTTP/1.1\r\n"
        "Host: 127.0.0.1\r\n"
        "Authorization: Basic YWxpY2U6c2VjcmV0\r\n"   /* alice:secret */
        "Content-Type: application/pkcs10\r\n"
        "Content-Length: 4\r\n"
        "Connection: close\r\n"
        "\r\n"
        "AAAA";
    char resp[1024];

    REQUIRE(send_and_read_all(port, get_attrs, sizeof(get_attrs) - 1,
                              resp, sizeof(resp)) > 0);
    REQUIRE(strstr(resp, " 204 ") != NULL);
    REQUIRE(strstr(resp, "Content-Length") == NULL);

    REQUIRE(send_and_read_all(port, enroll_noauth, sizeof(enroll_noauth) - 1,
                              resp, sizeof(resp)) > 0);
    REQUIRE(strstr(resp, " 401 ") != NULL);
    REQUIRE(strstr(resp, "WWW-Authenticate: Basic realm=") != NULL);

    REQUIRE(send_and_read_all(port, reenroll_nocert,
                              sizeof(reenroll_nocert) - 1,
                              resp, sizeof(resp)) > 0);
    REQUIRE(strstr(resp, " 403 ") != NULL);
    return 0;
}

static int values_only_policy_does_not_block(WolfCertServer* s)
{
    char url[128];
    snprintf(url, sizeof(url), "https://127.0.0.1:%u/.well-known/est",
             wolfcert_server_port(s));
    WolfCertServerCfg srv = { .protocol = WOLFCERT_PROTO_EST,
                              .server_url = url,
                              .trust_anchors = g_ca,
                              .trust_anchors_len = g_ca_len,
                              .verify_server = 1 };

    WolfCertClient* cli = NULL;
    REQUIRE(wolfcert_client_new(&cli) == WOLFCERT_OK);

    WolfCertKeyCfg  key_cfg = { .type = TEST_ENROLL_KEY_TYPE, .param = TEST_ENROLL_KEY_PARAM,
                                .dev_id = WOLFCERT_DEVID_SOFTWARE };
    WolfCertCertMeta meta = { .subject_dn = "CN=enforce-values-advisory" };

    WolfCertKey* key = NULL;
    WolfCertBuffer cert_pem = { 0 };
    int rc = wolfcert_client_enroll(cli, &srv, &key_cfg, &meta,
                                    &key, &cert_pem);
    REQUIRE(rc == WOLFCERT_OK);
    REQUIRE(cert_pem.len > 0);

    wolfcert_buffer_free(&cert_pem);
    wolfcert_key_free(key);
    wolfcert_client_free(cli);
    return 0;
}

int main(void)
{
    REQUIRE(wolfcert_init(NULL) == WOLFCERT_OK);

    WolfCertBuffer policy = { 0 };
    REQUIRE(build_policy(&policy) == WOLFCERT_OK);

    uint8_t *tls_cert = NULL, *tls_key = NULL;
    size_t tls_cert_len = 0, tls_key_len = 0;
    REQUIRE(gen_server_identity(&tls_cert, &tls_cert_len,
                                &tls_key, &tls_key_len) == 0);
    g_ca = tls_cert;
    g_ca_len = tls_cert_len;

    WolfCertServerCfgSrv cfg = {
        .protocol = WOLFCERT_PROTO_EST,
        .bind_host = "127.0.0.1", .bind_port = 0,
        .ca_store = test_ca_store(),
        .csr_attributes_der = policy.data,
        .csr_attributes_len = policy.len,
        .est_require_csr_attributes = 1,
        .tls_cert_pem = tls_cert, .tls_cert_pem_len = tls_cert_len,
        .tls_key_pem  = tls_key,  .tls_key_pem_len  = tls_key_len,
        .est_allow_anonymous_enroll = 1,
    };
    WolfCertServer* srv = NULL;
    REQUIRE(wolfcert_server_start(&cfg, &srv) == WOLFCERT_OK);
    pthread_t tid;
    REQUIRE(pthread_create(&tid, NULL, server_thread, srv) == 0);

    int rc = enroll_with_challenge(srv);
    if (rc == 0)
        rc = enroll_without_challenge(srv);

    wolfcert_server_stop(srv);
    pthread_join(tid, NULL);
    wolfcert_server_free(srv);
    wolfcert_buffer_free(&policy);
    if (rc != 0)
        return rc;

    WolfCertBuffer policy2 = { 0 };
    REQUIRE(build_values_only_policy(&policy2) == WOLFCERT_OK);
    WolfCertServerCfgSrv cfg2 = {
        .protocol = WOLFCERT_PROTO_EST,
        .bind_host = "127.0.0.1", .bind_port = 0,
        .ca_store = test_ca_store(),
        .csr_attributes_der = policy2.data,
        .csr_attributes_len = policy2.len,
        .est_require_csr_attributes = 1,
        .tls_cert_pem = tls_cert, .tls_cert_pem_len = tls_cert_len,
        .tls_key_pem  = tls_key,  .tls_key_pem_len  = tls_key_len,
        .est_allow_anonymous_enroll = 1,
    };
    WolfCertServer* srv2 = NULL;
    REQUIRE(wolfcert_server_start(&cfg2, &srv2) == WOLFCERT_OK);
    pthread_t tid2;
    REQUIRE(pthread_create(&tid2, NULL, server_thread, srv2) == 0);

    rc = values_only_policy_does_not_block(srv2);

    wolfcert_server_stop(srv2);
    pthread_join(tid2, NULL);
    wolfcert_server_free(srv2);
    wolfcert_buffer_free(&policy2);
    if (rc != 0)
        return rc;

    /* Raw HTTP against the bare-OID policy, so the 400 body is readable. */
    WolfCertBuffer policy_raw = { 0 };
    REQUIRE(build_policy(&policy_raw) == WOLFCERT_OK);
    WolfCertServerCfgSrv cfg_raw = {
        .protocol = WOLFCERT_PROTO_EST,
        .bind_host = "127.0.0.1", .bind_port = 0,
        .ca_store = test_ca_store(),
        .csr_attributes_der = policy_raw.data,
        .csr_attributes_len = policy_raw.len,
        .est_require_csr_attributes = 1,
        .tls_cert_pem = tls_cert, .tls_cert_pem_len = tls_cert_len,
        .tls_key_pem  = tls_key,  .tls_key_pem_len  = tls_key_len,
        .est_allow_anonymous_enroll = 1,
    };
    WolfCertServer* srv_raw = NULL;
    REQUIRE(wolfcert_server_start(&cfg_raw, &srv_raw) == WOLFCERT_OK);
    pthread_t tid_raw;
    REQUIRE(pthread_create(&tid_raw, NULL, server_thread, srv_raw) == 0);

    rc = reject_body_names_missing_oid(wolfcert_server_port(srv_raw));
    if (rc == 0)
        rc = reject_bodies_are_plaintext(wolfcert_server_port(srv_raw));

    wolfcert_server_stop(srv_raw);
    pthread_join(tid_raw, NULL);
    wolfcert_server_free(srv_raw);
    wolfcert_buffer_free(&policy_raw);
    if (rc != 0)
        return rc;

    /* Fourth server with no policy and Basic auth on, for bodiless replies. */
    WolfCertServerCfgSrv cfg_bare = {
        .protocol = WOLFCERT_PROTO_EST,
        .bind_host = "127.0.0.1", .bind_port = 0,
        .ca_store = test_ca_store(),
        .http_basic_user = "alice", .http_basic_pass = "secret",
        .tls_cert_pem = tls_cert, .tls_cert_pem_len = tls_cert_len,
        .tls_key_pem  = tls_key,  .tls_key_pem_len  = tls_key_len,
    };
    WolfCertServer* srv_bare = NULL;
    REQUIRE(wolfcert_server_start(&cfg_bare, &srv_bare) == WOLFCERT_OK);
    pthread_t tid_bare;
    REQUIRE(pthread_create(&tid_bare, NULL, server_thread, srv_bare) == 0);

    rc = bare_status_headers(wolfcert_server_port(srv_bare));

    wolfcert_server_stop(srv_bare);
    pthread_join(tid_bare, NULL);
    wolfcert_server_free(srv_bare);
    free(tls_cert);
    free(tls_key);
    if (rc != 0)
        return rc;

    test_ca_store_close();
    wolfcert_cleanup();
    printf("OK\n");
    return 0;
}
