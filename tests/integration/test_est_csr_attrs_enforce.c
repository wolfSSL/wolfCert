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
 * End-to-end coverage for server-side enforcement of the CsrAttrs
 * policy (RFC 7030 section 4.5.2). The test server advertises a bare-OID
 * challengePassword requirement + `est_require_csr_attributes = 1`:
 *
 *   - Client A sets meta.challenge_password so the CSR carries the
 *     attribute -> enrollment must succeed.
 *   - Client B omits it -> server rejects with HTTP 400 and the
 *     client surfaces WOLFCERT_ERR_HTTP.
 *
 * Enforcement happens presence-only in this phase (bare-OID items
 * only); Attribute-with-values items are advisory. See docs/TODO.md
 * for the value-comparison follow-up.
 */

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
#include <unistd.h>

#define REQUIRE(cond) \
    do {                                                                    \
        if (!(cond)) {                                                      \
            fprintf(stderr, "FAIL %s:%d %s\n", __FILE__, __LINE__, #cond);  \
            return 1;                                                       \
        }                                                                   \
    } while (0)

/* Server TLS trust anchor, pinned by the client (EST is TLS-only, RFC 7030). */
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

/* Build a policy that contains ONLY an Attribute-with-values item
 * (id-ecPublicKey pinning secp384r1) and no bare OIDs. Phase-3
 * enforcement is presence-only on bare OIDs, so a CSR that doesn't
 * carry the attribute must still be accepted - this is the policy
 * used to prove that skip is intentional. */
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

/* Client A - CSR carries challengePassword -> enrollment succeeds. */
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

    WolfCertKeyCfg  key_cfg = { .type = WOLFCERT_KEY_ECC, .param = 256,
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

/* Client B - CSR omits challengePassword -> server returns 400. */
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

    WolfCertKeyCfg  key_cfg = { .type = WOLFCERT_KEY_ECC, .param = 256,
                                .dev_id = WOLFCERT_DEVID_SOFTWARE };
    WolfCertCertMeta meta = {
        .subject_dn = "CN=enforce-reject",
        /* no challenge_password -> CSR lacks the required attribute */
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

/* Dial 127.0.0.1:port over plain TCP, send the request, and read the whole
 * response (headers + body) into `resp`. A receive timeout keeps a
 * misbehaving server from hanging the test. Returns bytes read, or -1. */
static int send_and_read_all(uint16_t port, const void* req, size_t req_len,
                             char* resp, size_t cap)
{
    struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };
    struct sockaddr_in sa = { .sin_family = AF_INET,
                              .sin_port = htons(port),
                              .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    const char* p = req;
    size_t left = req_len;
    size_t n = 0;
    int cs = socket(AF_INET, SOCK_STREAM, 0);
    if (cs < 0)
        return -1;
    setsockopt(cs, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    if (connect(cs, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
        close(cs);
        return -1;
    }
    while (left > 0) {
        ssize_t w = send(cs, p, left, 0);
        if (w <= 0) {
            close(cs);
            return -1;
        }
        p += (size_t)w;
        left -= (size_t)w;
    }
    while (n + 1 < cap) {
        ssize_t r = recv(cs, resp + n, cap - 1 - n, 0);
        if (r <= 0)
            break;
        n += (size_t)r;
    }
    resp[n] = '\0';
    close(cs);
    return (int)n;
}

/* Raw plain-HTTP probe of the enforcement 400 body: build a real CSR that
 * omits challengePassword, POST it to /simpleenroll, and assert the response
 * both fails with 400 and names the exact missing OID in dotted form. This is
 * the end-to-end check that the value-result OID copy in csr_attrs_enforce
 * renders the correct bytes; the client path above only observes rejection,
 * not the body. */
static int reject_body_names_missing_oid(uint16_t port)
{
    /* challengePassword dotted OID (see OID_CHALLENGE_PASSWORD above). */
    static const char EXPECT_OID[] = "1.2.840.113549.1.9.7";
    WolfCertKeyCfg key_cfg = { .type = WOLFCERT_KEY_ECC, .param = 256,
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

    /* EST simpleenroll carries base64 PKCS#10; the server base64-decodes the
     * request body (embedded newlines are tolerated by the decoder). */
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

/* Client C - server advertises ONLY an Attribute-with-values item
 * (no bare OIDs). The CSR doesn't carry anything matching it.
 * Enforcement is presence-only on bare OIDs, so this must still
 * succeed. Pins the "Attribute items are advisory" behaviour so a
 * future refactor flipping it to enforce-by-default breaks here. */
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

    WolfCertKeyCfg  key_cfg = { .type = WOLFCERT_KEY_ECC, .param = 256,
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

    /* EST runs over TLS (RFC 7030): pin a freshly minted server identity. */
    uint8_t *tls_cert = NULL, *tls_key = NULL;
    size_t tls_cert_len = 0, tls_key_len = 0;
    REQUIRE(gen_server_identity(&tls_cert, &tls_cert_len,
                                &tls_key, &tls_key_len) == 0);
    g_ca = tls_cert;
    g_ca_len = tls_cert_len;

    WolfCertServerCfgSrv cfg = {
        .protocol = WOLFCERT_PROTO_EST,
        .bind_host = "127.0.0.1", .bind_port = 0,
        .csr_attributes_der = policy.data,
        .csr_attributes_len = policy.len,
        .est_require_csr_attributes = 1,
        .tls_cert_pem = tls_cert, .tls_cert_pem_len = tls_cert_len,
        .tls_key_pem  = tls_key,  .tls_key_pem_len  = tls_key_len,
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

    /* Second server with a values-only policy; any CSR must pass. */
    WolfCertBuffer policy2 = { 0 };
    REQUIRE(build_values_only_policy(&policy2) == WOLFCERT_OK);
    WolfCertServerCfgSrv cfg2 = {
        .protocol = WOLFCERT_PROTO_EST,
        .bind_host = "127.0.0.1", .bind_port = 0,
        .csr_attributes_der = policy2.data,
        .csr_attributes_len = policy2.len,
        .est_require_csr_attributes = 1,
        .tls_cert_pem = tls_cert, .tls_cert_pem_len = tls_cert_len,
        .tls_key_pem  = tls_key,  .tls_key_pem_len  = tls_key_len,
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
    free(tls_cert);
    free(tls_key);
    if (rc != 0)
        return rc;

    /* Plain-HTTP server (no TLS) with the same bare-OID policy, so the raw
     * 400 body is readable: asserts it names the missing OID in dotted form.
     * The client path above proves rejection; this proves the reported OID
     * content (i.e. the value-result OID copy renders the right bytes). */
    WolfCertBuffer policy_raw = { 0 };
    REQUIRE(build_policy(&policy_raw) == WOLFCERT_OK);
    WolfCertServerCfgSrv cfg_raw = {
        .protocol = WOLFCERT_PROTO_EST,
        .bind_host = "127.0.0.1", .bind_port = 0,
        .csr_attributes_der = policy_raw.data,
        .csr_attributes_len = policy_raw.len,
        .est_require_csr_attributes = 1,
    };
    WolfCertServer* srv_raw = NULL;
    REQUIRE(wolfcert_server_start(&cfg_raw, &srv_raw) == WOLFCERT_OK);
    pthread_t tid_raw;
    REQUIRE(pthread_create(&tid_raw, NULL, server_thread, srv_raw) == 0);

    rc = reject_body_names_missing_oid(wolfcert_server_port(srv_raw));

    wolfcert_server_stop(srv_raw);
    pthread_join(tid_raw, NULL);
    wolfcert_server_free(srv_raw);
    wolfcert_buffer_free(&policy_raw);
    if (rc != 0)
        return rc;

    wolfcert_cleanup();
    printf("OK\n");
    return 0;
}
