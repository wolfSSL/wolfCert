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

/* EST /csrattrs round trip; a 204 or a 404 from /csrattrs reads as no
 * attributes. */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#define _GNU_SOURCE

#include <wolfcert/wolfcert.h>
#include <wolfcert/est.h>
#include <wolfcert/server.h>

#include "tls_test_util.h"

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

static void* server_thread(void* arg)
{
    wolfcert_server_run((WolfCertServer*)arg);
    return NULL;
}

static const uint8_t OID_CHALLENGE_PASSWORD[] = {
    0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x07
};
static const uint8_t OID_ECDSA_SHA384[] = {
    0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03
};
static const uint8_t OID_EC_PUBLIC_KEY[] = {
    0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01
};
static const uint8_t OID_SECP384R1[] = { 0x2B, 0x81, 0x04, 0x00, 0x22 };

int main(void)
{
    REQUIRE(wolfcert_init(NULL) == WOLFCERT_OK);

    /* id-ecPublicKey value: the secp384r1 OID as one TLV. */
    uint8_t curve_oid_tlv[16];
    curve_oid_tlv[0] = 0x06;
    curve_oid_tlv[1] = (uint8_t)sizeof(OID_SECP384R1);
    memcpy(&curve_oid_tlv[2], OID_SECP384R1, sizeof(OID_SECP384R1));
    size_t curve_tlv_len = 2 + sizeof(OID_SECP384R1);

    WolfCertCsrAttrItem items[] = {
        { .kind = WOLFCERT_CSRATTR_BARE_OID,
          .oid = OID_CHALLENGE_PASSWORD, .oid_len = sizeof(OID_CHALLENGE_PASSWORD) },
        { .kind = WOLFCERT_CSRATTR_BARE_OID,
          .oid = OID_ECDSA_SHA384, .oid_len = sizeof(OID_ECDSA_SHA384) },
        { .kind = WOLFCERT_CSRATTR_ATTRIBUTE,
          .oid = OID_EC_PUBLIC_KEY, .oid_len = sizeof(OID_EC_PUBLIC_KEY),
          .values_der = curve_oid_tlv, .values_len = curve_tlv_len },
    };
    WolfCertBuffer blob = { 0 };
    REQUIRE(wolfcert_csr_attrs_build(items, 3, &blob) == WOLFCERT_OK);
    REQUIRE(blob.len > 0);

    uint8_t *tls_cert = NULL, *tls_key = NULL;
    size_t tls_cert_len = 0, tls_key_len = 0;
    REQUIRE(gen_server_identity(&tls_cert, &tls_cert_len,
                                &tls_key, &tls_key_len) == 0);

    WolfCertServerCfgSrv cfg = {
        .protocol            = WOLFCERT_PROTO_EST,
        .bind_host           = "127.0.0.1",
        .bind_port           = 0,
        .ca_store            = test_ca_store(),
        .csr_attributes_der  = blob.data,
        .csr_attributes_len  = blob.len,
        .tls_cert_pem        = tls_cert, .tls_cert_pem_len = tls_cert_len,
        .tls_key_pem         = tls_key,  .tls_key_pem_len  = tls_key_len,
        .est_allow_anonymous_enroll = 1,
    };
    WolfCertServer* srv = NULL;
    REQUIRE(wolfcert_server_start(&cfg, &srv) == WOLFCERT_OK);
    pthread_t tid;
    REQUIRE(pthread_create(&tid, NULL, server_thread, srv) == 0);

    char url[128];
    snprintf(url, sizeof(url), "https://127.0.0.1:%u/.well-known/est",
             wolfcert_server_port(srv));
    WolfCertServerCfg cli = { .protocol = WOLFCERT_PROTO_EST, .server_url = url,
                              .trust_anchors = tls_cert,
                              .trust_anchors_len = tls_cert_len,
                              .verify_server = 1 };

    WolfCertBuffer raw = { 0 };
    REQUIRE(wolfcert_est_get_csr_attrs(&cli, &raw) == WOLFCERT_OK);
    REQUIRE(raw.len == blob.len);
    REQUIRE(memcmp(raw.data, blob.data, blob.len) == 0);

    WolfCertCsrAttrs parsed;
    REQUIRE(wolfcert_est_parse_csr_attrs(raw.data, raw.len, &parsed) == WOLFCERT_OK);
    REQUIRE(parsed.count == 3);
    REQUIRE(parsed.require_challenge_password == 1);
    REQUIRE(parsed.preferred_hash             == 384);
    REQUIRE(parsed.preferred_key_type         == WOLFCERT_KEY_ECC);
    REQUIRE(parsed.preferred_ecc_curve_bits   == 384);
    REQUIRE(wolfcert_csr_attrs_find(&parsed,
            OID_CHALLENGE_PASSWORD, sizeof(OID_CHALLENGE_PASSWORD)) != NULL);

    WolfCertKeyCfg   kc = { 0 };
    WolfCertCertMeta cm = { 0 };
    REQUIRE(wolfcert_csr_attrs_apply(&parsed, &kc, &cm) == WOLFCERT_OK);
    REQUIRE(kc.type  == WOLFCERT_KEY_ECC);
    REQUIRE(kc.param == 384);
    REQUIRE(cm.preferred_hash == 384);

    /* Caller-set RSA-2048 and SHA-256 are left unchanged by apply. */
    WolfCertKeyCfg   kc2 = { .type = WOLFCERT_KEY_RSA, .param = 2048 };
    WolfCertCertMeta cm2 = { .preferred_hash = 256 };
    REQUIRE(wolfcert_csr_attrs_apply(&parsed, &kc2, &cm2) == WOLFCERT_OK);
    REQUIRE(kc2.type  == WOLFCERT_KEY_RSA);
    REQUIRE(kc2.param == 2048);
    REQUIRE(cm2.preferred_hash == 256);

    wolfcert_csr_attrs_free(&parsed);
    wolfcert_buffer_free(&raw);
    wolfcert_server_stop(srv);
    pthread_join(tid, NULL);
    wolfcert_server_free(srv);

    /* Server with no csr_attributes_der: get_csr_attrs gives (NULL, 0). */
    WolfCertServerCfgSrv cfg2 = {
        .protocol = WOLFCERT_PROTO_EST,
        .bind_host = "127.0.0.1", .bind_port = 0,
        .ca_store = test_ca_store(),
        .tls_cert_pem = tls_cert, .tls_cert_pem_len = tls_cert_len,
        .tls_key_pem  = tls_key,  .tls_key_pem_len  = tls_key_len,
        .est_allow_anonymous_enroll = 1,
    };
    WolfCertServer* srv2 = NULL;
    REQUIRE(wolfcert_server_start(&cfg2, &srv2) == WOLFCERT_OK);
    pthread_t tid2;
    REQUIRE(pthread_create(&tid2, NULL, server_thread, srv2) == 0);

    char url2[128];
    snprintf(url2, sizeof(url2), "https://127.0.0.1:%u/.well-known/est",
             wolfcert_server_port(srv2));
    WolfCertServerCfg cli2 = { .protocol = WOLFCERT_PROTO_EST, .server_url = url2,
                               .trust_anchors = tls_cert,
                               .trust_anchors_len = tls_cert_len,
                               .verify_server = 1 };

    WolfCertBuffer empty = { 0 };
    REQUIRE(wolfcert_est_get_csr_attrs(&cli2, &empty) == WOLFCERT_OK);
    REQUIRE(empty.data == NULL);
    REQUIRE(empty.len  == 0);

    /* The stray path segment makes the server answer 404 for /csrattrs. */
    char url404[160];
    snprintf(url404, sizeof(url404),
             "https://127.0.0.1:%u/.well-known/est/nope",
             wolfcert_server_port(srv2));
    WolfCertServerCfg cli404 = { .protocol = WOLFCERT_PROTO_EST,
                                 .server_url = url404,
                                 .trust_anchors = tls_cert,
                                 .trust_anchors_len = tls_cert_len,
                                 .verify_server = 1 };

    WolfCertBuffer notfound = { 0 };
    REQUIRE(wolfcert_est_get_csr_attrs(&cli404, &notfound) == WOLFCERT_OK);
    REQUIRE(notfound.data == NULL);
    REQUIRE(notfound.len  == 0);

    wolfcert_server_stop(srv2);
    pthread_join(tid2, NULL);
    wolfcert_server_free(srv2);

    wolfcert_buffer_free(&blob);
    free(tls_cert);
    free(tls_key);
    test_ca_store_close();
    wolfcert_cleanup();
    printf("OK\n");
    return 0;
}
