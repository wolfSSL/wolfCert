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

/* auto_csrattrs picks ECC P-384 for an empty key_cfg, an explicit key_cfg.type
 * wins, and fetch_meta surfaces the SHA-384 hint. */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#define _GNU_SOURCE

#include <wolfcert/wolfcert.h>
#include <wolfcert/est.h>
#include <wolfcert/client.h>
#include <wolfcert/server.h>

#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/ecc.h>

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
static const uint8_t OID_ECDSA_SHA384[] = {
    0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03
};
static const uint8_t OID_EC_PUBLIC_KEY[] = {
    0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01
};
static const uint8_t OID_SECP384R1[] = { 0x2B, 0x81, 0x04, 0x00, 0x22 };

static int build_policy(WolfCertBuffer* out)
{
    /* The id-ecPublicKey attribute value is the TLV-encoded curve OID. */
    uint8_t curve_tlv[16];
    curve_tlv[0] = 0x06;
    curve_tlv[1] = (uint8_t)sizeof(OID_SECP384R1);
    memcpy(&curve_tlv[2], OID_SECP384R1, sizeof(OID_SECP384R1));
    size_t curve_tlv_len = 2 + sizeof(OID_SECP384R1);

    WolfCertCsrAttrItem items[3] = {
        { .kind = WOLFCERT_CSRATTR_BARE_OID,
          .oid = OID_CHALLENGE_PASSWORD,
          .oid_len = sizeof(OID_CHALLENGE_PASSWORD) },
        { .kind = WOLFCERT_CSRATTR_BARE_OID,
          .oid = OID_ECDSA_SHA384,
          .oid_len = sizeof(OID_ECDSA_SHA384) },
        { .kind = WOLFCERT_CSRATTR_ATTRIBUTE,
          .oid = OID_EC_PUBLIC_KEY,
          .oid_len = sizeof(OID_EC_PUBLIC_KEY),
          .values_der = curve_tlv, .values_len = curve_tlv_len },
    };
    return wolfcert_csr_attrs_build(items, 3, out);
}

/* Read the ECC curve id out of the issued cert's public key. */
#ifdef WOLFCERT_HAVE_ECC
static int inspect_cert(const uint8_t* pem, size_t pem_len,
                        int* out_curve_id)
{
    DerBuffer* der = NULL;
    int rc = wc_PemToDer(pem, (long)pem_len, CERT_TYPE, &der, NULL, NULL, NULL);
    if (rc != 0)
        return -1;

    DecodedCert dc;
    wc_InitDecodedCert(&dc, der->buffer, der->length, NULL);
    rc = wc_ParseCert(&dc, CERT_TYPE, NO_VERIFY, NULL);
    if (rc == 0) {
        ecc_key eck;
        wc_ecc_init(&eck);
        word32 idx = 0;
        if (wc_EccPublicKeyDecode(dc.publicKey, &idx, &eck,
                                  dc.pubKeySize) == 0 &&
            eck.dp != NULL) {
            *out_curve_id = eck.dp->id;
        } else {
            *out_curve_id = -1;
        }
        wc_ecc_free(&eck);
    }
    wc_FreeDecodedCert(&dc);
    wc_FreeDer(&der);
    return rc == 0 ? 0 : -1;
}

static int auto_apply_pins_everything(WolfCertServer* s)
{
    char url[128];
    snprintf(url, sizeof(url), "https://127.0.0.1:%u/.well-known/est",
             wolfcert_server_port(s));

    WolfCertServerCfg srv = {
        .protocol = WOLFCERT_PROTO_EST,
        .server_url = url,
        .proto_opts.est = { .auto_csrattrs = 1 },
        .trust_anchors = g_ca, .trust_anchors_len = g_ca_len,
        .verify_server = 1,
    };

    WolfCertClient* cli = NULL;
    REQUIRE(wolfcert_client_new(&cli) == WOLFCERT_OK);

    WolfCertKeyCfg key_cfg = { .dev_id = WOLFCERT_DEVID_SOFTWARE };
    WolfCertCertMeta meta = {
        .subject_dn = "CN=csrattrs-auto-1",
        .challenge_password = "hunter2",
    };

    WolfCertKey* key = NULL;
    WolfCertBuffer cert_pem = { 0 };
    int rc = wolfcert_client_enroll(cli, &srv, &key_cfg, &meta,
                                    &key, &cert_pem);
    REQUIRE(rc == WOLFCERT_OK);
    REQUIRE(key != NULL);
    REQUIRE(wolfcert_key_type(key) == WOLFCERT_KEY_ECC);

    int curve = 0;
    REQUIRE(inspect_cert(cert_pem.data, cert_pem.len, &curve) == 0);
    REQUIRE(curve == ECC_SECP384R1);

    wolfcert_buffer_free(&cert_pem);
    wolfcert_key_free(key);
    wolfcert_client_free(cli);
    return 0;
}
#endif /* WOLFCERT_HAVE_ECC */

#ifdef WOLFCERT_HAVE_RSA
static int explicit_caller_wins(WolfCertServer* s)
{
    char url[128];
    snprintf(url, sizeof(url), "https://127.0.0.1:%u/.well-known/est",
             wolfcert_server_port(s));
    WolfCertServerCfg srv = {
        .protocol = WOLFCERT_PROTO_EST,
        .server_url = url,
        .proto_opts.est = { .auto_csrattrs = 1 },
        .trust_anchors = g_ca, .trust_anchors_len = g_ca_len,
        .verify_server = 1,
    };

    WolfCertClient* cli = NULL;
    REQUIRE(wolfcert_client_new(&cli) == WOLFCERT_OK);

    WolfCertKeyCfg key_cfg = {
        .type = WOLFCERT_KEY_RSA, .param = 2048,
        .dev_id = WOLFCERT_DEVID_SOFTWARE,
    };
    WolfCertCertMeta meta = {
        .subject_dn = "CN=csrattrs-auto-2",
        .challenge_password = "hunter2",
    };

    WolfCertKey* key = NULL;
    WolfCertBuffer cert_pem = { 0 };
    int rc = wolfcert_client_enroll(cli, &srv, &key_cfg, &meta,
                                    &key, &cert_pem);
    REQUIRE(rc == WOLFCERT_OK);
    REQUIRE(wolfcert_key_type(key) == WOLFCERT_KEY_RSA);

    wolfcert_buffer_free(&cert_pem);
    wolfcert_key_free(key);
    wolfcert_client_free(cli);
    return 0;
}
#endif /* WOLFCERT_HAVE_RSA */

static int fetch_meta_overlays_hash(WolfCertServer* s)
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

    WolfCertCertMeta meta = { 0 };
    REQUIRE(wolfcert_client_fetch_meta(cli, &srv, &meta) == WOLFCERT_OK);
    REQUIRE(meta.preferred_hash == 384);

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
        .tls_cert_pem = tls_cert, .tls_cert_pem_len = tls_cert_len,
        .tls_key_pem  = tls_key,  .tls_key_pem_len  = tls_key_len,
        .est_allow_anonymous_enroll = 1,
    };
    WolfCertServer* srv = NULL;
    REQUIRE(wolfcert_server_start(&cfg, &srv) == WOLFCERT_OK);
    pthread_t tid;
    REQUIRE(pthread_create(&tid, NULL, server_thread, srv) == 0);

    int rc = 0;
#ifdef WOLFCERT_HAVE_ECC
    if (rc == 0)
        rc = auto_apply_pins_everything(srv);
#endif
#ifdef WOLFCERT_HAVE_RSA
    if (rc == 0)
        rc = explicit_caller_wins(srv);
#endif
    if (rc == 0)
        rc = fetch_meta_overlays_hash(srv);

    wolfcert_server_stop(srv);
    pthread_join(tid, NULL);
    wolfcert_server_free(srv);
    wolfcert_buffer_free(&policy);
    free(tls_cert);
    free(tls_key);
    if (rc != 0)
        return rc;

    test_ca_store_close();
    wolfcert_cleanup();
    printf("OK\n");
    return 0;
}
