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

/* EST with keys that never leave a mock CryptoCb key store, which keeps them
 * by key_id and counts the private-key operations it performs. */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#define _DARWIN_C_SOURCE
#define _GNU_SOURCE

#include <wolfcert/wolfcert.h>
#include <wolfcert/est.h>
#ifdef WOLFCERT_HAVE_SCEP
#include <wolfcert/scep.h>
#endif
#include <wolfcert/server.h>

#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/cryptocb.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#include "tls_test_util.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if !defined(WOLF_CRYPTO_CB) || !defined(WOLF_PRIVATE_KEY_ID)
int main(void)
{
    printf("SKIP (wolfSSL built without WOLF_CRYPTO_CB or "
           "WOLF_PRIVATE_KEY_ID)\n");
    return 77;
}
#else

#define REQUIRE(cond) \
    do {                                                                    \
        if (!(cond)) {                                                      \
            fprintf(stderr, "FAIL %s:%d %s\n", __FILE__, __LINE__, #cond);  \
            return 1;                                                       \
        }                                                                   \
    } while (0)

#define MOCK_DEVID 0x6d6b
#define MOCK_SLOTS 4

enum { MOCK_ECC = 1, MOCK_RSA, MOCK_MLDSA, MOCK_ED25519, MOCK_ED448 };

/* wolfSSL after 5.9.4 can name Ed25519 and Ed448 keys by id. */
#if defined(WOLFCERT_HAVE_ED25519) && defined(ED25519_MAX_ID_LEN)
#define MOCK_HAVE_ED25519
#endif
#if defined(WOLFCERT_HAVE_ED448) && defined(ED448_MAX_ID_LEN)
#define MOCK_HAVE_ED448
#endif

typedef struct {
    byte id[WOLFCERT_KEY_ID_MAX_LEN];
    int  id_len;
    int  type;
#ifdef WOLFCERT_HAVE_ECC
    ecc_key ecc;
#endif
#ifdef WOLFCERT_HAVE_RSA
    RsaKey  rsa;
#endif
#ifdef WOLFCERT_HAVE_MLDSA
    MlDsaKey mldsa;
#endif
#ifdef MOCK_HAVE_ED25519
    ed25519_key ed25519;
#endif
#ifdef MOCK_HAVE_ED448
    ed448_key ed448;
#endif
} MockSlot;

static MockSlot mock_slots[MOCK_SLOTS];
static int mock_sign_requests;
static int mock_keygens;
static int mock_private_ops;

static MockSlot* mock_find(const byte* id, int id_len)
{
    for (int i = 0; i < MOCK_SLOTS; i++) {
        if (mock_slots[i].id_len == id_len && id_len > 0 &&
            memcmp(mock_slots[i].id, id, (size_t)id_len) == 0)
            return &mock_slots[i];
    }
    return NULL;
}

static MockSlot* mock_new(const byte* id, int id_len, int type)
{
    if (mock_find(id, id_len) != NULL)
        return NULL;
    for (int i = 0; i < MOCK_SLOTS; i++) {
        if (mock_slots[i].id_len == 0) {
            memcpy(mock_slots[i].id, id, (size_t)id_len);
            mock_slots[i].id_len = id_len;
            mock_slots[i].type   = type;
            return &mock_slots[i];
        }
    }
    return NULL;
}

static int mock_cb(int devId, wc_CryptoInfo* info, void* ctx)
{
    (void)devId;
    (void)ctx;

    if (info->algo_type != WC_ALGO_TYPE_PK)
        return CRYPTOCB_UNAVAILABLE;

    switch (info->pk.type) {
#ifdef WOLFCERT_HAVE_ECC
    case WC_PK_TYPE_EC_KEYGEN: {
        ecc_key* key = info->pk.eckg.key;
        byte pub[1 + 2 * MAX_ECC_BYTES];
        word32 pub_len = sizeof(pub);
        MockSlot* s;
        int rc;

        if (key->idLen == 0)
            return CRYPTOCB_UNAVAILABLE;
        s = mock_new(key->id, key->idLen, MOCK_ECC);
        if (s == NULL)
            return BAD_STATE_E;
        rc = wc_ecc_init_ex(&s->ecc, NULL, INVALID_DEVID);
        if (rc == 0)
            rc = wc_ecc_make_key_ex(info->pk.eckg.rng, info->pk.eckg.size,
                                    &s->ecc, info->pk.eckg.curveId);
        if (rc == 0)
            rc = wc_ecc_export_x963(&s->ecc, pub, &pub_len);
        if (rc == 0)
            rc = wc_ecc_import_x963_ex(pub, pub_len, key,
                                       info->pk.eckg.curveId);
        if (rc == 0)
            mock_keygens++;
        return rc;
    }
    case WC_PK_TYPE_ECDSA_SIGN: {
        ecc_key* key = info->pk.eccsign.key;
        MockSlot* s = mock_find(key->id, key->idLen);
        int rc;

        mock_sign_requests++;
        if (s == NULL || s->type != MOCK_ECC)
            return CRYPTOCB_UNAVAILABLE;
        rc = wc_ecc_sign_hash(info->pk.eccsign.in, info->pk.eccsign.inlen,
                              info->pk.eccsign.out, info->pk.eccsign.outlen,
                              info->pk.eccsign.rng, &s->ecc);
        if (rc == 0)
            mock_private_ops++;
        return rc;
    }
#endif
#ifdef WOLFCERT_HAVE_RSA
    case WC_PK_TYPE_RSA_KEYGEN: {
        RsaKey* key = info->pk.rsakg.key;
        byte n[512], e[8];
        word32 n_len = sizeof(n), e_len = sizeof(e);
        MockSlot* s;
        int rc;

        if (key->idLen == 0)
            return CRYPTOCB_UNAVAILABLE;
        s = mock_new(key->id, key->idLen, MOCK_RSA);
        if (s == NULL)
            return BAD_STATE_E;
        rc = wc_InitRsaKey_ex(&s->rsa, NULL, INVALID_DEVID);
        if (rc == 0)
            rc = wc_MakeRsaKey(&s->rsa, info->pk.rsakg.size,
                               info->pk.rsakg.e, info->pk.rsakg.rng);
        if (rc == 0)
            rc = wc_RsaFlattenPublicKey(&s->rsa, e, &e_len, n, &n_len);
        if (rc == 0)
            rc = wc_RsaPublicKeyDecodeRaw(n, n_len, e, e_len, key);
        if (rc == 0)
            mock_keygens++;
        return rc;
    }
    case WC_PK_TYPE_RSA: {
        RsaKey* key = info->pk.rsa.key;
        MockSlot* s = mock_find(key->id, key->idLen);
        int rc;

        if (info->pk.rsa.type == RSA_PRIVATE_ENCRYPT)
            mock_sign_requests++;
        if (s == NULL || s->type != MOCK_RSA)
            return CRYPTOCB_UNAVAILABLE;
        rc = wc_RsaFunction(info->pk.rsa.in, info->pk.rsa.inLen,
                            info->pk.rsa.out, info->pk.rsa.outLen,
                            info->pk.rsa.type, &s->rsa, info->pk.rsa.rng);
        if (rc == 0 && (info->pk.rsa.type == RSA_PRIVATE_ENCRYPT ||
                        info->pk.rsa.type == RSA_PRIVATE_DECRYPT))
            mock_private_ops++;
        return rc;
    }
#endif
#ifdef WOLFCERT_HAVE_MLDSA
    case WC_PK_TYPE_PQC_SIG_KEYGEN: {
        MlDsaKey* key = (MlDsaKey*)info->pk.pqc_sig_kg.key;
        byte pub[WC_MLDSA_87_PUB_KEY_SIZE];
        word32 pub_len = sizeof(pub);
        MockSlot* s;
        int rc;

        if (info->pk.pqc_sig_kg.type != WC_PQC_SIG_TYPE_MLDSA ||
            key->idLen == 0)
            return CRYPTOCB_UNAVAILABLE;
        s = mock_new(key->id, key->idLen, MOCK_MLDSA);
        if (s == NULL)
            return BAD_STATE_E;
        rc = wc_MlDsaKey_Init(&s->mldsa, NULL, INVALID_DEVID);
        if (rc == 0)
            rc = wc_MlDsaKey_SetParams(&s->mldsa,
                                       (byte)info->pk.pqc_sig_kg.size);
        if (rc == 0)
            rc = wc_MlDsaKey_MakeKey(&s->mldsa, info->pk.pqc_sig_kg.rng);
        if (rc == 0)
            rc = wc_MlDsaKey_ExportPubRaw(&s->mldsa, pub, &pub_len);
        if (rc == 0)
            rc = wc_MlDsaKey_ImportPubRaw(key, pub, pub_len);
        if (rc == 0)
            mock_keygens++;
        return rc;
    }
    case WC_PK_TYPE_PQC_SIG_SIGN: {
        MlDsaKey* key = (MlDsaKey*)info->pk.pqc_sign.key;
        MockSlot* s;
        int rc;

        mock_sign_requests++;
        if (info->pk.pqc_sign.type != WC_PQC_SIG_TYPE_MLDSA ||
            info->pk.pqc_sign.preHashType != WC_HASH_TYPE_NONE ||
            info->pk.pqc_sign.addRnd != NULL)
            return CRYPTOCB_UNAVAILABLE;
        s = mock_find(key->id, key->idLen);
        if (s == NULL || s->type != MOCK_MLDSA)
            return CRYPTOCB_UNAVAILABLE;
        rc = wc_MlDsaKey_SignCtx(&s->mldsa, info->pk.pqc_sign.context,
                                 info->pk.pqc_sign.contextLen,
                                 info->pk.pqc_sign.out,
                                 info->pk.pqc_sign.outlen,
                                 info->pk.pqc_sign.in, info->pk.pqc_sign.inlen,
                                 info->pk.pqc_sign.rng);
        if (rc == 0)
            mock_private_ops++;
        return rc;
    }
#endif
#ifdef MOCK_HAVE_ED25519
    case WC_PK_TYPE_ED25519_KEYGEN: {
        ed25519_key* key = info->pk.ed25519kg.key;
        byte pub[ED25519_PUB_KEY_SIZE];
        word32 pub_len = sizeof(pub);
        MockSlot* s;
        int rc;

        if (key->idLen == 0)
            return CRYPTOCB_UNAVAILABLE;
        s = mock_new(key->id, key->idLen, MOCK_ED25519);
        if (s == NULL)
            return BAD_STATE_E;
        rc = wc_ed25519_init_ex(&s->ed25519, NULL, INVALID_DEVID);
        if (rc == 0)
            rc = wc_ed25519_make_key(info->pk.ed25519kg.rng,
                                     info->pk.ed25519kg.size, &s->ed25519);
        if (rc == 0)
            rc = wc_ed25519_export_public(&s->ed25519, pub, &pub_len);
        if (rc == 0)
            rc = wc_ed25519_import_public(pub, pub_len, key);
        if (rc == 0)
            mock_keygens++;
        return rc;
    }
    case WC_PK_TYPE_ED25519_SIGN: {
        ed25519_key* key = info->pk.ed25519sign.key;
        MockSlot* s = mock_find(key->id, key->idLen);
        int rc;

        mock_sign_requests++;
        if (s == NULL || s->type != MOCK_ED25519)
            return CRYPTOCB_UNAVAILABLE;
        rc = wc_ed25519_sign_msg_ex(info->pk.ed25519sign.in,
                                    info->pk.ed25519sign.inLen,
                                    info->pk.ed25519sign.out,
                                    info->pk.ed25519sign.outLen, &s->ed25519,
                                    info->pk.ed25519sign.type,
                                    info->pk.ed25519sign.context,
                                    info->pk.ed25519sign.contextLen);
        if (rc == 0)
            mock_private_ops++;
        return rc;
    }
#endif
#ifdef MOCK_HAVE_ED448
    case WC_PK_TYPE_ED448: {
        ed448_key* key = info->pk.ed448sign.key;
        MockSlot* s = mock_find(key->id, key->idLen);
        int rc;

        mock_sign_requests++;
        if (s == NULL || s->type != MOCK_ED448)
            return CRYPTOCB_UNAVAILABLE;
        rc = wc_ed448_sign_msg_ex(info->pk.ed448sign.in,
                                  info->pk.ed448sign.inLen,
                                  info->pk.ed448sign.out,
                                  info->pk.ed448sign.outLen, &s->ed448,
                                  info->pk.ed448sign.type,
                                  info->pk.ed448sign.context,
                                  info->pk.ed448sign.contextLen);
        if (rc == 0)
            mock_private_ops++;
        return rc;
    }
#endif
    default:
        return CRYPTOCB_UNAVAILABLE;
    }
}

#ifdef MOCK_HAVE_ED448
/* Provisions the store's key out of band, since not every wolfSSL with Ed448
 * key ids passes Ed448 keygen to a CryptoCb. */
static int mock_provision_ed448(const byte* id, int id_len, byte* cert,
                                int* cert_len)
{
    MockSlot* s = mock_new(id, id_len, MOCK_ED448);
    Cert c;
    WC_RNG rng;
    int n;

    if (s == NULL || wc_InitRng(&rng) != 0)
        return -1;
    n = wc_ed448_init_ex(&s->ed448, NULL, INVALID_DEVID);
    if (n == 0)
        n = wc_ed448_make_key(&rng, ED448_KEY_SIZE, &s->ed448);
    if (n == 0)
        n = wc_InitCert(&c);
    if (n == 0) {
        strncpy(c.subject.commonName, "ed448-provisioned", CTC_NAME_SIZE - 1);
        c.sigType = CTC_ED448;
        n = wc_MakeCert_ex(&c, cert, (word32)*cert_len, ED448_TYPE, &s->ed448,
                           &rng);
    }
    if (n > 0)
        n = wc_SignCert_ex(c.bodySz, c.sigType, cert, (word32)*cert_len,
                           ED448_TYPE, &s->ed448, &rng);
    wc_FreeRng(&rng);
    if (n <= 0)
        return -1;
    *cert_len = n;
    return 0;
}
#endif

static void mock_reset(void)
{
    for (int i = 0; i < MOCK_SLOTS; i++) {
#ifdef WOLFCERT_HAVE_ECC
        if (mock_slots[i].id_len > 0 && mock_slots[i].type == MOCK_ECC)
            wc_ecc_free(&mock_slots[i].ecc);
#endif
#ifdef WOLFCERT_HAVE_RSA
        if (mock_slots[i].id_len > 0 && mock_slots[i].type == MOCK_RSA)
            wc_FreeRsaKey(&mock_slots[i].rsa);
#endif
#ifdef WOLFCERT_HAVE_MLDSA
        if (mock_slots[i].id_len > 0 && mock_slots[i].type == MOCK_MLDSA)
            wc_MlDsaKey_Free(&mock_slots[i].mldsa);
#endif
#ifdef MOCK_HAVE_ED25519
        if (mock_slots[i].id_len > 0 && mock_slots[i].type == MOCK_ED25519)
            wc_ed25519_free(&mock_slots[i].ed25519);
#endif
#ifdef MOCK_HAVE_ED448
        if (mock_slots[i].id_len > 0 && mock_slots[i].type == MOCK_ED448)
            wc_ed448_free(&mock_slots[i].ed448);
#endif
    }
    memset(mock_slots, 0, sizeof(mock_slots));
}

static void* server_thread(void* arg)
{
    wolfcert_server_run((WolfCertServer*)arg);
    return NULL;
}

static int test_cfg_errors(void)
{
    static const uint8_t id[] = "dev-key";
    uint8_t long_id[WOLFCERT_KEY_ID_MAX_LEN + 1] = { 0 };
    WolfCertKeyCfg cfg = { .type = TEST_ENROLL_KEY_TYPE,
                           .param = TEST_ENROLL_KEY_PARAM,
                           .dev_id = WOLFCERT_DEVID_SOFTWARE,
                           .key_id = id, .key_id_len = sizeof(id) - 1 };
    WolfCertKey* k = NULL;

    REQUIRE(wolfcert_key_generate(&cfg, &k) == WOLFCERT_ERR_BAD_ARG);

    cfg.dev_id     = MOCK_DEVID;
    cfg.key_id     = long_id;
    cfg.key_id_len = sizeof(long_id);
    REQUIRE(wolfcert_key_generate(&cfg, &k) == WOLFCERT_ERR_BAD_ARG);

    cfg.key_id     = NULL;
    cfg.key_id_len = 4;
    REQUIRE(wolfcert_key_generate(&cfg, &k) == WOLFCERT_ERR_BAD_ARG);

#if defined(WOLFCERT_HAVE_ED25519) && !defined(MOCK_HAVE_ED25519)
    cfg.type       = WOLFCERT_KEY_ED25519;
    cfg.key_id     = id;
    cfg.key_id_len = sizeof(id) - 1;
    REQUIRE(wolfcert_key_generate(&cfg, &k) == WOLFCERT_ERR_UNSUPPORTED);
#endif

    REQUIRE(k == NULL);
    return 0;
}

/* Enroll a store-resident key over a bootstrap mTLS identity, reload it by id
 * from the issued certificate, then use it as the mTLS identity itself. */
static int run_key_type(const char* url, WolfCertKeyType type, int param,
                        const uint8_t* tls_cert, size_t tls_cert_len,
                        const uint8_t* boot_cert, size_t boot_cert_len,
                        const uint8_t* boot_key, size_t boot_key_len)
{
    static const uint8_t id[] = "wolfcert/device-key";
    const WolfCertCertMeta meta = { .subject_dn = "CN=devid-device,O=wolfSSL" };
    WolfCertKeyCfg kcfg = { .type = type, .param = param,
                            .dev_id = MOCK_DEVID,
                            .key_id = id, .key_id_len = sizeof(id) - 1 };
    WolfCertServerCfg cli = {
        .protocol          = WOLFCERT_PROTO_EST,
        .server_url        = url,
        .trust_anchors     = tls_cert,
        .trust_anchors_len = tls_cert_len,
        .verify_server     = 1,
        .client_cert       = boot_cert,
        .client_cert_len   = boot_cert_len,
        .client_key        = boot_key,
        .client_key_len    = boot_key_len,
    };
    WolfCertKey* key = NULL;
    WolfCertKey* reloaded = NULL;
    WolfCertBuffer out = { 0 };
    WolfCertBuffer csr = { 0 };
    WolfCertEstResult issued = { 0 };
    WolfCertBuffer renewed = { 0 };
    WolfCertEstResult second = { 0 };
    const uint8_t* got_id = NULL;
    size_t got_len = 0;
    int ops;
    int rc;

    mock_reset();
    mock_keygens = 0;
    mock_private_ops = 0;

#ifdef MOCK_HAVE_ED448
    if (type == WOLFCERT_KEY_ED448) {
        static byte prov[1024];
        int prov_len = sizeof(prov);

        REQUIRE(wolfcert_key_generate(&kcfg, &key) ==
                WOLFCERT_ERR_UNSUPPORTED);
        REQUIRE(mock_provision_ed448(id, sizeof(id) - 1, prov, &prov_len) == 0);
        REQUIRE(wolfcert_key_from_id(&kcfg, prov, (size_t)prov_len, &key) ==
                WOLFCERT_OK);
        mock_keygens++;
    }
    else
#endif
    REQUIRE(wolfcert_key_generate(&kcfg, &key) == WOLFCERT_OK);
    REQUIRE(mock_keygens == 1);
    REQUIRE(wolfcert_key_id(key, &got_id, &got_len) == WOLFCERT_OK);
    REQUIRE(got_len == sizeof(id) - 1 && memcmp(got_id, id, got_len) == 0);
    REQUIRE(wolfcert_key_to_pem(key, &out) == WOLFCERT_ERR_UNSUPPORTED);
    REQUIRE(wolfcert_key_to_der(key, &out) == WOLFCERT_ERR_UNSUPPORTED);
    REQUIRE(out.data == NULL);

    REQUIRE(wolfcert_csr_build(key, &meta, &csr) == WOLFCERT_OK);
    REQUIRE(mock_private_ops == 1);
#ifdef WOLFCERT_HAVE_SCEP
    if (type == WOLFCERT_KEY_RSA) {
        static const uint8_t dummy[] = { 0x30, 0x00 };
        static const uint8_t txid[] = { '1' };
        const WolfCertServerCfg scep = {
            .protocol   = WOLFCERT_PROTO_SCEP,
            .server_url = "http://127.0.0.1:9/scep",
        };
        WolfCertScepResult res;
        int before = mock_private_ops;
        int src;

        for (int call = 0; call < 4; call++) {
            if (call == 0)
                src = wolfcert_scep_pkcs_req(&scep, NULL, dummy,
                        sizeof(dummy), dummy, sizeof(dummy), key, csr.data,
                        csr.len, &res);
            else if (call == 1)
                src = wolfcert_scep_renewal_req(&scep, NULL, dummy,
                        sizeof(dummy), dummy, sizeof(dummy), dummy,
                        sizeof(dummy), key, csr.data, csr.len, &res);
            else if (call == 2)
                src = wolfcert_scep_get_cert_initial(&scep, NULL, dummy,
                        sizeof(dummy), dummy, sizeof(dummy), dummy,
                        sizeof(dummy), key, csr.data, csr.len, txid,
                        sizeof(txid), &res);
            else
                src = wolfcert_scep_get_cert(&scep, NULL, dummy,
                        sizeof(dummy), dummy, sizeof(dummy), dummy,
                        sizeof(dummy), key, dummy, sizeof(dummy), &res);
            if (src != WOLFCERT_ERR_UNSUPPORTED)
                fprintf(stderr, "SCEP call %d rc=%d\n", call, src);
            REQUIRE(src == WOLFCERT_ERR_UNSUPPORTED);
            REQUIRE(strstr(wolfcert_last_error_message(), "key_id") != NULL);
            REQUIRE(mock_private_ops == before);
            wolfcert_scep_result_free(&res);
        }

        /* The session calls too, over a listener that never answers. */
        const WolfCertScepCaps caps = { 0 };
        WolfCertScepSession* ss = NULL;
        uint16_t hole_port = 0;
        int hole = black_hole_listener(&hole_port);
        char hole_url[64];

        REQUIRE(hole >= 0);
        snprintf(hole_url, sizeof(hole_url), "http://127.0.0.1:%u/scep",
                 hole_port);
        WolfCertServerCfg scep_sess = scep;
        scep_sess.server_url = hole_url;
        REQUIRE(wolfcert_scep_session_open(&scep_sess, &ss) == WOLFCERT_OK);
        for (int call = 0; call < 3; call++) {
            if (call == 0)
                src = wolfcert_scep_session_pkcs_req(ss, &caps, dummy,
                        sizeof(dummy), dummy, sizeof(dummy), key, csr.data,
                        csr.len, &res);
            else if (call == 1)
                src = wolfcert_scep_session_renewal_req(ss, &caps, dummy,
                        sizeof(dummy), dummy, sizeof(dummy), dummy,
                        sizeof(dummy), key, csr.data, csr.len, &res);
            else
                src = wolfcert_scep_session_get_cert_initial(ss, &caps,
                        dummy, sizeof(dummy), dummy, sizeof(dummy), dummy,
                        sizeof(dummy), key, csr.data, csr.len, txid,
                        sizeof(txid), &res);
            if (src != WOLFCERT_ERR_UNSUPPORTED)
                fprintf(stderr, "SCEP session call %d rc=%d\n", call, src);
            REQUIRE(src == WOLFCERT_ERR_UNSUPPORTED);
            REQUIRE(strstr(wolfcert_last_error_message(), "key_id") != NULL);
            REQUIRE(mock_private_ops == before);
            wolfcert_scep_result_free(&res);
        }
        wolfcert_scep_session_close(ss);
        close(hole);
    }
#endif
    rc = wolfcert_est_simple_enroll(&cli, csr.data, csr.len, &issued);
    wolfcert_buffer_free(&csr);
    if (rc != WOLFCERT_OK)
        fprintf(stderr, "enroll rc=%d (%s)\n", rc,
                wolfcert_last_error_message());
    REQUIRE(rc == WOLFCERT_OK);

    /* Reload by id from the issued certificate as PEM, ahead of another
     * certificate, and as DER padded like a fixed-size flash slot. */
    REQUIRE(wolfcert_key_from_id(&kcfg, issued.cert_pem.data,
                                 issued.cert_pem.len, &reloaded) ==
            WOLFCERT_OK);
    REQUIRE(wolfcert_key_type(reloaded) == type);
    REQUIRE(wolfcert_key_to_pem(reloaded, &out) == WOLFCERT_ERR_UNSUPPORTED);
    {
        static uint8_t buf[16384];
        int der_len = wc_CertPemToDer(issued.cert_pem.data,
                                      (int)issued.cert_pem.len, buf,
                                      sizeof(buf), CERT_TYPE);
        WolfCertKey* other = NULL;

        REQUIRE(der_len > 0);
        memset(buf + der_len, 0xff, sizeof(buf) - (size_t)der_len);
        REQUIRE(wolfcert_key_from_id(&kcfg, buf, sizeof(buf), &other) ==
                WOLFCERT_OK);
        REQUIRE(wolfcert_key_type(other) == type);
        wolfcert_key_free(other);
        other = NULL;

        REQUIRE(issued.cert_pem.len + tls_cert_len <= sizeof(buf));
        memcpy(buf, issued.cert_pem.data, issued.cert_pem.len);
        memcpy(buf + issued.cert_pem.len, tls_cert, tls_cert_len);
        REQUIRE(wolfcert_key_from_id(&kcfg, buf,
                                     issued.cert_pem.len + tls_cert_len,
                                     &other) == WOLFCERT_OK);
        REQUIRE(wolfcert_key_type(other) == type);
        wolfcert_key_free(other);
        other = NULL;

        WolfCertKeyCfg wrong = kcfg;
        if (type == WOLFCERT_KEY_ECC || type == WOLFCERT_KEY_RSA) {
            wrong.param = type == WOLFCERT_KEY_RSA ? 3072 : 384;
            REQUIRE(wolfcert_key_from_id(&wrong, issued.cert_pem.data,
                                         issued.cert_pem.len, &other) ==
                    WOLFCERT_ERR_BAD_ARG);
        }
#if defined(WOLFCERT_HAVE_MLDSA) && !defined(WOLFSSL_NO_ML_DSA_65)
        if (type == WOLFCERT_KEY_MLDSA44) {
            wrong.type = WOLFCERT_KEY_MLDSA65;
            REQUIRE(wolfcert_key_from_id(&wrong, issued.cert_pem.data,
                                         issued.cert_pem.len, &other) !=
                    WOLFCERT_OK);
        }
#endif
        REQUIRE(other == NULL);
    }

#ifdef KEEP_PEER_CERT
    /* /simplereenroll authenticates with the store key: one signature for the
     * CSR, at least one more for the TLS handshake. */
    WolfCertClient* client = NULL;
    WolfCertKey* unused = NULL;
    const WolfCertCertMeta renew_meta = { 0 };

    REQUIRE(wolfcert_client_new(&client) == WOLFCERT_OK);
    ops = mock_private_ops;
    rc = wolfcert_client_reenroll(client, &cli, issued.cert_pem.data,
                                  issued.cert_pem.len, reloaded, NULL,
                                  &renew_meta, &unused, &renewed);
    wolfcert_client_free(client);
    REQUIRE(unused == NULL);
    if (rc != WOLFCERT_OK)
        fprintf(stderr, "reenroll rc=%d (%s)\n", rc,
                wolfcert_last_error_message());
    REQUIRE(rc == WOLFCERT_OK);
    REQUIRE(mock_private_ops >= ops + 2);
#endif

    /* The store key as the mTLS identity by id, one-shot and in a session. */
    cli.client_cert       = issued.cert_pem.data;
    cli.client_cert_len   = issued.cert_pem.len;
    cli.client_key        = id;
    cli.client_key_len    = sizeof(id) - 1;
    cli.client_key_src    = WOLFCERT_CLIENT_KEY_ID;
    cli.client_key_dev_id = MOCK_DEVID;
    REQUIRE(wolfcert_csr_build(reloaded, &meta, &csr) == WOLFCERT_OK);
    ops = mock_private_ops;
    rc = wolfcert_est_simple_enroll(&cli, csr.data, csr.len, &second);
    wolfcert_buffer_free(&csr);
    if (rc != WOLFCERT_OK)
        fprintf(stderr, "id enroll rc=%d (%s)\n", rc,
                wolfcert_last_error_message());
    REQUIRE(rc == WOLFCERT_OK);
    REQUIRE(mock_private_ops > ops);

    WolfCertEstSession* sess = NULL;
    WolfCertEstResult third = { 0 };
    REQUIRE(wolfcert_csr_build(reloaded, &meta, &csr) == WOLFCERT_OK);
    ops = mock_private_ops;
    REQUIRE(wolfcert_est_session_open(&cli, &sess) == WOLFCERT_OK);
    rc = wolfcert_est_session_simple_enroll(sess, csr.data, csr.len, &third);
    wolfcert_est_session_close(sess);
    wolfcert_buffer_free(&csr);
    REQUIRE(rc == WOLFCERT_OK);
    REQUIRE(mock_private_ops > ops);
    wolfcert_est_result_free(&third);

    wolfcert_est_result_free(&second);
    wolfcert_buffer_free(&renewed);
    wolfcert_est_result_free(&issued);
    wolfcert_key_free(reloaded);
    wolfcert_key_free(key);
    mock_reset();
    return 0;
}

/* A PEM client key signs in software even with a client_key_dev_id. */
static int test_client_key_src(const char* url,
                               const uint8_t* tls_cert, size_t tls_cert_len,
                               const uint8_t* boot_cert, size_t boot_cert_len,
                               const uint8_t* boot_key, size_t boot_key_len)
{
    const WolfCertCertMeta meta = { .subject_dn = "CN=devid-accel,O=wolfSSL" };
    WolfCertKeyCfg kcfg = { .type = TEST_ENROLL_KEY_TYPE,
                            .param = TEST_ENROLL_KEY_PARAM,
                            .dev_id = WOLFCERT_DEVID_SOFTWARE };
    WolfCertServerCfg cli = {
        .protocol          = WOLFCERT_PROTO_EST,
        .server_url        = url,
        .trust_anchors     = tls_cert,
        .trust_anchors_len = tls_cert_len,
        .verify_server     = 1,
        .client_cert       = boot_cert,
        .client_cert_len   = boot_cert_len,
        .client_key        = boot_key,
        .client_key_len    = boot_key_len,
        .client_key_src    = WOLFCERT_CLIENT_KEY_BUFFER,
        .client_key_dev_id = MOCK_DEVID,
    };
    WolfCertKey* key = NULL;
    WolfCertBuffer csr = { 0 };
    WolfCertEstResult cert = { 0 };
    int requests;

    REQUIRE(wolfcert_key_generate(&kcfg, &key) == WOLFCERT_OK);
    REQUIRE(wolfcert_csr_build(key, &meta, &csr) == WOLFCERT_OK);

    requests = mock_sign_requests;
    REQUIRE(wolfcert_est_simple_enroll(&cli, csr.data, csr.len, &cert) ==
            WOLFCERT_OK);
    REQUIRE(mock_sign_requests == requests);
    wolfcert_est_result_free(&cert);

    cli.client_key_src = (WolfCertClientKeySrc)7;
    REQUIRE(wolfcert_est_simple_enroll(&cli, csr.data, csr.len, &cert) ==
            WOLFCERT_ERR_BAD_ARG);
    cli.client_key_src = WOLFCERT_CLIENT_KEY_BUFFER;
    wolfcert_buffer_free(&csr);
    wolfcert_key_free(key);
    key = NULL;

#ifdef KEEP_PEER_CERT
    /* A dev_id key without a key_id signs its CSR on the device and the
     * handshake in software. */
    const WolfCertCertMeta renew_meta = { 0 };
    WolfCertClient* client = NULL;
    WolfCertKey* unused = NULL;
    WolfCertBuffer renewed = { 0 };

    kcfg.dev_id = MOCK_DEVID;
    REQUIRE(wolfcert_key_generate(&kcfg, &key) == WOLFCERT_OK);
    REQUIRE(wolfcert_csr_build(key, &meta, &csr) == WOLFCERT_OK);
    REQUIRE(wolfcert_est_simple_enroll(&cli, csr.data, csr.len, &cert) ==
            WOLFCERT_OK);
    REQUIRE(wolfcert_client_new(&client) == WOLFCERT_OK);
    requests = mock_sign_requests;
    int rc = wolfcert_client_reenroll(client, &cli, cert.cert_pem.data,
                                      cert.cert_pem.len, key, NULL,
                                      &renew_meta, &unused, &renewed);
    wolfcert_client_free(client);
    if (rc != WOLFCERT_OK)
        fprintf(stderr, "dev reenroll rc=%d (%s)\n", rc,
                wolfcert_last_error_message());
    REQUIRE(rc == WOLFCERT_OK);
    REQUIRE(mock_sign_requests == requests + 1);
    wolfcert_buffer_free(&renewed);
    wolfcert_est_result_free(&cert);
    wolfcert_buffer_free(&csr);
    wolfcert_key_free(key);
#endif
    return 0;
}

/* A failed enroll or rekey still hands back a key made under a key_id. */
static int test_failure_keeps_key(const char* url, const uint8_t* tls_cert,
                                  size_t tls_cert_len)
{
    static const uint8_t id[] = "wolfcert/orphan-key";
    static const uint8_t junk[] = { 0x30, 0x03, 0x02, 0x01, 0x00 };
    const WolfCertCertMeta meta = { .subject_dn = "CN=devid-orphan" };
    const WolfCertCertMeta renew = { 0 };
    WolfCertKeyCfg kcfg = { .type = TEST_ENROLL_KEY_TYPE,
                            .param = TEST_ENROLL_KEY_PARAM,
                            .dev_id = MOCK_DEVID,
                            .key_id = id, .key_id_len = sizeof(id) - 1 };
    WolfCertKeyCfg scfg = { .type = TEST_ENROLL_KEY_TYPE,
                            .param = TEST_ENROLL_KEY_PARAM,
                            .dev_id = WOLFCERT_DEVID_SOFTWARE };
    WolfCertServerCfg cli = {
        .protocol          = WOLFCERT_PROTO_EST,
        .server_url        = url,
        .trust_anchors     = tls_cert,
        .trust_anchors_len = tls_cert_len,
        .verify_server     = 1,
    };
    WolfCertKey* key = NULL;
    WolfCertKey* cur = NULL;
    WolfCertBuffer cert = { 0 };
    const uint8_t* got_id = NULL;
    size_t got_len = 0;

    mock_reset();
    REQUIRE(wolfcert_client_enroll(NULL, &cli, &kcfg, &meta, &key, &cert) !=
            WOLFCERT_OK);
    REQUIRE(key != NULL);
    REQUIRE(wolfcert_key_id(key, &got_id, &got_len) == WOLFCERT_OK);
    REQUIRE(got_len == sizeof(id) - 1 && memcmp(got_id, id, got_len) == 0);
    wolfcert_key_free(key);
    key = NULL;

    mock_reset();
    REQUIRE(wolfcert_key_generate(&scfg, &cur) == WOLFCERT_OK);
    REQUIRE(wolfcert_client_reenroll(NULL, &cli, junk, sizeof(junk), cur,
                                     &kcfg, &renew, &key, &cert) ==
            WOLFCERT_ERR_PARSE);
    REQUIRE(key != NULL);
    wolfcert_key_free(key);
    key = NULL;

    REQUIRE(wolfcert_client_enroll(NULL, &cli, &scfg, &meta, &key, &cert) !=
            WOLFCERT_OK);
    REQUIRE(key == NULL);

    /* An early failure also leaves out_key defined. */
    key = cur;
    scfg.param = 123;
    REQUIRE(wolfcert_client_enroll(NULL, &cli, &scfg, &meta, &key, &cert) !=
            WOLFCERT_OK);
    REQUIRE(key == NULL);
    key = cur;
    REQUIRE(wolfcert_client_reenroll(NULL, &cli, junk, sizeof(junk), cur,
                                     NULL, &meta, &key, &cert) ==
            WOLFCERT_ERR_BAD_ARG);
    REQUIRE(key == NULL);
    scfg.param = TEST_ENROLL_KEY_PARAM;
    REQUIRE(wolfcert_client_reenroll(NULL, &cli, junk, sizeof(junk), cur,
                                     &scfg, &renew, &key, &cert) ==
            WOLFCERT_ERR_PARSE);
    REQUIRE(key == NULL);
    REQUIRE(cert.data == NULL);

    /* A protocol the client calls cannot enroll creates no key. */
    cli.protocol = WOLFCERT_PROTO_SCEP;
    int gens = mock_keygens;
    REQUIRE(wolfcert_client_enroll(NULL, &cli, &kcfg, &meta, &key, &cert) ==
            WOLFCERT_ERR_UNSUPPORTED);
    REQUIRE(wolfcert_client_reenroll(NULL, &cli, junk, sizeof(junk), cur,
                                     &kcfg, &renew, &key, &cert) ==
            WOLFCERT_ERR_UNSUPPORTED);
    REQUIRE(key == NULL);
    REQUIRE(mock_keygens == gens);
    wolfcert_key_free(cur);
    mock_reset();
    return 0;
}

int main(void)
{
    uint8_t* tls_cert = NULL; size_t tls_cert_len = 0;
    uint8_t* tls_key  = NULL; size_t tls_key_len  = 0;
    uint8_t* boot_cert = NULL; size_t boot_cert_len = 0;
    uint8_t* boot_key  = NULL; size_t boot_key_len  = 0;
    WolfCertServer* srv = NULL;
    WolfCertBuffer ca_der = { 0 };
    WolfCertBuffer ca_key = { 0 };
    uint8_t* bundle = NULL;
    size_t bundle_cap;
    pthread_t tid;
    char url[128];
    int pem_len;

    REQUIRE(wolfcert_init(NULL) == WOLFCERT_OK);
    REQUIRE(wc_CryptoCb_RegisterDevice(MOCK_DEVID, mock_cb, NULL) == 0);
    REQUIRE(test_cfg_errors() == 0);

    REQUIRE(mint_self_id("127.0.0.1", 0, &tls_cert, &tls_cert_len,
                         &tls_key, &tls_key_len) == 0);
    REQUIRE(mint_self_id("factory-bootstrap", 1, &boot_cert, &boot_cert_len,
                         &boot_key, &boot_key_len) == 0);

    WolfCertServerCfgSrv cfg = {
        .protocol          = WOLFCERT_PROTO_EST,
        .bind_host         = "127.0.0.1",
        .bind_port         = 0,
        .tls_cert_pem      = tls_cert, .tls_cert_pem_len      = tls_cert_len,
        .tls_key_pem       = tls_key,  .tls_key_pem_len       = tls_key_len,
        .tls_client_ca_pem = boot_cert, .tls_client_ca_pem_len = boot_cert_len,
    };

    /* Mint the CA first so the server can also trust the certs it issues. */
    REQUIRE(wolfcert_server_start(&cfg, &srv) == WOLFCERT_OK);
    REQUIRE(wolfcert_server_get_ca(srv, WOLFCERT_ENCODING_DER, &ca_der,
                                   &ca_key) == WOLFCERT_OK);
    wolfcert_server_free(srv);
    srv = NULL;
    cfg.ca_cert     = ca_der.data;
    cfg.ca_cert_len = ca_der.len;
    cfg.ca_key      = ca_key.data;
    cfg.ca_key_len  = ca_key.len;

    bundle_cap = boot_cert_len + ca_der.len * 2 + 256;
    bundle = (uint8_t*)malloc(bundle_cap);
    REQUIRE(bundle != NULL);
    memcpy(bundle, boot_cert, boot_cert_len);
    pem_len = wc_DerToPem(ca_der.data, (word32)ca_der.len,
                          bundle + boot_cert_len,
                          (word32)(bundle_cap - boot_cert_len), CERT_TYPE);
    REQUIRE(pem_len > 0);
    cfg.tls_client_ca_pem     = bundle;
    cfg.tls_client_ca_pem_len = boot_cert_len + (size_t)pem_len;

    REQUIRE(wolfcert_server_start(&cfg, &srv) == WOLFCERT_OK);
    REQUIRE(pthread_create(&tid, NULL, server_thread, srv) == 0);
    snprintf(url, sizeof(url), "https://127.0.0.1:%u/.well-known/est",
             wolfcert_server_port(srv));

#ifdef WOLFCERT_HAVE_ECC
    REQUIRE(run_key_type(url, WOLFCERT_KEY_ECC, 256, tls_cert, tls_cert_len,
                         boot_cert, boot_cert_len, boot_key,
                         boot_key_len) == 0);
#endif
#ifdef WOLFCERT_HAVE_RSA
    REQUIRE(run_key_type(url, WOLFCERT_KEY_RSA, 2048, tls_cert, tls_cert_len,
                         boot_cert, boot_cert_len, boot_key,
                         boot_key_len) == 0);
#endif
#ifdef WOLFCERT_HAVE_MLDSA
#ifndef WOLFSSL_NO_ML_DSA_44
    REQUIRE(run_key_type(url, WOLFCERT_KEY_MLDSA44, 0, tls_cert, tls_cert_len,
                         boot_cert, boot_cert_len, boot_key,
                         boot_key_len) == 0);
#endif
#ifndef WOLFSSL_NO_ML_DSA_65
    REQUIRE(run_key_type(url, WOLFCERT_KEY_MLDSA65, 0, tls_cert, tls_cert_len,
                         boot_cert, boot_cert_len, boot_key,
                         boot_key_len) == 0);
#endif
#ifndef WOLFSSL_NO_ML_DSA_87
    REQUIRE(run_key_type(url, WOLFCERT_KEY_MLDSA87, 0, tls_cert, tls_cert_len,
                         boot_cert, boot_cert_len, boot_key,
                         boot_key_len) == 0);
#endif
#endif
#ifdef MOCK_HAVE_ED25519
    REQUIRE(run_key_type(url, WOLFCERT_KEY_ED25519, 0, tls_cert, tls_cert_len,
                         boot_cert, boot_cert_len, boot_key,
                         boot_key_len) == 0);
#endif
#ifdef MOCK_HAVE_ED448
    REQUIRE(run_key_type(url, WOLFCERT_KEY_ED448, 0, tls_cert, tls_cert_len,
                         boot_cert, boot_cert_len, boot_key, boot_key_len) == 0);
#endif
    REQUIRE(test_client_key_src(url, tls_cert, tls_cert_len, boot_cert,
                                boot_cert_len, boot_key, boot_key_len) == 0);
    REQUIRE(test_failure_keeps_key(url, tls_cert, tls_cert_len) == 0);

    wolfcert_server_stop(srv);
    pthread_join(tid, NULL);
    wolfcert_server_free(srv);
    wolfcert_buffer_free(&ca_der);
    wolfcert_buffer_free_secure(&ca_key);
    free(bundle);
    free(tls_cert);
    free(tls_key);
    free(boot_cert);
    free(boot_key);
    wc_CryptoCb_UnRegisterDevice(MOCK_DEVID);
    wolfcert_cleanup();
    printf("est_devid_roundtrip: OK\n");
    return 0;
}
#endif
