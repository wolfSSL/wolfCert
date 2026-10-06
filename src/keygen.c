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

#include <wolfcert/keygen.h>
#include <wolfcert/errors.h>
#include "internal.h"
#include "key_algs.h"

#include <wolfssl/wolfcrypt/memory.h>

#include <string.h>

static WolfCertKey* alloc_shell(WolfCertKeyType type, int dev_id,
                                const uint8_t* id, size_t id_len, void* heap)
{
    WolfCertKey* k = (WolfCertKey*)WOLFCERT_XMALLOC(sizeof(*k), heap);
    if (k == NULL)
        return NULL;

    memset(k, 0, sizeof(*k));
    k->type   = type;
    k->dev_id = dev_id;
    k->heap   = heap;

    if (id_len > 0) {
        memcpy(k->id, id, id_len);
        k->id_len = id_len;
    }

    return k;
}

static int check_key_id(const WolfCertKeyCfg* cfg)
{
    if (cfg->key_id_len == 0)
        return cfg->key_id == NULL ? WOLFCERT_OK
               : WOLFCERT_ERR(WOLFCERT_ERR_BAD_ARG, "keygen",
                              "key_id is set but key_id_len is 0");

    return wolfcert_key_id_check(cfg->key_id, cfg->key_id_len, cfg->dev_id,
                                 "keygen");
}

static void free_shell(WolfCertKey* k)
{
    if (k == NULL)
        return;

    const WolfCertKeyAlg* a = wolfcert_key_alg(k->type);
    if (a && a->free_)
        a->free_(k);

    WOLFCERT_XFREE(k, k->heap);
}

int wolfcert_key_generate(const WolfCertKeyCfg* cfg, WolfCertKey** out_key)
{
    if (cfg == NULL || out_key == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    const WolfCertKeyAlg* alg = wolfcert_key_alg(cfg->type);
    if (alg == NULL)
        return WOLFCERT_ERR(WOLFCERT_ERR_UNSUPPORTED, "keygen",
                            "unknown or disabled key type %d", (int)cfg->type);

    int rc = check_key_id(cfg);
    if (rc != WOLFCERT_OK)
        return rc;

    void* heap = cfg->heap ? cfg->heap : wolfcert_default_heap();
    WolfCertKey* k = alloc_shell(cfg->type, cfg->dev_id, cfg->key_id,
                                 cfg->key_id_len, heap);
    if (k == NULL)
        return WOLFCERT_ERR_MEMORY;

    /* The RNG is set up first; a DRBG alloc between the large ML-DSA
     * allocations tripped a glibc sysmalloc assertion. */
    WC_RNG rng;
    rc = wc_InitRng_ex(&rng, heap, cfg->dev_id);
    if (rc != 0) {
        free_shell(k);
        return WOLFCERT_ERR_WC(rc, "keygen", "InitRng");
    }

    rc = alg->alloc_init(k);
    if (rc != WOLFCERT_OK) {
        wc_FreeRng(&rng);
        free_shell(k);
        return rc;
    }

    rc = alg->make(k, cfg, &rng);
    wc_FreeRng(&rng);
    if (rc != WOLFCERT_OK) {
        free_shell(k);
        return rc;
    }

    /* wolfSSL 5.9.4 falls back to software keygen when the device declines. */
    if (k->id_len > 0 && alg->host_priv != NULL && alg->host_priv(k)) {
        free_shell(k);
        return WOLFCERT_ERR(WOLFCERT_ERR_UNSUPPORTED, "keygen",
                            "CryptoCb device %d did not generate the key",
                            cfg->dev_id);
    }

    *out_key = k;
    return WOLFCERT_OK;
}

/* The first algorithm whose priv_decode accepts the DER sets the key type. */
int wolfcert_key_from_pem(const uint8_t* data, size_t data_len,
                          void* heap, WolfCertKey** out_key)
{
    if (data == NULL || data_len == 0 || out_key == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    if (heap == NULL)
        heap = wolfcert_default_heap();

    /* PEM input converts with the first PEM type wolfSSL accepts. */
    static const int pem_try_types[] = {
        PRIVATEKEY_TYPE, ECC_PRIVATEKEY_TYPE
#ifdef WOLFCERT_HAVE_ED25519
        , ED25519_TYPE
#endif
#ifdef WOLFCERT_HAVE_ED448
        , ED448_TYPE
#endif
#ifdef WOLFCERT_HAVE_MLDSA
#ifndef WOLFSSL_NO_ML_DSA_44
        , ML_DSA_44_TYPE
#endif
#ifndef WOLFSSL_NO_ML_DSA_65
        , ML_DSA_65_TYPE
#endif
#ifndef WOLFSSL_NO_ML_DSA_87
        , ML_DSA_87_TYPE
#endif
#endif
    };

    DerBuffer*     der = NULL;       /* owned only when we convert from PEM */
    const uint8_t* der_bytes;
    word32         der_len;

    if (wolfcert_buffer_is_der(data, data_len)) {
        der_bytes = data;
        der_len   = (word32)data_len;
    }
    else {
        int rc = -1;
        for (size_t i = 0; i < sizeof(pem_try_types)/sizeof(pem_try_types[0]); ++i) {
            rc = wc_PemToDer(data, (long)data_len, pem_try_types[i], &der, NULL, NULL, NULL);
            if (rc == 0 && der != NULL && der->buffer != NULL)
                break;

            if (der != NULL) {
                wc_FreeDer(&der);
                der = NULL;
            }
        }

        if (rc != 0 || der == NULL) {
            if (der != NULL)
                wc_FreeDer(&der);
            return WOLFCERT_ERR_PARSE;
        }

        der_bytes = der->buffer;
        der_len   = der->length;
    }

    const WolfCertKeyAlg* const* list = wolfcert_key_algs_all();
    for (; *list != NULL; ++list) {
        const WolfCertKeyAlg* a = *list;
        WolfCertKey* k = alloc_shell(a->type, WOLFCERT_DEVID_SOFTWARE, NULL, 0,
                                     heap);
        if (k == NULL) {
            if (der != NULL)
                wc_FreeDer(&der);
            return WOLFCERT_ERR_MEMORY;
        }

        if (a->alloc_init(k) != WOLFCERT_OK) {
            free_shell(k);
            continue;
        }

        if (a->priv_decode(k, der_bytes, der_len) == WOLFCERT_OK) {
            if (der != NULL)
                wc_FreeDer(&der);
            *out_key = k;
            return WOLFCERT_OK;
        }

        free_shell(k);
    }
    if (der != NULL)
        wc_FreeDer(&der);

    return WOLFCERT_ERR_PARSE;
}

/* SubjectPublicKeyInfo of a PEM or DER certificate, in a fresh buffer. */
static int cert_spki(const uint8_t* cert, size_t cert_len, void* heap,
                     uint8_t** out, word32* out_len)
{
    WolfCertBuffer pem_der = { 0 };
    const uint8_t* der = cert;
    size_t         der_len = cert_len;
    uint8_t*       spki = NULL;
    word32         spki_len = 0;
    int            rc = WOLFCERT_OK;

    if (!wolfcert_buffer_is_der(cert, cert_len)) {
        rc = wolfcert_pem_cert_to_der(cert, cert_len, &pem_der, heap);
        der = pem_der.data;
        der_len = pem_der.len;
    }
    if (rc == WOLFCERT_OK &&
        (wc_GetSubjectPubKeyInfoDerFromCert(der, (word32)der_len, NULL,
                                            &spki_len) < 0 || spki_len == 0))
        rc = WOLFCERT_ERR(WOLFCERT_ERR_PARSE, "keygen",
                          "public key source is not a certificate");
    if (rc == WOLFCERT_OK) {
        spki = (uint8_t*)WOLFCERT_XMALLOC(spki_len, heap);
        if (spki == NULL)
            rc = WOLFCERT_ERR_MEMORY;
    }
    if (rc == WOLFCERT_OK &&
        wc_GetSubjectPubKeyInfoDerFromCert(der, (word32)der_len, spki,
                                           &spki_len) < 0)
        rc = WOLFCERT_ERR_PARSE;

    wolfcert_buffer_free(&pem_der);
    if (rc != WOLFCERT_OK) {
        WOLFCERT_XFREE(spki, heap);
        return rc;
    }

    *out     = spki;
    *out_len = spki_len;
    return WOLFCERT_OK;
}

/* The key must have a curve or RSA size keygen makes, and a non-zero param
 * must name that one. */
static int check_param(const WolfCertKey* k, int param)
{
    int have = 0;

#if !defined(WOLFCERT_HAVE_RSA) && !defined(WOLFCERT_HAVE_ECC)
    (void)k;
#endif
#ifdef WOLFCERT_HAVE_RSA
    if (k->type == WOLFCERT_KEY_RSA) {
        if (!wolfcert_rsa_bits_ok(k->rsa_bits))
            return WOLFCERT_ERR(WOLFCERT_ERR_UNSUPPORTED, "keygen",
                                "RSA-%d is not 2048, 3072 or 4096",
                                k->rsa_bits);
        have = k->rsa_bits;
    }
#endif
#ifdef WOLFCERT_HAVE_ECC
    if (k->type == WOLFCERT_KEY_ECC &&
        wolfcert_ecc_param_from_curve(k->curve_id, &have) != WOLFCERT_OK)
        return WOLFCERT_ERR(WOLFCERT_ERR_UNSUPPORTED, "keygen",
                            "public key is not on P-256, P-384 or P-521");
#endif
    if (param != 0 && have != 0 && param != have)
        return WOLFCERT_ERR(WOLFCERT_ERR_BAD_ARG, "keygen",
                            "public key is %d bits, param is %d", have, param);
    return WOLFCERT_OK;
}

int wolfcert_key_from_id(const WolfCertKeyCfg* cfg,
                         const uint8_t* cert, size_t cert_len,
                         WolfCertKey** out_key)
{
    if (out_key == NULL)
        return WOLFCERT_ERR_BAD_ARG;
    *out_key = NULL;
    if (cfg == NULL || cfg->key_id_len == 0 || cert == NULL || cert_len == 0)
        return WOLFCERT_ERR_BAD_ARG;

    int rc = check_key_id(cfg);
    if (rc != WOLFCERT_OK)
        return rc;

    const WolfCertKeyAlg* alg = wolfcert_key_alg(cfg->type);
    if (alg == NULL || alg->pub_decode == NULL)
        return WOLFCERT_ERR(WOLFCERT_ERR_UNSUPPORTED, "keygen",
                            "key type %d cannot take a key_id", (int)cfg->type);

    void* heap = cfg->heap ? cfg->heap : wolfcert_default_heap();
    uint8_t* spki = NULL;
    word32   spki_len = 0;
    rc = cert_spki(cert, cert_len, heap, &spki, &spki_len);
    if (rc != WOLFCERT_OK)
        return rc;

    WolfCertKey* k = alloc_shell(cfg->type, cfg->dev_id, cfg->key_id,
                                 cfg->key_id_len, heap);
    if (k == NULL) {
        WOLFCERT_XFREE(spki, heap);
        return WOLFCERT_ERR_MEMORY;
    }

    rc = alg->alloc_init(k);
    if (rc == WOLFCERT_OK) {
        rc = alg->pub_decode(k, spki, spki_len);
        if (rc == WOLFCERT_ERR_PARSE)
            rc = WOLFCERT_ERR(WOLFCERT_ERR_PARSE, "keygen",
                              "certificate key is not a type %d key",
                              (int)cfg->type);
    }
    WOLFCERT_XFREE(spki, heap);
    if (rc == WOLFCERT_OK)
        rc = check_param(k, cfg->param);
    if (rc != WOLFCERT_OK) {
        free_shell(k);
        return rc;
    }

    *out_key = k;
    return WOLFCERT_OK;
}

/* Serialize a software key's private DER into a freshly allocated buffer. */
int wolfcert_key_export_der(const WolfCertKey* key, uint8_t** out_der,
                            int* out_len, void* heap)
{
    const WolfCertKeyAlg* alg = wolfcert_key_alg(key->type);
    if (alg == NULL)
        return WOLFCERT_ERR_UNSUPPORTED;
    if (key->id_len > 0)
        return WOLFCERT_ERR(WOLFCERT_ERR_UNSUPPORTED, "keygen",
                            "the private key stays in CryptoCb device %d",
                            key->dev_id);

    size_t der_cap = alg->der_cap_hint;
    if (key->type == WOLFCERT_KEY_RSA) {
        size_t bits = key->rsa_bits ? (size_t)key->rsa_bits : 4096;
        der_cap = bits + 2048;
    }

    uint8_t* der = (uint8_t*)WOLFCERT_XMALLOC(der_cap, heap);
    if (der == NULL)
        return WOLFCERT_ERR_MEMORY;

    int der_len = alg->priv_to_der(key, der, (word32)der_cap);
    if (der_len <= 0) {
        wc_ForceZero(der, der_cap);
        WOLFCERT_XFREE(der, heap);
        return WOLFCERT_ERR_WC(der_len, "keygen", "priv_to_der");
    }

    *out_der = der;
    *out_len = der_len;

    return WOLFCERT_OK;
}

int wolfcert_key_to_der(const WolfCertKey* key, WolfCertBuffer* out_der)
{
    if (key == NULL || out_der == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    uint8_t* der = NULL;
    int      der_len = 0;
    int rc = wolfcert_key_export_der(key, &der, &der_len, key->heap);
    if (rc != WOLFCERT_OK)
        return rc;

    out_der->data = der;
    out_der->len  = (size_t)der_len;
    out_der->heap = key->heap;

    return WOLFCERT_OK;
}

int wolfcert_key_to_pem(const WolfCertKey* key, WolfCertBuffer* out_pem)
{
    if (key == NULL || out_pem == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    const WolfCertKeyAlg* alg = wolfcert_key_alg(key->type);
    if (alg == NULL)
        return WOLFCERT_ERR_UNSUPPORTED;

    void* heap = key->heap;
    uint8_t* der = NULL;
    int      der_len = 0;
    int rc = wolfcert_key_export_der(key, &der, &der_len, heap);
    if (rc != WOLFCERT_OK)
        return rc;

    size_t pem_cap = (size_t)der_len * 2 + 256;
    uint8_t* pem = (uint8_t*)WOLFCERT_XMALLOC(pem_cap, heap);
    if (pem == NULL) {
        wc_ForceZero(der, (word32)der_len);
        WOLFCERT_XFREE(der, heap);
        return WOLFCERT_ERR_MEMORY;
    }

    int pem_len = wc_DerToPem(der, (word32)der_len, pem, (word32)pem_cap, alg->pem_type);

    wc_ForceZero(der, (word32)der_len);
    WOLFCERT_XFREE(der, heap);
    if (pem_len <= 0) {
        /* wc_DerToPem may have written partial base64 of the private key
         * before failing, so scrub the buffer before releasing it. */
        wc_ForceZero(pem, (word32)pem_cap);
        WOLFCERT_XFREE(pem, heap);
        return WOLFCERT_ERR_WC(pem_len, "keygen", "DerToPem");
    }

    out_pem->data = pem;
    out_pem->len = (size_t)pem_len;
    out_pem->heap = heap;

    return WOLFCERT_OK;
}

void wolfcert_key_free(WolfCertKey* key)
{
    free_shell(key);
}

WolfCertKeyType wolfcert_key_type(const WolfCertKey* k)
{
    return k ? k->type   : 0;
}

int wolfcert_key_dev_id(const WolfCertKey* k)
{
    return k ? k->dev_id : 0;
}

int wolfcert_key_id(const WolfCertKey* k, const uint8_t** id, size_t* id_len)
{
    if (k == NULL || id == NULL || id_len == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    *id     = k->id_len > 0 ? k->id : NULL;
    *id_len = k->id_len;
    return WOLFCERT_OK;
}
