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

/* Test-server CA: generation, loading and issuance from a CSR. */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include "internal.h"
#include "key_algs.h"
#include <wolfcert/errors.h>

#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/memory.h>
#ifdef WOLFCERT_HAVE_ED25519
#  include <wolfssl/wolfcrypt/ed25519.h>
#endif
#ifdef WOLFCERT_HAVE_ED448
#  include <wolfssl/wolfcrypt/ed448.h>
#endif
#ifdef WOLFCERT_HAVE_MLDSA
#  include <wolfssl/wolfcrypt/wc_mldsa.h>
#endif

#include <stdio.h>
#include <string.h>

/* Wrap the CA key in a WolfCertKey so the key_algs table can act on it. */
static WolfCertKey* ca_as_key(WolfCertCa* ca, WolfCertKey* shim)
{
    memset(shim, 0, sizeof(*shim));
    shim->type   = ca->type;
    shim->heap   = ca->heap;
    shim->dev_id = WOLFCERT_DEVID_SOFTWARE;
    shim->impl   = ca->impl;
    return shim;
}

static void ca_sync_from_shim(WolfCertCa* ca, const WolfCertKey* shim)
{
    ca->impl = shim->impl;
}

static int gen_self_signed_cert(WolfCertCa* ca)
{
    const WolfCertKeyAlg* alg = wolfcert_key_alg(ca->type);
    if (alg == NULL)
        return WOLFCERT_ERR_UNSUPPORTED;

    Cert* cert = wc_CertNew(ca->heap);
    if (cert == NULL)
        return WOLFCERT_ERR_MEMORY;

    wc_InitCert_ex(cert, ca->heap, WOLFCERT_DEVID_SOFTWARE);

    snprintf(cert->subject.commonName, sizeof(cert->subject.commonName),
             "%s", "wolfCert Test CA");
    snprintf(cert->subject.org, sizeof(cert->subject.org), "%s", "wolfCert");
    snprintf(cert->subject.country, sizeof(cert->subject.country), "%s", "US");

    cert->isCA       = 1;
    /* RFC 5280 section 4.2.1.9: a CA marks basicConstraints critical. */
    cert->basicConstCrit = 1;
    cert->selfSigned = 1;
    cert->daysValid  = 3650;
    cert->sigType    = alg->ctc_sig_default;

    /* RFC 8894 section 2.1.2: this key signs certificates and SCEP CertReps,
     * and on RSA it also decrypts the pkcsPKIEnvelope. */
    const char* usage = ca->type == WOLFCERT_KEY_RSA
                        ? "keyCertSign,cRLSign,digitalSignature,keyEncipherment"
                        : "keyCertSign,cRLSign,digitalSignature";
    int ku = wc_SetKeyUsage(cert, usage);
    if (ku != 0) {
        wc_CertFree(cert);
        return WOLFCERT_ERR_WC(ku, "ca", "SetKeyUsage");
    }

    WC_RNG rng;
    if (wc_InitRng_ex(&rng, ca->heap, WOLFCERT_DEVID_SOFTWARE) != 0) {
        wc_CertFree(cert);
        return WOLFCERT_ERR_CRYPTO;
    }

    size_t cap = alg->der_cap_hint + 4096;
    uint8_t* der = (uint8_t*)WOLFCERT_XMALLOC(cap, ca->heap);
    if (der == NULL) {
        wc_FreeRng(&rng);
        wc_CertFree(cert);
        return WOLFCERT_ERR_MEMORY;
    }

    int body = wc_MakeCert_ex(cert, der, (word32)cap,
                              alg->wc_keytype_enum, ca->impl, &rng);
    if (body <= 0) {
        WOLFCERT_XFREE(der, ca->heap);
        wc_FreeRng(&rng);
        wc_CertFree(cert);
        return WOLFCERT_ERR_WC(body, "ca", "MakeCert_ex");
    }

    int sz = wc_SignCert_ex(body, cert->sigType, der, (word32)cap,
                            alg->wc_keytype_enum, ca->impl, &rng);

    wc_FreeRng(&rng);
    wc_CertFree(cert);
    if (sz <= 0) {
        WOLFCERT_XFREE(der, ca->heap);
        return WOLFCERT_ERR_WC(sz, "ca", "SignCert_ex");
    }

    ca->cert_der     = der;
    ca->cert_der_len = (size_t)sz;
    return WOLFCERT_OK;
}

int wolfcert_ca_generate(WolfCertCa* ca, WolfCertKeyType type, int param, void* heap)
{
    if (ca == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    memset(ca, 0, sizeof(*ca));
    ca->type = type ? type : WOLFCERT_DEFAULT_KEY_TYPE;
    ca->heap = heap;

    int p = param;
    if (p == 0) {
        if (ca->type == WOLFCERT_KEY_RSA)
            p = 2048;
        else if (ca->type == WOLFCERT_KEY_ECC)
            p = 256;
    }

    const WolfCertKeyAlg* alg = wolfcert_key_alg(ca->type);
    if (alg == NULL)
        return WOLFCERT_ERR_UNSUPPORTED;

    WolfCertKey shim;
    ca_as_key(ca, &shim);

    int rc = alg->alloc_init(&shim);
    if (rc != WOLFCERT_OK)
        return rc;

    ca_sync_from_shim(ca, &shim);

    WC_RNG rng;
    if (wc_InitRng_ex(&rng, heap, WOLFCERT_DEVID_SOFTWARE) != 0) {
        alg->free_(&shim);
        ca->impl = NULL;
        return WOLFCERT_ERR_CRYPTO;
    }

    WolfCertKeyCfg cfg = { .type = ca->type, .param = p,
                           .dev_id = WOLFCERT_DEVID_SOFTWARE, .heap = heap };

    rc = alg->make(&shim, &cfg, &rng);

    wc_FreeRng(&rng);
    if (rc != WOLFCERT_OK) {
        alg->free_(&shim);
        ca->impl = NULL;
        return rc;
    }

    /* Kept as DER for wolfcert_ca_export and the SCEP server's PKCS#7 calls. */
    size_t kcap = alg->der_cap_hint + 2048;
    ca->key_der = (uint8_t*)WOLFCERT_XMALLOC(kcap, heap);
    if (ca->key_der == NULL) {
        alg->free_(&shim);
        ca->impl = NULL;
        return WOLFCERT_ERR_MEMORY;
    }

    int ks = alg->priv_to_der(&shim, ca->key_der, (word32)kcap);
    if (ks <= 0) {
        WOLFCERT_XFREE(ca->key_der, heap);
        ca->key_der = NULL;
        alg->free_(&shim);
        ca->impl = NULL;
        return WOLFCERT_ERR_WC(ks, "ca", "priv_to_der");
    }
    ca->key_der_len = (size_t)ks;

    rc = gen_self_signed_cert(ca);
    if (rc != WOLFCERT_OK) {
        wolfcert_ca_free(ca);
        return rc;
    }
    return WOLFCERT_OK;
}

/* Check the cert is a CA holding the public half of the key. */
static int ca_check_pair(const WolfCertKeyAlg* alg, WolfCertKey* key,
                         const uint8_t* cert_der, size_t cert_len, void* heap)
{
    DecodedCert* dc = (DecodedCert*)WOLFCERT_XMALLOC(sizeof(*dc), heap);
    if (dc == NULL)
        return WOLFCERT_ERR_MEMORY;

    wc_InitDecodedCert(dc, cert_der, (word32)cert_len, heap);

    int rc = wc_ParseCert(dc, CERT_TYPE, NO_VERIFY, NULL);
    if (rc == MEMORY_E) {
        rc = WOLFCERT_ERR_MEMORY;
    }
    else if (rc != 0) {
        rc = WOLFCERT_ERR(WOLFCERT_ERR_PARSE, "ca",
                          "CA certificate does not parse");
    }
    else if (!dc->isCA ||
             (dc->extKeyUsageSet && (dc->extKeyUsage & KEYUSE_KEY_CERT_SIGN) == 0)) {
        rc = WOLFCERT_ERR(WOLFCERT_ERR_PARSE, "ca",
                          "CA certificate is not a CA "
                          "(basicConstraints/keyUsage)");
    }
    else if (dc->keyOID != (word32)alg->key_oid || dc->publicKey == NULL) {
        rc = WOLFCERT_ERR(WOLFCERT_ERR_PARSE, "ca",
                          "CA certificate and key use different algorithms");
    }
    else {
        rc = alg->pub_check(key, dc->publicKey, dc->pubKeySize);
        if (rc != WOLFCERT_OK && rc != WOLFCERT_ERR_MEMORY)
            rc = WOLFCERT_ERR(rc, "ca",
                              "CA certificate does not match the CA key");
    }

    wc_FreeDecodedCert(dc);
    WOLFCERT_XFREE(dc, heap);
    return rc;
}

static int ca_copy(const uint8_t* in, size_t in_len, WolfCertBuffer* out,
                   void* heap)
{
    out->data = (uint8_t*)WOLFCERT_XMALLOC(in_len, heap);
    if (out->data == NULL)
        return WOLFCERT_ERR_MEMORY;

    memcpy(out->data, in, in_len);
    out->len  = in_len;
    out->heap = heap;
    return WOLFCERT_OK;
}

/* 1 when in is exactly one DER element. */
static int ca_der_single(const uint8_t* in, size_t in_len)
{
    word32 idx = 1;
    int len = 0;

    return (size_t)(word32)in_len == in_len &&
           GetLength(in, &idx, &len, (word32)in_len) >= 0 &&
           (size_t)idx + (size_t)len == in_len;
}

/* Copy a certificate given as PEM or DER into a DER buffer. */
static int ca_cert_der(const uint8_t* in, size_t in_len, WolfCertBuffer* out,
                       void* heap)
{
    if (!wolfcert_buffer_is_der(in, in_len))
        return wolfcert_pem_cert_to_der(in, in_len, out, heap);

    if (!ca_der_single(in, in_len))
        return WOLFCERT_ERR_PARSE;

    return ca_copy(in, in_len, out, heap);
}

int wolfcert_ca_load(WolfCertCa* ca, const uint8_t* cert, size_t cert_len,
                     const uint8_t* key, size_t key_len, void* heap)
{
    if (ca == NULL || cert == NULL || cert_len == 0 || key == NULL ||
            key_len == 0)
        return WOLFCERT_ERR_BAD_ARG;

    if (heap == NULL)
        heap = wolfcert_default_heap();

    memset(ca, 0, sizeof(*ca));
    ca->heap = heap;

    WolfCertBuffer cert_buf = { .heap = heap };
    WolfCertBuffer key_buf  = { .heap = heap };
    WolfCertKey* k = NULL;
    const WolfCertKeyAlg* alg = NULL;

    int rc = ca_cert_der(cert, cert_len, &cert_buf, heap);
    if (rc != WOLFCERT_OK && rc != WOLFCERT_ERR_MEMORY)
        rc = WOLFCERT_ERR(rc, "ca", "ca_cert is not a PEM or DER certificate");

    if (rc == WOLFCERT_OK) {
        if (wolfcert_buffer_is_der(key, key_len) &&
                !ca_der_single(key, key_len))
            rc = WOLFCERT_ERR_PARSE;
        else
            rc = wolfcert_key_from_pem(key, key_len, heap, &k);
        if (rc != WOLFCERT_OK && rc != WOLFCERT_ERR_MEMORY)
            rc = WOLFCERT_ERR(rc, "ca", "ca_key is not a supported PEM or "
                              "DER private key");
    }

    /* The pair check restores an ECC public point that the re-encode needs. */
    if (rc == WOLFCERT_OK) {
        alg = wolfcert_key_alg(k->type);
        rc = (alg == NULL) ? WOLFCERT_ERR_UNSUPPORTED
                           : ca_check_pair(alg, k, cert_buf.data, cert_buf.len,
                                           heap);
    }

    /* Re-encoding stores RSA and ECC keys in the form their PEM label names. */
    if (rc == WOLFCERT_OK)
        rc = wolfcert_key_to_der(k, &key_buf);

    if (rc == WOLFCERT_OK) {
        ca->type         = k->type;
        ca->impl         = k->impl;
        ca->cert_der     = cert_buf.data;
        ca->cert_der_len = cert_buf.len;
        ca->key_der      = key_buf.data;
        ca->key_der_len  = key_buf.len;
        k->impl       = NULL;
        cert_buf.data = NULL;
        key_buf.data  = NULL;
    }

    wolfcert_key_free(k);
    wolfcert_buffer_free(&cert_buf);
    wolfcert_buffer_free_secure(&key_buf);
    return rc;
}

/* Copy der into out, as PEM of pem_type unless enc is DER. */
static int ca_encode(const uint8_t* der, size_t der_len, WolfCertEncoding enc,
                     int pem_type, WolfCertBuffer* out, void* heap)
{
    if (enc == WOLFCERT_ENCODING_DER)
        return ca_copy(der, der_len, out, heap);

    size_t cap = der_len * 2 + 256;
    uint8_t* pem = (uint8_t*)WOLFCERT_XMALLOC(cap, heap);
    if (pem == NULL)
        return WOLFCERT_ERR_MEMORY;

    int n = wc_DerToPem(der, (word32)der_len, pem, (word32)cap, pem_type);
    if (n <= 0) {
        wc_ForceZero(pem, (word32)cap);
        WOLFCERT_XFREE(pem, heap);
        return WOLFCERT_ERR_RC_WC(WOLFCERT_ERR_CRYPTO, n, "ca", "DerToPem");
    }

    out->data = pem;
    out->len  = (size_t)n;
    out->heap = heap;
    return WOLFCERT_OK;
}

int wolfcert_ca_export(const WolfCertCa* ca, WolfCertEncoding enc,
                       WolfCertBuffer* out_cert, WolfCertBuffer* out_key)
{
    const WolfCertKeyAlg* alg = wolfcert_key_alg(ca->type);
    int rc;

    if (enc != WOLFCERT_ENCODING_PEM && enc != WOLFCERT_ENCODING_DER)
        return WOLFCERT_ERR(WOLFCERT_ERR_BAD_ARG, "ca", "bad encoding %d",
                            (int)enc);
    if (alg == NULL || ca->cert_der == NULL || ca->key_der == NULL)
        return WOLFCERT_ERR(WOLFCERT_ERR_UNSUPPORTED, "ca", "no CA to export");

    rc = ca_encode(ca->cert_der, ca->cert_der_len, enc, CERT_TYPE, out_cert,
                   ca->heap);
    if (rc == WOLFCERT_OK && out_key != NULL) {
        rc = ca_encode(ca->key_der, ca->key_der_len, enc, alg->pem_type,
                       out_key, ca->heap);
        if (rc != WOLFCERT_OK)
            wolfcert_buffer_free(out_cert);
    }

    return rc;
}

void wolfcert_ca_free(WolfCertCa* ca)
{
    if (ca == NULL)
        return;

    const WolfCertKeyAlg* alg = wolfcert_key_alg(ca->type);
    if (alg != NULL && ca->impl != NULL) {
        WolfCertKey shim;
        memset(&shim, 0, sizeof(shim));

        shim.type = ca->type;
        shim.heap = ca->heap;
        shim.impl = ca->impl;
        alg->free_(&shim);
    }

    WOLFCERT_XFREE(ca->cert_der, ca->heap);
    if (ca->key_der != NULL && ca->key_der_len > 0)
        wc_ForceZero(ca->key_der, ca->key_der_len);
    WOLFCERT_XFREE(ca->key_der,  ca->heap);
    memset(ca, 0, sizeof(*ca));
}

/* WolfCertKeyType for a CSR keyOID, or 0 when unsupported. */
static WolfCertKeyType subject_type_from_oid(word32 keyOID)
{
    switch (keyOID) {
        case RSAk:
            return WOLFCERT_KEY_RSA;
        case ECDSAk:
            return WOLFCERT_KEY_ECC;
#ifdef WOLFCERT_HAVE_ED25519
        case ED25519k:
            return WOLFCERT_KEY_ED25519;
#endif
#ifdef WOLFCERT_HAVE_ED448
        case ED448k:
            return WOLFCERT_KEY_ED448;
#endif
#ifdef WOLFCERT_HAVE_MLDSA
        case ML_DSA_44k:
            return WOLFCERT_KEY_MLDSA44;
        case ML_DSA_65k:
            return WOLFCERT_KEY_MLDSA65;
        case ML_DSA_87k:
            return WOLFCERT_KEY_MLDSA87;
#endif
        default:
            return 0;
    }
}

/* Decode the CSR public key into the wolfSSL key wc_MakeCert_ex takes. */
static int decode_subject_pubkey(word32 keyOID,
                                 const uint8_t* spki_der, word32 spki_len,
                                 void* heap, void** out_impl,
                                 const WolfCertKeyAlg** out_alg)
{
    WolfCertKeyType st = subject_type_from_oid(keyOID);
    if (st == 0)
        return WOLFCERT_ERR_UNSUPPORTED;

    const WolfCertKeyAlg* alg = wolfcert_key_alg(st);
    if (alg == NULL)
        return WOLFCERT_ERR_UNSUPPORTED;

#ifdef WOLFCERT_HAVE_RSA
    if (keyOID == RSAk) {
        RsaKey* rk = (RsaKey*)WOLFCERT_XMALLOC(sizeof(*rk), heap);
        if (rk == NULL)
            return WOLFCERT_ERR_MEMORY;

        if (wc_InitRsaKey_ex(rk, heap, WOLFCERT_DEVID_SOFTWARE) != 0) {
            WOLFCERT_XFREE(rk, heap);
            return WOLFCERT_ERR_CRYPTO;
        }

        word32 idx = 0;
        int rc = wc_RsaPublicKeyDecode(spki_der, &idx, rk, spki_len);
        if (rc != 0) {
            wc_FreeRsaKey(rk);
            WOLFCERT_XFREE(rk, heap);
            return WOLFCERT_ERR_PARSE;
        }

        *out_impl = rk;
    }
    else
#endif
#ifdef WOLFCERT_HAVE_ECC
    if (keyOID == ECDSAk) {
        ecc_key* ek = (ecc_key*)WOLFCERT_XMALLOC(sizeof(*ek), heap);
        if (ek == NULL)
            return WOLFCERT_ERR_MEMORY;

        if (wc_ecc_init_ex(ek, heap, WOLFCERT_DEVID_SOFTWARE) != 0) {
            WOLFCERT_XFREE(ek, heap);
            return WOLFCERT_ERR_CRYPTO;
        }

        word32 idx = 0;
        int rc = wc_EccPublicKeyDecode(spki_der, &idx, ek, spki_len);
        if (rc != 0) {
            wc_ecc_free(ek);
            WOLFCERT_XFREE(ek, heap);
            return WOLFCERT_ERR_PARSE;
        }

        *out_impl = ek;
    }
    else
#endif
#ifdef WOLFCERT_HAVE_ED25519
    if (keyOID == ED25519k) {
        ed25519_key* ek = (ed25519_key*)WOLFCERT_XMALLOC(sizeof(*ek), heap);
        if (ek == NULL)
            return WOLFCERT_ERR_MEMORY;

        if (wc_ed25519_init_ex(ek, heap, WOLFCERT_DEVID_SOFTWARE) != 0) {
            WOLFCERT_XFREE(ek, heap);
            return WOLFCERT_ERR_CRYPTO;
        }

        /* dc.publicKey for Ed25519 is the raw 32-byte key. */
        int rc = wc_ed25519_import_public(spki_der, spki_len, ek);
        if (rc != 0) {
            wc_ed25519_free(ek);
            WOLFCERT_XFREE(ek, heap);
            return WOLFCERT_ERR_PARSE;
        }

        *out_impl = ek;
    }
    else
#endif
#ifdef WOLFCERT_HAVE_ED448
    if (keyOID == ED448k) {
        ed448_key* ek = (ed448_key*)WOLFCERT_XMALLOC(sizeof(*ek), heap);
        if (ek == NULL)
            return WOLFCERT_ERR_MEMORY;

        if (wc_ed448_init_ex(ek, heap, WOLFCERT_DEVID_SOFTWARE) != 0) {
            WOLFCERT_XFREE(ek, heap);
            return WOLFCERT_ERR_CRYPTO;
        }

        int rc = wc_ed448_import_public(spki_der, spki_len, ek);
        if (rc != 0) {
            wc_ed448_free(ek);
            WOLFCERT_XFREE(ek, heap);
            return WOLFCERT_ERR_PARSE;
        }

        *out_impl = ek;
    }
    else
#endif
#ifdef WOLFCERT_HAVE_MLDSA
    if (0
#ifndef WOLFSSL_NO_ML_DSA_44
        || keyOID == ML_DSA_44k
#endif
#ifndef WOLFSSL_NO_ML_DSA_65
        || keyOID == ML_DSA_65k
#endif
#ifndef WOLFSSL_NO_ML_DSA_87
        || keyOID == ML_DSA_87k
#endif
        ) {
        MlDsaKey* dk = (MlDsaKey*)WOLFCERT_XMALLOC(sizeof(*dk), heap);
        if (dk == NULL)
            return WOLFCERT_ERR_MEMORY;

        if (wc_MlDsaKey_Init(dk, heap, WOLFCERT_DEVID_SOFTWARE) != 0) {
            WOLFCERT_XFREE(dk, heap);
            return WOLFCERT_ERR_CRYPTO;
        }

        int lvl = -1;
#ifndef WOLFSSL_NO_ML_DSA_44
        if (keyOID == ML_DSA_44k)
            lvl = WC_ML_DSA_44;
#endif
#ifndef WOLFSSL_NO_ML_DSA_65
        if (keyOID == ML_DSA_65k)
            lvl = WC_ML_DSA_65;
#endif
#ifndef WOLFSSL_NO_ML_DSA_87
        if (keyOID == ML_DSA_87k)
            lvl = WC_ML_DSA_87;
#endif

        word32 idx = 0;
        if (lvl < 0 || wc_MlDsaKey_SetParams(dk, lvl) != 0 ||
                wc_MlDsaKey_PublicKeyDecode(dk, spki_der, spki_len, &idx) != 0) {
            wc_MlDsaKey_Free(dk);
            WOLFCERT_XFREE(dk, heap);
            return WOLFCERT_ERR_PARSE;
        }

        *out_impl = dk;
    }
    else
#endif
    {
        return WOLFCERT_ERR_UNSUPPORTED;
    }

    *out_alg = alg;
    return WOLFCERT_OK;
}

static void free_subject_pubkey(word32 keyOID, void* impl, void* heap)
{
    if (impl == NULL)
        return;

#ifdef WOLFCERT_HAVE_RSA
    if (keyOID == RSAk) {
        wc_FreeRsaKey((RsaKey*)impl);
        WOLFCERT_XFREE(impl, heap);
    }
    else
#endif
#ifdef WOLFCERT_HAVE_ECC
    if (keyOID == ECDSAk) {
        wc_ecc_free((ecc_key*)impl);
        WOLFCERT_XFREE(impl, heap);
    }
    else
#endif
#ifdef WOLFCERT_HAVE_ED25519
    if (keyOID == ED25519k) {
        wc_ed25519_free((ed25519_key*)impl);
        WOLFCERT_XFREE(impl, heap);
    }
    else
#endif
#ifdef WOLFCERT_HAVE_ED448
    if (keyOID == ED448k) {
        wc_ed448_free((ed448_key*)impl);
        WOLFCERT_XFREE(impl, heap);
    }
    else
#endif
#ifdef WOLFCERT_HAVE_MLDSA
    if (keyOID == ML_DSA_44k || keyOID == ML_DSA_65k ||
        keyOID == ML_DSA_87k) {
        wc_MlDsaKey_Free((MlDsaKey*)impl);
        WOLFCERT_XFREE(impl, heap);
    }
    else
#endif
    {
        /* Unreachable while these guards mirror decode_subject_pubkey. */
        WOLFCERT_LOG_DBG("ca", "free_subject_pubkey: unhandled keyOID %u",
                         (unsigned)keyOID);
    }
}

/* 1 when every GeneralName in san is an rfc822Name, dNSName, URI, iPAddress or
 * registeredID, the forms the test CA issues. */
static int san_types_issuable(const byte* san, word32 san_len)
{
    word32 idx = 0;
    word32 end;
    int len = 0;
    byte tag = 0;

    if (GetASNTag(san, &idx, &tag, san_len) < 0 ||
            tag != (ASN_SEQUENCE | ASN_CONSTRUCTED) ||
            GetLength(san, &idx, &len, san_len) < 0)
        return 0;

    end = idx + (word32)len;
    while (idx < end) {
        if (GetASNTag(san, &idx, &tag, end) < 0 ||
                GetLength(san, &idx, &len, end) < 0)
            return 0;
        if (tag != (ASN_CONTEXT_SPECIFIC | ASN_RFC822_TYPE) &&
                tag != (ASN_CONTEXT_SPECIFIC | ASN_DNS_TYPE) &&
                tag != (ASN_CONTEXT_SPECIFIC | ASN_URI_TYPE) &&
                tag != (ASN_CONTEXT_SPECIFIC | ASN_IP_TYPE) &&
                tag != (ASN_CONTEXT_SPECIFIC | ASN_RID_TYPE))
            return 0;
        idx += (word32)len;
    }

    return 1;
}

/* Copy the CSR's subjectAltName into the issued cert byte for byte. */
static int copy_csr_san(const DecodedCert* dc, Cert* nc)
{
    const byte* san = NULL;
    word32 san_len = 0;

    if (wolfcert_find_san(dc, &san, &san_len) != WOLFCERT_OK)
        return WOLFCERT_ERR(WOLFCERT_ERR_PARSE, "ca",
                            "CSR extensions do not parse");
    if (san_len > sizeof(nc->altNames))
        return WOLFCERT_ERR(WOLFCERT_ERR_UNSUPPORTED, "ca",
                            "CSR SAN is %u bytes, limit %d", (unsigned)san_len,
                            (int)sizeof(nc->altNames));
    if (san != NULL && !san_types_issuable(san, san_len))
        return WOLFCERT_ERR(WOLFCERT_ERR_UNSUPPORTED, "ca",
            "CSR carries an otherName, x400Address, directoryName or "
            "ediPartyName SAN");

    if (san != NULL)
        memcpy(nc->altNames, san, san_len);
    nc->altNamesSz = (int)san_len;
    nc->altNamesCrit = dc->extSubjAltNameCrit;
    return WOLFCERT_OK;
}

/* Truncating would issue a certificate stating a subject the CSR did not ask
 * for, so an over-long RDN is refused instead. */
#define COPY_SUBJ(field, dst)                                                 \
    do {                                                                      \
        if (dc->field != NULL && dc->field##Len > 0) {                        \
            if ((size_t)dc->field##Len >= sizeof(dst))                        \
                return WOLFCERT_ERR(WOLFCERT_ERR_BAD_ARG, "ca",               \
                    "CSR subject %s is %d bytes, limit %d", #field,           \
                    dc->field##Len, (int)sizeof(dst) - 1);                    \
            memcpy(dst, dc->field, (size_t)dc->field##Len);                   \
            dst[dc->field##Len] = '\0';                                       \
        }                                                                     \
    } while (0)

#define COPY_SUBJ_E(field, dst, encdst)                                       \
    do {                                                                      \
        COPY_SUBJ(field, dst);                                                \
        if (dc->field != NULL && dc->field##Len > 0)                          \
            encdst = dc->field##Enc;                                          \
    } while (0)

/* wolfSSL has no API to carry a decoded subject into a Cert, so it is rebuilt
 * RDN by RDN and a component with no copy here is dropped without an error. */
WOLFCERT_TEST_VIS int wolfcert_copy_csr_subject(const DecodedCert* dc, Cert* nc)
{
    COPY_SUBJ_E(subjectCN,     nc->subject.commonName, nc->subject.commonNameEnc);
    COPY_SUBJ_E(subjectO,      nc->subject.org,        nc->subject.orgEnc);
    COPY_SUBJ_E(subjectOU,     nc->subject.unit,       nc->subject.unitEnc);
    COPY_SUBJ_E(subjectC,      nc->subject.country,    nc->subject.countryEnc);
    COPY_SUBJ_E(subjectST,     nc->subject.state,      nc->subject.stateEnc);
    COPY_SUBJ_E(subjectL,      nc->subject.locality,   nc->subject.localityEnc);
    COPY_SUBJ_E(subjectStreet, nc->subject.street,     nc->subject.streetEnc);
    COPY_SUBJ_E(subjectSN,     nc->subject.sur,        nc->subject.surEnc);
    COPY_SUBJ_E(subjectGN,     nc->subject.givenName,  nc->subject.givenNameEnc);
    COPY_SUBJ(subjectEmail,    nc->subject.email);
    COPY_SUBJ_E(subjectSND,    nc->subject.serialDev,  nc->subject.serialDevEnc);
    COPY_SUBJ_E(subjectUID,    nc->subject.userId,     nc->subject.userIdEnc);
    COPY_SUBJ_E(subjectPC,     nc->subject.postalCode, nc->subject.postalCodeEnc);
#ifdef WOLFSSL_CERT_EXT
    COPY_SUBJ_E(subjectBC,     nc->subject.busCat,     nc->subject.busCatEnc);
    /* No subjectJC/subjectJS: wolfSSL decodes the jurisdiction RDNs but its
     * generator has no encoder entry for them, so a copy would never emit. */
#endif
    return WOLFCERT_OK;
}

#undef COPY_SUBJ_E
#undef COPY_SUBJ

/* Parse the PKCS#10 request and check its self-signature. */
int wolfcert_csr_verify(const uint8_t* csr_der, size_t csr_len, void* heap)
{
    DecodedCert dc;
    int rc;

    wc_InitDecodedCert(&dc, (byte*)csr_der, (word32)csr_len, heap);
    rc = wc_ParseCert(&dc, CERTREQ_TYPE, VERIFY, NULL);
    wc_FreeDecodedCert(&dc);
    if (rc == MEMORY_E)
        return WOLFCERT_ERR_WC(rc, "ca", "ParseCert(CSR)");
    if (rc != 0)
        return WOLFCERT_ERR(WOLFCERT_ERR_PARSE, "ca",
            "CSR does not parse or verify (%d)", rc);

    return WOLFCERT_OK;
}

int wolfcert_ca_issue(WolfCertCa* ca,
                      const uint8_t* csr_der, size_t csr_len,
                      uint8_t** out_cert, size_t* out_len)
{
    DecodedCert dc;
    WC_RNG rng;
    Cert* nc = NULL;
    void* sub_impl = NULL;
    const WolfCertKeyAlg* sub_alg = NULL;
    const WolfCertKeyAlg* ca_alg;
    uint8_t* der = NULL;
    void* heap;
    size_t der_cap = 0;
    int body_sz = 0;
    int sig_sz = 0;
    int rng_ok = 0;
    int rc;

    if (ca == NULL || csr_der == NULL || out_cert == NULL || out_len == NULL)
        return WOLFCERT_ERR_BAD_ARG;
    heap = ca->heap;

    ca_alg = wolfcert_key_alg(ca->type);
    if (ca_alg == NULL)
        return WOLFCERT_ERR_UNSUPPORTED;

    /* VERIFY checks the PKCS#10 self-signature, the proof-of-possession. */
    wc_InitDecodedCert(&dc, (byte*)csr_der, (word32)csr_len, heap);
    rc = wc_ParseCert(&dc, CERTREQ_TYPE, VERIFY, NULL);
    if (rc != 0)
        rc = WOLFCERT_ERR_WC(rc, "ca", "ParseCert(CSR)");

    if (rc == 0) {
        nc = wc_CertNew(heap);
        if (nc == NULL)
            rc = WOLFCERT_ERR_MEMORY;
    }

    if (rc == 0) {
        wc_InitCert_ex(nc, heap, WOLFCERT_DEVID_SOFTWARE);

        rc = wolfcert_copy_csr_subject(&dc, nc);
        if (rc == WOLFCERT_OK &&
                wc_SetIssuerBuffer(nc, ca->cert_der, (int)ca->cert_der_len) != 0)
            rc = WOLFCERT_ERR_CRYPTO;
    }

    if (rc == 0) {
        nc->sigType   = ca_alg->ctc_sig_default;
        nc->daysValid = 365;
        nc->isCA      = 0;

        rc = copy_csr_san(&dc, nc);
    }

    if (rc == 0) {
        rc = decode_subject_pubkey(dc.keyOID, dc.publicKey, dc.pubKeySize,
                                   heap, &sub_impl, &sub_alg);
    }

    if (rc == 0) {
        der_cap = csr_len + ca->cert_der_len + ca_alg->der_cap_hint + 1024;
        der = (uint8_t*)WOLFCERT_XMALLOC(der_cap, heap);
        if (der == NULL)
            rc = WOLFCERT_ERR_MEMORY;
    }

    if (rc == 0) {
        if (wc_InitRng_ex(&rng, heap, WOLFCERT_DEVID_SOFTWARE) != 0)
            rc = WOLFCERT_ERR_CRYPTO;
        else
            rng_ok = 1;
    }

    if (rc == 0) {
        body_sz = wc_MakeCert_ex(nc, der, (word32)der_cap,
                                 sub_alg->wc_keytype_enum, sub_impl, &rng);
        if (body_sz <= 0)
            rc = WOLFCERT_ERR_WC(body_sz, "ca", "MakeCert_ex(issue keyOID=%u)",
                                 (unsigned)dc.keyOID);
    }

    if (rc == 0) {
        sig_sz = wc_SignCert_ex(body_sz, nc->sigType, der, (word32)der_cap,
                                ca_alg->wc_keytype_enum, ca->impl, &rng);
        if (sig_sz <= 0)
            rc = WOLFCERT_ERR_WC(sig_sz, "ca", "SignCert_ex(issue)");
    }

    if (rc == 0) {
        *out_cert = der;
        *out_len  = (size_t)sig_sz;
        der = NULL;   /* ownership moves to the caller */
    }

    if (rng_ok)
        wc_FreeRng(&rng);
    if (sub_impl != NULL)
        free_subject_pubkey(dc.keyOID, sub_impl, heap);
    if (nc != NULL)
        wc_CertFree(nc);
    wc_FreeDecodedCert(&dc);
    WOLFCERT_XFREE(der, heap);
    return rc;
}
