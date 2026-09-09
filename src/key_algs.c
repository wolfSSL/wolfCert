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
 * Algorithm dispatch table. See key_algs.h for the contract.
 */

#include "internal.h"
#include "key_algs.h"

#include <wolfcert/errors.h>

#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/rsa.h>
#ifdef WOLFCERT_HAVE_ED25519
#  include <wolfssl/wolfcrypt/ed25519.h>
#endif
#ifdef WOLFCERT_HAVE_ED448
#  include <wolfssl/wolfcrypt/ed448.h>
#endif
#ifdef WOLFCERT_HAVE_MLDSA
#  include <wolfssl/wolfcrypt/wc_mldsa.h>
#endif

#include <string.h>

/* ---- RSA ---------------------------------------------------------------- */

#ifdef WOLFCERT_HAVE_RSA
static int rsa_alloc_init(struct WolfCertKey* k)
{
    RsaKey* rk = (RsaKey*)WOLFCERT_XMALLOC(sizeof(*rk), k->heap);
    if (rk == NULL)
        return WOLFCERT_ERR_MEMORY;

    int rc = wc_InitRsaKey_ex(rk, k->heap, k->dev_id);
    if (rc != 0) {
        WOLFCERT_XFREE(rk, k->heap);
        return WOLFCERT_ERR_WC(rc, "keygen", "InitRsaKey_ex");
    }

    k->impl = rk;
    return WOLFCERT_OK;
}

static int rsa_make(struct WolfCertKey* k, const WolfCertKeyCfg* cfg, WC_RNG* rng)
{
    int bits = cfg->param;
    if (bits != 2048 && bits != 3072 && bits != 4096)
        return WOLFCERT_ERR(WOLFCERT_ERR_UNSUPPORTED, "keygen", "bad RSA size %d", bits);

    k->rsa_bits = bits;
    int rc = wc_MakeRsaKey((RsaKey*)k->impl, bits, WC_RSA_EXPONENT, rng);

    return rc == 0 ? WOLFCERT_OK : WOLFCERT_ERR_WC(rc, "keygen", "MakeRsaKey");
}

static int rsa_priv_decode(struct WolfCertKey* k, const uint8_t* der, word32 len)
{
    word32 idx = 0;
    int rc = wc_RsaPrivateKeyDecode(der, &idx, (RsaKey*)k->impl, len);

    return rc == 0 ? WOLFCERT_OK : WOLFCERT_ERR_PARSE;
}

static int rsa_priv_to_der(const struct WolfCertKey* k, uint8_t* buf, word32 cap)
{
    return wc_RsaKeyToDer((RsaKey*)k->impl, buf, cap);
}

static int rsa_pub_check(struct WolfCertKey* k, const uint8_t* pub,
                         word32 pub_len)
{
    RsaKey* cert_key;
    uint8_t* buf = NULL;
    word32 idx = 0;
    int cap, mine, theirs;
    int rc;

    cert_key = (RsaKey*)WOLFCERT_XMALLOC(sizeof(*cert_key), k->heap);
    if (cert_key == NULL)
        return WOLFCERT_ERR_MEMORY;

    rc = wc_InitRsaKey_ex(cert_key, k->heap, k->dev_id);
    if (rc != 0) {
        WOLFCERT_XFREE(cert_key, k->heap);
        return WOLFCERT_ERR_WC(rc, "keygen", "InitRsaKey_ex");
    }

    rc = wc_RsaPublicKeyDecode(pub, &idx, cert_key, pub_len);
    if (rc != 0) {
        rc = WOLFCERT_ERR_PARSE;
        goto out;
    }

    /* Size the scratch from the keys themselves: a fixed cap would report an
     * oversized stored CA as a crypto failure. */
    mine   = wc_RsaPublicKeyDerSize((RsaKey*)k->impl, 0);
    theirs = wc_RsaPublicKeyDerSize(cert_key, 0);
    if (mine <= 0 || theirs <= 0) {
        rc = WOLFCERT_ERR_CRYPTO;
        goto out;
    }
    if (mine != theirs) {
        rc = WOLFCERT_ERR_PARSE;
        goto out;
    }

    cap = mine;
    buf = (uint8_t*)WOLFCERT_XMALLOC(2 * (size_t)cap, k->heap);
    if (buf == NULL) {
        rc = WOLFCERT_ERR_MEMORY;
        goto out;
    }

    /* Both sides go through the same encoder so the comparison does not
     * depend on how the certificate framed its public key. */
    mine   = wc_RsaKeyToPublicDer_ex((RsaKey*)k->impl, buf, (word32)cap, 0);
    theirs = wc_RsaKeyToPublicDer_ex(cert_key, buf + cap, (word32)cap, 0);
    if (mine <= 0 || theirs <= 0)
        rc = WOLFCERT_ERR_CRYPTO;
    else if (mine != theirs || memcmp(buf, buf + cap, (size_t)mine) != 0)
        rc = WOLFCERT_ERR_PARSE;
    else
        rc = WOLFCERT_OK;

out:
    wc_FreeRsaKey(cert_key);
    WOLFCERT_XFREE(buf, k->heap);
    WOLFCERT_XFREE(cert_key, k->heap);
    return rc;
}

static void rsa_free(struct WolfCertKey* k)
{
    if (k->impl == NULL)
        return;

    wc_FreeRsaKey((RsaKey*)k->impl);
    WOLFCERT_XFREE(k->impl, k->heap);
    k->impl = NULL;
}
#endif /* WOLFCERT_HAVE_RSA */

/* ---- ECC ---------------------------------------------------------------- */

#ifdef WOLFCERT_HAVE_ECC
static int ecc_alloc_init(struct WolfCertKey* k)
{
    ecc_key* ek = (ecc_key*)WOLFCERT_XMALLOC(sizeof(*ek), k->heap);
    if (ek == NULL)
        return WOLFCERT_ERR_MEMORY;

    int rc = wc_ecc_init_ex(ek, k->heap, k->dev_id);
    if (rc != 0) {
        WOLFCERT_XFREE(ek, k->heap);
        return WOLFCERT_ERR_WC(rc, "keygen", "ecc_init_ex");
    }

    k->impl = ek;
    return WOLFCERT_OK;
}

static int ecc_make(struct WolfCertKey* k, const WolfCertKeyCfg* cfg, WC_RNG* rng)
{
    int curve = 0, ksize = 0;
    int rc = wolfcert_ecc_curve_from_param(cfg->param, &curve, &ksize);
    if (rc != WOLFCERT_OK)
        return rc;

    k->curve_id = curve;
    rc = wc_ecc_make_key_ex(rng, ksize, (ecc_key*)k->impl, curve);

    return rc == 0 ? WOLFCERT_OK : WOLFCERT_ERR_WC(rc, "keygen", "ecc_make_key_ex");
}

static int ecc_priv_decode(struct WolfCertKey* k, const uint8_t* der, word32 len)
{
    word32 idx = 0;
    int rc = wc_EccPrivateKeyDecode(der, &idx, (ecc_key*)k->impl, len);
    if (rc != 0)
        return WOLFCERT_ERR_PARSE;

    k->curve_id = wc_ecc_get_curve_id(((ecc_key*)k->impl)->idx);

    return WOLFCERT_OK;
}

static int ecc_priv_to_der(const struct WolfCertKey* k, uint8_t* buf, word32 cap)
{
    return wc_EccKeyToDer((ecc_key*)k->impl, buf, cap);
}

/* Uncompressed X9.63 point: the 0x04 marker plus two coordinates. */
#define ECC_X963_CAP (1 + 2 * MAX_ECC_BYTES)

static int ecc_pub_check(struct WolfCertKey* k, const uint8_t* pub,
                         word32 pub_len)
{
    ecc_key* cert_key;
    byte mine[ECC_X963_CAP];
    byte theirs[ECC_X963_CAP];
    word32 mine_len = sizeof(mine);
    word32 theirs_len = sizeof(theirs);
    word32 idx = 0;
    int rc;

    cert_key = (ecc_key*)WOLFCERT_XMALLOC(sizeof(*cert_key), k->heap);
    if (cert_key == NULL)
        return WOLFCERT_ERR_MEMORY;

    rc = wc_ecc_init_ex(cert_key, k->heap, k->dev_id);
    if (rc != 0) {
        WOLFCERT_XFREE(cert_key, k->heap);
        return WOLFCERT_ERR_WC(rc, "keygen", "ecc_init_ex");
    }

    /* A SEC1 private key need not carry its public point, so derive it when
     * the decoder did not supply one. */
    if (((ecc_key*)k->impl)->type == ECC_PRIVATEKEY_ONLY)
        (void)wc_ecc_make_pub((ecc_key*)k->impl, NULL);

    rc = wc_EccPublicKeyDecode(pub, &idx, cert_key, pub_len);
    if (rc != 0)
        rc = wc_ecc_import_x963(pub, pub_len, cert_key);
    if (rc != 0) {
        rc = WOLFCERT_ERR_PARSE;
        goto out;
    }

    if (wc_ecc_export_x963((ecc_key*)k->impl, mine, &mine_len) != 0 ||
        wc_ecc_export_x963(cert_key, theirs, &theirs_len) != 0)
        rc = WOLFCERT_ERR_CRYPTO;
    else if (mine_len != theirs_len || memcmp(mine, theirs, mine_len) != 0)
        rc = WOLFCERT_ERR_PARSE;
    else
        rc = WOLFCERT_OK;

out:
    wc_ecc_free(cert_key);
    WOLFCERT_XFREE(cert_key, k->heap);
    return rc;
}

static void ecc_free(struct WolfCertKey* k)
{
    if (k->impl == NULL)
        return;

    wc_ecc_free((ecc_key*)k->impl);
    WOLFCERT_XFREE(k->impl, k->heap);
    k->impl = NULL;
}
#endif /* WOLFCERT_HAVE_ECC */

/* ---- Ed25519 ----------------------------------------------------------- */

#ifdef WOLFCERT_HAVE_ED25519
static int ed25519_alloc_init(struct WolfCertKey* k)
{
    ed25519_key* ek = (ed25519_key*)WOLFCERT_XMALLOC(sizeof(*ek), k->heap);
    if (ek == NULL)
        return WOLFCERT_ERR_MEMORY;

    int rc = wc_ed25519_init_ex(ek, k->heap, k->dev_id);
    if (rc != 0) {
        WOLFCERT_XFREE(ek, k->heap);
        return WOLFCERT_ERR_WC(rc, "keygen", "ed25519_init_ex");
    }

    k->impl = ek;
    return WOLFCERT_OK;
}

static int ed25519_make(struct WolfCertKey* k, const WolfCertKeyCfg* cfg, WC_RNG* rng)
{
    (void)cfg;
    int rc = wc_ed25519_make_key(rng, ED25519_KEY_SIZE, (ed25519_key*)k->impl);

    return rc == 0 ? WOLFCERT_OK : WOLFCERT_ERR_WC(rc, "keygen", "ed25519_make_key");
}

static int ed25519_priv_decode(struct WolfCertKey* k, const uint8_t* der, word32 len)
{
    word32 idx = 0;
    return wc_Ed25519PrivateKeyDecode(der, &idx, (ed25519_key*)k->impl, len) == 0
           ? WOLFCERT_OK : WOLFCERT_ERR_PARSE;
}

static int ed25519_priv_to_der(const struct WolfCertKey* k, uint8_t* buf, word32 cap)
{
    /* PrivateKeyToDer emits a PKCS#8 v1 PrivateKeyInfo (no public-key field),
     * which OpenSSL accepts; KeyToDer's v2 OneAsymmetricKey-with-pubkey does
     * not. Paired with PKCS8_PRIVATEKEY_TYPE in the alg table. */
    return wc_Ed25519PrivateKeyToDer((ed25519_key*)k->impl, buf, cap);
}

static int ed25519_pub_check(struct WolfCertKey* k, const uint8_t* pub,
                             word32 pub_len)
{
    byte mine[ED25519_PUB_KEY_SIZE];
    int rc;

    if (pub_len != sizeof(mine))
        return WOLFCERT_ERR_PARSE;

    rc = wc_ed25519_make_public((ed25519_key*)k->impl, mine, sizeof(mine));
    if (rc != 0)
        return WOLFCERT_ERR_WC(rc, "keygen", "ed25519_make_public");

    if (memcmp(mine, pub, sizeof(mine)) != 0)
        return WOLFCERT_ERR_PARSE;

    /* On wolfSSL 5.9.2 make_public only sets pubKeySet, leaving key->p empty
     * while wc_ed25519_sign_msg() hashes it -- so import the half we just
     * verified. Newer wolfSSL stores it itself and this is a no-op. */
    rc = wc_ed25519_import_public(mine, sizeof(mine), (ed25519_key*)k->impl);

    return rc == 0 ? WOLFCERT_OK
                   : WOLFCERT_ERR_WC(rc, "keygen", "ed25519_import_public");
}

static void ed25519_free(struct WolfCertKey* k)
{
    if (k->impl == NULL)
        return;

    wc_ed25519_free((ed25519_key*)k->impl);
    WOLFCERT_XFREE(k->impl, k->heap);
    k->impl = NULL;
}
#endif

/* ---- Ed448 ------------------------------------------------------------- */

#ifdef WOLFCERT_HAVE_ED448
static int ed448_alloc_init(struct WolfCertKey* k)
{
    ed448_key* ek = (ed448_key*)WOLFCERT_XMALLOC(sizeof(*ek), k->heap);
    if (ek == NULL)
        return WOLFCERT_ERR_MEMORY;

    int rc = wc_ed448_init_ex(ek, k->heap, k->dev_id);
    if (rc != 0) {
        WOLFCERT_XFREE(ek, k->heap);
        return WOLFCERT_ERR_WC(rc, "keygen", "ed448_init_ex");
    }

    k->impl = ek;
    return WOLFCERT_OK;
}

static int ed448_make(struct WolfCertKey* k, const WolfCertKeyCfg* cfg, WC_RNG* rng)
{
    (void)cfg;
    int rc = wc_ed448_make_key(rng, ED448_KEY_SIZE, (ed448_key*)k->impl);

    return rc == 0 ? WOLFCERT_OK : WOLFCERT_ERR_WC(rc, "keygen", "ed448_make_key");
}

static int ed448_priv_decode(struct WolfCertKey* k, const uint8_t* der, word32 len)
{
    word32 idx = 0;
    return wc_Ed448PrivateKeyDecode(der, &idx, (ed448_key*)k->impl, len) == 0
           ? WOLFCERT_OK : WOLFCERT_ERR_PARSE;
}

static int ed448_priv_to_der(const struct WolfCertKey* k, uint8_t* buf, word32 cap)
{
    return wc_Ed448PrivateKeyToDer((ed448_key*)k->impl, buf, cap);
}

static int ed448_pub_check(struct WolfCertKey* k, const uint8_t* pub,
                           word32 pub_len)
{
    byte mine[ED448_PUB_KEY_SIZE];
    int rc;

    if (pub_len != sizeof(mine))
        return WOLFCERT_ERR_PARSE;

    rc = wc_ed448_make_public((ed448_key*)k->impl, mine, sizeof(mine));
    if (rc != 0)
        return WOLFCERT_ERR_WC(rc, "keygen", "ed448_make_public");

    if (memcmp(mine, pub, sizeof(mine)) != 0)
        return WOLFCERT_ERR_PARSE;

    /* wc_ed448_make_public() sets pubKeySet but, unlike its Ed25519
     * counterpart, leaves key->p untouched -- and wc_ed448_sign_msg() gates
     * on the flag while hashing key->p. Import the half we just verified, or
     * every certificate this CA issues is signed over an all-zero key. */
    rc = wc_ed448_import_public(mine, sizeof(mine), (ed448_key*)k->impl);

    return rc == 0 ? WOLFCERT_OK
                   : WOLFCERT_ERR_WC(rc, "keygen", "ed448_import_public");
}

static void ed448_free(struct WolfCertKey* k)
{
    if (k->impl == NULL)
        return;

    wc_ed448_free((ed448_key*)k->impl);
    WOLFCERT_XFREE(k->impl, k->heap);
    k->impl = NULL;
}
#endif

/* ---- ML-DSA ------------------------------------------------------------ */

#ifdef WOLFCERT_HAVE_MLDSA
static int mldsa_level_for(WolfCertKeyType t)
{
    switch (t) {
#ifndef WOLFSSL_NO_ML_DSA_44
        case WOLFCERT_KEY_MLDSA44:
            return WC_ML_DSA_44;
#endif
#ifndef WOLFSSL_NO_ML_DSA_65
        case WOLFCERT_KEY_MLDSA65:
            return WC_ML_DSA_65;
#endif
#ifndef WOLFSSL_NO_ML_DSA_87
        case WOLFCERT_KEY_MLDSA87:
            return WC_ML_DSA_87;
#endif
        default:
            return -1;
    }
}

static int mldsa_alloc_init(struct WolfCertKey* k)
{
    MlDsaKey* dk = (MlDsaKey*)WOLFCERT_XMALLOC(sizeof(*dk), k->heap);
    if (dk == NULL)
        return WOLFCERT_ERR_MEMORY;

    int rc = wc_MlDsaKey_Init(dk, k->heap, k->dev_id);
    if (rc != 0) {
        WOLFCERT_XFREE(dk, k->heap);
        return WOLFCERT_ERR_WC(rc, "keygen", "MlDsaKey_Init");
    }

    int lvl = mldsa_level_for(k->type);
    if (lvl < 0 || wc_MlDsaKey_SetParams(dk, lvl) != 0) {
        wc_MlDsaKey_Free(dk);
        WOLFCERT_XFREE(dk, k->heap);
        return WOLFCERT_ERR_UNSUPPORTED;
    }

    k->impl = dk;
    return WOLFCERT_OK;
}

static int mldsa_make(struct WolfCertKey* k, const WolfCertKeyCfg* cfg, WC_RNG* rng)
{
    (void)cfg;
    int rc = wc_MlDsaKey_MakeKey((MlDsaKey*)k->impl, rng);

    return rc == 0 ? WOLFCERT_OK : WOLFCERT_ERR_WC(rc, "keygen", "MlDsaKey_MakeKey");
}

static int mldsa_priv_decode(struct WolfCertKey* k, const uint8_t* der, word32 len)
{
    word32 idx = 0;
    int rc = wc_MlDsaKey_PrivateKeyDecode((MlDsaKey*)k->impl, der, len, &idx);
    return rc == 0 ? WOLFCERT_OK : WOLFCERT_ERR_PARSE;
}

static int mldsa_priv_to_der(const struct WolfCertKey* k, uint8_t* buf, word32 cap)
{
    /* PKCS#8 v1 PrivateKeyInfo (no public-key field). */
    return wc_MlDsaKey_PrivateKeyToDer((MlDsaKey*)k->impl, buf, cap);
}

/* Reloading an ML-DSA CA from a store needs wc_MlDsaKey_CheckKey(); say so
 * here rather than letting the link fail. */
#ifndef WOLFSSL_MLDSA_CHECK_KEY
#error "wolfCert's ML-DSA support needs wc_MlDsaKey_CheckKey(): rebuild wolfSSL " \
       "without WOLFSSL_DILITHIUM_NO_CHECK_KEY / WOLFSSL_MLDSA_VERIFY_ONLY."
#endif

/* Unlike its siblings this hook mutates `key`: the certificate's public half
 * is adopted into it, since none can be derived from a PKCS#8 v1 private key.
 * A key that fails the check therefore carries an unverified public half and
 * must be discarded -- wolfcert_ca_load() frees the shim on any failure. */
static int mldsa_pub_check(struct WolfCertKey* k, const uint8_t* pub,
                           word32 pub_len)
{
    if (wc_MlDsaKey_ImportPubRaw((MlDsaKey*)k->impl, pub, pub_len) != 0)
        return WOLFCERT_ERR_PARSE;

    return wc_MlDsaKey_CheckKey((MlDsaKey*)k->impl) == 0 ? WOLFCERT_OK
                                                         : WOLFCERT_ERR_PARSE;
}

static void mldsa_free(struct WolfCertKey* k)
{
    if (k->impl == NULL)
        return;

    wc_MlDsaKey_Free((MlDsaKey*)k->impl);
    WOLFCERT_XFREE(k->impl, k->heap);
    k->impl = NULL;
}
#endif

/* ---- table -------------------------------------------------------------- */

#ifdef WOLFCERT_HAVE_RSA
static const WolfCertKeyAlg ALG_RSA = {
    .type            = WOLFCERT_KEY_RSA,
    .wc_keytype_enum = RSA_TYPE,
    .ctc_sig_default = CTC_SHA256wRSA,
    .key_oid         = RSAk,
    .pem_type        = PRIVATEKEY_TYPE,
    .der_cap_hint    = 4096,
    .alloc_init      = rsa_alloc_init,
    .make            = rsa_make,
    .priv_decode     = rsa_priv_decode,
    .priv_to_der     = rsa_priv_to_der,
    .pub_check       = rsa_pub_check,
    .free_           = rsa_free,
};
#endif

#ifdef WOLFCERT_HAVE_ECC
static const WolfCertKeyAlg ALG_ECC = {
    .type            = WOLFCERT_KEY_ECC,
    .wc_keytype_enum = ECC_TYPE,
    .ctc_sig_default = CTC_SHA256wECDSA,
    .key_oid         = ECDSAk,
    .pem_type        = ECC_PRIVATEKEY_TYPE,
    .der_cap_hint    = 512,
    .alloc_init      = ecc_alloc_init,
    .make            = ecc_make,
    .priv_decode     = ecc_priv_decode,
    .priv_to_der     = ecc_priv_to_der,
    .pub_check       = ecc_pub_check,
    .free_           = ecc_free,
};
#endif

#ifdef WOLFCERT_HAVE_ED25519
static const WolfCertKeyAlg ALG_ED25519 = {
    .type            = WOLFCERT_KEY_ED25519,
    .wc_keytype_enum = ED25519_TYPE,
    .ctc_sig_default = CTC_ED25519,
    .key_oid         = ED25519k,
    .pem_type        = PKCS8_PRIVATEKEY_TYPE,
    .der_cap_hint    = 128,
    .alloc_init      = ed25519_alloc_init,
    .make            = ed25519_make,
    .priv_decode     = ed25519_priv_decode,
    .priv_to_der     = ed25519_priv_to_der,
    .pub_check       = ed25519_pub_check,
    .free_           = ed25519_free,
};
#endif

#ifdef WOLFCERT_HAVE_ED448
static const WolfCertKeyAlg ALG_ED448 = {
    .type            = WOLFCERT_KEY_ED448,
    .wc_keytype_enum = ED448_TYPE,
    .ctc_sig_default = CTC_ED448,
    .key_oid         = ED448k,
    .pem_type        = PKCS8_PRIVATEKEY_TYPE,
    .der_cap_hint    = 192,
    .alloc_init      = ed448_alloc_init,
    .make            = ed448_make,
    .priv_decode     = ed448_priv_decode,
    .priv_to_der     = ed448_priv_to_der,
    .pub_check       = ed448_pub_check,
    .free_           = ed448_free,
};
#endif

#ifdef WOLFCERT_HAVE_MLDSA
/* Each parameter set can be turned off independently in wolfSSL via
 * WOLFSSL_NO_ML_DSA_{44,65,87} (visible here through wolfssl's options.h /
 * user_settings.h). Gate each level so wolfCert only advertises the sets the
 * underlying wolfSSL actually provides. */
#ifndef WOLFSSL_NO_ML_DSA_44
static const WolfCertKeyAlg ALG_MLDSA44 = {
    .type            = WOLFCERT_KEY_MLDSA44,
    .wc_keytype_enum = ML_DSA_44_TYPE,
    .ctc_sig_default = CTC_ML_DSA_44,
    .key_oid         = ML_DSA_44k,
    .pem_type        = PKCS8_PRIVATEKEY_TYPE,
    .der_cap_hint    = 8192,
    .alloc_init      = mldsa_alloc_init,
    .make            = mldsa_make,
    .priv_decode     = mldsa_priv_decode,
    .priv_to_der     = mldsa_priv_to_der,
    .pub_check       = mldsa_pub_check,
    .free_           = mldsa_free,
};
#endif

#ifndef WOLFSSL_NO_ML_DSA_65
static const WolfCertKeyAlg ALG_MLDSA65 = {
    .type            = WOLFCERT_KEY_MLDSA65,
    .wc_keytype_enum = ML_DSA_65_TYPE,
    .ctc_sig_default = CTC_ML_DSA_65,
    .key_oid         = ML_DSA_65k,
    .pem_type        = PKCS8_PRIVATEKEY_TYPE,
    .der_cap_hint    = 12288,
    .alloc_init      = mldsa_alloc_init,
    .make            = mldsa_make,
    .priv_decode     = mldsa_priv_decode,
    .priv_to_der     = mldsa_priv_to_der,
    .pub_check       = mldsa_pub_check,
    .free_           = mldsa_free,
};
#endif

#ifndef WOLFSSL_NO_ML_DSA_87
static const WolfCertKeyAlg ALG_MLDSA87 = {
    .type            = WOLFCERT_KEY_MLDSA87,
    .wc_keytype_enum = ML_DSA_87_TYPE,
    .ctc_sig_default = CTC_ML_DSA_87,
    .key_oid         = ML_DSA_87k,
    .pem_type        = PKCS8_PRIVATEKEY_TYPE,
    .der_cap_hint    = 16384,
    .alloc_init      = mldsa_alloc_init,
    .make            = mldsa_make,
    .priv_decode     = mldsa_priv_decode,
    .priv_to_der     = mldsa_priv_to_der,
    .pub_check       = mldsa_pub_check,
    .free_           = mldsa_free,
};
#endif
#endif

static const WolfCertKeyAlg* const ALL_ALGS[] = {
#ifdef WOLFCERT_HAVE_RSA
    &ALG_RSA,
#endif
#ifdef WOLFCERT_HAVE_ECC
    &ALG_ECC,
#endif
#ifdef WOLFCERT_HAVE_ED25519
    &ALG_ED25519,
#endif
#ifdef WOLFCERT_HAVE_ED448
    &ALG_ED448,
#endif
#ifdef WOLFCERT_HAVE_MLDSA
#ifndef WOLFSSL_NO_ML_DSA_44
    &ALG_MLDSA44,
#endif
#ifndef WOLFSSL_NO_ML_DSA_65
    &ALG_MLDSA65,
#endif
#ifndef WOLFSSL_NO_ML_DSA_87
    &ALG_MLDSA87,
#endif
#endif
    NULL
};

const WolfCertKeyAlg* wolfcert_key_alg(WolfCertKeyType t)
{
    for (const WolfCertKeyAlg* const* p = ALL_ALGS; *p != NULL; ++p)
        if ((*p)->type == t)
            return *p;
    return NULL;
}

const WolfCertKeyAlg* const* wolfcert_key_algs_all(void) { return ALL_ALGS; }
