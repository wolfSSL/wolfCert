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
 * CA generation, persistence, and "issue from CSR" helpers shared by the
 * EST and SCEP test servers. Extends naturally to whatever key types the
 * dispatch table (src/key_algs.c) supports.
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include "internal.h"
#include "key_algs.h"
#include <wolfcert/errors.h>

#include <wolfssl/options.h>
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

/* The CA uses the same algorithm dispatch as device keys. We borrow the
 * WolfCertKey alloc_init / make / priv_to_der / free_ routines by having
 * a small shim struct that looks like a WolfCertKey so the table
 * entries can act on it. */
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

/* ---- self-sign the CA cert ---------------------------------------------- */

static int gen_self_signed_cert(WolfCertCa* ca)
{
    const WolfCertKeyAlg* alg = wolfcert_key_alg(ca->type);
    if (alg == NULL)
        return WOLFCERT_ERR_UNSUPPORTED;

    Cert* cert = wc_CertNew(ca->heap);
    if (cert == NULL)
        return WOLFCERT_ERR_MEMORY;

    wc_InitCert_ex(cert, ca->heap, WOLFCERT_DEVID_SOFTWARE);

    /* Bounded copies: snprintf always NUL-terminates and truncates rather
     * than overflowing the fixed CTC_NAME_SIZE subject fields. */
    snprintf(cert->subject.commonName, sizeof(cert->subject.commonName),
             "%s", "wolfCert Test CA");
    snprintf(cert->subject.org, sizeof(cert->subject.org), "%s", "wolfCert");
    snprintf(cert->subject.country, sizeof(cert->subject.country), "%s", "US");

    cert->isCA       = 1;
    cert->selfSigned = 1;
    cert->daysValid  = 3650;
    cert->sigType    = alg->ctc_sig_default;

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

/* ---- CA lifecycle ------------------------------------------------------- */

int wolfcert_ca_generate(WolfCertCa* ca, WolfCertKeyType type, int param, void* heap)
{
    if (ca == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    memset(ca, 0, sizeof(*ca));
    ca->type = type ? type : WOLFCERT_DEFAULT_KEY_TYPE;
    ca->heap = heap;

    /* Default params when caller doesn't specify one. */
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

    /* Serialize the private key once - used by the SCEP server when it
     * needs to hand a DER-encoded key to wolfSSL's PKCS7 decryption. */
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

int wolfcert_ca_load(WolfCertCa* ca, WolfCertStoreOps* store, void* heap)
{
    if (ca == NULL || store == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    memset(ca, 0, sizeof(*ca));
    ca->heap = heap;

    WolfCertBuffer cert_buf = { .heap = heap };
    WolfCertBuffer key_buf  = { .heap = heap };

    int cert_rc = store->read(store->ctx, "ca.cert.der", &cert_buf);
    int key_rc  = store->read(store->ctx, "ca.key.der", &key_buf);
    int rc;

    if (cert_rc != WOLFCERT_OK || key_rc != WOLFCERT_OK) {
        wolfcert_buffer_free(&cert_buf);
        wolfcert_buffer_free(&key_buf);

        if (cert_rc == WOLFCERT_ERR_NOT_FOUND && key_rc == WOLFCERT_ERR_NOT_FOUND)
            return WOLFCERT_ERR_NOT_FOUND;

        /* Half a pair is a damaged store, not an empty one. Reporting
         * NOT_FOUND here would let the caller mint a CA over the survivor. */
        if (cert_rc == WOLFCERT_ERR_NOT_FOUND || key_rc == WOLFCERT_ERR_NOT_FOUND)
            return WOLFCERT_ERR(WOLFCERT_ERR_PARSE, "ca",
                "CA store is incomplete: %s is missing",
                cert_rc == WOLFCERT_ERR_NOT_FOUND ? "ca.cert.der" : "ca.key.der");

        rc = (cert_rc != WOLFCERT_OK) ? cert_rc : key_rc;
        return WOLFCERT_ERR(rc, "ca", "CA store read failed");
    }

    /* Iterate every registered algorithm and see which private-key decoder
     * accepts the stored bytes. */
    const WolfCertKeyAlg* const* list = wolfcert_key_algs_all();

    for (; *list != NULL; ++list) {
        const WolfCertKeyAlg* a = *list;
        WolfCertKey shim;

        memset(&shim, 0, sizeof(shim));
        shim.type = a->type;
        shim.heap = heap;
        shim.dev_id = WOLFCERT_DEVID_SOFTWARE;

        if (a->alloc_init(&shim) != WOLFCERT_OK)
            continue;

        if (a->priv_decode(&shim, key_buf.data, (word32)key_buf.len) == WOLFCERT_OK) {
            ca->type = a->type;
            ca->impl = shim.impl;
            ca->cert_der     = cert_buf.data;
            ca->cert_der_len = cert_buf.len;
            ca->key_der      = key_buf.data;
            ca->key_der_len  = key_buf.len;
            cert_buf.data = NULL;
            key_buf.data = NULL;
            return WOLFCERT_OK;
        }
        a->free_(&shim);
    }

    wolfcert_buffer_free(&cert_buf);
    wolfcert_buffer_free(&key_buf);
    return WOLFCERT_ERR(WOLFCERT_ERR_PARSE, "ca",
        "stored CA key does not decode as any supported algorithm");
}

int wolfcert_ca_save(const WolfCertCa* ca, WolfCertStoreOps* store)
{
    if (ca == NULL || store == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    int rc = store->write(store->ctx, "ca.cert.der", ca->cert_der, ca->cert_der_len, 0);
    if (rc != WOLFCERT_OK)
        return rc;

    rc = store->write(store->ctx, "ca.key.der", ca->key_der, ca->key_der_len, 1);

    /* A certificate without its key is a damaged store that every later load
     * rejects, so drop the half that landed. */
    if (rc != WOLFCERT_OK && store->remove != NULL)
        (void)store->remove(store->ctx, "ca.cert.der");

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

/* ---- issue a cert for a CSR -------------------------------------------- */

/* Map dc.keyOID from the parsed CSR to a WolfCertKeyType. Returns 0 when
 * the OID isn't a supported key type. */
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

/* Wraps wolfSSL's per-algorithm public-key-decode into one function that
 * hands back a typed backing-struct pointer suitable for wc_MakeCert_ex. */
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

        /* dc.publicKey for Ed25519 is the raw 32-byte public key; wolfSSL's
         * decoder expects an SPKI wrapper, so import directly. */
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
        /* Unreachable: decode_subject_pubkey only succeeds for a keyOID whose
         * algorithm is compiled in, and the guards here mirror it exactly. A
         * hit means that invariant was broken (and `impl` is leaked). */
        WOLFCERT_LOG_DBG("ca", "free_subject_pubkey: unhandled keyOID %u",
                         (unsigned)keyOID);
    }
}

/* Carry the subjectAltName from the parsed CSR into the issued cert. wolfSSL
 * only transcribes the subject DN, and it also splits parsed alt names by type
 * (rfc822Name lands in altEmailNames, not altNames), so we recombine the
 * carriable lists -- DNS / URI / IP / registeredID in altNames and rfc822Name
 * in altEmailNames -- into one list and flatten it into the GeneralNames
 * SEQUENCE that Cert.altNames expects.
 *
 * directoryName and otherName cannot be faithfully re-encoded from a parsed
 * cert via wc_FlattenAltNames (the parser strips the directoryName SEQUENCE
 * wrapper, and wolfSSL's cert generator has no path to restore it). Rather
 * than silently issue a cert missing a SAN entry the requester asked for, we
 * reject such a CSR. The altDirNames / altOtherNamesRaw lists (and the
 * rfc822Name split) only exist when wolfSSL keeps name-constraint state. */
static int flatten_csr_san(DecodedCert* dc, Cert* nc, void* heap)
{
    DNS_entry* merged = NULL;
    int rc = 0;

#ifndef IGNORE_NAME_CONSTRAINTS
    if (dc->altDirNames != NULL || dc->altOtherNamesRaw != NULL)
        return WOLFCERT_ERR(WOLFCERT_ERR_UNSUPPORTED, "ca",
            "CSR carries a directoryName/otherName SAN that cannot be issued");
#endif

    const DNS_entry* srcs[] = {
        dc->altNames,
#ifndef IGNORE_NAME_CONSTRAINTS
        dc->altEmailNames,
#endif
    };

    for (size_t i = 0; i < sizeof(srcs) / sizeof(srcs[0]) && rc == 0; ++i) {
        for (const DNS_entry* e = srcs[i]; e != NULL && rc == 0; e = e->next)
            rc = wc_SetDNSEntry(heap, e->name, e->len, e->type, &merged);
    }
    if (rc != 0) {
        FreeAltNames(merged, heap);
        return WOLFCERT_ERR_WC(rc, "ca", "SetDNSEntry(issue SAN)");
    }

    /* Encode straight into nc->altNames / altNamesSz (0 when no SAN). */
    rc = wc_SetAltNamesFromList(nc, merged);

    FreeAltNames(merged, heap);
    if (rc != 0)
        return WOLFCERT_ERR_WC(rc, "ca", "SetAltNamesFromList(issue)");
    return WOLFCERT_OK;
}

#define COPY_SUBJ(field, dst)                                                 \
    do {                                                                     \
        if (dc.field != NULL && dc.field##Len > 0) {                           \
            size_t n = (size_t)dc.field##Len < CTC_NAME_SIZE - 1              \
                       ? (size_t)dc.field##Len : CTC_NAME_SIZE - 1;           \
            memcpy(dst, dc.field, n); dst[n] = '\0';                          \
        }                                                                    \
    } while (0)

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
    size_t der_cap = 8192;
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

    /* Verify the PKCS#10 self-signature: it is the proof-of-possession that
     * the requester holds the private key for the public key being certified.
     * Parsing with VERIFY makes wolfSSL confirm the CertificationRequest
     * signature against the embedded SubjectPublicKeyInfo. */
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

        COPY_SUBJ(subjectCN,    nc->subject.commonName);
        COPY_SUBJ(subjectO,     nc->subject.org);
        COPY_SUBJ(subjectOU,    nc->subject.unit);
        COPY_SUBJ(subjectC,     nc->subject.country);
        COPY_SUBJ(subjectST,    nc->subject.state);
        COPY_SUBJ(subjectL,     nc->subject.locality);
        COPY_SUBJ(subjectSN,    nc->subject.sur);
        /* wolfSSL only stores subject ids up to ASN_USER_ID, so givenName
         * never arrives; copy it anyway for when that gap closes. */
        COPY_SUBJ(subjectGN,    nc->subject.givenName);
        COPY_SUBJ(subjectEmail, nc->subject.email);
        COPY_SUBJ(subjectSND,   nc->subject.serialDev);
        COPY_SUBJ(subjectUID,   nc->subject.userId);
        COPY_SUBJ(subjectPC,    nc->subject.postalCode);
#ifdef WOLFSSL_CERT_EXT
        COPY_SUBJ(subjectBC,    nc->subject.busCat);
#endif

        if (wc_SetIssuerBuffer(nc, ca->cert_der, (int)ca->cert_der_len) != 0)
            rc = WOLFCERT_ERR_CRYPTO;
    }

    if (rc == 0) {
        nc->sigType   = ca_alg->ctc_sig_default;
        nc->daysValid = 365;
        nc->isCA      = 0;

        /* Carry the requested subjectAltName from the CSR into the issued
         * cert. */
        rc = flatten_csr_san(&dc, nc, heap);
    }

    if (rc == 0) {
        /* Decode the subject's public key into a wolfSSL struct. */
        rc = decode_subject_pubkey(dc.keyOID, dc.publicKey, dc.pubKeySize,
                                   heap, &sub_impl, &sub_alg);
    }

    if (rc == 0) {
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
