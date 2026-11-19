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

/* Degenerate (certs-only) PKCS#7 SignedData parse and build helpers. */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include "internal.h"
#include <wolfcert/errors.h>

#include <wolfssl/wolfcrypt/pkcs7.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/sha256.h>

#include <stdint.h>
#include <string.h>

static int acc_append(WolfCertBuffer* acc, size_t* cap, const uint8_t* data,
                      size_t n, void* heap)
{
    if (acc->len + n > *cap) {
        size_t nc = *cap ? *cap : 2048;
        while (nc < acc->len + n)
            nc *= 2;

        uint8_t* nb = (uint8_t*)WOLFCERT_XREALLOC(acc->data, nc, heap);
        if (nb == NULL)
            return WOLFCERT_ERR_MEMORY;

        acc->data = nb;
        *cap = nc;
    }

    memcpy(acc->data + acc->len, data, n);
    acc->len += n;

    return WOLFCERT_OK;
}

static int append_cert(WolfCertBuffer* acc, size_t* cap, const uint8_t* der,
                       word32 der_len, int as_pem, void* heap)
{
    if (!as_pem)
        return acc_append(acc, cap, der, der_len, heap);

    size_t pem_cap = (size_t)der_len * 2 + 256;
    uint8_t* pem = (uint8_t*)WOLFCERT_XMALLOC(pem_cap, heap);
    if (pem == NULL)
        return WOLFCERT_ERR_MEMORY;

    int n = wc_DerToPem(der, der_len, pem, (word32)pem_cap, CERT_TYPE);
    if (n <= 0) {
        WOLFCERT_XFREE(pem, heap);
        return WOLFCERT_ERR_CRYPTO;
    }

    int rc = acc_append(acc, cap, pem, (size_t)n, heap);
    WOLFCERT_XFREE(pem, heap);

    return rc;
}

#ifdef WOLFCERT_HAVE_ECC
/* For ECC, publicKey is the whole SPKI; hash the curve id and the
 * uncompressed point so a re-encoded SPKI still matches. */
static int hash_ecc_key(const DecodedCert* dc,
                        uint8_t hash[WC_SHA256_DIGEST_SIZE], void* heap)
{
    enum { ID_LEN = 4, BUF_LEN = ID_LEN + 1 + 2 * MAX_ECC_BYTES };
    word32 pt_len = BUF_LEN - ID_LEN;
    int    id = 0;
    int    rc;

    uint8_t* buf = (uint8_t*)WOLFCERT_XMALLOC(BUF_LEN, heap);
    if (buf == NULL)
        return WOLFCERT_ERR_MEMORY;

    rc = wolfcert_ecc_pub_x963(dc->publicKey, dc->pubKeySize, INVALID_DEVID,
                               buf + ID_LEN, &pt_len, &id, heap);
    if (rc == WOLFCERT_OK) {
        buf[0] = (uint8_t)((word32)id >> 24);
        buf[1] = (uint8_t)((word32)id >> 16);
        buf[2] = (uint8_t)((word32)id >> 8);
        buf[3] = (uint8_t)id;
        rc = wc_Sha256Hash(buf, ID_LEN + pt_len, hash);
        rc = rc == 0 ? WOLFCERT_OK : WOLFCERT_ERR_WC(rc, "pkcs7", "Sha256Hash");
    }

    WOLFCERT_XFREE(buf, heap);
    return rc;
}
#endif

/* SHA-256 of a parsed object's public key; ASN_CRIT_EXT_E still fills it. */
static int hash_public_key(DecodedCert* dc, int type, word32* key_oid,
                           uint8_t hash[WC_SHA256_DIGEST_SIZE], void* heap)
{
    int rc = wc_ParseCert(dc, type, NO_VERIFY, NULL);

    if (rc == MEMORY_E)
        return WOLFCERT_ERR_MEMORY;
    if ((rc != 0 && rc != ASN_CRIT_EXT_E) || dc->publicKey == NULL ||
            dc->pubKeySize == 0)
        return WOLFCERT_ERR_PARSE;

    *key_oid = dc->keyOID;
#ifdef WOLFCERT_HAVE_ECC
    if (dc->keyOID == ECDSAk)
        return hash_ecc_key(dc, hash, heap);
#else
    (void)heap;
#endif
    rc = wc_Sha256Hash(dc->publicKey, dc->pubKeySize, hash);
    return rc == 0 ? WOLFCERT_OK : WOLFCERT_ERR_WC(rc, "pkcs7", "Sha256Hash");
}

WOLFCERT_TEST_VIS int wolfcert_public_key_hash(const uint8_t* der,
    size_t der_len, int type, word32* key_oid,
    uint8_t hash[WC_SHA256_DIGEST_SIZE], void* heap)
{
    int rc;

    if (der == NULL || der_len == 0 || key_oid == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    DecodedCert* dc = (DecodedCert*)WOLFCERT_XMALLOC(sizeof(*dc), heap);
    if (dc == NULL)
        return WOLFCERT_ERR_MEMORY;

    wc_InitDecodedCert(dc, der, (word32)der_len, heap);
    rc = hash_public_key(dc, type, key_oid, hash, heap);
    wc_FreeDecodedCert(dc);
    WOLFCERT_XFREE(dc, heap);
    return rc;
}

int wolfcert_cert_der_hash(const uint8_t* cert, size_t cert_len,
                           uint8_t hash[WC_SHA256_DIGEST_SIZE], void* heap)
{
    WolfCertBuffer der = { 0 };
    int rc = WOLFCERT_OK;

    if (cert == NULL || cert_len == 0)
        return WOLFCERT_ERR_BAD_ARG;

    if (wolfcert_buffer_is_der(cert, cert_len)) {
        der.data = (uint8_t*)cert;
        der.len  = wolfcert_der_first_len(cert, cert_len);
        if (der.len == 0)
            rc = WOLFCERT_ERR_PARSE;
    }
    else {
        rc = wolfcert_pem_cert_to_der(cert, cert_len, &der, heap);
    }

    if (rc == WOLFCERT_OK) {
        rc = wc_Sha256Hash(der.data, (word32)der.len, hash);
        rc = rc == 0 ? WOLFCERT_OK : WOLFCERT_ERR_WC(rc, "pkcs7", "Sha256Hash");
    }
    if (der.data != cert)
        wolfcert_buffer_free(&der);
    return rc;
}

/* Body offset and end of the TLV at off within in[0, end), tag 0 for any. */
static int der_tlv(const uint8_t* in, size_t end, size_t off, uint8_t tag,
                   size_t* body, size_t* next)
{
    word32 idx = (word32)off + 1;
    int len = 0;

    if (off >= end || (tag != 0 && in[off] != tag) ||
            GetLength(in, &idx, &len, (word32)end) < 0)
        return -1;
    *body = idx;
    *next = (size_t)idx + (size_t)len;
    return 0;
}

/* The SubjectPublicKeyInfo of a DER PKCS#10 request, found by structure
 * alone. */
static int find_csr_spki(const uint8_t* der, size_t len,
                         const uint8_t** spki, size_t* spki_len)
{
    size_t body, end, p, next;
    int skip = 2;

    if (der == NULL || len == 0 || (size_t)(word32)len != len ||
            der_tlv(der, len, 0, ASN_SEQUENCE | ASN_CONSTRUCTED, &body,
                    &end) != 0 ||
            der_tlv(der, end, body, ASN_SEQUENCE | ASN_CONSTRUCTED, &p,
                    &end) != 0)
        return WOLFCERT_ERR_PARSE;

    while (skip-- > 0) {
        if (der_tlv(der, end, p, 0, &body, &p) != 0)
            return WOLFCERT_ERR_PARSE;
    }
    if (der_tlv(der, end, p, ASN_SEQUENCE | ASN_CONSTRUCTED, &body,
                &next) != 0)
        return WOLFCERT_ERR_PARSE;

    *spki = der + p;
    *spki_len = next - p;
    return WOLFCERT_OK;
}

static int hash_csr_spki(const uint8_t* der, size_t len,
                         uint8_t hash[WC_SHA256_DIGEST_SIZE])
{
    const uint8_t* spki = NULL;
    size_t spki_len = 0;
    int rc = find_csr_spki(der, len, &spki, &spki_len);

    if (rc == WOLFCERT_OK) {
        rc = wc_Sha256Hash(spki, (word32)spki_len, hash);
        rc = rc == 0 ? WOLFCERT_OK : WOLFCERT_ERR_WC(rc, "pkcs7", "Sha256Hash");
    }
    return rc;
}

static int hash_cert_spki(const uint8_t* cert, word32 cert_len,
                          uint8_t hash[WC_SHA256_DIGEST_SIZE], void* heap)
{
    uint8_t* spki = NULL;
    word32   spki_len = 0;
    int      rc = wolfcert_cert_spki(cert, cert_len, heap, &spki, &spki_len);

    if (rc == WOLFCERT_OK) {
        rc = wc_Sha256Hash(spki, spki_len, hash);
        rc = rc == 0 ? WOLFCERT_OK : WOLFCERT_ERR_WC(rc, "pkcs7", "Sha256Hash");
    }
    WOLFCERT_XFREE(spki, heap);
    return rc;
}

WOLFCERT_TEST_VIS int wolfcert_issued_match_init(WolfCertIssuedMatch* m,
    const uint8_t* csr, size_t csr_len, const uint8_t* old_hash,
    int allow_old, void* heap)
{
    int rc;

    memset(m, 0, sizeof(*m));
    if (csr == NULL || csr_len == 0)
        return WOLFCERT_ERR_BAD_ARG;

    rc = wolfcert_public_key_hash(csr, csr_len, CERTREQ_TYPE, &m->key_oid,
                                  m->key_hash, heap);
    if (rc != WOLFCERT_OK && rc != WOLFCERT_ERR_PARSE)
        return rc;
    m->raw_spki = (rc != WOLFCERT_OK);
    if (m->raw_spki)
        m->key_oid = 0;

    /* The SPKI bytes match a key or a cert this wolfSSL cannot decode. */
    rc = hash_csr_spki(csr, csr_len, m->spki_hash);
    m->has_spki = (rc == WOLFCERT_OK);
    if (rc != WOLFCERT_OK && rc != WOLFCERT_ERR_PARSE)
        return rc;
    if (m->raw_spki && !m->has_spki)
        return WOLFCERT_ERR(WOLFCERT_ERR_PARSE, "pkcs7",
                            "cannot read the public key of the CSR");

    if (old_hash != NULL) {
        memcpy(m->old_hash, old_hash, sizeof(m->old_hash));
        m->has_old   = 1;
        m->allow_old = allow_old;
    }
    return WOLFCERT_OK;
}

/* RSASSA-PSS and rsaEncryption SPKIs carry the same RSAPublicKey. */
static word32 key_family(word32 oid)
{
    return oid == RSAPSSk ? (word32)RSAk : oid;
}

/* *holds is 1 when cert carries m's key; only running out of memory makes
 * one cert fail the whole reply. */
static int cert_holds_key(const uint8_t* cert, word32 cert_len,
                          const WolfCertIssuedMatch* m, DecodedCert* dc,
                          void* heap, int* holds)
{
    uint8_t hash[WC_SHA256_DIGEST_SIZE];
    word32  oid = 0;
    int     rc;

    *holds = 0;
    if (!m->raw_spki) {
        wc_InitDecodedCert(dc, cert, cert_len, heap);
        rc = hash_public_key(dc, CERT_TYPE, &oid, hash, heap);
        wc_FreeDecodedCert(dc);
        if (rc == WOLFCERT_OK) {
            if (key_family(oid) == key_family(m->key_oid))
                *holds = memcmp(hash, m->key_hash, sizeof(hash)) == 0;
            return WOLFCERT_OK;
        }
        if (rc == WOLFCERT_ERR_MEMORY)
            return rc;
    }
    if (!m->has_spki)
        return WOLFCERT_OK;

    rc = hash_cert_spki(cert, cert_len, hash, heap);
    if (rc == WOLFCERT_ERR_MEMORY)
        return rc;
    if (rc == WOLFCERT_OK)
        *holds = memcmp(hash, m->spki_hash, sizeof(hash)) == 0;
    return WOLFCERT_OK;
}

/* Index in p7->cert[] of the first cert holding the CSR's public key,
 * preferring one other than the cert being renewed. */
static int find_issued_cert(const PKCS7* p7, const WolfCertIssuedMatch* m,
                            void* heap, int* out_idx)
{
    uint8_t hash[WC_SHA256_DIGEST_SIZE];
    int     old_idx = -1;
    int     holds = 0;
    int     filled = 0;
    int     rc = WOLFCERT_OK;

    DecodedCert* dc = (DecodedCert*)WOLFCERT_XMALLOC(sizeof(*dc), heap);
    if (dc == NULL)
        return WOLFCERT_ERR_MEMORY;

    *out_idx = -1;
    for (int i = 0; rc == WOLFCERT_OK && *out_idx < 0 &&
                    i < MAX_PKCS7_CERTS; ++i) {
        int is_old = 0;

        if (p7->cert[i] == NULL || p7->certSz[i] == 0)
            continue;
        filled++;

        if (m->has_old) {
            rc = wc_Sha256Hash(p7->cert[i], p7->certSz[i], hash);
            if (rc != 0) {
                rc = WOLFCERT_ERR_WC(rc, "pkcs7", "Sha256Hash");
                break;
            }
            is_old = memcmp(hash, m->old_hash, sizeof(hash)) == 0;
        }

        rc = cert_holds_key(p7->cert[i], p7->certSz[i], m, dc, heap, &holds);
        if (rc == WOLFCERT_OK && holds && !is_old)
            *out_idx = i;
        else if (rc == WOLFCERT_OK && holds && old_idx < 0)
            old_idx = i;
    }

    if (rc == WOLFCERT_OK && filled == 0)
        rc = WOLFCERT_ERR_NOT_FOUND;
    /* A CA may answer a same-key renewal with the unchanged cert. */
    if (rc == WOLFCERT_OK && *out_idx < 0 && m->allow_old)
        *out_idx = old_idx;
    if (rc == WOLFCERT_OK && *out_idx < 0 && filled == MAX_PKCS7_CERTS)
        rc = WOLFCERT_ERR(WOLFCERT_ERR_PROTOCOL, "pkcs7",
                          "no certificate in the reply holds the CSR's key; "
                          "the reply may carry more than MAX_PKCS7_CERTS (%d) "
                          "certificates, and wolfSSL keeps only the first %d",
                          MAX_PKCS7_CERTS, MAX_PKCS7_CERTS);
    else if (rc == WOLFCERT_OK && *out_idx < 0)
        rc = WOLFCERT_ERR(WOLFCERT_ERR_PROTOCOL, "pkcs7",
                          "no certificate in the reply holds the CSR's key");

    WOLFCERT_XFREE(dc, heap);
    return rc;
}

/* With a match, the issued cert goes first and the rest follow. */
static int pkcs7_certs_extract(const uint8_t* p7_der, size_t p7_der_len,
                               const WolfCertIssuedMatch* match,
                               WolfCertBuffer* out, void* heap, int as_pem)
{
    int first = -1;

    if (p7_der == NULL || p7_der_len == 0 || out == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    PKCS7* p7 = wc_PKCS7_New(heap, INVALID_DEVID);
    if (p7 == NULL)
        return WOLFCERT_ERR_MEMORY;

    int rc = wc_PKCS7_VerifySignedData(p7, (byte*)p7_der, (word32)p7_der_len);
    if (rc != 0) {
        wc_PKCS7_Free(p7);
        return WOLFCERT_ERR_WC(rc, "pkcs7", "VerifySignedData");
    }

    rc = WOLFCERT_OK;
    if (match != NULL)
        rc = find_issued_cert(p7, match, heap, &first);
    /* With no match the certs still go out as received, with the error. */
    int no_match = (rc == WOLFCERT_ERR_PROTOCOL);
    if (no_match)
        rc = WOLFCERT_OK;

    WolfCertBuffer acc = { .heap = heap };
    size_t cap = 0;

    if (rc == WOLFCERT_OK && first >= 0)
        rc = append_cert(&acc, &cap, p7->cert[first], p7->certSz[first],
                         as_pem, heap);

    for (int i = 0; rc == WOLFCERT_OK && i < MAX_PKCS7_CERTS; ++i) {
        if (i == first || p7->cert[i] == NULL || p7->certSz[i] == 0)
            continue;

        rc = append_cert(&acc, &cap, p7->cert[i], p7->certSz[i], as_pem, heap);
    }

    wc_PKCS7_Free(p7);
    if (rc == WOLFCERT_OK && acc.len == 0)
        rc = no_match ? WOLFCERT_ERR_PROTOCOL : WOLFCERT_ERR_NOT_FOUND;
    if (rc != WOLFCERT_OK) {
        WOLFCERT_XFREE(acc.data, heap);
        return rc;
    }

    *out = acc;
    return no_match ? WOLFCERT_ERR_PROTOCOL : WOLFCERT_OK;
}

WOLFCERT_TEST_VIS int wolfcert_pkcs7_certs_to_pem(const uint8_t* p7_der,
    size_t p7_der_len, WolfCertBuffer* out_pem, void* heap)
{
    return pkcs7_certs_extract(p7_der, p7_der_len, NULL, out_pem, heap, 1);
}

WOLFCERT_TEST_VIS int wolfcert_pkcs7_certs_to_der(const uint8_t* p7_der,
    size_t p7_der_len, WolfCertBuffer* out_der, void* heap)
{
    return pkcs7_certs_extract(p7_der, p7_der_len, NULL, out_der, heap, 0);
}

WOLFCERT_TEST_VIS int wolfcert_pkcs7_issued_to_pem(const uint8_t* p7_der,
    size_t p7_der_len, const WolfCertIssuedMatch* match,
    WolfCertBuffer* out_pem, void* heap)
{
    if (match == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    return pkcs7_certs_extract(p7_der, p7_der_len, match, out_pem, heap, 1);
}

static int validate_certs(const uint8_t* const* certs, const size_t* lens, size_t count)
{
    for (size_t i = 0; i < count; ++i) {
        if (certs[i] == NULL || lens[i] < 2)
            return WOLFCERT_ERR_BAD_ARG;

        if (certs[i][0] != 0x30)
            return WOLFCERT_ERR_PARSE;
    }

    return WOLFCERT_OK;
}

WOLFCERT_TEST_VIS int wolfcert_pkcs7_build_certs_only(const uint8_t* const* certs_der,
    const size_t* certs_len, size_t count, WolfCertBuffer* out_der, void* heap)
{
    if (certs_der == NULL || certs_len == NULL || count == 0 || out_der == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    int rc = validate_certs(certs_der, certs_len, count);
    if (rc != WOLFCERT_OK)
        return rc;

    /* wc_PKCS7_InitWithCert() would set publicKeyOID, which makes the encoder
     * demand a content hash for ECDSA and RSA-PSS certs. */
    PKCS7* p7 = wc_PKCS7_New(heap, INVALID_DEVID);
    if (p7 == NULL)
        return WOLFCERT_ERR_MEMORY;

    /* wc_PKCS7_AddCertificate() prepends, so add in reverse to keep the emitted
     * certs SET in the caller's order. */
    rc = 0;
    for (size_t i = count; rc == 0 && i-- > 0; ) {
        rc = wc_PKCS7_AddCertificate(p7, (byte*)certs_der[i], (word32)certs_len[i]);
    }

    if (rc == 0)
        rc = wc_PKCS7_SetSignerIdentifierType(p7, DEGENERATE_SID);

    if (rc != 0) {
        int e = WOLFCERT_ERR_WC(rc, "pkcs7", "certs-only setup");
        wc_PKCS7_Free(p7);
        return e;
    }

    p7->detached   = 1;
    p7->contentOID = DATA;

    size_t certs_body = 0;
    for (size_t i = 0; i < count; ++i) {
        certs_body += certs_len[i];
    }

    /* 512 bytes covers the ContentInfo and SignedData wrapper. */
    word32 cap = (word32)(certs_body + 512);
    uint8_t* buf = (uint8_t*)WOLFCERT_XMALLOC(cap, heap);
    if (buf == NULL) {
        wc_PKCS7_Free(p7);
        return WOLFCERT_ERR_MEMORY;
    }

    int n = wc_PKCS7_EncodeSignedData(p7, buf, cap);

    wc_PKCS7_Free(p7);
    if (n <= 0) {
        int e = WOLFCERT_ERR_WC(n, "pkcs7", "EncodeSignedData");
        WOLFCERT_XFREE(buf, heap);
        return e;
    }

    out_der->data = buf;
    out_der->len  = (size_t)n;
    out_der->heap = heap;

    return WOLFCERT_OK;
}
