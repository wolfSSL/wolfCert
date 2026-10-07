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
 * Degenerate (certs-only) PKCS#7 / CMS SignedData helpers:
 *   - extract certificates from a certs-only SignedData blob, returning them
 *     concatenated as PEM or DER.
 *   - build a certs-only SignedData around a set of DER certificates.
 *
 * Both directions go through wolfSSL's wc_PKCS7 API: extraction is validated
 * by wc_PKCS7_VerifySignedData(), encoding uses a DEGENERATE_SID SignedData
 * (wc_PKCS7_EncodeSignedData() with no signer). Heap hints thread through for
 * wolfSSL static-memory builds.
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include "internal.h"
#include <wolfcert/errors.h>

#include <wolfssl/wolfcrypt/pkcs7.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#include <stdint.h>
#include <string.h>

/* ---- certs-only (degenerate) SignedData extraction --------------------- *
 *
 * wc_PKCS7_VerifySignedData validates the structure; the certificates are then
 * read from the input itself. */

/* Append `n` bytes to a growable WolfCertBuffer. */
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

/* Append one certificate to `acc`, either as raw DER or PEM-encoded. */
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

/* Read the TLV header at *idx. Returns 0 with *len set, 1 for an indefinite
 * length, or -1 when it is malformed. */
static int tlv_header(const uint8_t* der, word32* idx, word32 max, byte* tag,
                      int* len)
{
    if (GetASNTag(der, idx, tag, max) < 0 || *idx >= max)
        return -1;

    if (der[*idx] == ASN_INDEF_LENGTH) {
        (*idx)++;
        *len = 0;
        return 1;
    }

    if (GetLength(der, idx, len, max) < 0)
        return -1;

    return 0;
}

/* Move *idx past the end-of-contents marker that closes the indefinite-length
 * element whose header was just read. */
static int skip_indef(const uint8_t* der, word32* idx, word32 max)
{
    int depth = 1;
    int hr;
    byte tag;
    int len;

    while (depth > 0) {
        hr = tlv_header(der, idx, max, &tag, &len);
        if (hr < 0)
            return -1;

        if (hr == 1)
            depth++;
        else if (tag == 0 && len == 0)
            depth--;
        else
            *idx += (word32)len;
    }

    return 0;
}

/* Find the certificate list inside the bundle.
 * Returns -1 when no certificate list is found. */
static int pkcs7_cert_set(const uint8_t* der, word32 der_len, word32* start,
                          word32* end)
{
    /* Headers from the start of the bundle down to its certificate list.
     * enter = 1 steps inside the element, 0 skips over it. */
    static const struct { byte tag; byte enter; } path[] = {
        { ASN_CONSTRUCTED | ASN_SEQUENCE,         1 },
        { ASN_OBJECT_ID,                          0 },
        { ASN_CONSTRUCTED | ASN_CONTEXT_SPECIFIC, 1 },
        { ASN_CONSTRUCTED | ASN_SEQUENCE,         1 },
        { ASN_INTEGER,                            0 },
        { ASN_CONSTRUCTED | ASN_SET,              0 },
        { ASN_CONSTRUCTED | ASN_SEQUENCE,         0 },
        { ASN_CONSTRUCTED | ASN_CONTEXT_SPECIFIC, 1 },
    };
    const size_t n = sizeof(path) / sizeof(path[0]);
    word32 idx = 0;
    size_t i;
    byte tag;
    int len = 0;
    int hr = 0;

    for (i = 0; i < n; i++) {
        hr = tlv_header(der, &idx, der_len, &tag, &len);
        if (hr < 0 || tag != path[i].tag)
            return -1;

        if (!path[i].enter && hr == 0)
            idx += (word32)len;
        else if (!path[i].enter && skip_indef(der, &idx, der_len) != 0)
            return -1;
    }

    *start = idx;
    if (hr == 0) {
        *end = idx + (word32)len;
    }
    else {
        /* An indefinite-length list ends just before its end-of-contents. */
        if (skip_indef(der, &idx, der_len) != 0)
            return -1;

        *end = idx - ASN_INDEF_END_SZ;
    }

    return 0;
}

/* Is [idx, end) a certificate body: tbsCertificate, signatureAlgorithm and
 * signatureValue, with nothing after? Returns 0 when it is. */
static int cert_shape(const uint8_t* der, word32 idx, word32 end)
{
    static const byte parts[] = {
        ASN_CONSTRUCTED | ASN_SEQUENCE,
        ASN_CONSTRUCTED | ASN_SEQUENCE,
        ASN_BIT_STRING
    };
    size_t i;
    byte tag;
    int len;

    for (i = 0; i < sizeof(parts); i++) {
        if (tlv_header(der, &idx, end, &tag, &len) != 0 || tag != parts[i])
            return -1;

        idx += (word32)len;
    }

    return (idx == end) ? 0 : -1;
}

/* Append every certificate in the certificates field at [idx, end) of `der`,
 * skipping the tagged CertificateChoices alternatives [0] to [3]. */
static int append_cert_set(WolfCertBuffer* acc, size_t* cap, const uint8_t* der,
                           word32 idx, word32 end, int as_pem, void* heap)
{
    size_t count = 0;
    int rc = WOLFCERT_OK;
    word32 at;
    byte tag = 0;
    int len;

    while (rc == WOLFCERT_OK && idx < end) {
        at = idx;
        if (tlv_header(der, &idx, end, &tag, &len) != 0)
            rc = WOLFCERT_ERR(WOLFCERT_ERR_PARSE, "pkcs7",
                              "malformed certificates field");
        else if (tag == (ASN_CONSTRUCTED | ASN_SEQUENCE) &&
                cert_shape(der, idx, idx + (word32)len) != 0)
            rc = WOLFCERT_ERR(WOLFCERT_ERR_PARSE, "pkcs7",
                              "certificates field holds a non-certificate");
        else if (tag != (ASN_CONSTRUCTED | ASN_SEQUENCE) &&
                (tag < (ASN_CONSTRUCTED | ASN_CONTEXT_SPECIFIC) ||
                 tag > (ASN_CONSTRUCTED | ASN_CONTEXT_SPECIFIC | 3)))
            rc = WOLFCERT_ERR(WOLFCERT_ERR_PARSE, "pkcs7",
                              "certificates field holds an unknown entry");
        else
            idx += (word32)len;

        if (rc == WOLFCERT_OK && tag == (ASN_CONSTRUCTED | ASN_SEQUENCE) &&
                ++count > WOLFCERT_PKCS7_MAX_CERTS)
            rc = WOLFCERT_ERR(WOLFCERT_ERR_UNSUPPORTED, "pkcs7",
                              "bundle holds more than WOLFCERT_PKCS7_MAX_CERTS "
                              "certificates");

        if (rc == WOLFCERT_OK && tag == (ASN_CONSTRUCTED | ASN_SEQUENCE))
            rc = append_cert(acc, cap, der + at, idx - at, as_pem, heap);
    }

    return rc;
}

static int pkcs7_certs_extract(const uint8_t* p7_der, size_t p7_der_len,
                               WolfCertBuffer* out, void* heap, int as_pem)
{
    WolfCertBuffer acc = { .heap = heap };
    size_t cap = 0;
    PKCS7* p7;
    word32 start;
    word32 end;
    int rc;

    if (p7_der == NULL || p7_der_len == 0 || out == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    p7 = wc_PKCS7_New(heap, WOLFCERT_DEVID_SOFTWARE);
    if (p7 == NULL)
        return WOLFCERT_ERR_MEMORY;

    rc = wc_PKCS7_VerifySignedData(p7, (byte*)p7_der, (word32)p7_der_len);
    if (rc != 0)
        rc = WOLFCERT_ERR_WC(rc, "pkcs7", "VerifySignedData");
    else if (pkcs7_cert_set(p7_der, (word32)p7_der_len, &start, &end) != 0)
        rc = WOLFCERT_ERR(WOLFCERT_ERR_PARSE, "pkcs7",
                          "cannot locate the certificate list in bundle");
    else
        rc = append_cert_set(&acc, &cap, p7_der, start, end, as_pem, heap);

    wc_PKCS7_Free(p7);
    if (rc == WOLFCERT_OK && acc.len == 0)
        rc = WOLFCERT_ERR_NOT_FOUND;

    if (rc != WOLFCERT_OK) {
        WOLFCERT_XFREE(acc.data, heap);
        return rc;
    }

    *out = acc;
    return WOLFCERT_OK;
}

WOLFCERT_TEST_VIS int wolfcert_pkcs7_certs_to_pem(const uint8_t* p7_der,
    size_t p7_der_len, WolfCertBuffer* out_pem, void* heap)
{
    return pkcs7_certs_extract(p7_der, p7_der_len, out_pem, heap, 1);
}

WOLFCERT_TEST_VIS int wolfcert_pkcs7_certs_to_der(const uint8_t* p7_der,
    size_t p7_der_len, WolfCertBuffer* out_der, void* heap)
{
    return pkcs7_certs_extract(p7_der, p7_der_len, out_der, heap, 0);
}

/* ---- degenerate (certs-only) SignedData encoder ------------------------ *
 *
 * Driven through the public wc_PKCS7 API: a DEGENERATE_SID SignedData with no
 * signer, attributes or eContent (hashOID left 0). Certificates are loaded with
 * wc_PKCS7_AddCertificate() and emitted as the certs SET by
 * wc_PKCS7_EncodeSignedData(). We deliberately avoid wc_PKCS7_InitWithCert():
 * it parses the cert and sets pkcs7->publicKeyOID, which makes the encoder's
 * signer-path validation reject ECDSA/RSA-PSS certs (it demands a pre-computed
 * content hash) even though a degenerate bundle has no signer at all. */

/* Light validation: every cert DER must start with SEQUENCE tag 0x30. The full
 * decode happens inside wolfSSL; this just gives a stable WOLFCERT_ERR_PARSE for
 * obviously non-DER input ahead of the wc_PKCS7 calls. */
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

    PKCS7* p7 = wc_PKCS7_New(heap, WOLFCERT_DEVID_SOFTWARE);
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

    /* No signer, no eContent: a degenerate certs-only bundle. */
    p7->detached   = 1;
    p7->contentOID = DATA;

    size_t certs_body = 0;
    for (size_t i = 0; i < count; ++i) {
        certs_body += certs_len[i];
    }

    /* Wrapper overhead (ContentInfo + SignedData + empty SETs) is a few dozen
     * bytes; 512 is a comfortable upper bound. */
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
