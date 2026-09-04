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
 * SCEP pkiMessage build/parse helpers.
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include "../internal.h"
#include <wolfcert/errors.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/pkcs7.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/ecc.h>

#include <string.h>

/* ---- SCEP OIDs & message types ------------------------------------------ */

static const byte OID_MSG_TYPE[]    = { 0x06,0x0A,0x60,0x86,0x48,0x01,0x86,0xF8,0x45,0x01,0x09,0x02 };
static const byte OID_TRANS_ID[]    = { 0x06,0x0A,0x60,0x86,0x48,0x01,0x86,0xF8,0x45,0x01,0x09,0x07 };
static const byte OID_SENDER_NONCE[]= { 0x06,0x0A,0x60,0x86,0x48,0x01,0x86,0xF8,0x45,0x01,0x09,0x05 };
static const byte OID_RECIP_NONCE[] = { 0x06,0x0A,0x60,0x86,0x48,0x01,0x86,0xF8,0x45,0x01,0x09,0x06 };
static const byte OID_PKI_STATUS[]  = { 0x06,0x0A,0x60,0x86,0x48,0x01,0x86,0xF8,0x45,0x01,0x09,0x03 };
static const byte OID_FAIL_INFO[]   = { 0x06,0x0A,0x60,0x86,0x48,0x01,0x86,0xF8,0x45,0x01,0x09,0x04 };

/* ---- small DER helpers --------------------------------------------------
 *
 * Each writer takes the caller's buffer capacity and returns -1 instead of
 * overflowing. Keeping the bounds check in the writer (rather than in each
 * caller after the fact) makes scratch-buffer overflows impossible.
 */

static int der_put_len(byte* out, size_t cap, size_t n)
{
    if (n < 0x80) {
        if (cap < 1)
            return -1;

        out[0] = (byte)n;
        return 1;
    }

    if (n <= 0xFF) {
        if (cap < 2)
            return -1;

        out[0] = 0x81;
        out[1] = (byte)n;
        return 2;
    }

    if (n <= 0xFFFF) {
        if (cap < 3)
            return -1;

        out[0] = 0x82;
        out[1] = (byte)(n>>8);
        out[2] = (byte)n;
        return 3;
    }

    if (cap < 4)
        return -1;

    out[0] = 0x83;
    out[1] = (byte)(n>>16);
    out[2] = (byte)(n>>8);
    out[3] = (byte)n;
    return 4;
}

/* Emit the raw AttributeValue - a bare PrintableString or OCTET STRING
 * with NO outer SET. wolfSSL's PKCS7 encoder wraps each attribute's
 * value in the CMS-mandated `SET OF AttributeValue` itself; pre-wrapping
 * here would land SET { SET { ... } } on the wire, which every other
 * RFC 8894 implementation rejects.
 *
 * Returns total bytes written, or -1 if `cap` is too small. */
static int enc_printable_n(const byte* v, size_t vl, byte* out, size_t cap)
{
    if (cap < 1)
        return -1;

    out[0] = 0x13;
    int ll = der_put_len(out + 1, cap - 1, vl);
    if (ll < 0 || 1 + (size_t)ll + vl > cap)
        return -1;

    memcpy(out + 1 + ll, v, vl);
    return (int)(1 + (size_t)ll + vl);
}

static int enc_printable(const char* s, byte* out, size_t cap)
{
    return enc_printable_n((const byte*)s, strlen(s), out, cap);
}

static int enc_octet(const byte* v, size_t vl, byte* out, size_t cap)
{
    if (cap < 1)
        return -1;

    out[0] = 0x04;
    int ll = der_put_len(out + 1, cap - 1, vl);
    if (ll < 0 || 1 + (size_t)ll + vl > cap)
        return -1;

    memcpy(out + 1 + ll, v, vl);
    return (int)(1 + (size_t)ll + vl);
}

/* ---- signed attribs builder -------------------------------------------- */

static int build_signed_attribs(const WolfCertScepAttrs* a,
                                PKCS7Attrib* attrs, int* attrs_count,
                                uint8_t* scratch, size_t scratch_cap)
{
    int n = 0;
    size_t off = 0;

    if (a->message_type != NULL) {
        int vl = enc_printable(a->message_type, scratch + off, scratch_cap - off);
        if (vl < 0)
            return WOLFCERT_ERR_MEMORY;

        attrs[n].oid = OID_MSG_TYPE;
        attrs[n].oidSz = sizeof(OID_MSG_TYPE);
        attrs[n].value = scratch + off;
        attrs[n].valueSz = (word32)vl;
        off += (size_t)vl;
        n++;
    }

    if (a->transaction_id != NULL) {
        /* Encode by length, not through a NUL-terminated copy: the
         * transactionID is a peer-chosen identifier that RFC 8894 does not
         * bound, and quietly truncating it would put a value on the wire that
         * no longer matches the transaction it names. Too long for the scratch
         * buffer is an error here, never a silent trim. */
        int vl = enc_printable_n(a->transaction_id, a->transaction_id_len,
                                 scratch + off, scratch_cap - off);
        if (vl < 0)
            return WOLFCERT_ERR_MEMORY;

        attrs[n].oid = OID_TRANS_ID;
        attrs[n].oidSz = sizeof(OID_TRANS_ID);
        attrs[n].value = scratch + off;
        attrs[n].valueSz = (word32)vl;
        off += (size_t)vl;
        n++;
    }
    if (a->sender_nonce != NULL) {
        int vl = enc_octet(a->sender_nonce, a->sender_nonce_len,
                           scratch + off, scratch_cap - off);
        if (vl < 0)
            return WOLFCERT_ERR_MEMORY;

        attrs[n].oid = OID_SENDER_NONCE;
        attrs[n].oidSz = sizeof(OID_SENDER_NONCE);
        attrs[n].value = scratch + off;
        attrs[n].valueSz = (word32)vl;
        off += (size_t)vl;
        n++;
    }
    if (a->recipient_nonce != NULL) {
        int vl = enc_octet(a->recipient_nonce, a->recipient_nonce_len,
                           scratch + off, scratch_cap - off);
        if (vl < 0)
            return WOLFCERT_ERR_MEMORY;

        attrs[n].oid = OID_RECIP_NONCE;
        attrs[n].oidSz = sizeof(OID_RECIP_NONCE);
        attrs[n].value = scratch + off;
        attrs[n].valueSz = (word32)vl;
        off += (size_t)vl;
        n++;
    }
    if (a->pki_status != NULL) {
        int vl = enc_printable(a->pki_status, scratch + off, scratch_cap - off);
        if (vl < 0)
            return WOLFCERT_ERR_MEMORY;

        attrs[n].oid = OID_PKI_STATUS;
        attrs[n].oidSz = sizeof(OID_PKI_STATUS);
        attrs[n].value = scratch + off;
        attrs[n].valueSz = (word32)vl;
        off += (size_t)vl;
        n++;
    }
    if (a->fail_info != NULL) {
        int vl = enc_printable(a->fail_info, scratch + off, scratch_cap - off);
        if (vl < 0)
            return WOLFCERT_ERR_MEMORY;

        attrs[n].oid = OID_FAIL_INFO;
        attrs[n].oidSz = sizeof(OID_FAIL_INFO);
        attrs[n].value = scratch + off;
        attrs[n].valueSz = (word32)vl;
        off += (size_t)vl;
        n++;
    }

    *attrs_count = n;
    return WOLFCERT_OK;
}

/* ---- public API --------------------------------------------------------- */

WOLFCERT_TEST_VIS int wolfcert_scep_envelop(const uint8_t* ra_cert_der,
    size_t ra_cert_len, const uint8_t* payload, size_t payload_len, int enc_oid,
    WolfCertBuffer* out_der, void* heap)
{
    PKCS7* p7 = wc_PKCS7_New(heap, WOLFCERT_DEVID_SOFTWARE);
    if (p7 == NULL)
        return WOLFCERT_ERR_MEMORY;

    int rc = wc_PKCS7_InitWithCert(p7, (byte*)ra_cert_der, (word32)ra_cert_len);
    if (rc != 0) {
        wc_PKCS7_Free(p7);
        return WOLFCERT_ERR_WC(rc, "scep", "InitWithCert");
    }

    /* RFC 8894 is RSA-only: the pkcsPKIEnvelope is encrypted to the RA/CA
     * public key with CMS key transport, which wolfSSL only supports for an
     * RSA recipient. A non-RSA (e.g. ECC) RA certificate would otherwise fall
     * through to the key-agreement path and fail deep in the encoder with
     * BAD_KEYWRAP_ALG_E; reject it up front with an actionable diagnostic. */
    if (p7->publicKeyOID != RSAk) {
        wc_PKCS7_Free(p7);
        return WOLFCERT_ERR(WOLFCERT_ERR_UNSUPPORTED, "scep",
            "SCEP requires an RSA RA/CA certificate (RFC 8894); the server "
            "presented a non-RSA key");
    }

    WC_RNG rng;
    if (wc_InitRng_ex(&rng, heap, WOLFCERT_DEVID_SOFTWARE) != 0) {
        wc_PKCS7_Free(p7);
        return WOLFCERT_ERR_CRYPTO;
    }

    p7->rng          = &rng;
    p7->content      = (byte*)payload;
    p7->contentSz    = (word32)payload_len;
    p7->contentOID   = DATA;
    p7->encryptOID   = enc_oid;
    p7->keyWrapOID   = 0;

    size_t cap = payload_len + ra_cert_len + 4096;
    uint8_t* buf = (uint8_t*)WOLFCERT_XMALLOC(cap, heap);
    if (buf == NULL) {
        wc_FreeRng(&rng);
        wc_PKCS7_Free(p7);
        return WOLFCERT_ERR_MEMORY;
    }

    int n = wc_PKCS7_EncodeEnvelopedData(p7, buf, (word32)cap);

    wc_FreeRng(&rng);
    wc_PKCS7_Free(p7);
    if (n <= 0) {
        WOLFCERT_XFREE(buf, heap);
        return WOLFCERT_ERR_WC(n, "scep", "EncodeEnvelopedData");
    }

    out_der->data = buf;
    out_der->len = (size_t)n;
    out_der->heap = heap;
    return WOLFCERT_OK;
}

int wolfcert_scep_deenvelop(const uint8_t* recipient_cert_der, size_t recipient_cert_len,
                             const uint8_t* recipient_key_der,  size_t recipient_key_len,
                             const uint8_t* env_der, size_t env_len,
                             WolfCertBuffer* out_plain, void* heap)
{
    /* env_len is server-controlled and drives cap = env_len + 4096 (plus a
     * word32 cast into wolfSSL). Reject an empty or over-large envelope so the
     * allocation stays bounded on constrained targets; see
     * WOLFCERT_SCEP_MAX_MSG_SZ. */
    if (env_len == 0 || env_len > WOLFCERT_SCEP_MAX_MSG_SZ)
        return WOLFCERT_ERR_BAD_ARG;

    PKCS7* p7 = wc_PKCS7_New(heap, WOLFCERT_DEVID_SOFTWARE);
    if (p7 == NULL)
        return WOLFCERT_ERR_MEMORY;

    int rc = wc_PKCS7_InitWithCert(p7, (byte*)recipient_cert_der,
                                   (word32)recipient_cert_len);
    if (rc != 0) {
        wc_PKCS7_Free(p7);
        return WOLFCERT_ERR_WC(rc, "scep", "InitWithCert");
    }

    p7->privateKey   = (byte*)recipient_key_der;
    p7->privateKeySz = (word32)recipient_key_len;

    size_t cap = env_len + 4096;
    uint8_t* buf = (uint8_t*)WOLFCERT_XMALLOC(cap, heap);
    if (buf == NULL) {
        wc_PKCS7_Free(p7);
        return WOLFCERT_ERR_MEMORY;
    }

    int n = wc_PKCS7_DecodeEnvelopedData(p7, (byte*)env_der, (word32)env_len,
                                         buf, (word32)cap);

    wc_PKCS7_Free(p7);
    if (n <= 0) {
        WOLFCERT_XFREE(buf, heap);
        return WOLFCERT_ERR_WC(n, "scep", "DecodeEnvelopedData");
    }

    out_plain->data = buf;
    out_plain->len = (size_t)n;
    out_plain->heap = heap;
    return WOLFCERT_OK;
}

WOLFCERT_TEST_VIS int wolfcert_scep_self_signed_rsa(RsaKey* key,
    const uint8_t* csr_der, size_t csr_len, uint8_t** out_der, size_t* out_len,
    void* heap)
{
    DecodedCert dc;
    Cert*    cert;
    WC_RNG   rng;
    uint8_t* der;
    size_t   cap;
    int      n;
    int      rc;

    if (key == NULL || csr_der == NULL || out_der == NULL || out_len == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    /* csr_len drives cap = csr_len + 4096 (plus a word32 cast into wolfSSL).
     * Reject an empty or over-large request so the allocation stays bounded on
     * constrained targets; see WOLFCERT_SCEP_MAX_MSG_SZ. */
    if (csr_len == 0 || csr_len > WOLFCERT_SCEP_MAX_MSG_SZ)
        return WOLFCERT_ERR_BAD_ARG;
    cap = csr_len + 4096;

    cert = wc_CertNew(heap);
    if (cert == NULL)
        return WOLFCERT_ERR_MEMORY;

    wc_InitCert_ex(cert, heap, WOLFCERT_DEVID_SOFTWARE);

    /* RFC 8894 section 2.3: the signer certificate SHOULD carry the same
     * subject name as the enclosed PKCS#10 request. The certificate is
     * self-signed, so its issuer name is the same DN.
     *
     * wolfSSL recovers the raw name length with XSTRLEN while encoding, so the
     * raw-name path cannot represent a DN that contains a 0x00 byte (e.g. a
     * BMPString value or a length octet whose low byte is zero). Use it only
     * for a NUL-free DN that leaves room for a terminator, and fall back to the
     * request's common name otherwise. The signer subject is not security
     * relevant: issuance binds on the public key, not this name. */
    wc_InitDecodedCert(&dc, (const byte*)csr_der, (word32)csr_len, heap);
    rc = wc_ParseCert(&dc, CERTREQ_TYPE, NO_VERIFY, NULL);
    if (rc != 0) {
        wc_FreeDecodedCert(&dc);
        wc_CertFree(cert);
        return WOLFCERT_ERR_PARSE;
    }

    if (dc.subjectRaw != NULL && dc.subjectRawLen > 0 &&
            dc.subjectRawLen < (int)sizeof(cert->sbjRaw) &&
            memchr(dc.subjectRaw, 0x00, (size_t)dc.subjectRawLen) == NULL) {
        memcpy(cert->sbjRaw, dc.subjectRaw, (size_t)dc.subjectRawLen);
        cert->sbjRaw[dc.subjectRawLen] = '\0';
        memcpy(cert->issRaw, dc.subjectRaw, (size_t)dc.subjectRawLen);
        cert->issRaw[dc.subjectRawLen] = '\0';
    }
    else if (dc.subjectCN != NULL && dc.subjectCNLen > 0) {
        int cn = dc.subjectCNLen < CTC_NAME_SIZE - 1
                 ? dc.subjectCNLen : CTC_NAME_SIZE - 1;
        memcpy(cert->subject.commonName, dc.subjectCN, (size_t)cn);
        cert->subject.commonName[cn] = '\0';
    }
    else {
        strncpy(cert->subject.commonName, "SCEP Enrollee", CTC_NAME_SIZE - 1);
        cert->subject.commonName[CTC_NAME_SIZE - 1] = '\0';
    }
    wc_FreeDecodedCert(&dc);

    cert->selfSigned = 1;
    cert->sigType    = CTC_SHA256wRSA;
    cert->daysValid  = 2;

    /* RFC 8894 section 1: the signer certificate must assert digitalSignature
     * and keyEncipherment. */
    rc = wc_SetKeyUsage(cert, "digitalSignature,keyEncipherment");
    if (rc != 0) {
        wc_CertFree(cert);
        return WOLFCERT_ERR_WC(rc, "scep", "SetKeyUsage");
    }

    if (wc_InitRng_ex(&rng, heap, WOLFCERT_DEVID_SOFTWARE) != 0) {
        wc_CertFree(cert);
        return WOLFCERT_ERR_CRYPTO;
    }

    der = (uint8_t*)WOLFCERT_XMALLOC(cap, heap);
    if (der == NULL) {
        wc_FreeRng(&rng);
        wc_CertFree(cert);
        return WOLFCERT_ERR_MEMORY;
    }

    n = wc_MakeSelfCert(cert, der, (word32)cap, key, &rng);

    wc_FreeRng(&rng);
    wc_CertFree(cert);
    if (n <= 0) {
        WOLFCERT_XFREE(der, heap);
        return WOLFCERT_ERR_WC(n, "scep", "MakeSelfCert");
    }

    *out_der = der;
    *out_len = (size_t)n;
    return WOLFCERT_OK;
}

WOLFCERT_TEST_VIS int wolfcert_scep_build_pki_message(const uint8_t* envelope_der,
    size_t envelope_len, const uint8_t* signer_cert_der, size_t signer_cert_len,
    const uint8_t* signer_key_der,  size_t signer_key_len, int hash_oid,
    const WolfCertScepAttrs* attrs, WolfCertBuffer* out_der, void* heap)
{
    PKCS7* p7 = wc_PKCS7_New(heap, WOLFCERT_DEVID_SOFTWARE);
    if (p7 == NULL)
        return WOLFCERT_ERR_MEMORY;

    int rc = wc_PKCS7_InitWithCert(p7, (byte*)signer_cert_der, (word32)signer_cert_len);
    if (rc != 0) {
        wc_PKCS7_Free(p7);
        return WOLFCERT_ERR_WC(rc, "scep", "InitWithCert");
    }

    WC_RNG rng;
    if (wc_InitRng_ex(&rng, heap, WOLFCERT_DEVID_SOFTWARE) != 0) {
        wc_PKCS7_Free(p7);
        return WOLFCERT_ERR_CRYPTO;
    }

    /* A CertRep with pkiStatus PENDING/FAILURE (RFC 8894 section 3.2.2) has no
     * pkcsPKIEnvelope: the SignedData encapsulates no content. Emit a detached
     * SignedData in that case so the eContent is genuinely absent; wolfSSL
     * computes the messageDigest over the empty content internally. */
    int detached = (envelope_der == NULL || envelope_len == 0);

    p7->rng          = &rng;
    p7->privateKey   = (byte*)signer_key_der;
    p7->privateKeySz = (word32)signer_key_len;
    p7->encryptOID   = RSAk;
    p7->hashOID      = hash_oid ? hash_oid : SHA256h;
    if (!detached) {
        p7->content   = (byte*)envelope_der;
        p7->contentSz = (word32)envelope_len;
    }
    else {
        rc = wc_PKCS7_SetDetached(p7, 1);
        if (rc != 0) {
            wc_FreeRng(&rng);
            wc_PKCS7_Free(p7);
            return WOLFCERT_ERR_WC(rc, "scep", "SetDetached");
        }
    }

    PKCS7Attrib attrs_arr[8];
    uint8_t scratch[1024];
    int nattr = 0;
    rc = build_signed_attribs(attrs, attrs_arr, &nattr, scratch, sizeof(scratch));
    if (rc != WOLFCERT_OK) {
        wc_FreeRng(&rng);
        wc_PKCS7_Free(p7);
        return rc;
    }

    if (nattr > 0) {
        p7->signedAttribs   = attrs_arr;
        p7->signedAttribsSz = (word32)nattr;
    }

    /* wolfSSL's PKCS7 encoder mutates internal state on each
     * EncodeSignedData call, so retry-on-BUFFER_E with the same PKCS7
     * object is unreliable. Give the encoder a single right-sized one-shot
     * buffer instead: the envelope content and signer cert pass through
     * verbatim, and WOLFCERT_SCEP_PKI_SLACK bounds the signed attributes,
     * signature, and ASN.1 framing on top. */
    size_t cap = envelope_len + signer_cert_len + WOLFCERT_SCEP_PKI_SLACK;
    uint8_t* buf = (uint8_t*)WOLFCERT_XMALLOC(cap, heap);
    if (buf == NULL) {
        wc_FreeRng(&rng);
        wc_PKCS7_Free(p7);
        return WOLFCERT_ERR_MEMORY;
    }

    int sz = wc_PKCS7_EncodeSignedData(p7, buf, (word32)cap);

    wc_FreeRng(&rng);
    wc_PKCS7_Free(p7);
    if (sz <= 0) {
        WOLFCERT_XFREE(buf, heap);
        return WOLFCERT_ERR_WC(sz, "scep", "EncodeSignedData");
    }

    out_der->data = buf;
    out_der->len = (size_t)sz;
    out_der->heap = heap;
    return WOLFCERT_OK;
}

WOLFCERT_TEST_VIS int wolfcert_scep_build_next_ca_response(const uint8_t* next_ca_cert,
                                         size_t next_ca_cert_len,
                                         const uint8_t* ca_cert, size_t ca_cert_len,
                                         const uint8_t* ca_key, size_t ca_key_len,
                                         WolfCertBuffer* out_der, void* heap)
{
    const uint8_t* cs[1];
    size_t         cl[1];
    WolfCertBuffer inner = { 0 };
    WolfCertScepAttrs attrs;
    int rc;

    if (next_ca_cert == NULL || ca_cert == NULL || ca_key == NULL ||
            out_der == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    cs[0] = next_ca_cert;
    cl[0] = next_ca_cert_len;
    rc = wolfcert_pkcs7_build_certs_only(cs, cl, 1, &inner, heap);
    if (rc != WOLFCERT_OK)
        return rc;

    /* Sign the certs-only bundle with the current CA key, carrying no SCEP
     * signed attributes: this is a plain SignedData, not a pkiMessage. */
    memset(&attrs, 0, sizeof(attrs));
    rc = wolfcert_scep_build_pki_message(inner.data, inner.len,
                                         ca_cert, ca_cert_len,
                                         ca_key, ca_key_len,
                                         SHA256h, &attrs, out_der, heap);

    wolfcert_buffer_free(&inner);
    return rc;
}

WOLFCERT_TEST_VIS int wolfcert_scep_verify_next_ca_response(const uint8_t* resp_der,
                                          size_t resp_len,
                                          const uint8_t* current_ca_der,
                                          size_t current_ca_len,
                                          WolfCertBuffer* out_pem, void* heap)
{
    WolfCertBuffer content = { 0 };
    uint8_t* signer = NULL;
    size_t   signer_len = 0;
    int      rc;

    if (resp_der == NULL || current_ca_der == NULL || out_pem == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    rc = wolfcert_scep_parse_pki_message(resp_der, resp_len, &content,
            NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
            &signer, &signer_len, NULL, heap);

    /* Bind the rollover message to the trusted current CA: its SignedData
     * signer must share that CA's public key. */
    if (rc == WOLFCERT_OK) {
        rc = wolfcert_scep_verify_rep_signer(signer, signer_len,
                                             current_ca_der, current_ca_len, heap);
    }

    if (rc == WOLFCERT_OK) {
        rc = wolfcert_pkcs7_certs_to_pem(content.data, content.len, out_pem, heap);
    }

    WOLFCERT_XFREE(signer, heap);
    wolfcert_buffer_free(&content);
    return rc;
}

WOLFCERT_TEST_VIS int wolfcert_scep_parse_pki_message(const uint8_t* pki_der,
    size_t pki_len, WolfCertBuffer* out_envelope, uint8_t** out_transaction_id,
    size_t* out_tid_len, uint8_t** out_sender_nonce, size_t* out_snonce_len,
    uint8_t** out_recipient_nonce,size_t* out_rnonce_len, char** out_message_type,
    char** out_pki_status, uint8_t** out_signer_cert, size_t* out_signer_cert_len,
    char** out_fail_info, void* heap)
{
    PKCS7* p7 = wc_PKCS7_New(heap, WOLFCERT_DEVID_SOFTWARE);
    if (p7 == NULL)
        return WOLFCERT_ERR_MEMORY;

    wc_PKCS7_AllowDegenerate(p7, 0);

    int rc = wc_PKCS7_VerifySignedData(p7, (byte*)pki_der, (word32)pki_len);
    if (rc != 0) {
        wc_PKCS7_Free(p7);
        return WOLFCERT_ERR_WC(rc, "scep", "VerifySignedData");
    }

    /* A CertRep with pkiStatus PENDING/FAILURE (RFC 8894 section 3.2.2) carries
     * no pkcsPKIEnvelope, so the SignedData encapsulates no content. wolfSSL
     * verifies the absent eContent against the hash of empty content, and the
     * signed attributes (pkiStatus, transactionID, nonces, ...) stay
     * authenticated; report the envelope as empty in that case. */
    if (p7->content != NULL && p7->contentSz != 0) {
        uint8_t* env = (uint8_t*)WOLFCERT_XMALLOC(p7->contentSz, heap);
        if (env == NULL) {
            wc_PKCS7_Free(p7);
            return WOLFCERT_ERR_MEMORY;
        }

        memcpy(env, p7->content, p7->contentSz);
        out_envelope->data = env;
        out_envelope->len  = p7->contentSz;
        out_envelope->heap = heap;
    }
    else {
        out_envelope->data = NULL;
        out_envelope->len  = 0;
        out_envelope->heap = heap;
    }

    if (out_signer_cert != NULL && out_signer_cert_len != NULL) {
        *out_signer_cert = NULL;
        *out_signer_cert_len = 0;
        /* Return the certificate that actually produced the verified
         * signature, which wolfSSL matches by SignerInfo identity. It is not
         * necessarily the first certificate in the bundle, so a caller binding
         * the signer to a trust anchor must not trust cert[0]. */
        if (p7->verifyCert != NULL && p7->verifyCertSz > 0) {
            uint8_t* sc = (uint8_t*)WOLFCERT_XMALLOC(p7->verifyCertSz, heap);
            if (sc != NULL) {
                memcpy(sc, p7->verifyCert, p7->verifyCertSz);
                *out_signer_cert     = sc;
                *out_signer_cert_len = p7->verifyCertSz;
            }
        }
    }

    if (out_transaction_id) {
        *out_transaction_id = NULL;
        *out_tid_len = 0;
    }

    if (out_sender_nonce) {
        *out_sender_nonce = NULL;
        *out_snonce_len = 0;
    }

    if (out_recipient_nonce) {
        *out_recipient_nonce = NULL;
        *out_rnonce_len = 0;
    }

    if (out_message_type)
        *out_message_type = NULL;

    if (out_pki_status)
        *out_pki_status = NULL;

    if (out_fail_info)
        *out_fail_info = NULL;

    for (PKCS7DecodedAttrib* a = p7->decodedAttrib; a != NULL; a = a->next) {
        /* PKCS7DecodedAttrib.value can arrive in either of two shapes
         * depending on the wolfSSL version / producer:
         *   (a) the outer `SET OF AttributeValue` (tag 0x31 + content), or
         *   (b) the first AttributeValue already stripped of the SET
         *       (tag 0x13 PrintableString, 0x04 OCTET STRING, ...).
         * Detect and unwrap whichever one we got. */
        if (a->valueSz < 2 || a->value == NULL)
            continue;

        const byte* v = a->value;
        size_t off = 0;

        if (v[0] == 0x31) {
            off = 2;
            if (v[1] == 0x81) {
                if (a->valueSz < 3)
                    continue;
                off = 3;
            }
            else if (v[1] == 0x82) {
                if (a->valueSz < 4)
                    continue;
                off = 4;
            }
        }

        if (off + 2 > a->valueSz)
            continue;

        size_t vlen = v[off + 1];
        size_t voff = off + 2;
        if (v[off + 1] == 0x81) {
            if (off + 3 > a->valueSz)
                continue;

            vlen = v[off + 2];
            voff = off + 3;
        }
        else if (v[off + 1] == 0x82) {
            if (off + 4 > a->valueSz)
                continue;
            vlen = ((size_t)v[off + 2] << 8) | v[off + 3];
            voff = off + 4;
        }

        if (voff + vlen > a->valueSz)
            continue;

        off = voff;

        if (a->oidSz == sizeof(OID_MSG_TYPE) &&
            memcmp(a->oid, OID_MSG_TYPE, a->oidSz) == 0 && out_message_type) {
            char* s = (char*)WOLFCERT_XMALLOC(vlen + 1, heap);
            if (s) {
                memcpy(s, v + off, vlen);
                s[vlen] = '\0';
                *out_message_type = s;
            }
        }
        else if (a->oidSz == sizeof(OID_PKI_STATUS) &&
                 memcmp(a->oid, OID_PKI_STATUS, a->oidSz) == 0 && out_pki_status) {
            char* s = (char*)WOLFCERT_XMALLOC(vlen + 1, heap);
            if (s) {
                memcpy(s, v + off, vlen);
                s[vlen] = '\0';
                *out_pki_status = s;
            }
        }
        else if (a->oidSz == sizeof(OID_FAIL_INFO) &&
                 memcmp(a->oid, OID_FAIL_INFO, a->oidSz) == 0 && out_fail_info) {
            char* s = (char*)WOLFCERT_XMALLOC(vlen + 1, heap);
            if (s) {
                memcpy(s, v + off, vlen);
                s[vlen] = '\0';
                *out_fail_info = s;
            }
        }
        else if (a->oidSz == sizeof(OID_TRANS_ID) &&
                 memcmp(a->oid, OID_TRANS_ID, a->oidSz) == 0 && out_transaction_id) {
            uint8_t* b = (uint8_t*)WOLFCERT_XMALLOC(vlen, heap);
            if (b) {
                memcpy(b, v + off, vlen);
                *out_transaction_id = b;
                *out_tid_len = vlen;
            }
        }
        else if (a->oidSz == sizeof(OID_SENDER_NONCE) &&
                 memcmp(a->oid, OID_SENDER_NONCE, a->oidSz) == 0 && out_sender_nonce) {
            uint8_t* b = (uint8_t*)WOLFCERT_XMALLOC(vlen, heap);
            if (b) {
                memcpy(b, v + off, vlen);
                *out_sender_nonce = b;
                *out_snonce_len = vlen;
            }
        }
        else if (a->oidSz == sizeof(OID_RECIP_NONCE) &&
                 memcmp(a->oid, OID_RECIP_NONCE, a->oidSz) == 0 && out_recipient_nonce) {
            uint8_t* b = (uint8_t*)WOLFCERT_XMALLOC(vlen, heap);
            if (b) {
                memcpy(b, v + off, vlen);
                *out_recipient_nonce = b;
                *out_rnonce_len = vlen;
            }
        }
    }

    wc_PKCS7_Free(p7);
    return WOLFCERT_OK;
}

/* Build RFC 8894 section 3.3.2 IssuerAndSubject:
 *   IssuerAndSubject ::= SEQUENCE { issuer Name, subject Name }
 * where the issuer Name is copied from the RA/CA cert and the subject
 * Name is copied from the CSR. This is the enveloped content of a
 * GetCertInitial (messageType 20) pkiMessage - it lets the server
 * locate the pending request by DN when transactionID matching is
 * ambiguous. */
int wolfcert_scep_issuer_and_subject(const uint8_t* issuer_cert_der, size_t issuer_cert_len,
                                      const uint8_t* csr_der,         size_t csr_len,
                                      WolfCertBuffer* out_der, void* heap)
{
    if (issuer_cert_der == NULL || csr_der == NULL || out_der == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    DecodedCert ic;
    wc_InitDecodedCert(&ic, (byte*)issuer_cert_der,
                                        (word32)issuer_cert_len, heap);

    int rc = wc_ParseCert(&ic, CERT_TYPE, NO_VERIFY, NULL);
    if (rc != 0) {
        wc_FreeDecodedCert(&ic);
        return WOLFCERT_ERR_PARSE;
    }

    DecodedCert sc;
    wc_InitDecodedCert(&sc, (byte*)csr_der, (word32)csr_len, heap);

    rc = wc_ParseCert(&sc, CERTREQ_TYPE, NO_VERIFY, NULL);
    if (rc != 0) {
        wc_FreeDecodedCert(&ic);
        wc_FreeDecodedCert(&sc);
        return WOLFCERT_ERR_PARSE;
    }

    if (ic.subjectRaw == NULL || ic.subjectRawLen <= 0 ||
            sc.subjectRaw == NULL || sc.subjectRawLen <= 0) {
        wc_FreeDecodedCert(&ic);
        wc_FreeDecodedCert(&sc);
        return WOLFCERT_ERR_PARSE;
    }

    size_t inner = (size_t)ic.subjectRawLen + (size_t)sc.subjectRawLen;
    size_t cap   = inner + 8;
    uint8_t* buf = (uint8_t*)WOLFCERT_XMALLOC(cap, heap);
    if (buf == NULL) {
        wc_FreeDecodedCert(&ic);
        wc_FreeDecodedCert(&sc);
        return WOLFCERT_ERR_MEMORY;
    }

    buf[0] = 0x30;
    int ll = der_put_len(buf + 1, cap - 1, inner);
    if (ll < 0) {
        WOLFCERT_XFREE(buf, heap);
        wc_FreeDecodedCert(&ic);
        wc_FreeDecodedCert(&sc);
        return WOLFCERT_ERR_MEMORY;
    }

    size_t off = 1 + (size_t)ll;
    memcpy(buf + off, ic.subjectRaw, (size_t)ic.subjectRawLen);
    off += (size_t)ic.subjectRawLen;
    memcpy(buf + off, sc.subjectRaw, (size_t)sc.subjectRawLen);
    off += (size_t)sc.subjectRawLen;

    wc_FreeDecodedCert(&ic);
    wc_FreeDecodedCert(&sc);
    out_der->data = buf;
    out_der->len = off;
    out_der->heap = heap;

    return WOLFCERT_OK;
}

/* Extract the raw SPKI (SubjectPublicKeyInfo) from either a cert or a CSR
 * DER. Used by the server to verify the signer-cert pub key matches the
 * pub key in the enclosed CSR. */
int wolfcert_extract_spki(const uint8_t* der, size_t len, int is_csr,
                           uint8_t** out_spki, size_t* out_len, void* heap)
{
    DecodedCert dc;
    wc_InitDecodedCert(&dc, (byte*)der, (word32)len, heap);

    int rc = wc_ParseCert(&dc, is_csr ? CERTREQ_TYPE : CERT_TYPE, NO_VERIFY, NULL);
    if (rc != 0) {
        wc_FreeDecodedCert(&dc);
        return WOLFCERT_ERR_PARSE;
    }

    if (dc.publicKey == NULL || dc.pubKeySize == 0) {
        wc_FreeDecodedCert(&dc);
        return WOLFCERT_ERR_PARSE;
    }

    uint8_t* buf = (uint8_t*)WOLFCERT_XMALLOC(dc.pubKeySize, heap);
    if (buf == NULL) {
        wc_FreeDecodedCert(&dc);
        return WOLFCERT_ERR_MEMORY;
    }

    memcpy(buf, dc.publicKey, dc.pubKeySize);
    *out_spki = buf;
    *out_len = dc.pubKeySize;
    wc_FreeDecodedCert(&dc);

    return WOLFCERT_OK;
}

/* Total length (tag + length octets + value) of the DER SEQUENCE at `p`, or 0
 * if it is not a SEQUENCE that fits in `len`. Walks a concatenated-DER cert
 * bundle one certificate at a time. */
static size_t der_seq_len(const uint8_t* p, size_t len)
{
    size_t clen, hdr, nb, i;

    if (len < 2 || p[0] != 0x30)
        return 0;

    if ((p[1] & 0x80) == 0) {
        hdr  = 2;
        clen = p[1];
    }
    else {
        nb = (size_t)(p[1] & 0x7F);
        if (nb == 0 || nb > 4 || len < 2 + nb)
            return 0;

        clen = 0;
        for (i = 0; i < nb; i++)
            clen = (clen << 8) | p[2 + i];
        hdr = 2 + nb;
    }

    if (clen > len - hdr)
        return 0;

    return hdr + clen;
}

WOLFCERT_TEST_VIS int wolfcert_scep_verify_rep_signer(const uint8_t* signer_cert,
                                    size_t signer_cert_len,
                                    const uint8_t* ca_bundle, size_t ca_bundle_len,
                                    void* heap)
{
    uint8_t* signer_spki = NULL;
    size_t   signer_spki_len = 0;
    uint8_t* ca_spki = NULL;
    size_t   ca_spki_len = 0;
    size_t   off = 0;
    size_t   clen;
    int      matched = 0;

    if (signer_cert == NULL || ca_bundle == NULL)
        return WOLFCERT_ERR_AUTH;

    if (wolfcert_extract_spki(signer_cert, signer_cert_len, 0,
                              &signer_spki, &signer_spki_len, heap) != WOLFCERT_OK)
        return WOLFCERT_ERR_AUTH;

    /* RFC 8894: the CertRep is signed by the CA or its RA. Accept the signer
     * if it shares a public key with any certificate in the trusted GetCACert
     * bundle (one or more concatenated DER certs). */
    while (off < ca_bundle_len && !matched) {
        clen = der_seq_len(ca_bundle + off, ca_bundle_len - off);
        if (clen == 0)
            break;

        if (wolfcert_extract_spki(ca_bundle + off, clen, 0,
                                  &ca_spki, &ca_spki_len, heap) == WOLFCERT_OK) {
            if (ca_spki_len == signer_spki_len &&
                    memcmp(ca_spki, signer_spki, signer_spki_len) == 0)
                matched = 1;
            WOLFCERT_XFREE(ca_spki, heap);
            ca_spki = NULL;
        }

        off += clen;
    }

    WOLFCERT_XFREE(signer_spki, heap);
    return matched ? WOLFCERT_OK : WOLFCERT_ERR_AUTH;
}

WOLFCERT_TEST_VIS int wolfcert_scep_check_cert_rep(const char* msg_type,
                                 const uint8_t* rx_tid, size_t rx_tid_len,
                                 const uint8_t* sent_tid, size_t sent_tid_len)
{
    if (msg_type == NULL || strcmp(msg_type, "3") != 0)
        return WOLFCERT_ERR_PROTOCOL;

    if (rx_tid == NULL || sent_tid == NULL || rx_tid_len != sent_tid_len ||
            memcmp(rx_tid, sent_tid, sent_tid_len) != 0)
        return WOLFCERT_ERR_PROTOCOL;

    return WOLFCERT_OK;
}
