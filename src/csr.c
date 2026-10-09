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

#include <wolfcert/csr.h>
#include <wolfcert/errors.h>
#include "internal.h"
#include "key_algs.h"

#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#include <ctype.h>
#include <stddef.h>
#include <string.h>

struct rdn_field {
    const char* key;
    size_t      key_len;
    size_t      off;
    size_t      cap;
};

static const struct rdn_field rdn_fields[] = {
    { "CN",               2,  offsetof(CertName, commonName), CTC_NAME_SIZE },
    { "commonName",       10, offsetof(CertName, commonName), CTC_NAME_SIZE },
    { "O",                1,  offsetof(CertName, org),        CTC_NAME_SIZE },
    { "OU",               2,  offsetof(CertName, unit),       CTC_NAME_SIZE },
    { "C",                1,  offsetof(CertName, country),    CTC_NAME_SIZE },
    { "ST",               2,  offsetof(CertName, state),      CTC_NAME_SIZE },
    { "L",                1,  offsetof(CertName, locality),   CTC_NAME_SIZE },
    { "SN",               2,  offsetof(CertName, sur),        CTC_NAME_SIZE },
    { "GN",               2,  offsetof(CertName, givenName),  CTC_NAME_SIZE },
    { "emailAddress",     12, offsetof(CertName, email),      CTC_NAME_SIZE },
    { "serialNumber",     12, offsetof(CertName, serialDev),  CTC_NAME_SIZE },
    { "UID",              3,  offsetof(CertName, userId),     CTC_NAME_SIZE },
    { "userId",           6,  offsetof(CertName, userId),     CTC_NAME_SIZE },
    { "postalCode",       10, offsetof(CertName, postalCode), CTC_NAME_SIZE },
    { "street",            6, offsetof(CertName, street),     CTC_NAME_SIZE },
#ifdef WOLFSSL_CERT_EXT
    { "businessCategory", 16, offsetof(CertName, busCat),     CTC_NAME_SIZE },
#endif
};

static int assign_rdn(CertName* subject, const char* key, size_t klen,
                      const char* val, size_t vlen)
{
    for (size_t i = 0; i < sizeof(rdn_fields)/sizeof(rdn_fields[0]); ++i) {
        if (rdn_fields[i].key_len == klen &&
                strncmp(rdn_fields[i].key, key, klen) == 0) {
            char* dst = (char*)subject + rdn_fields[i].off;
            /* Truncating would request a subject the caller did not ask for. */
            if (vlen >= rdn_fields[i].cap)
                return WOLFCERT_ERR(WOLFCERT_ERR_BAD_ARG, "csr",
                    "subject %.*s is %zu bytes, limit %zu", (int)klen, key,
                    vlen, rdn_fields[i].cap - 1);
            /* wolfSSL encodes these two as PrintableString. */
            if ((rdn_fields[i].off == offsetof(CertName, country) ||
                    rdn_fields[i].off == offsetof(CertName, serialDev)) &&
                    !wolfcert_is_printable_string((const uint8_t*)val, vlen))
                return WOLFCERT_ERR(WOLFCERT_ERR_BAD_ARG, "csr",
                    "subject %.*s is not a PrintableString", (int)klen, key);
            /* And emailAddress as IA5String, which is 7-bit. */
            if (rdn_fields[i].off == offsetof(CertName, email)) {
                for (size_t j = 0; j < vlen; ++j) {
                    if ((unsigned char)val[j] >= 0x80)
                        return WOLFCERT_ERR(WOLFCERT_ERR_BAD_ARG, "csr",
                            "subject %.*s is not an IA5String", (int)klen, key);
                }
            }
            memcpy(dst, val, vlen);
            dst[vlen] = '\0';
            return WOLFCERT_OK;
        }
    }
    return WOLFCERT_ERR_UNSUPPORTED;
}

static const char* trim_ws(const char* s, const char* end, size_t* out_len)
{
    while (s < end && isspace((unsigned char)*s))
        ++s;
    while (end > s && isspace((unsigned char)end[-1]))
        --end;
    *out_len = (size_t)(end - s);
    return s;
}

/* Subject DNs are "CN=dev,O=Acme" strings; values containing ',' need
 * WolfCertCertMeta::customize. */
static int parse_subject_dn(const char* dn, CertName* subject)
{
    if (dn == NULL)
        return WOLFCERT_OK;

    const char* p = dn;
    const char* end = dn + strlen(dn);

    while (p < end) {
        const char* comma = memchr(p, ',', (size_t)(end - p));
        const char* pair_end = comma ? comma : end;
        const char* eq = memchr(p, '=', (size_t)(pair_end - p));
        if (eq == NULL)
            return WOLFCERT_ERR_PARSE;

        size_t klen, vlen;
        const char* k = trim_ws(p, eq, &klen);
        const char* v = trim_ws(eq + 1, pair_end, &vlen);
        if (klen == 0 || vlen == 0)
            return WOLFCERT_ERR_PARSE;

        int rc = assign_rdn(subject, k, klen, v, vlen);
        if (rc != WOLFCERT_OK)
            return rc;

        if (comma == NULL)
            break;
        p = comma + 1;
    }
    return WOLFCERT_OK;
}

static int build_san_seq(const WolfCertCertMeta* meta, Cert* cert, void* heap)
{
    DNS_entry* list = NULL;
    int rc = 0;

    for (size_t i = 0; i < meta->san_dns_len && rc == 0; ++i) {
        rc = wc_SetDNSEntry(heap, meta->san_dns[i],
                            (int)strlen(meta->san_dns[i]), ASN_DNS_TYPE, &list);
    }

    for (size_t i = 0; i < meta->san_uri_len && rc == 0; ++i) {
        rc = wc_SetDNSEntry(heap, meta->san_uri[i],
                            (int)strlen(meta->san_uri[i]), ASN_URI_TYPE, &list);
    }

    for (size_t i = 0; i < meta->san_email_len && rc == 0; ++i) {
        rc = wc_SetDNSEntry(heap, meta->san_email[i],
                            (int)strlen(meta->san_email[i]), ASN_RFC822_TYPE,
                            &list);
    }

    for (size_t i = 0; i < meta->san_ip_len && rc == 0; ++i) {
        uint8_t ipbuf[16];
        size_t iplen = 0;
        int erc = wolfcert_parse_ip(meta->san_ip[i], ipbuf, &iplen);
        if (erc != WOLFCERT_OK) {
            FreeAltNames(list, heap);
            return erc;
        }
        rc = wc_SetDNSEntry(heap, (const char*)ipbuf, (int)iplen, ASN_IP_TYPE,
                            &list);
    }

    if (rc != 0) {
        FreeAltNames(list, heap);
        return WOLFCERT_ERR_WC(rc, "csr", "SetDNSEntry");
    }

    rc = wc_SetAltNamesFromList(cert, list);

    FreeAltNames(list, heap);
    if (rc != 0)
        return WOLFCERT_ERR_WC(rc, "csr", "SetAltNamesFromList");
    return WOLFCERT_OK;
}

/* RFC 5480 pairs P-256, P-384 and P-521 with SHA-256, SHA-384 and SHA-512. */
#ifdef WOLFCERT_HAVE_ECC
static int ecdsa_sig_for_curve(int curve_id)
{
    switch (curve_id) {
#ifdef WOLFSSL_SHA384
        case ECC_SECP384R1:
            return CTC_SHA384wECDSA;
#endif
#ifdef WOLFSSL_SHA512
        case ECC_SECP521R1:
            return CTC_SHA512wECDSA;
#elif defined(WOLFSSL_SHA384)
        case ECC_SECP521R1:
            return CTC_SHA384wECDSA;
#endif
        case ECC_SECP256R1:
        default:
            return CTC_SHA256wECDSA;
    }
}
#endif

/* CTC_* signature type for a hash size in bits, or 0 when the key's family
 * or the wolfSSL build has no such hash. */
static int sig_type_for_hash(WolfCertKeyType type, int preferred_hash)
{
#ifdef WOLFCERT_HAVE_RSA
    if (type == WOLFCERT_KEY_RSA) {
        switch (preferred_hash) {
            case 256:
                return CTC_SHA256wRSA;
#ifdef WOLFSSL_SHA384
            case 384:
                return CTC_SHA384wRSA;
#endif
#ifdef WOLFSSL_SHA512
            case 512:
                return CTC_SHA512wRSA;
#endif
            default:
                return 0;
        }
    }
#endif
#ifdef WOLFCERT_HAVE_ECC
    if (type == WOLFCERT_KEY_ECC) {
        switch (preferred_hash) {
            case 256:
                return CTC_SHA256wECDSA;
#ifdef WOLFSSL_SHA384
            case 384:
                return CTC_SHA384wECDSA;
#endif
#ifdef WOLFSSL_SHA512
            case 512:
                return CTC_SHA512wECDSA;
#endif
            default:
                return 0;
        }
    }
#endif
    (void)type;
    (void)preferred_hash;
    return 0;
}

static int choose_sig_type(const WolfCertKey* key, const WolfCertKeyAlg* alg,
                           const WolfCertCertMeta* meta)
{
    if (meta != NULL && meta->preferred_hash != 0) {
        int sig = sig_type_for_hash(key->type, meta->preferred_hash);
        if (sig != 0)
            return sig;
    }

#ifdef WOLFCERT_HAVE_ECC
    if (key->type == WOLFCERT_KEY_ECC)
        return ecdsa_sig_for_curve(key->curve_id);
#endif

    return alg->ctc_sig_default;
}

/* Copy renew_cert's Subject and SAN into cert */
static int copy_cert_identity(Cert* cert, const uint8_t* renew_cert,
                              size_t renew_cert_len, void* heap)
{
    WolfCertBuffer pem_der = { 0 };
    const uint8_t* der = renew_cert;
    size_t der_len = renew_cert_len;
    DecodedCert* dc = NULL;
    const byte* san = NULL;
    word32 san_len = 0;
    int rc = WOLFCERT_OK;
    int wrc;

    if (!wolfcert_buffer_is_der(renew_cert, renew_cert_len)) {
        rc = wolfcert_pem_cert_to_der(renew_cert, renew_cert_len, &pem_der,
                                      heap);
        if (rc == WOLFCERT_ERR_PARSE)
            rc = WOLFCERT_ERR(WOLFCERT_ERR_PARSE, "csr",
                              "certificate being renewed is not PEM or DER");
        der = pem_der.data;
        der_len = pem_der.len;
    }

    if (rc == WOLFCERT_OK) {
        dc = (DecodedCert*)WOLFCERT_XMALLOC(sizeof(*dc), heap);
        if (dc == NULL)
            rc = WOLFCERT_ERR_MEMORY;
    }
    if (rc == WOLFCERT_OK) {
        wc_InitDecodedCert(dc, der, (word32)der_len, heap);
        wrc = wc_ParseCert(dc, CERT_TYPE, NO_VERIFY, NULL);
        /* Only the identity is read; an unknown critical extension is fine */
        if (wrc != 0 && wrc != ASN_CRIT_EXT_E)
            rc = WOLFCERT_ERR(WOLFCERT_ERR_PARSE, "csr",
                              "certificate being renewed does not parse (%d)",
                              wrc);
    }

    /* Leave an empty Name blank; copy any other into sbjRaw if NUL-free */
    if (rc == WOLFCERT_OK && dc->subjectRaw != NULL &&
            dc->subjectRawLen == 0) {
        memset(&cert->subject, 0, sizeof(cert->subject));
        cert->sbjRaw[0] = '\0';
    }
    else if (rc == WOLFCERT_OK &&
            (dc->subjectRaw == NULL || dc->subjectRawLen <= 0 ||
             dc->subjectRawLen >= (int)sizeof(cert->sbjRaw) ||
             memchr(dc->subjectRaw, 0x00, (size_t)dc->subjectRawLen) != NULL)) {
        rc = WOLFCERT_ERR(WOLFCERT_ERR_UNSUPPORTED, "csr",
                          "certificate subject cannot be carried into a CSR");
    }
    else if (rc == WOLFCERT_OK) {
        memcpy(cert->sbjRaw, dc->subjectRaw, (size_t)dc->subjectRawLen);
        cert->sbjRaw[dc->subjectRawLen] = '\0';
    }

    if (rc == WOLFCERT_OK &&
            wolfcert_find_san(dc, &san, &san_len) != WOLFCERT_OK)
        rc = WOLFCERT_ERR(WOLFCERT_ERR_PARSE, "csr",
                          "certificate extensions do not parse");
    if (rc == WOLFCERT_OK && san_len > sizeof(cert->altNames))
        rc = WOLFCERT_ERR(WOLFCERT_ERR_UNSUPPORTED, "csr",
                          "certificate SAN is %u bytes, limit %zu",
                          (unsigned)san_len, sizeof(cert->altNames));
    if (rc == WOLFCERT_OK) {
        if (san != NULL)
            memcpy(cert->altNames, san, san_len);
        cert->altNamesSz = (int)san_len;
        cert->altNamesCrit = dc->extSubjAltNameCrit;
    }

    if (dc != NULL) {
        wc_FreeDecodedCert(dc);
        WOLFCERT_XFREE(dc, heap);
    }
    wolfcert_buffer_free(&pem_der);
    return rc;
}

int wolfcert_csr_meta_sets_identity(const WolfCertCertMeta* meta)
{
    return meta->subject_dn != NULL || meta->san_dns_len != 0 ||
           meta->san_ip_len != 0 || meta->san_uri_len != 0 ||
           meta->san_email_len != 0;
}

int wolfcert_csr_build(const WolfCertKey* key, const WolfCertCertMeta* meta,
                       WolfCertBuffer* out_der)
{
    return wolfcert_csr_build_ex(key, meta, NULL, 0, out_der);
}

int wolfcert_csr_build_ex(const WolfCertKey* key, const WolfCertCertMeta* meta,
                          const uint8_t* renew_cert, size_t renew_cert_len,
                          WolfCertBuffer* out_der)
{
    if (key == NULL || meta == NULL || out_der == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    if (renew_cert != NULL && wolfcert_csr_meta_sets_identity(meta))
        return WOLFCERT_ERR(WOLFCERT_ERR_BAD_ARG, "csr",
            "a renewal keeps the certificate's subject and SAN");

    void* heap = key->heap ? key->heap : wolfcert_default_heap();

    Cert* cert = wc_CertNew(heap);
    if (cert == NULL)
        return WOLFCERT_ERR_MEMORY;
    wc_InitCert_ex(cert, heap, key->dev_id);

    int rc = parse_subject_dn(meta->subject_dn, &cert->subject);
    if (rc != WOLFCERT_OK) {
        wc_CertFree(cert);
        return rc;
    }

    rc = build_san_seq(meta, cert, heap);
    if (rc != WOLFCERT_OK) {
        wc_CertFree(cert);
        return rc;
    }

    if (meta->challenge_password != NULL) {
        size_t cpl = strlen(meta->challenge_password);
        if (cpl >= sizeof(cert->challengePw)) {
            wc_CertFree(cert);
            return WOLFCERT_ERR(WOLFCERT_ERR_BAD_ARG, "csr",
                "challenge_password exceeds wolfSSL CTC_NAME_SIZE (%zu)",
                sizeof(cert->challengePw) - 1);
        }
        memcpy(cert->challengePw, meta->challenge_password, cpl);
        cert->challengePw[cpl] = '\0';
    }

    if (meta->key_usage != NULL) {
        int r = wc_SetKeyUsage(cert, meta->key_usage);
        if (r != 0) {
            wc_CertFree(cert);
            return WOLFCERT_ERR_WC(r, "csr", "SetKeyUsage");
        }
    }
    if (meta->extended_key_usage != NULL) {
        int r = wc_SetExtKeyUsage(cert, meta->extended_key_usage);
        if (r != 0) {
            wc_CertFree(cert);
            return WOLFCERT_ERR_WC(r, "csr", "SetExtKeyUsage");
        }
    }

    if (meta->customize != NULL) {
        int r = meta->customize((void*)cert, meta->customize_ctx);
        if (r != WOLFCERT_OK) {
            wc_CertFree(cert);
            return r;
        }
    }

    /* After customize, so the callback cannot change a renewal's identity */
    if (renew_cert != NULL) {
        rc = copy_cert_identity(cert, renew_cert, renew_cert_len, heap);
        if (rc != WOLFCERT_OK) {
            wc_CertFree(cert);
            return rc;
        }
    }

    const WolfCertKeyAlg* alg = wolfcert_key_alg(key->type);
    if (alg == NULL) {
        wc_CertFree(cert);
        return WOLFCERT_ERR_UNSUPPORTED;
    }
    cert->sigType = choose_sig_type(key, alg, meta);

    size_t der_cap = alg->der_cap_hint + 1024;
    if (key->type == WOLFCERT_KEY_RSA) {
        size_t bits = key->rsa_bits ? (size_t)key->rsa_bits : 4096;
        der_cap = bits + 2048;
    }
    der_cap += (size_t)cert->altNamesSz + strlen((const char*)cert->sbjRaw);
    uint8_t* der = (uint8_t*)WOLFCERT_XMALLOC(der_cap, heap);
    if (der == NULL) {
        wc_CertFree(cert);
        return WOLFCERT_ERR_MEMORY;
    }

    int body_sz = wc_MakeCertReq_ex(cert, der, (word32)der_cap,
                                    alg->wc_keytype_enum, key->impl);
    if (body_sz < 0) {
        WOLFCERT_XFREE(der, heap);
        wc_CertFree(cert);
        return WOLFCERT_ERR_WC(body_sz, "csr", "MakeCertReq_ex");
    }

    WC_RNG rng;
    int rrc = wc_InitRng_ex(&rng, heap, key->dev_id);
    if (rrc != 0) {
        WOLFCERT_XFREE(der, heap);
        wc_CertFree(cert);
        return WOLFCERT_ERR_WC(rrc, "csr", "InitRng");
    }

    int sig_sz = wc_SignCert_ex(body_sz, cert->sigType, der, (word32)der_cap,
                                alg->wc_keytype_enum, key->impl, &rng);

    wc_FreeRng(&rng);
    wc_CertFree(cert);
    if (sig_sz < 0) {
        WOLFCERT_XFREE(der, heap);
        return WOLFCERT_ERR_WC(sig_sz, "csr", "SignCert");
    }

    uint8_t* shrunk = (uint8_t*)WOLFCERT_XREALLOC(der, (size_t)sig_sz, heap);

    out_der->data = shrunk ? shrunk : der;
    out_der->len  = (size_t)sig_sz;
    out_der->heap = heap;

    return WOLFCERT_OK;
}

int wolfcert_csr_der_to_pem(const uint8_t* der, size_t der_len,
                            WolfCertBuffer* out_pem)
{
    if (der == NULL || der_len == 0 || out_pem == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    void* heap = wolfcert_default_heap();
    size_t cap = der_len * 2 + 256;
    uint8_t* buf = (uint8_t*)WOLFCERT_XMALLOC(cap, heap);
    if (buf == NULL)
        return WOLFCERT_ERR_MEMORY;

    int n = wc_DerToPem(der, (word32)der_len, buf, (word32)cap, CERTREQ_TYPE);
    if (n <= 0) {
        WOLFCERT_XFREE(buf, heap);
        return WOLFCERT_ERR_WC(n, "csr", "DerToPem");
    }

    out_pem->data = buf;
    out_pem->len = (size_t)n;
    out_pem->heap = heap;

    return WOLFCERT_OK;
}

int wolfcert_csr_pem_to_der(const uint8_t* pem, size_t pem_len,
                            WolfCertBuffer* out_der)
{
    if (pem == NULL || pem_len == 0 || out_der == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    void* heap = wolfcert_default_heap();
    DerBuffer* der = NULL;

    int rc = wc_PemToDer(pem, (long)pem_len, CERTREQ_TYPE, &der, NULL, NULL, NULL);
    if (rc != 0 || der == NULL) {
        if (der != NULL)
            wc_FreeDer(&der);
        return WOLFCERT_ERR_PARSE;
    }

    uint8_t* buf = (uint8_t*)WOLFCERT_XMALLOC(der->length, heap);
    if (buf == NULL) {
        wc_FreeDer(&der);
        return WOLFCERT_ERR_MEMORY;
    }

    memcpy(buf, der->buffer, der->length);
    out_der->data = buf;
    out_der->len = der->length;
    out_der->heap = heap;

    wc_FreeDer(&der);
    return WOLFCERT_OK;
}
