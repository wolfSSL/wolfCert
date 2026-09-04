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

#include <wolfcert/csr.h>
#include <wolfcert/errors.h>
#include "internal.h"
#include "key_algs.h"

#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#include <arpa/inet.h>
#include <ctype.h>
#include <stddef.h>
#include <string.h>

/* ---- Subject DN parsing ---------------------------------------------------
 *
 * Accepts a simple comma-separated DN string, e.g.
 *   "CN=device-1,O=Acme,OU=Devices,C=US"
 * Literal ',' or '=' inside an attribute value are not supported; callers
 * that need them should use WolfCertCertMeta::customize. */

static void copy_name(char* dst, size_t dst_cap, const char* src, size_t src_len)
{
    size_t n = src_len < dst_cap - 1 ? src_len : dst_cap - 1;
    memcpy(dst, src, n);
    dst[n] = '\0';
}

/* Subject-DN attribute table. Declared `static const` so it lives in .rodata
 * rather than being rebuilt on the stack on every call; `off` is the byte
 * offset of the target field within wolfSSL's CertName, so the actual
 * destination is computed per-call from the caller's `subject`. */
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
    /* Additional RDNs carried by wolfSSL's CertName beyond the common set
     * above. UID is common in device / factory
     * certs; postalCode and businessCategory show up in regulated-industry
     * profiles (e.g. EV cert issuance). */
    { "UID",              3,  offsetof(CertName, userId),     CTC_NAME_SIZE },
    { "userId",           6,  offsetof(CertName, userId),     CTC_NAME_SIZE },
    { "postalCode",       10, offsetof(CertName, postalCode), CTC_NAME_SIZE },
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
            copy_name((char*)subject + rdn_fields[i].off, rdn_fields[i].cap,
                      val, vlen);
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

/* ---- SAN encoder (into a bounded caller-supplied buffer) ------------------
 *
 * Builds a wolfSSL alt-name list with wc_SetDNSEntry() (which copies each
 * value) and encodes it into the GeneralNames SEQUENCE that Cert.altNames
 * expects via wc_FlattenAltNames(). wolfSSL owns all list allocation; the
 * list is released with FreeAltNames(). */

static int encode_ip(const char* s, uint8_t out[16], size_t* out_len)
{
    uint8_t buf4[4], buf16[16];

    if (inet_pton(AF_INET, s, buf4) == 1) {
        memcpy(out, buf4, 4);
        *out_len = 4;
        return WOLFCERT_OK;
    }

    if (inet_pton(AF_INET6, s, buf16) == 1) {
        memcpy(out, buf16, 16);
        *out_len = 16;
        return WOLFCERT_OK;
    }

    return WOLFCERT_ERR_PARSE;
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
        int erc = encode_ip(meta->san_ip[i], ipbuf, &iplen);
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

    /* Encode straight into cert->altNames / altNamesSz. A NULL list (no SAN
     * requested) sets altNamesSz to 0. */
    rc = wc_SetAltNamesFromList(cert, list);

    FreeAltNames(list, heap);
    if (rc != 0)
        return WOLFCERT_ERR_WC(rc, "csr", "SetAltNamesFromList");
    return WOLFCERT_OK;
}

/* ---- CSR build ------------------------------------------------------------ */

/* ECDSA hash is traditionally matched to the curve (RFC 5480): P-256 -> SHA-256,
 * P-384 -> SHA-384, P-521 -> SHA-512. Other algorithms use the sig type from
 * the dispatch table. */
#ifdef WOLFCERT_HAVE_ECC
static int ecdsa_sig_for_curve(int curve_id)
{
    switch (curve_id) {
        case ECC_SECP384R1:
            return CTC_SHA384wECDSA;
        case ECC_SECP521R1:
            return CTC_SHA512wECDSA;
        case ECC_SECP256R1:
        default:
            return CTC_SHA256wECDSA;
    }
}
#endif

/* Map a caller-requested hash size (in bits) onto wolfSSL's CTC_*
 * signature-type constants for the key's algorithm family. Returns 0
 * when the combination isn't supported - the caller then falls back
 * to the per-key default. Ed25519 / Ed448 / ML-DSA don't use a
 * separate hash so `preferred_hash` is ignored for them (they return
 * the algorithm's default). */
static int sig_type_for_hash(WolfCertKeyType type, int preferred_hash)
{
#ifdef WOLFCERT_HAVE_RSA
    if (type == WOLFCERT_KEY_RSA) {
        switch (preferred_hash) {
            case 256:
                return CTC_SHA256wRSA;
            case 384:
                return CTC_SHA384wRSA;
            case 512:
                return CTC_SHA512wRSA;
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
            case 384:
                return CTC_SHA384wECDSA;
            case 512:
                return CTC_SHA512wECDSA;
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
    /* Explicit hash override from the caller (or from
     * wolfcert_csr_attrs_apply of a server-pinned /csrattrs hint)
     * takes precedence, but only for algorithm families where the
     * hash is a meaningful choice. */
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

int wolfcert_csr_build(const WolfCertKey* key, const WolfCertCertMeta* meta,
                       WolfCertBuffer* out_der)
{
    if (key == NULL || meta == NULL || out_der == NULL)
        return WOLFCERT_ERR_BAD_ARG;

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

    /* SAN into cert->altNames[] (encoded directly by build_san_seq). */
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

    const WolfCertKeyAlg* alg = wolfcert_key_alg(key->type);
    if (alg == NULL) {
        wc_CertFree(cert);
        return WOLFCERT_ERR_UNSUPPORTED;
    }
    cert->sigType = choose_sig_type(key, alg, meta);

    /* Size the DER buffer: algorithm hint + RSA modulus head room. */
    size_t der_cap = alg->der_cap_hint + 1024;
    if (key->type == WOLFCERT_KEY_RSA) {
        size_t bits = key->rsa_bits ? (size_t)key->rsa_bits : 4096;
        der_cap = bits + 2048;
    }
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
