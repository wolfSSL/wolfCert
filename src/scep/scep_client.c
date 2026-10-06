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

#include <wolfcert/scep.h>
#include <wolfcert/http.h>
#include <wolfcert/errors.h>
#include "../internal.h"

#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/memory.h>
#ifndef NO_SHA
#include <wolfssl/wolfcrypt/sha.h>
#endif
#include <wolfssl/wolfcrypt/sha256.h>
#ifdef WOLFSSL_SHA512
#include <wolfssl/wolfcrypt/sha512.h>
#endif

#include <stdio.h>
#include <string.h>

static char* append_query(const char* base, const char* op, void* heap)
{
    size_t bl = strlen(base), ol = strlen(op);
    int has_q = (strchr(base, '?') != NULL);
    char* url = (char*)WOLFCERT_XMALLOC(bl + ol + 24, heap);
    if (url == NULL)
        return NULL;

    snprintf(url, bl + ol + 24, "%s%soperation=%s", base, has_q ? "&" : "?", op);

    return url;
}

/* RFC 8894 section 3.5.2: each GetCACaps line is one whole capability token. */
static int has_cap(const char* body, size_t len, const char* needle)
{
    size_t nl;
    size_t i = 0;

    if (body == NULL || needle == NULL)
        return 0;

    nl = strlen(needle);

    while (i < len) {
        size_t start = i;
        size_t tlen;

        while (i < len && body[i] != '\n')
            ++i;

        tlen = i - start;
        if (tlen > 0 && body[start + tlen - 1] == '\r')
            --tlen;

        if (tlen == nl && wolfcert_ascii_ncasecmp(body + start, needle, nl) == 0)
            return 1;

        if (i < len)
            ++i;
    }

    return 0;
}

void wolfcert_scep_result_free(WolfCertScepResult* r)
{
    if (r == NULL)
        return;

    wolfcert_buffer_free(&r->cert_pem);
    WOLFCERT_XFREE(r->transaction_id, r->heap);

    r->transaction_id     = NULL;
    r->transaction_id_len = 0;
    r->fail_info          = -1;
}

int wolfcert_scep_verify_ca_fingerprint(const uint8_t* ca_der, size_t ca_der_len,
                                        const uint8_t* expected, size_t expected_len,
                                        WolfCertScepFpAlg alg)
{
    uint8_t digest[64];
    size_t  digest_len = 0;
    int     rc = 0;

    if (ca_der == NULL || ca_der_len == 0 || expected == NULL || expected_len == 0)
        return WOLFCERT_ERR_BAD_ARG;

    /* AUTO picks the digest from the fingerprint length. */
    if (alg == WOLFCERT_SCEP_FP_AUTO) {
        switch (expected_len) {
            case 20: alg = WOLFCERT_SCEP_FP_SHA1;   break;
            case 32: alg = WOLFCERT_SCEP_FP_SHA256; break;
            case 64: alg = WOLFCERT_SCEP_FP_SHA512; break;
            default:
                return WOLFCERT_ERR(WOLFCERT_ERR_BAD_ARG, "scep",
                    "fingerprint length does not match SHA-1/SHA-256/SHA-512");
        }
    }

    switch (alg) {
        case WOLFCERT_SCEP_FP_SHA256:
            digest_len = WC_SHA256_DIGEST_SIZE;
            rc = wc_Sha256Hash(ca_der, (word32)ca_der_len, digest);
            break;
#ifndef NO_SHA
        case WOLFCERT_SCEP_FP_SHA1:
            digest_len = WC_SHA_DIGEST_SIZE;
            rc = wc_ShaHash(ca_der, (word32)ca_der_len, digest);
            break;
#endif
#ifdef WOLFSSL_SHA512
        case WOLFCERT_SCEP_FP_SHA512:
            digest_len = WC_SHA512_DIGEST_SIZE;
            rc = wc_Sha512Hash(ca_der, (word32)ca_der_len, digest);
            break;
#endif
        default:
            return WOLFCERT_ERR(WOLFCERT_ERR_UNSUPPORTED, "scep",
                "requested fingerprint digest is not compiled into wolfSSL");
    }

    if (rc != 0)
        return WOLFCERT_ERR_WC(rc, "scep", "fingerprint hash");

    if (expected_len != digest_len)
        return WOLFCERT_ERR(WOLFCERT_ERR_BAD_ARG, "scep",
            "expected fingerprint length does not match the digest size");

    if (wc_ConstantCompare(expected, digest, (int)digest_len) != 0)
        return WOLFCERT_ERR(WOLFCERT_ERR_AUTH, "scep",
            "CA certificate fingerprint mismatch");

    return WOLFCERT_OK;
}

WOLFCERT_TEST_VIS int wolfcert_scep_pick_hash_oid(const WolfCertScepCaps* caps,
                                                  WolfCertScepSigningHash want)
{
    switch (want) {
        case WOLFCERT_SCEP_HASH_SHA256:
            return SHA256h;
        case WOLFCERT_SCEP_HASH_SHA384:
#ifdef WOLFSSL_SHA384
            return SHA384h;
#else
            return WOLFCERT_ERR(WOLFCERT_ERR_UNSUPPORTED, "scep",
                "SHA-384 signing hash requested but wolfSSL lacks it");
#endif
        case WOLFCERT_SCEP_HASH_SHA512:
#ifdef WOLFSSL_SHA512
            return SHA512h;
#else
            return WOLFCERT_ERR(WOLFCERT_ERR_UNSUPPORTED, "scep",
                "SHA-512 signing hash requested but wolfSSL lacks it");
#endif
        case WOLFCERT_SCEP_HASH_AUTO:
        default:
            break;
    }

    if (caps == NULL)
        return SHA256h;
#ifdef WOLFSSL_SHA512
    if (caps->sha512)
        return SHA512h;
#endif
#ifdef WOLFSSL_SHA384
    if (caps->sha384)
        return SHA384h;
#endif

    return SHA256h;
}

/* Percent-encode every byte outside the RFC 3986 unreserved set. */
static char* url_encode(const uint8_t* in, size_t in_len, void* heap)
{
    char* out = (char*)WOLFCERT_XMALLOC(in_len * 3 + 1, heap);
    if (out == NULL)
        return NULL;

    size_t o = 0;
    for (size_t i = 0; i < in_len; ++i) {
        unsigned char c = in[i];
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') ||
            c == '-' || c == '_' || c == '.' || c == '~') {
            out[o++] = (char)c;
        }
        else {
            out[o++] = '%';
            /* RFC 3986 section 2.1: upper-case hex is the normal form. */
            wolfcert_hex_encode(&c, 1, 1, &out[o]);
            o += 2;
        }
    }
    out[o] = '\0';

    return out;
}

WOLFCERT_TEST_VIS char* wolfcert_scep_build_getca_url(const char* base,
    const char* op, const char* ca_id, void* heap)
{
    char* head = append_query(base, op, heap);
    if (head == NULL)
        return NULL;

    /* GetCACaps, GetCACert and GetNextCACert may omit the CA identifier. */
    if (ca_id == NULL || ca_id[0] == '\0')
        return head;

    char* enc = url_encode((const uint8_t*)ca_id, strlen(ca_id), heap);
    if (enc == NULL) {
        WOLFCERT_XFREE(head, heap);
        return NULL;
    }

    size_t need = strlen(head) + strlen("&message=") + strlen(enc) + 1;
    char* url = (char*)WOLFCERT_XMALLOC(need, heap);
    if (url == NULL) {
        WOLFCERT_XFREE(head, heap);
        WOLFCERT_XFREE(enc, heap);
        return NULL;
    }
    snprintf(url, need, "%s&message=%s", head, enc);

    WOLFCERT_XFREE(head, heap);
    WOLFCERT_XFREE(enc, heap);
    return url;
}

/* PKIOperation GET URL (RFC 8894 section 4.1); WOLFCERT_ERR_UNSUPPORTED when
 * it would exceed WOLFCERT_SCEP_MAX_GET_URL. */
WOLFCERT_TEST_VIS int wolfcert_scep_build_pki_get_url(const char* base,
                             const uint8_t* pki_msg,
                             size_t pki_len, void* heap, char** out_url)
{
    WolfCertBuffer b64 = { 0 };
    int rc = wolfcert_base64_encode(pki_msg, pki_len, &b64, heap);
    if (rc != WOLFCERT_OK)
        return rc;

    char* enc = url_encode(b64.data, b64.len, heap);
    wolfcert_buffer_free(&b64);
    if (enc == NULL)
        return WOLFCERT_ERR_MEMORY;

    char* head = append_query(base, "PKIOperation", heap);
    if (head == NULL) {
        WOLFCERT_XFREE(enc, heap);
        return WOLFCERT_ERR_MEMORY;
    }

    size_t need = strlen(head) + strlen("&message=") + strlen(enc) + 1;
    if (need > WOLFCERT_SCEP_MAX_GET_URL) {
        WOLFCERT_XFREE(enc, heap);
        WOLFCERT_XFREE(head, heap);
        return WOLFCERT_ERR(WOLFCERT_ERR_UNSUPPORTED, "scep",
            "pkiMessage too large for an HTTP GET; the CA must advertise "
            "POSTPKIOperation");
    }

    char* url = (char*)WOLFCERT_XMALLOC(need, heap);
    if (url == NULL) {
        WOLFCERT_XFREE(enc, heap);
        WOLFCERT_XFREE(head, heap);
        return WOLFCERT_ERR_MEMORY;
    }
    snprintf(url, need, "%s&message=%s", head, enc);

    WOLFCERT_XFREE(enc, heap);
    WOLFCERT_XFREE(head, heap);
    *out_url = url;

    return WOLFCERT_OK;
}

/* RFC 8894 section 4.1: POST when the CA advertises POSTPKIOperation or the
 * caps are unknown, otherwise GET with the message in the query. */
static int scep_build_transport(const char* server_url, const WolfCertScepCaps* caps,
                                const uint8_t* pki_msg, size_t pki_len, void* heap,
                                char** out_url, int* out_use_post)
{
    int use_post = (caps == NULL || caps->post_pki_operation);
    *out_use_post = use_post;

    if (use_post) {
        char* url = append_query(server_url, "PKIOperation", heap);
        if (url == NULL)
            return WOLFCERT_ERR_MEMORY;
        *out_url = url;
        return WOLFCERT_OK;
    }

    return wolfcert_scep_build_pki_get_url(server_url, pki_msg, pki_len, heap,
                                           out_url);
}

/* PKCSReq (19) serves CAs that predate RenewalReq (17); either way the signer
 * is the cert being replaced. */
static const char* scep_renewal_msg_type(WolfCertScepRenewalMsgType m)
{
    return (m == WOLFCERT_SCEP_RENEWAL_MSG_PKCS_REQ) ? "19" : "17";
}

#define SCEP_TXID_RAND_SZ 16

typedef struct {
    const uint8_t*       id;      /* explicit transactionID, or NULL to derive */
    size_t               id_len;
    WolfCertScepTxidMode mode;    /* derivation used when `id` is NULL */
} ScepTxidSel;

/* transactionID from the signer key, derived as wolfSCEP does: SHA-256 over
 * DecodedCert.publicKey in upper-case hex. */
static int derive_txid_pubkey(const uint8_t* signer_cert, size_t signer_cert_len,
                              uint8_t** out_txid, size_t* out_txid_len, void* heap)
{
    /* DecodedCert is too large for an MCU task stack. */
    DecodedCert* dc = (DecodedCert*)WOLFCERT_XMALLOC(sizeof(*dc), heap);
    if (dc == NULL)
        return WOLFCERT_ERR_MEMORY;

    wc_InitDecodedCert(dc, signer_cert, (word32)signer_cert_len, heap);
    int rc = wc_ParseCert(dc, CERT_TYPE, NO_VERIFY, NULL);
    if (rc != 0) {
        wc_FreeDecodedCert(dc);
        WOLFCERT_XFREE(dc, heap);
        return WOLFCERT_ERR_WC(rc, "scep", "parse signer cert for transactionID");
    }

    uint8_t digest[WC_SHA256_DIGEST_SIZE];
    rc = wc_Sha256Hash(dc->publicKey, dc->pubKeySize, digest);
    wc_FreeDecodedCert(dc);
    WOLFCERT_XFREE(dc, heap);
    if (rc != 0)
        return WOLFCERT_ERR_WC(rc, "scep", "hash signer public key");

    size_t hexlen = WC_SHA256_DIGEST_SIZE * 2;
    uint8_t* txid = (uint8_t*)WOLFCERT_XMALLOC(hexlen, heap);
    if (txid == NULL)
        return WOLFCERT_ERR_MEMORY;

    wolfcert_hex_encode(digest, WC_SHA256_DIGEST_SIZE, 1, (char*)txid);
    *out_txid     = txid;
    *out_txid_len = hexlen;
    return WOLFCERT_OK;
}

/* Copy the inherited ID, derive it from the signer key, or pick at random. */
static int scep_build_txid(const ScepTxidSel* sel,
                           const uint8_t* signer_cert, size_t signer_cert_len,
                           WC_RNG* rng, void* heap,
                           uint8_t** out_txid, size_t* out_txid_len)
{
    if (sel->id != NULL) {
        uint8_t* txid = (uint8_t*)WOLFCERT_XMALLOC(sel->id_len, heap);
        if (txid == NULL)
            return WOLFCERT_ERR_MEMORY;

        memcpy(txid, sel->id, sel->id_len);
        *out_txid     = txid;
        *out_txid_len = sel->id_len;
        return WOLFCERT_OK;
    }

    if (sel->mode == WOLFCERT_SCEP_TXID_PUBKEY_HASH)
        return derive_txid_pubkey(signer_cert, signer_cert_len,
                                  out_txid, out_txid_len, heap);

    uint8_t rand_bytes[SCEP_TXID_RAND_SZ];
    int rng_rc = wc_RNG_GenerateBlock(rng, rand_bytes, sizeof(rand_bytes));
    if (rng_rc != 0) {
        wc_ForceZero(rand_bytes, (word32)sizeof(rand_bytes));
        return WOLFCERT_ERR_WC(rng_rc, "scep",
                               "RNG failed generating transactionID");
    }

    size_t hexlen = sizeof(rand_bytes) * 2;
    uint8_t* txid = (uint8_t*)WOLFCERT_XMALLOC(hexlen, heap);
    if (txid != NULL)
        wolfcert_hex_encode(rand_bytes, sizeof(rand_bytes), 0, (char*)txid);

    wc_ForceZero(rand_bytes, (word32)sizeof(rand_bytes));
    if (txid == NULL)
        return WOLFCERT_ERR_MEMORY;

    *out_txid     = txid;
    *out_txid_len = hexlen;
    return WOLFCERT_OK;
}

WOLFCERT_TEST_VIS int wolfcert_scep_pem_has_cert(const uint8_t* pem, size_t pem_len,
                                     const uint8_t* issuer, size_t issuer_len,
                                     const uint8_t* serial, size_t serial_len,
                                     void* heap)
{
    static const char BEGIN[] = "-----BEGIN CERTIFICATE-----";
    const size_t blen = sizeof(BEGIN) - 1;
    DecodedCert* dc;
    const char* p;
    const char* end;
    int match = 0;

    if (pem == NULL || issuer == NULL || serial == NULL || pem_len < blen)
        return 0;

    dc = (DecodedCert*)WOLFCERT_XMALLOC(sizeof(*dc), heap);
    if (dc == NULL)
        return WOLFCERT_ERR(WOLFCERT_ERR_MEMORY, "scep",
            "GetCert: cannot allocate a DecodedCert");

    p   = (const char*)pem;
    end = p + pem_len;

    /* Compare the remaining length: p + blen would run past the buffer. */
    while (match == 0 && (size_t)(end - p) >= blen) {
        WolfCertBuffer der = { 0 };
        int rc;

        if (memcmp(p, BEGIN, blen) != 0) {
            p++;
            continue;
        }

        /* A bad entry must not end the search: the target may sit behind it. */
        rc = wolfcert_pem_cert_to_der((const uint8_t*)p, (size_t)(end - p),
                                      &der, heap);
        if (rc == WOLFCERT_ERR_MEMORY) {
            match = WOLFCERT_ERR(WOLFCERT_ERR_MEMORY, "scep",
                "GetCert: out of memory decoding a certificate");
        }
        else if (rc == WOLFCERT_OK) {
            wc_InitDecodedCert(dc, der.data, (word32)der.len, heap);
            rc = wc_ParseCert(dc, CERT_TYPE, NO_VERIFY, NULL);
            if (rc == MEMORY_E) {
                match = WOLFCERT_ERR(WOLFCERT_ERR_MEMORY, "scep",
                    "GetCert: out of memory parsing a certificate");
            }
            else if (rc == 0) {
                match = dc->serialSz > 0 &&
                        (size_t)dc->serialSz == serial_len &&
                        memcmp(dc->serial, serial, serial_len) == 0 &&
                        dc->issuerRaw != NULL && dc->issuerRawLen > 0 &&
                        (size_t)dc->issuerRawLen == issuer_len &&
                        memcmp(dc->issuerRaw, issuer, issuer_len) == 0;
            }
            wc_FreeDecodedCert(dc);
        }

        wolfcert_buffer_free(&der);
        p += blen;
    }

    WOLFCERT_XFREE(dc, heap);
    return match;
}

/* GetCACaps reply into *out (RFC 8894 section 3.5.2). */
static void scep_finish_caps(const WolfCertHttpResponse* resp,
                             WolfCertScepCaps* out)
{
    const char* b = (const char*)resp->body;

    out->post_pki_operation = has_cap(b, resp->body_len, "POSTPKIOperation");
    out->renewal            = has_cap(b, resp->body_len, "Renewal");
    out->sha256             = has_cap(b, resp->body_len, "SHA-256");
    out->sha384             = has_cap(b, resp->body_len, "SHA-384");
    out->sha512             = has_cap(b, resp->body_len, "SHA-512");
    out->aes                = has_cap(b, resp->body_len, "AES");
    out->scep_standard      = has_cap(b, resp->body_len, "SCEPStandard");
    out->get_next_ca_cert   = has_cap(b, resp->body_len, "GetNextCACert");

    /* RFC 8894 section 3.5.2, Table 7 */
    if (out->scep_standard) {
        out->post_pki_operation = 1;
        out->aes                = 1;
        out->sha256             = 1;
    }
}

/* GetCACert reply into *out_ca: a certs-only PKCS#7, or one raw DER cert. */
static int scep_finish_ca_cert(const WolfCertHttpResponse* resp,
                               WolfCertEncoding enc, WolfCertBuffer* out_ca,
                               void* heap)
{
    static const char ca_ra_type[] = "application/x-x509-ca-ra-cert";
    const char* p;
    uint8_t* buf;
    size_t cap;
    size_t len;
    int is_p7 = 0;
    int n;

    if (resp->body_len == 0)
        return WOLFCERT_ERR(WOLFCERT_ERR_HTTP, "scep",
            "GetCACert: 200 response carried no certificate");

    /* Media types compare case-insensitively; ';' parameters are ignored. */
    if (resp->content_type != NULL &&
            wolfcert_ascii_ncasecmp(resp->content_type, ca_ra_type,
                                    sizeof(ca_ra_type) - 1) == 0) {
        p = resp->content_type + sizeof(ca_ra_type) - 1;
        while (*p == ' ' || *p == '\t')
            ++p;
        is_p7 = (*p == '\0' || *p == ';');
    }
    if (!is_p7)
        is_p7 = wolfcert_scep_is_signed_data(resp->body, resp->body_len);

    if (is_p7 && enc == WOLFCERT_ENCODING_DER)
        return wolfcert_pkcs7_certs_to_der(resp->body, resp->body_len, out_ca,
                                           heap);
    if (is_p7)
        return wolfcert_pkcs7_certs_to_pem(resp->body, resp->body_len, out_ca,
                                           heap);

    cap = (enc == WOLFCERT_ENCODING_DER) ? resp->body_len
                                         : resp->body_len * 2 + 256;
    buf = (uint8_t*)WOLFCERT_XMALLOC(cap, heap);
    if (buf == NULL)
        return WOLFCERT_ERR_MEMORY;

    if (enc == WOLFCERT_ENCODING_DER) {
        memcpy(buf, resp->body, resp->body_len);
        len = resp->body_len;
    }
    else {
        n = wc_DerToPem(resp->body, (word32)resp->body_len, buf, (word32)cap,
                        CERT_TYPE);
        if (n <= 0) {
            WOLFCERT_XFREE(buf, heap);
            return WOLFCERT_ERR_CRYPTO;
        }
        len = (size_t)n;
    }

    out_ca->data = buf;
    out_ca->len  = len;
    out_ca->heap = heap;
    return WOLFCERT_OK;
}

enum scep_session_op {
    SCEP_OP_GET_CA_CAPS,
    SCEP_OP_GET_CA_CERT,
    SCEP_OP_GET_NEXT_CA_CERT,
    /* The PKIOperations, from here to the end. */
    SCEP_OP_PKCS_REQ,
    SCEP_OP_RENEWAL,
    SCEP_OP_GET_CERT_INITIAL,
    SCEP_OP_GET_CERT
};

/* The arguments of one SCEP call. cert is the signer or the cert being
 * renewed, ca_bundle the current CA for GetNextCACert; one output is set. */
typedef struct {
    const WolfCertScepCaps* caps;
    const uint8_t*          ra_cert;
    size_t                  ra_cert_len;
    const uint8_t*          ca_bundle;
    size_t                  ca_bundle_len;
    const uint8_t*          cert;
    size_t                  cert_len;
    const WolfCertKey*      key;
    const uint8_t*          csr;
    size_t                  csr_len;
    const uint8_t*          txid;
    size_t                  txid_len;
    const uint8_t*          serial;
    size_t                  serial_len;
    WolfCertScepCaps*       caps_out;
    WolfCertBuffer*         buf_out;
    WolfCertScepResult*     res_out;
    enum scep_session_op    op;
    WolfCertEncoding        enc;
} ScepCall;

static const void* scep_call_out(const ScepCall* c)
{
    if (c->res_out != NULL)
        return c->res_out;
    if (c->buf_out != NULL)
        return c->buf_out;
    return c->caps_out;
}

static int scep_call_check(const ScepCall* c)
{
    int pki = c->op >= SCEP_OP_PKCS_REQ;
    int ok;

    switch (c->op) {
        case SCEP_OP_GET_CA_CAPS:
            ok = c->caps_out != NULL;
            break;
        case SCEP_OP_GET_CA_CERT:
            ok = c->buf_out != NULL &&
                 (c->enc == WOLFCERT_ENCODING_PEM ||
                  c->enc == WOLFCERT_ENCODING_DER);
            break;
        case SCEP_OP_GET_NEXT_CA_CERT:
            ok = c->buf_out != NULL && c->ca_bundle != NULL &&
                 c->ca_bundle_len > 0 &&
                 (c->enc == WOLFCERT_ENCODING_PEM ||
                  c->enc == WOLFCERT_ENCODING_DER);
            break;
        case SCEP_OP_PKCS_REQ:
            ok = c->csr != NULL && c->csr_len > 0;
            break;
        case SCEP_OP_RENEWAL:
            ok = c->cert != NULL && c->cert_len > 0 &&
                 c->csr != NULL && c->csr_len > 0;
            break;
        case SCEP_OP_GET_CERT_INITIAL:
            ok = (c->cert == NULL || c->cert_len > 0) &&
                 c->csr != NULL && c->csr_len > 0 &&
                 c->txid != NULL && c->txid_len > 0 &&
                 wolfcert_is_printable_string(c->txid, c->txid_len);
            break;
        case SCEP_OP_GET_CERT:
            ok = c->cert != NULL && c->cert_len > 0 &&
                 c->serial != NULL && c->serial_len > 0;
            break;
        default:
            ok = 0;
            break;
    }

    if (ok && pki)
        ok = c->res_out != NULL && c->ra_cert != NULL && c->ra_cert_len > 0 &&
             c->ca_bundle != NULL && c->ca_bundle_len > 0 && c->key != NULL;
    if (!ok)
        return WOLFCERT_ERR_BAD_ARG;

    if (pki && c->key->type != WOLFCERT_KEY_RSA)
        return WOLFCERT_ERR(WOLFCERT_ERR_UNSUPPORTED, "scep",
            "SCEP (RFC 8894) requires an RSA signer for pkiMessage; "
            "Ed25519/Ed448/ML-DSA are not permitted");

    /* PKCS#7 takes the private key as DER, which a key_id key cannot give. */
    if (pki && c->key->id_len > 0)
        return WOLFCERT_ERR(WOLFCERT_ERR_UNSUPPORTED, "scep",
                            "SCEP cannot sign or decrypt with a key_id key");

    return WOLFCERT_OK;
}

struct WolfCertScepSession {
    WolfCertHttpSession*      http;
    char*                     server_url;     /* full SCEP endpoint URL, owned */
    void*                     heap;
    WolfCertScepTxidMode       txid_mode;
    WolfCertScepContentCipher  content_cipher;
    WolfCertScepRenewalMsgType renewal_msg_type;
    WolfCertScepSigningHash    signing_hash;
    char*                      ca_id;          /* owned copy, or NULL */

    /* In-flight state of the single active round trip. */
    int                  in_active;
    enum scep_session_op in_op;        /* valid when in_active */
    WolfCertEncoding     in_enc;
    char*                in_url;       /* owned request URL */
    WolfCertBuffer       in_pki;       /* built pkiMessage, owned (POST body) */
    WolfCertHttpRequest  in_req;
    WolfCertHttpResponse in_resp;

    const uint8_t* in_ca_bundle;  size_t in_ca_bundle_len;  /* in use */
    uint8_t*       in_ca_bundle_copy;  /* owned, for an _nb request */
    const uint8_t* in_signer;     size_t in_signer_len;     /* in use */
    uint8_t*       in_signer_copy;     /* owned: _nb copy or self-signed */
    uint8_t* in_signer_key;  size_t in_signer_key_len;   /* key DER, zeroized */
    uint8_t* in_txid;        size_t in_txid_len;         /* owned, from scep_prepare */
    uint8_t  in_nonce[SCEP_NONCE_SZ];
    WolfCertBuffer       in_ias;       /* IssuerAndSubject or IssuerAndSerial sent, owned */
    const void*          in_out;       /* caller's output, checked on resume */
};

static uint8_t* dup_buf(const uint8_t* src, size_t len, void* heap)
{
    if (src == NULL || len == 0)
        return NULL;
    uint8_t* p = (uint8_t*)WOLFCERT_XMALLOC(len, heap);
    if (p != NULL)
        memcpy(p, src, len);
    return p;
}

/* Check srv and set up a session that is not connected yet. */
static int scep_session_new(const WolfCertServerCfg* srv,
                            WolfCertScepSession** out)
{
    if (srv == NULL || srv->server_url == NULL || out == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    void* heap = srv->heap ? srv->heap : wolfcert_default_heap();

    /* The protocol check must precede every read of proto_opts.scep. */
    int rc = wolfcert_cfg_require_proto(srv, WOLFCERT_PROTO_SCEP, "scep");
    if (rc != WOLFCERT_OK)
        return rc;

    WolfCertUrl u;
    rc = wolfcert_http_url_parse(srv->server_url, &u, heap);
    if (rc != WOLFCERT_OK)
        return rc;

    int tls = u.tls;
    wolfcert_http_url_free(&u);
    if (tls && !srv->verify_server)
        return WOLFCERT_ERR(WOLFCERT_ERR_TLS, "scep",
            "TLS SCEP endpoint requires server authentication: set verify_server "
            "or use a plaintext http:// URL");

    WolfCertScepSession* s = (WolfCertScepSession*)WOLFCERT_XMALLOC(sizeof(*s), heap);
    if (s == NULL)
        return WOLFCERT_ERR_MEMORY;

    memset(s, 0, sizeof(*s));
    s->heap             = heap;
    s->txid_mode        = srv->proto_opts.scep.txid_mode;
    s->content_cipher   = srv->proto_opts.scep.content_cipher;
    s->renewal_msg_type = srv->proto_opts.scep.renewal_msg_type;
    s->signing_hash     = srv->proto_opts.scep.signing_hash;
    s->server_url       = wolfcert_strdup(srv->server_url, heap);
    if (srv->proto_opts.scep.ca_id != NULL)
        s->ca_id = wolfcert_strdup(srv->proto_opts.scep.ca_id, heap);
    if (s->server_url == NULL ||
        (srv->proto_opts.scep.ca_id != NULL && s->ca_id == NULL)) {
        wolfcert_scep_session_close(s);
        return WOLFCERT_ERR_MEMORY;
    }

    *out = s;
    return WOLFCERT_OK;
}

static int scep_session_connect(WolfCertScepSession* s,
                                const WolfCertServerCfg* srv)
{
    WolfCertHttpSessionCfg hcfg = {
        .base_url           = s->server_url,
        .trust_anchors      = srv->trust_anchors,
        .trust_anchors_len  = srv->trust_anchors_len,
        .verify_server      = srv->verify_server,
        .timeout_ms         = srv->timeout_ms,
        .max_response_bytes = srv->max_response_bytes,
        .client_cert        = srv->client_cert,
        .client_cert_len    = srv->client_cert_len,
        .client_key         = srv->client_key,
        .client_key_len     = srv->client_key_len,
        .client_key_src     = srv->client_key_src,
        .client_key_dev_id  = srv->client_key_dev_id,
        .transport          = srv->transport,
        .heap               = s->heap,
    };

    return wolfcert_http_session_open(&hcfg, &s->http);
}

int wolfcert_scep_session_open(const WolfCertServerCfg* srv, WolfCertScepSession** out)
{
    WolfCertScepSession* s = NULL;
    int rc;

    if (out == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    rc = scep_session_new(srv, &s);
    if (rc == WOLFCERT_OK)
        rc = scep_session_connect(s, srv);
    if (rc == WOLFCERT_OK)
        *out = s;
    else
        wolfcert_scep_session_close(s);
    return rc;
}

int wolfcert_scep_session_fd(const WolfCertScepSession* s)
{
    return s != NULL ? wolfcert_http_session_fd(s->http) : -1;
}

/* Free the request in flight; its response stays for the parse. */
static void scep_session_free_request(WolfCertScepSession* s)
{
    WOLFCERT_XFREE(s->in_url, s->heap);
    s->in_url = NULL;
    wolfcert_buffer_free(&s->in_pki);
    memset(&s->in_req, 0, sizeof(s->in_req));
}

static void scep_session_reset(WolfCertScepSession* s)
{
    scep_session_free_request(s);
    wolfcert_http_response_free(&s->in_resp);
    memset(&s->in_resp, 0, sizeof(s->in_resp));

    WOLFCERT_XFREE(s->in_ca_bundle_copy, s->heap);
    s->in_ca_bundle_copy = NULL;
    s->in_ca_bundle = NULL;
    s->in_ca_bundle_len = 0;
    WOLFCERT_XFREE(s->in_signer_copy, s->heap);
    s->in_signer_copy = NULL;
    s->in_signer = NULL;
    s->in_signer_len = 0;
    if (s->in_signer_key != NULL) {
        wc_ForceZero(s->in_signer_key, (word32)s->in_signer_key_len);
        WOLFCERT_XFREE(s->in_signer_key, s->heap);
        s->in_signer_key = NULL;
    }
    s->in_signer_key_len = 0;
    WOLFCERT_XFREE(s->in_txid, s->heap);
    s->in_txid = NULL;
    s->in_txid_len = 0;
    wc_ForceZero(s->in_nonce, (word32)sizeof(s->in_nonce));
    wolfcert_buffer_free(&s->in_ias);
    s->in_out    = NULL;
    s->in_active = 0;
}

void wolfcert_scep_session_close(WolfCertScepSession* s)
{
    if (s == NULL)
        return;

    scep_session_reset(s);
    if (s->http)
        wolfcert_http_session_close(s->http);

    WOLFCERT_XFREE(s->server_url, s->heap);
    WOLFCERT_XFREE(s->ca_id, s->heap);
    WOLFCERT_XFREE(s, s->heap);
}

/* Clear the caller's output, unless it is the in-flight request's. */
static void scep_call_clear(const WolfCertScepSession* s, const ScepCall* c)
{
    if (s != NULL && s->in_active && scep_call_out(c) == s->in_out)
        return;

    if (c->res_out != NULL) {
        memset(c->res_out, 0, sizeof(*c->res_out));
        c->res_out->fail_info = -1;
    }
    if (c->caps_out != NULL)
        memset(c->caps_out, 0, sizeof(*c->caps_out));
    if (c->buf_out != NULL)
        memset(c->buf_out, 0, sizeof(*c->buf_out));
}

/* Put c's request in flight; url passes to s. post sends s->in_pki. */
static void scep_session_start(WolfCertScepSession* s, const ScepCall* c,
                               char* url, int post)
{
    s->in_url = url;
    s->in_req = (WolfCertHttpRequest){
        .method = post ? "POST" : "GET",
        .url    = url,
        .heap   = s->heap,
    };
    if (post) {
        s->in_req.content_type = "application/x-pki-message";
        s->in_req.body         = s->in_pki.data;
        s->in_req.body_len     = s->in_pki.len;
    }
    s->in_op     = c->op;
    s->in_enc    = c->enc;
    s->in_out    = scep_call_out(c);
    s->in_active = 1;
}

/* A resumed _nb poll must name the in-flight operation, output and
 * encoding. */
static int scep_session_resume_check(const WolfCertScepSession* s,
                                     const ScepCall* c)
{
    if (s->in_op != c->op)
        return WOLFCERT_ERR(WOLFCERT_ERR_BAD_ARG, "scep",
            "a different SCEP operation is already in flight on this session");
    if (scep_call_out(c) != s->in_out)
        return WOLFCERT_ERR(WOLFCERT_ERR_BAD_ARG, "scep",
            "output pointer differs from the in-flight request; pass the "
            "same pointer to each poll call");
    if (c->enc != s->in_enc)
        return WOLFCERT_ERR(WOLFCERT_ERR_BAD_ARG, "scep",
            "encoding differs from the in-flight request");
    return WOLFCERT_OK;
}

/* Build c's pkiMessage, signed with s->in_signer and s->in_signer_key; the
 * transactionID and senderNonce stay in s to validate the CertRep. */
static int scep_prepare(WolfCertScepSession* s, const ScepCall* c,
                        const char* msg_type,
                        const uint8_t* envelope_content, size_t envelope_content_len,
                        WolfCertBuffer* out_pki)
{
    void* heap = s->heap;
    const WolfCertScepCaps* caps = c->caps;
    ScepTxidSel txid_sel = {
        .id = c->txid, .id_len = c->txid_len, .mode = s->txid_mode
    };
    int hash_oid = wolfcert_scep_pick_hash_oid(caps, s->signing_hash);
    int enc_oid;

    if (hash_oid < 0)
        return hash_oid;

    /* AUTO follows RFC 8894: GetCACaps "AES" means AES-128-CBC, else 3DES. */
    switch (s->content_cipher) {
        case WOLFCERT_SCEP_CIPHER_AES128:
            enc_oid = AES128CBCb;
            break;
        case WOLFCERT_SCEP_CIPHER_AES256:
#if !defined(WOLFSSL_AES_256) || !defined(HAVE_AES_CBC)
            return WOLFCERT_ERR(WOLFCERT_ERR_UNSUPPORTED, "scep",
                "AES-256-CBC content cipher requested but wolfSSL lacks it");
#else
            enc_oid = AES256CBCb;
            break;
#endif
        case WOLFCERT_SCEP_CIPHER_DES3:
#ifdef NO_DES3
            return WOLFCERT_ERR(WOLFCERT_ERR_UNSUPPORTED, "scep",
                "3DES content cipher requested but wolfSSL was built NO_DES3");
#else
            enc_oid = DES3b;
            break;
#endif
        case WOLFCERT_SCEP_CIPHER_AUTO:
        default:
            if (caps != NULL && caps->aes) {
                enc_oid = AES128CBCb;
            }
            else {
#ifdef NO_DES3
                return WOLFCERT_ERR(WOLFCERT_ERR_UNSUPPORTED, "scep",
                    "no usable content cipher: CA does not advertise AES and "
                    "wolfSSL lacks the 3DES fallback");
#else
                enc_oid = DES3b;
#endif
            }
            break;
    }

    WolfCertBuffer env = { 0 };
    int rc = wolfcert_scep_envelop(c->ra_cert, c->ra_cert_len,
                                    envelope_content, envelope_content_len,
                                    enc_oid, &env, heap);
    if (rc != WOLFCERT_OK)
        return rc;

    WC_RNG rng;
    int rng_rc = wc_InitRng_ex(&rng, heap, WOLFCERT_DEVID_SOFTWARE);
    if (rng_rc != 0) {
        wolfcert_buffer_free(&env);
        return WOLFCERT_ERR_WC(rng_rc, "scep", "RNG init failed");
    }

    rng_rc = wc_RNG_GenerateBlock(&rng, s->in_nonce, SCEP_NONCE_SZ);
    if (rng_rc != 0) {
        wc_FreeRng(&rng);
        wolfcert_buffer_free(&env);
        return WOLFCERT_ERR_WC(rng_rc, "scep", "RNG failed generating senderNonce");
    }

    rc = scep_build_txid(&txid_sel, s->in_signer, s->in_signer_len, &rng, heap,
                         &s->in_txid, &s->in_txid_len);
    wc_FreeRng(&rng);
    if (rc != WOLFCERT_OK) {
        wolfcert_buffer_free(&env);
        return rc;
    }

    WolfCertScepAttrs attrs = {
        .transaction_id     = s->in_txid, .transaction_id_len = s->in_txid_len,
        .sender_nonce       = s->in_nonce, .sender_nonce_len = SCEP_NONCE_SZ,
        .message_type       = msg_type,
    };
    rc = wolfcert_scep_build_pki_message(env.data, env.len,
                                          s->in_signer, s->in_signer_len,
                                          s->in_signer_key, s->in_signer_key_len,
                                          hash_oid, &attrs, out_pki, heap);

    wolfcert_buffer_free(&env);
    return rc;
}

/* Validate the CertRep in s->in_resp against the request in s and fill
 * `out`. */
static int scep_finish(const WolfCertScepSession* s, WolfCertScepResult* out)
{
    void* heap = s->heap;
    WolfCertBuffer resp_env = { 0 };
    WolfCertBuffer inner = { 0 };
    char*   status = NULL;
    char*   fail_info = NULL;
    char* resp_mt = NULL;
    uint8_t* rx_tid = NULL;
    size_t rx_tid_len = 0;
    uint8_t* rx_sn  = NULL;
    size_t rx_sn_len  = 0;
    uint8_t* rx_rn  = NULL;
    size_t rx_rn_len  = 0;
    uint8_t* rx_signer = NULL;
    size_t rx_signer_len = 0;
    int rc = wolfcert_scep_parse_pki_message(s->in_resp.body,
            s->in_resp.body_len, &resp_env,
            &rx_tid, &rx_tid_len, &rx_sn, &rx_sn_len, &rx_rn, &rx_rn_len,
            &resp_mt, &status, &rx_signer, &rx_signer_len, &fail_info, heap);

    WOLFCERT_XFREE(rx_sn,  heap);

    /* RFC 8894: a CertRep is messageType 3 and echoes our transactionID. */
    if (rc == WOLFCERT_OK) {
        rc = wolfcert_scep_check_cert_rep(resp_mt, rx_tid, rx_tid_len,
                                          s->in_txid, s->in_txid_len);
        if (rc != WOLFCERT_OK)
            rc = WOLFCERT_ERR(WOLFCERT_ERR_PROTOCOL, "scep",
                              "CertRep messageType or transactionID does not "
                              "match the request");
    }
    WOLFCERT_XFREE(resp_mt, heap);

    /* Authenticate the CertRep: its signer's key must match a cert in the
     * GetCACert bundle. */
    if (rc == WOLFCERT_OK) {
        rc = wolfcert_scep_verify_rep_signer(rx_signer, rx_signer_len,
                                             s->in_ca_bundle,
                                             s->in_ca_bundle_len, heap);
        if (rc == WOLFCERT_ERR_MEMORY)
            rc = WOLFCERT_ERR(rc, "scep", "out of memory checking the CertRep signer");
        else if (rc != WOLFCERT_OK)
            rc = WOLFCERT_ERR(WOLFCERT_ERR_AUTH, "scep",
                              "CertRep is not signed by the CA/RA certificate");
    }
    WOLFCERT_XFREE(rx_signer, heap);

    /* RFC 8894 section 3.2.1.5: recipientNonce must echo our senderNonce. */
    if (rc == WOLFCERT_OK &&
        (rx_rn == NULL || rx_rn_len != SCEP_NONCE_SZ ||
         memcmp(rx_rn, s->in_nonce, SCEP_NONCE_SZ) != 0)) {
        rc = WOLFCERT_ERR(WOLFCERT_ERR_PROTOCOL, "scep",
                          "CertRep recipientNonce missing or does not echo "
                          "senderNonce");
    }
    WOLFCERT_XFREE(rx_rn, heap);

    /* RFC 8894 section 3.2.1.3: a CertRep carries pkiStatus 0, 2 or 3. */
    if (rc == WOLFCERT_OK &&
        (status == NULL || (strcmp(status, "0") != 0 &&
                            strcmp(status, "2") != 0 &&
                            strcmp(status, "3") != 0))) {
        rc = WOLFCERT_ERR(WOLFCERT_ERR_PROTOCOL, "scep",
                          "CertRep pkiStatus missing or not 0, 2 or 3");
    }

    /* RFC 8894 section 3.2.1.4: a FAILURE CertRep carries failInfo 0..4. */
    if (rc == WOLFCERT_OK && strcmp(status, "2") == 0 &&
        (fail_info == NULL || fail_info[0] < '0' || fail_info[0] > '4' ||
         fail_info[1] != '\0')) {
        rc = WOLFCERT_ERR(WOLFCERT_ERR_PROTOCOL, "scep",
                          "FAILURE CertRep failInfo missing or not 0..4");
    }

    if (rc == WOLFCERT_OK) {
        /* Ownership of rx_tid moves to out. */
        out->transaction_id     = rx_tid;
        out->transaction_id_len = rx_tid_len;
        rx_tid = NULL;

        if (strcmp(status, "3") == 0) {
            out->status = WOLFCERT_SCEP_STATUS_PENDING;
        }
        else if (strcmp(status, "2") == 0) {
            out->status    = WOLFCERT_SCEP_STATUS_FAILURE;
            out->fail_info = fail_info[0] - '0';
        }
        else {
            rc = wolfcert_scep_deenvelop(s->in_signer, s->in_signer_len,
                                          s->in_signer_key, s->in_signer_key_len,
                                          resp_env.data, resp_env.len, &inner,
                                          heap);
            if (rc == WOLFCERT_OK)
                rc = wolfcert_pkcs7_certs_to_pem(inner.data, inner.len,
                                                 &out->cert_pem, heap);
            if (rc == WOLFCERT_OK)
                out->status = WOLFCERT_SCEP_STATUS_SUCCESS;
        }
    }

    WOLFCERT_XFREE(rx_tid, heap);
    WOLFCERT_XFREE(status, heap);
    WOLFCERT_XFREE(fail_info, heap);
    wolfcert_buffer_free(&inner);
    wolfcert_buffer_free(&resp_env);
    return rc;
}

/* Sign c's PKIOperation with the caller's cert, or with a transient
 * self-signed one when there is none, and put it in flight. */
static int scep_session_begin_pki_op(WolfCertScepSession* s, const ScepCall* c,
                                     int nb)
{
    void* heap = s->heap;
    const char* msg_type = "19";
    const uint8_t* content = c->csr;
    size_t content_len = c->csr_len;
    WolfCertBuffer pki = { 0 };
    char* url = NULL;
    int use_post = 0;
    int key_len = 0;
    int rc = WOLFCERT_OK;

    c->res_out->heap = heap;

    if (c->cert == NULL) {
        rc = wolfcert_scep_self_signed_rsa((RsaKey*)c->key->impl,
                                            c->csr, c->csr_len,
                                            &s->in_signer_copy,
                                            &s->in_signer_len, heap);
        s->in_signer = s->in_signer_copy;
    }
    else {
        if (nb) {
            s->in_signer_copy = dup_buf(c->cert, c->cert_len, heap);
            if (s->in_signer_copy == NULL)
                rc = WOLFCERT_ERR_MEMORY;
        }
        s->in_signer     = nb ? s->in_signer_copy : c->cert;
        s->in_signer_len = c->cert_len;
    }

    if (rc == WOLFCERT_OK) {
        if (nb) {
            s->in_ca_bundle_copy = dup_buf(c->ca_bundle, c->ca_bundle_len, heap);
            if (s->in_ca_bundle_copy == NULL)
                rc = WOLFCERT_ERR_MEMORY;
        }
        s->in_ca_bundle     = nb ? s->in_ca_bundle_copy : c->ca_bundle;
        s->in_ca_bundle_len = c->ca_bundle_len;
    }

    switch (c->op) {
        case SCEP_OP_RENEWAL:
            msg_type = scep_renewal_msg_type(s->renewal_msg_type);
            break;
        case SCEP_OP_GET_CERT_INITIAL:
            msg_type = "20";
            if (rc == WOLFCERT_OK)
                rc = wolfcert_scep_issuer_and_subject(c->ra_cert, c->ra_cert_len,
                                                      c->csr, c->csr_len,
                                                      &s->in_ias, heap);
            break;
        case SCEP_OP_GET_CERT:
            msg_type = "21";
            if (rc == WOLFCERT_OK)
                rc = wolfcert_scep_issuer_and_serial(c->ra_cert, c->ra_cert_len,
                                                     c->serial, c->serial_len,
                                                     &s->in_ias, heap);
            break;
        default:
            break;
    }
    if (s->in_ias.data != NULL) {
        content     = s->in_ias.data;
        content_len = s->in_ias.len;
    }

    if (rc == WOLFCERT_OK)
        rc = wolfcert_key_export_der(c->key, &s->in_signer_key, &key_len,
                                     heap);
    s->in_signer_key_len = (size_t)key_len;
    if (rc == WOLFCERT_OK)
        rc = scep_prepare(s, c, msg_type, content, content_len, &pki);
    if (rc == WOLFCERT_OK)
        rc = scep_build_transport(s->server_url, c->caps, pki.data, pki.len,
                                  heap, &url, &use_post);

    if (rc == WOLFCERT_OK) {
        s->in_pki = pki;
        scep_session_start(s, c, url, use_post);
    }
    else {
        wolfcert_buffer_free(&pki);
        scep_session_reset(s);
    }
    return rc;
}

/* Put the GetCACaps, GetCACert or GetNextCACert request for c in flight. */
static int scep_session_begin_get(WolfCertScepSession* s, const ScepCall* c,
                                  int nb)
{
    const char* name = (c->op == SCEP_OP_GET_CA_CAPS) ? "GetCACaps" :
                       (c->op == SCEP_OP_GET_CA_CERT) ? "GetCACert" :
                                                        "GetNextCACert";
    char* url = wolfcert_scep_build_getca_url(s->server_url, name, s->ca_id,
                                              s->heap);
    if (url == NULL)
        return WOLFCERT_ERR_MEMORY;

    if (c->op == SCEP_OP_GET_NEXT_CA_CERT) {
        if (nb) {
            s->in_ca_bundle_copy = dup_buf(c->ca_bundle, c->ca_bundle_len,
                                           s->heap);
            if (s->in_ca_bundle_copy == NULL) {
                WOLFCERT_XFREE(url, s->heap);
                return WOLFCERT_ERR_MEMORY;
            }
        }
        s->in_ca_bundle     = nb ? s->in_ca_bundle_copy : c->ca_bundle;
        s->in_ca_bundle_len = c->ca_bundle_len;
    }

    scep_session_start(s, c, url, 0);
    return WOLFCERT_OK;
}

/* A GetCert reply must hold the requested issuer and serial. */
static int scep_check_get_cert(const WolfCertScepSession* s,
                               WolfCertScepResult* out)
{
    const uint8_t* issuer = NULL;
    size_t         issuer_len = 0;
    const uint8_t* serial = NULL;
    size_t         serial_len = 0;
    int has;
    int rc = wolfcert_scep_parse_issuer_and_serial(s->in_ias.data, s->in_ias.len,
                                                   &issuer, &issuer_len,
                                                   &serial, &serial_len);
    if (rc == WOLFCERT_OK)
        has = wolfcert_scep_pem_has_cert(out->cert_pem.data, out->cert_pem.len,
                                         issuer, issuer_len, serial, serial_len,
                                         s->heap);
    else
        has = rc;
    if (has == 1)
        return WOLFCERT_OK;

    wolfcert_buffer_free(&out->cert_pem);
    out->status = WOLFCERT_SCEP_STATUS_UNSET;
    return (has < 0) ? has : WOLFCERT_ERR(WOLFCERT_ERR_PROTOCOL, "scep",
        "GetCert returned no certificate with the requested issuer and serial");
}

/* Parse s->in_resp into c's output and end the request. */
static int scep_session_finish(WolfCertScepSession* s, const ScepCall* c)
{
    const WolfCertHttpResponse* r = &s->in_resp;
    int rc;

    if (s->in_op == SCEP_OP_GET_NEXT_CA_CERT && r->status_code == 404) {
        rc = WOLFCERT_ERR_NOT_FOUND;
    }
    else if (r->status_code != 200) {
        rc = WOLFCERT_ERR_HTTP;
    }
    else if (s->in_op == SCEP_OP_GET_CA_CAPS) {
        scep_finish_caps(r, c->caps_out);
        rc = WOLFCERT_OK;
    }
    else if (s->in_op == SCEP_OP_GET_CA_CERT) {
        rc = scep_finish_ca_cert(r, c->enc, c->buf_out, s->heap);
    }
    else if (s->in_op == SCEP_OP_GET_NEXT_CA_CERT) {
        /* RFC 8894 section 4.7.1: the current CA signs a SignedData whose
         * content is a certs-only bundle holding the next CA cert. */
        rc = wolfcert_scep_verify_next_ca_response(r->body, r->body_len,
                s->in_ca_bundle, s->in_ca_bundle_len, c->enc, c->buf_out,
                s->heap);
    }
    else {
        rc = scep_finish(s, c->res_out);
        if (rc == WOLFCERT_OK && s->in_op == SCEP_OP_GET_CERT &&
            c->res_out->status == WOLFCERT_SCEP_STATUS_SUCCESS)
            rc = scep_check_get_cert(s, c->res_out);
    }

    scep_session_reset(s);
    return rc;
}

/* Build c's request into s and put it in flight. */
static int scep_session_begin(WolfCertScepSession* s, const ScepCall* c, int nb)
{
    if (c->op >= SCEP_OP_PKCS_REQ)
        return scep_session_begin_pki_op(s, c, nb);
    return scep_session_begin_get(s, c, nb);
}

/* Send or continue the request in flight, then parse the reply into c's
 * output. */
static int scep_session_send(WolfCertScepSession* s, const ScepCall* c, int nb)
{
    int rc;

    if (nb)
        rc = wolfcert_http_session_request_nb(s->http, &s->in_req, &s->in_resp);
    else
        rc = wolfcert_http_session_request(s->http, &s->in_req, &s->in_resp);

    if (nb && (rc == WOLFCERT_ERR_WANT_READ || rc == WOLFCERT_ERR_WANT_WRITE))
        return rc;

    if (rc == WOLFCERT_OK) {
        scep_session_free_request(s);
        return scep_session_finish(s, c);
    }

    scep_session_reset(s);
    return rc;
}

/* Run c on s, or continue the _nb request in flight, and parse the reply. */
static int scep_session_call(WolfCertScepSession* s, const ScepCall* c, int nb)
{
    int rc;

    if (scep_call_out(c) == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    scep_call_clear(s, c);
    if (s == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    if (s->in_active && !nb)
        return WOLFCERT_ERR(WOLFCERT_ERR_BAD_ARG, "scep",
            "a SCEP request is in flight on this session; continue it with "
            "the _nb call");

    if (s->in_active) {
        rc = scep_session_resume_check(s, c);
    }
    else {
        rc = scep_call_check(c);
        if (rc == WOLFCERT_OK)
            rc = scep_session_begin(s, c, nb);
    }
    if (rc != WOLFCERT_OK)
        return rc;

    return scep_session_send(s, c, nb);
}

int wolfcert_scep_session_get_ca_caps(WolfCertScepSession* s,
                                      WolfCertScepCaps* out_caps)
{
    ScepCall c = { .op = SCEP_OP_GET_CA_CAPS, .caps_out = out_caps };

    return scep_session_call(s, &c, 0);
}

int wolfcert_scep_session_get_ca_caps_nb(WolfCertScepSession* s,
                                         WolfCertScepCaps* out_caps)
{
    ScepCall c = { .op = SCEP_OP_GET_CA_CAPS, .caps_out = out_caps };

    return scep_session_call(s, &c, 1);
}

int wolfcert_scep_session_get_ca_cert(WolfCertScepSession* s,
                                      WolfCertEncoding enc,
                                      WolfCertBuffer* out_ca)
{
    ScepCall c = { .op = SCEP_OP_GET_CA_CERT, .enc = enc, .buf_out = out_ca };

    return scep_session_call(s, &c, 0);
}

int wolfcert_scep_session_get_ca_cert_nb(WolfCertScepSession* s,
                                         WolfCertEncoding enc,
                                         WolfCertBuffer* out_ca)
{
    ScepCall c = { .op = SCEP_OP_GET_CA_CERT, .enc = enc, .buf_out = out_ca };

    return scep_session_call(s, &c, 1);
}

int wolfcert_scep_session_get_next_ca_cert(WolfCertScepSession* s,
                                           WolfCertEncoding enc,
                                           const uint8_t* current_ca_der,
                                           size_t current_ca_len,
                                           WolfCertBuffer* out_next_ca)
{
    ScepCall c = { .op = SCEP_OP_GET_NEXT_CA_CERT, .enc = enc,
                   .ca_bundle = current_ca_der, .ca_bundle_len = current_ca_len,
                   .buf_out = out_next_ca };

    return scep_session_call(s, &c, 0);
}

int wolfcert_scep_session_get_next_ca_cert_nb(WolfCertScepSession* s,
                                              WolfCertEncoding enc,
                                              const uint8_t* current_ca_der,
                                              size_t current_ca_len,
                                              WolfCertBuffer* out_next_ca)
{
    ScepCall c = { .op = SCEP_OP_GET_NEXT_CA_CERT, .enc = enc,
                   .ca_bundle = current_ca_der, .ca_bundle_len = current_ca_len,
                   .buf_out = out_next_ca };

    return scep_session_call(s, &c, 1);
}

int wolfcert_scep_session_pkcs_req(WolfCertScepSession* s,
                                   const WolfCertScepCaps* caps,
                                   const uint8_t* ra_cert, size_t ra_cert_len,
                                   const uint8_t* ca_bundle, size_t ca_bundle_len,
                                   const WolfCertKey* new_key,
                                   const uint8_t* csr_der, size_t csr_der_len,
                                   WolfCertScepResult* out)
{
    ScepCall c = { .op = SCEP_OP_PKCS_REQ, .caps = caps,
                   .ra_cert = ra_cert, .ra_cert_len = ra_cert_len,
                   .ca_bundle = ca_bundle, .ca_bundle_len = ca_bundle_len,
                   .key = new_key, .csr = csr_der, .csr_len = csr_der_len,
                   .res_out = out };

    return scep_session_call(s, &c, 0);
}

int wolfcert_scep_session_pkcs_req_nb(WolfCertScepSession* s,
                                      const WolfCertScepCaps* caps,
                                      const uint8_t* ra_cert, size_t ra_cert_len,
                                      const uint8_t* ca_bundle, size_t ca_bundle_len,
                                      const WolfCertKey* new_key,
                                      const uint8_t* csr_der, size_t csr_der_len,
                                      WolfCertScepResult* out)
{
    ScepCall c = { .op = SCEP_OP_PKCS_REQ, .caps = caps,
                   .ra_cert = ra_cert, .ra_cert_len = ra_cert_len,
                   .ca_bundle = ca_bundle, .ca_bundle_len = ca_bundle_len,
                   .key = new_key, .csr = csr_der, .csr_len = csr_der_len,
                   .res_out = out };

    return scep_session_call(s, &c, 1);
}

int wolfcert_scep_session_renewal_req(WolfCertScepSession* s,
                                      const WolfCertScepCaps* caps,
                                      const uint8_t* ra_cert, size_t ra_cert_len,
                                      const uint8_t* ca_bundle, size_t ca_bundle_len,
                                      const uint8_t* current_cert, size_t current_cert_len,
                                      const WolfCertKey* current_key,
                                      const uint8_t* csr_der, size_t csr_der_len,
                                      WolfCertScepResult* out)
{
    ScepCall c = { .op = SCEP_OP_RENEWAL, .caps = caps,
                   .ra_cert = ra_cert, .ra_cert_len = ra_cert_len,
                   .ca_bundle = ca_bundle, .ca_bundle_len = ca_bundle_len,
                   .cert = current_cert, .cert_len = current_cert_len,
                   .key = current_key, .csr = csr_der, .csr_len = csr_der_len,
                   .res_out = out };

    return scep_session_call(s, &c, 0);
}

int wolfcert_scep_session_renewal_req_nb(WolfCertScepSession* s,
                                         const WolfCertScepCaps* caps,
                                         const uint8_t* ra_cert, size_t ra_cert_len,
                                         const uint8_t* ca_bundle, size_t ca_bundle_len,
                                         const uint8_t* current_cert, size_t current_cert_len,
                                         const WolfCertKey* current_key,
                                         const uint8_t* csr_der, size_t csr_der_len,
                                         WolfCertScepResult* out)
{
    ScepCall c = { .op = SCEP_OP_RENEWAL, .caps = caps,
                   .ra_cert = ra_cert, .ra_cert_len = ra_cert_len,
                   .ca_bundle = ca_bundle, .ca_bundle_len = ca_bundle_len,
                   .cert = current_cert, .cert_len = current_cert_len,
                   .key = current_key, .csr = csr_der, .csr_len = csr_der_len,
                   .res_out = out };

    return scep_session_call(s, &c, 1);
}

int wolfcert_scep_session_get_cert_initial(WolfCertScepSession* s,
                                           const WolfCertScepCaps* caps,
                                           const uint8_t* ra_cert, size_t ra_cert_len,
                                           const uint8_t* ca_bundle, size_t ca_bundle_len,
                                           const uint8_t* signer_cert, size_t signer_cert_len,
                                           const WolfCertKey* signer_key,
                                           const uint8_t* csr_der, size_t csr_der_len,
                                           const uint8_t* transaction_id, size_t transaction_id_len,
                                           WolfCertScepResult* out)
{
    ScepCall c = { .op = SCEP_OP_GET_CERT_INITIAL, .caps = caps,
                   .ra_cert = ra_cert, .ra_cert_len = ra_cert_len,
                   .ca_bundle = ca_bundle, .ca_bundle_len = ca_bundle_len,
                   .cert = signer_cert, .cert_len = signer_cert_len,
                   .key = signer_key, .csr = csr_der, .csr_len = csr_der_len,
                   .txid = transaction_id, .txid_len = transaction_id_len,
                   .res_out = out };

    return scep_session_call(s, &c, 0);
}

int wolfcert_scep_session_get_cert_initial_nb(WolfCertScepSession* s,
                                              const WolfCertScepCaps* caps,
                                              const uint8_t* ra_cert, size_t ra_cert_len,
                                              const uint8_t* ca_bundle, size_t ca_bundle_len,
                                              const uint8_t* signer_cert, size_t signer_cert_len,
                                              const WolfCertKey* signer_key,
                                              const uint8_t* csr_der, size_t csr_der_len,
                                              const uint8_t* transaction_id, size_t transaction_id_len,
                                              WolfCertScepResult* out)
{
    ScepCall c = { .op = SCEP_OP_GET_CERT_INITIAL, .caps = caps,
                   .ra_cert = ra_cert, .ra_cert_len = ra_cert_len,
                   .ca_bundle = ca_bundle, .ca_bundle_len = ca_bundle_len,
                   .cert = signer_cert, .cert_len = signer_cert_len,
                   .key = signer_key, .csr = csr_der, .csr_len = csr_der_len,
                   .txid = transaction_id, .txid_len = transaction_id_len,
                   .res_out = out };

    return scep_session_call(s, &c, 1);
}

int wolfcert_scep_session_get_cert(WolfCertScepSession* s,
                                   const WolfCertScepCaps* caps,
                                   const uint8_t* ra_cert, size_t ra_cert_len,
                                   const uint8_t* ca_bundle, size_t ca_bundle_len,
                                   const uint8_t* signer_cert, size_t signer_cert_len,
                                   const WolfCertKey* signer_key,
                                   const uint8_t* serial, size_t serial_len,
                                   WolfCertScepResult* out)
{
    ScepCall c = { .op = SCEP_OP_GET_CERT, .caps = caps,
                   .ra_cert = ra_cert, .ra_cert_len = ra_cert_len,
                   .ca_bundle = ca_bundle, .ca_bundle_len = ca_bundle_len,
                   .cert = signer_cert, .cert_len = signer_cert_len,
                   .key = signer_key, .serial = serial, .serial_len = serial_len,
                   .res_out = out };

    return scep_session_call(s, &c, 0);
}

int wolfcert_scep_session_get_cert_nb(WolfCertScepSession* s,
                                      const WolfCertScepCaps* caps,
                                      const uint8_t* ra_cert, size_t ra_cert_len,
                                      const uint8_t* ca_bundle, size_t ca_bundle_len,
                                      const uint8_t* signer_cert, size_t signer_cert_len,
                                      const WolfCertKey* signer_key,
                                      const uint8_t* serial, size_t serial_len,
                                      WolfCertScepResult* out)
{
    ScepCall c = { .op = SCEP_OP_GET_CERT, .caps = caps,
                   .ra_cert = ra_cert, .ra_cert_len = ra_cert_len,
                   .ca_bundle = ca_bundle, .ca_bundle_len = ca_bundle_len,
                   .cert = signer_cert, .cert_len = signer_cert_len,
                   .key = signer_key, .serial = serial, .serial_len = serial_len,
                   .res_out = out };

    return scep_session_call(s, &c, 1);
}

static int scep_one_shot(const WolfCertServerCfg* srv, const ScepCall* c)
{
    WolfCertScepSession* s = NULL;
    int rc;

    if (scep_call_out(c) == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    scep_call_clear(NULL, c);
    rc = scep_call_check(c);
    if (rc == WOLFCERT_OK)
        rc = scep_session_new(srv, &s);
    if (rc == WOLFCERT_OK)
        rc = scep_session_begin(s, c, 0);
    if (rc == WOLFCERT_OK)
        rc = scep_session_connect(s, srv);
    if (rc == WOLFCERT_OK) {
        wolfcert_http_session_set_close(s->http);
        rc = scep_session_send(s, c, 0);
    }

    wolfcert_scep_session_close(s);
    return rc;
}

int wolfcert_scep_get_ca_caps(const WolfCertServerCfg* srv, WolfCertScepCaps* out)
{
    ScepCall c = { .op = SCEP_OP_GET_CA_CAPS, .caps_out = out };

    return scep_one_shot(srv, &c);
}

int wolfcert_scep_get_ca_cert(const WolfCertServerCfg* srv,
                              WolfCertEncoding enc, WolfCertBuffer* out_ca)
{
    ScepCall c = { .op = SCEP_OP_GET_CA_CERT, .enc = enc, .buf_out = out_ca };

    return scep_one_shot(srv, &c);
}

int wolfcert_scep_get_next_ca_cert(const WolfCertServerCfg* srv,
                                   WolfCertEncoding enc,
                                   const uint8_t* current_ca_der,
                                   size_t current_ca_len,
                                   WolfCertBuffer* out_next_ca)
{
    ScepCall c = { .op = SCEP_OP_GET_NEXT_CA_CERT, .enc = enc,
                   .ca_bundle = current_ca_der, .ca_bundle_len = current_ca_len,
                   .buf_out = out_next_ca };

    return scep_one_shot(srv, &c);
}

int wolfcert_scep_pkcs_req(const WolfCertServerCfg* srv,
                           const WolfCertScepCaps*  caps,
                           const uint8_t* ra_cert, size_t ra_cert_len,
                           const uint8_t* ca_bundle, size_t ca_bundle_len,
                           const WolfCertKey*       new_key,
                           const uint8_t* csr_der, size_t csr_der_len,
                           WolfCertScepResult*      out)
{
    ScepCall c = { .op = SCEP_OP_PKCS_REQ, .caps = caps,
                   .ra_cert = ra_cert, .ra_cert_len = ra_cert_len,
                   .ca_bundle = ca_bundle, .ca_bundle_len = ca_bundle_len,
                   .key = new_key, .csr = csr_der, .csr_len = csr_der_len,
                   .res_out = out };

    return scep_one_shot(srv, &c);
}

int wolfcert_scep_renewal_req(const WolfCertServerCfg* srv,
                              const WolfCertScepCaps*  caps,
                              const uint8_t* ra_cert, size_t ra_cert_len,
                              const uint8_t* ca_bundle, size_t ca_bundle_len,
                              const uint8_t* current_cert, size_t current_cert_len,
                              const WolfCertKey* current_key,
                              const uint8_t* csr_der, size_t csr_der_len,
                              WolfCertScepResult* out)
{
    ScepCall c = { .op = SCEP_OP_RENEWAL, .caps = caps,
                   .ra_cert = ra_cert, .ra_cert_len = ra_cert_len,
                   .ca_bundle = ca_bundle, .ca_bundle_len = ca_bundle_len,
                   .cert = current_cert, .cert_len = current_cert_len,
                   .key = current_key, .csr = csr_der, .csr_len = csr_der_len,
                   .res_out = out };

    return scep_one_shot(srv, &c);
}

int wolfcert_scep_get_cert_initial(const WolfCertServerCfg* srv,
                                   const WolfCertScepCaps*  caps,
                                   const uint8_t* ra_cert, size_t ra_cert_len,
                                   const uint8_t* ca_bundle, size_t ca_bundle_len,
                                   const uint8_t* signer_cert, size_t signer_cert_len,
                                   const WolfCertKey* signer_key,
                                   const uint8_t* csr_der, size_t csr_der_len,
                                   const uint8_t* transaction_id,
                                   size_t transaction_id_len,
                                   WolfCertScepResult* out)
{
    ScepCall c = { .op = SCEP_OP_GET_CERT_INITIAL, .caps = caps,
                   .ra_cert = ra_cert, .ra_cert_len = ra_cert_len,
                   .ca_bundle = ca_bundle, .ca_bundle_len = ca_bundle_len,
                   .cert = signer_cert, .cert_len = signer_cert_len,
                   .key = signer_key, .csr = csr_der, .csr_len = csr_der_len,
                   .txid = transaction_id, .txid_len = transaction_id_len,
                   .res_out = out };

    return scep_one_shot(srv, &c);
}

int wolfcert_scep_get_cert(const WolfCertServerCfg* srv,
                           const WolfCertScepCaps* caps,
                           const uint8_t* ra_cert, size_t ra_cert_len,
                           const uint8_t* ca_bundle, size_t ca_bundle_len,
                           const uint8_t* signer_cert, size_t signer_cert_len,
                           const WolfCertKey* signer_key,
                           const uint8_t* serial, size_t serial_len,
                           WolfCertScepResult* out)
{
    ScepCall c = { .op = SCEP_OP_GET_CERT, .caps = caps,
                   .ra_cert = ra_cert, .ra_cert_len = ra_cert_len,
                   .ca_bundle = ca_bundle, .ca_bundle_len = ca_bundle_len,
                   .cert = signer_cert, .cert_len = signer_cert_len,
                   .key = signer_key, .serial = serial, .serial_len = serial_len,
                   .res_out = out };

    return scep_one_shot(srv, &c);
}
