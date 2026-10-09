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
#define _GNU_SOURCE

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

/* RFC 8894 defines no HTTP-layer authentication, so no Basic credentials. */
static void fill_common(const WolfCertServerCfg* srv, WolfCertHttpRequest* req)
{
    req->trust_anchors      = srv->trust_anchors;
    req->trust_anchors_len  = srv->trust_anchors_len;
    req->verify_server      = srv->verify_server;
    req->timeout_ms         = srv->timeout_ms;
    req->max_response_bytes = srv->max_response_bytes;
    req->heap               = srv->heap;

    req->client_cert        = srv->client_cert;
    req->client_cert_len    = srv->client_cert_len;
    req->client_key         = srv->client_key;
    req->client_key_len     = srv->client_key_len;
    req->transport          = srv->transport;
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

/* The protocol check must precede every read of proto_opts.scep. Plain
 * http:// is allowed, but an https:// endpoint requires verify_server. */
static int scep_check_cfg(const WolfCertServerCfg* srv, void* heap)
{
    WolfCertUrl u;
    int rc = wolfcert_cfg_require_proto(srv, WOLFCERT_PROTO_SCEP, "scep");
    if (rc != WOLFCERT_OK)
        return rc;

    rc = wolfcert_http_url_parse(srv->server_url, &u, heap);
    if (rc != WOLFCERT_OK)
        return rc;

    int tls = u.tls;
    wolfcert_http_url_free(&u);

    if (tls && !srv->verify_server)
        return WOLFCERT_ERR(WOLFCERT_ERR_TLS, "scep",
            "TLS SCEP endpoint requires server authentication: set verify_server "
            "or use a plaintext http:// URL");

    return WOLFCERT_OK;
}

int wolfcert_scep_get_ca_caps(const WolfCertServerCfg* srv, WolfCertScepCaps* out)
{
    if (srv == NULL || srv->server_url == NULL || out == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    void* heap = srv->heap ? srv->heap : wolfcert_default_heap();
    int trc = scep_check_cfg(srv, heap);
    if (trc != WOLFCERT_OK)
        return trc;

    memset(out, 0, sizeof(*out));

    char* url = wolfcert_scep_build_getca_url(srv->server_url, "GetCACaps",
                                              srv->proto_opts.scep.ca_id, heap);
    if (url == NULL)
        return WOLFCERT_ERR_MEMORY;

    WolfCertHttpRequest req = { .method = "GET", .url = url };
    fill_common(srv, &req);

    WolfCertHttpResponse resp = { 0 };
    int rc = wolfcert_http_request(&req, &resp);

    WOLFCERT_XFREE(url, heap);
    if (rc != WOLFCERT_OK)
        return rc;

    if (resp.status_code != 200) {
        wolfcert_http_response_free(&resp);
        return WOLFCERT_ERR_HTTP;
    }

    const char* b = (const char*)resp.body;
    out->post_pki_operation = has_cap(b, resp.body_len, "POSTPKIOperation");
    out->renewal            = has_cap(b, resp.body_len, "Renewal");
    out->sha256             = has_cap(b, resp.body_len, "SHA-256");
    out->sha384             = has_cap(b, resp.body_len, "SHA-384");
    out->sha512             = has_cap(b, resp.body_len, "SHA-512");
    out->aes                = has_cap(b, resp.body_len, "AES");
    out->scep_standard      = has_cap(b, resp.body_len, "SCEPStandard");
    out->get_next_ca_cert   = has_cap(b, resp.body_len, "GetNextCACert");

    /* RFC 8894 section 3.5.2, Table 7 */
    if (out->scep_standard) {
        out->post_pki_operation = 1;
        out->aes                = 1;
        out->sha256             = 1;
    }

    wolfcert_http_response_free(&resp);

    return WOLFCERT_OK;
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

int wolfcert_scep_get_ca_cert(const WolfCertServerCfg* srv, WolfCertBuffer* out_ca_pem)
{
    return wolfcert_scep_get_ca_cert_enc(srv, WOLFCERT_ENCODING_PEM, out_ca_pem);
}

int wolfcert_scep_get_ca_cert_enc(const WolfCertServerCfg* srv, WolfCertEncoding enc,
                                  WolfCertBuffer* out_ca)
{
    if (srv == NULL || srv->server_url == NULL || out_ca == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    void* heap = srv->heap ? srv->heap : wolfcert_default_heap();
    int trc = scep_check_cfg(srv, heap);
    if (trc != WOLFCERT_OK)
        return trc;


    char* url = wolfcert_scep_build_getca_url(srv->server_url, "GetCACert",
                                              srv->proto_opts.scep.ca_id, heap);
    if (url == NULL)
        return WOLFCERT_ERR_MEMORY;

    WolfCertHttpRequest req = { .method = "GET", .url = url };
    fill_common(srv, &req);

    WolfCertHttpResponse resp = { 0 };
    int rc = wolfcert_http_request(&req, &resp);

    WOLFCERT_XFREE(url, heap);
    if (rc != WOLFCERT_OK)
        return rc;

    if (resp.status_code != 200) {
        wolfcert_http_response_free(&resp);
        return WOLFCERT_ERR_HTTP;
    }

    if (resp.body_len == 0) {
        wolfcert_http_response_free(&resp);
        return WOLFCERT_ERR(WOLFCERT_ERR_HTTP, "scep",
            "GetCACert: 200 response carried no certificate");
    }

    /* Media types compare case-insensitively; ';' parameters are ignored. */
    static const char ca_ra_type[] = "application/x-x509-ca-ra-cert";
    int is_p7 = 0;
    if (resp.content_type != NULL &&
            wolfcert_ascii_ncasecmp(resp.content_type, ca_ra_type,
                                    sizeof(ca_ra_type) - 1) == 0) {
        const char* p = resp.content_type + sizeof(ca_ra_type) - 1;
        while (*p == ' ' || *p == '\t')
            ++p;
        is_p7 = (*p == '\0' || *p == ';');
    }
    if (is_p7) {
        if (enc == WOLFCERT_ENCODING_DER) {
            rc = wolfcert_pkcs7_certs_to_der(resp.body, resp.body_len, out_ca, heap);
        }
        else {
            rc = wolfcert_pkcs7_certs_to_pem(resp.body, resp.body_len, out_ca, heap);
        }
    }
    else if (enc == WOLFCERT_ENCODING_DER) {
        /* A single CA cert arrives as raw DER. */
        uint8_t* der = (uint8_t*)WOLFCERT_XMALLOC(resp.body_len, heap);
        if (der == NULL) {
            rc = WOLFCERT_ERR_MEMORY;
            goto out;
        }

        memcpy(der, resp.body, resp.body_len);
        out_ca->data = der;
        out_ca->len  = resp.body_len;
        out_ca->heap = heap;
        rc = WOLFCERT_OK;
    }
    else {
        size_t cap = resp.body_len * 2 + 256;
        uint8_t* pem = (uint8_t*)WOLFCERT_XMALLOC(cap, heap);
        if (pem == NULL) {
            rc = WOLFCERT_ERR_MEMORY;
            goto out;
        }

        int n = wc_DerToPem(resp.body, (word32)resp.body_len, pem, (word32)cap, CERT_TYPE);
        if (n <= 0) {
            WOLFCERT_XFREE(pem, heap);
            rc = WOLFCERT_ERR_CRYPTO;
            goto out;
        }

        out_ca->data = pem;
        out_ca->len  = (size_t)n;
        out_ca->heap = heap;
        rc = WOLFCERT_OK;
    }

out:
    wolfcert_http_response_free(&resp);
    return rc;
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

static int pick_hash_oid(const WolfCertScepCaps* caps)
{
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

static int run_pki_op(const WolfCertServerCfg* srv,
                      const WolfCertScepCaps* caps,
                      const uint8_t* pki_msg, size_t pki_len,
                      uint8_t** out_resp, size_t* out_resp_len)
{
    void* heap = srv->heap ? srv->heap : wolfcert_default_heap();

    char* url = NULL;
    int   use_post = 0;
    int rc = scep_build_transport(srv->server_url, caps, pki_msg, pki_len, heap,
                                  &url, &use_post);
    if (rc != WOLFCERT_OK)
        return rc;

    WolfCertHttpRequest req = { .method = use_post ? "POST" : "GET", .url = url };
    if (use_post) {
        req.content_type = "application/x-pki-message";
        req.body         = pki_msg;
        req.body_len     = pki_len;
    }

    fill_common(srv, &req);
    WolfCertHttpResponse resp = { 0 };
    rc = wolfcert_http_request(&req, &resp);

    WOLFCERT_XFREE(url, heap);
    if (rc != WOLFCERT_OK)
        return rc;

    if (resp.status_code != 200) {
        wolfcert_http_response_free(&resp);
        return WOLFCERT_ERR_HTTP;
    }

    *out_resp     = resp.body;
    *out_resp_len = resp.body_len;
    resp.body = NULL;
    wolfcert_http_response_free(&resp);

    return WOLFCERT_OK;
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

/* Build the pkiMessage; the caller keeps *out_txid and out_nonce to validate
 * the CertRep. */
static int scep_prepare(void* heap, const WolfCertScepCaps* caps,
                        const uint8_t* ra_cert, size_t ra_cert_len,
                        const uint8_t* signer_cert, size_t signer_cert_len,
                        const uint8_t* signer_key, size_t signer_key_len,
                        const char* msg_type,
                        const uint8_t* envelope_content, size_t envelope_content_len,
                        const ScepTxidSel* txid_sel,
                        WolfCertScepContentCipher cipher,
                        WolfCertBuffer* out_pki,
                        uint8_t** out_txid, size_t* out_txid_len,
                        uint8_t* out_nonce)
{
    int hash_oid = pick_hash_oid(caps);
    int enc_oid;

    /* AUTO follows RFC 8894: GetCACaps "AES" means AES-128-CBC, else 3DES. */
    switch (cipher) {
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
    int rc = wolfcert_scep_envelop(ra_cert, ra_cert_len,
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

    rng_rc = wc_RNG_GenerateBlock(&rng, out_nonce, SCEP_NONCE_SZ);
    if (rng_rc != 0) {
        wc_ForceZero(out_nonce, SCEP_NONCE_SZ);
        wc_FreeRng(&rng);
        wolfcert_buffer_free(&env);
        return WOLFCERT_ERR_WC(rng_rc, "scep", "RNG failed generating senderNonce");
    }

    uint8_t* txid = NULL;
    size_t   txid_len = 0;
    rc = scep_build_txid(txid_sel, signer_cert, signer_cert_len, &rng, heap,
                         &txid, &txid_len);
    wc_FreeRng(&rng);
    if (rc != WOLFCERT_OK) {
        wc_ForceZero(out_nonce, SCEP_NONCE_SZ);
        wolfcert_buffer_free(&env);
        return rc;
    }

    WolfCertScepAttrs attrs = {
        .transaction_id     = txid, .transaction_id_len = txid_len,
        .sender_nonce       = out_nonce, .sender_nonce_len = SCEP_NONCE_SZ,
        .message_type       = msg_type,
    };
    rc = wolfcert_scep_build_pki_message(env.data, env.len,
                                          signer_cert, signer_cert_len,
                                          signer_key, signer_key_len,
                                          hash_oid, &attrs, out_pki, heap);

    wolfcert_buffer_free(&env);
    if (rc != WOLFCERT_OK) {
        WOLFCERT_XFREE(txid, heap);
        return rc;
    }

    *out_txid     = txid;
    *out_txid_len = txid_len;

    return WOLFCERT_OK;
}

/* Validate a CertRep against the request and fill `out`; reads but does not
 * free `resp`. */
static int scep_finish(void* heap,
                       const uint8_t* resp, size_t resp_len,
                       const uint8_t* ca_bundle, size_t ca_bundle_len,
                       const uint8_t* signer_cert, size_t signer_cert_len,
                       const uint8_t* signer_key, size_t signer_key_len,
                       const uint8_t* txid, size_t txid_len,
                       const uint8_t* nonce,
                       WolfCertScepResult* out)
{
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
    int rc = wolfcert_scep_parse_pki_message(resp, resp_len, &resp_env,
            &rx_tid, &rx_tid_len, &rx_sn, &rx_sn_len, &rx_rn, &rx_rn_len,
            &resp_mt, &status, &rx_signer, &rx_signer_len, &fail_info, heap);

    WOLFCERT_XFREE(rx_sn,  heap);

    /* RFC 8894: a CertRep is messageType 3 and echoes our transactionID. */
    if (rc == WOLFCERT_OK) {
        rc = wolfcert_scep_check_cert_rep(resp_mt, rx_tid, rx_tid_len,
                                          txid, txid_len);
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
                                             ca_bundle, ca_bundle_len, heap);
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
         memcmp(rx_rn, nonce, SCEP_NONCE_SZ) != 0)) {
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
            rc = wolfcert_scep_deenvelop(signer_cert, signer_cert_len,
                                          signer_key, signer_key_len,
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

/* A NULL `txid_override` derives the transactionID per txid_mode. */
static int do_scep_round_trip(const WolfCertServerCfg* srv,
                              const WolfCertScepCaps*   caps,
                              const uint8_t* ra_cert, size_t ra_cert_len,
                              const uint8_t* ca_bundle, size_t ca_bundle_len,
                              const uint8_t* signer_cert, size_t signer_cert_len,
                              const uint8_t* signer_key,  size_t signer_key_len,
                              const char* msg_type,
                              const uint8_t* envelope_content, size_t envelope_content_len,
                              const uint8_t* txid_override, size_t txid_override_len,
                              WolfCertScepResult* out)
{
    void* heap = srv->heap ? srv->heap : wolfcert_default_heap();
    out->heap = heap;
    out->fail_info = -1;

    ScepTxidSel txid_sel = {
        .id = txid_override, .id_len = txid_override_len,
        .mode = srv->proto_opts.scep.txid_mode
    };

    WolfCertBuffer pki = { 0 };
    uint8_t* txid = NULL;
    size_t   txid_len = 0;
    uint8_t  nonce[SCEP_NONCE_SZ];
    int rc = scep_prepare(heap, caps, ra_cert, ra_cert_len,
                          signer_cert, signer_cert_len, signer_key, signer_key_len,
                          msg_type, envelope_content, envelope_content_len,
                          &txid_sel, srv->proto_opts.scep.content_cipher,
                          &pki, &txid, &txid_len, nonce);
    if (rc != WOLFCERT_OK)
        return rc;

    uint8_t* resp = NULL;
    size_t resp_len = 0;
    rc = run_pki_op(srv, caps, pki.data, pki.len, &resp, &resp_len);
    wolfcert_buffer_free(&pki);

    if (rc == WOLFCERT_OK) {
        rc = scep_finish(heap, resp, resp_len, ca_bundle, ca_bundle_len,
                         signer_cert, signer_cert_len, signer_key, signer_key_len,
                         txid, txid_len, nonce, out);
        WOLFCERT_XFREE(resp, heap);
    }

    wc_ForceZero(nonce, (word32)sizeof(nonce));
    WOLFCERT_XFREE(txid, heap);

    return rc;
}

/* The caller has already checked that key->type is WOLFCERT_KEY_RSA. */
static int rsa_key_to_der(const WolfCertKey* key, void* heap,
                          uint8_t** out_der, size_t* out_len)
{
    size_t bits = key->rsa_bits ? (size_t)key->rsa_bits : 4096;
    size_t cap = bits + 2048;
    uint8_t* der = (uint8_t*)WOLFCERT_XMALLOC(cap, heap);
    int n;

    if (der == NULL)
        return WOLFCERT_ERR_MEMORY;

    n = wc_RsaKeyToDer((RsaKey*)key->impl, der, (word32)cap);
    if (n <= 0) {
        wc_ForceZero(der, (word32)cap);
        WOLFCERT_XFREE(der, heap);
        return WOLFCERT_ERR_WC(n, "scep", "RsaKeyToDer");
    }

    *out_der = der;
    *out_len = (size_t)n;

    return WOLFCERT_OK;
}

int wolfcert_scep_pkcs_req_ex(const WolfCertServerCfg* srv,
                              const WolfCertScepCaps*  caps,
                              const uint8_t* ra_cert, size_t ra_cert_len,
                              const uint8_t* ca_bundle, size_t ca_bundle_len,
                              const WolfCertKey*       new_key,
                              const uint8_t* csr_der, size_t csr_der_len,
                              WolfCertScepResult*      out)
{
    if (out == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    memset(out, 0, sizeof(*out));
    out->fail_info = -1;

    if (srv == NULL || ra_cert == NULL || ra_cert_len == 0 ||
        ca_bundle == NULL || ca_bundle_len == 0 || new_key == NULL ||
        csr_der == NULL || csr_der_len == 0)
        return WOLFCERT_ERR_BAD_ARG;

    if (new_key->type != WOLFCERT_KEY_RSA)
        return WOLFCERT_ERR(WOLFCERT_ERR_UNSUPPORTED, "scep",
            "SCEP (RFC 8894) requires an RSA signer for pkiMessage; "
            "Ed25519/Ed448/ML-DSA are not permitted");
    void* heap = srv->heap ? srv->heap : wolfcert_default_heap();
    int trc = scep_check_cfg(srv, heap);
    if (trc != WOLFCERT_OK)
        return trc;

    uint8_t* signer_der = NULL;
    size_t signer_len = 0;
    int rc = wolfcert_scep_self_signed_rsa((RsaKey*)new_key->impl,
                                            csr_der, csr_der_len,
                                            &signer_der, &signer_len, heap);
    if (rc != WOLFCERT_OK)
        return rc;

    uint8_t* key_der = NULL;
    size_t key_der_len = 0;
    rc = rsa_key_to_der(new_key, heap, &key_der, &key_der_len);
    if (rc != WOLFCERT_OK) {
        WOLFCERT_XFREE(signer_der, heap);
        return rc;
    }

    rc = do_scep_round_trip(srv, caps, ra_cert, ra_cert_len,
                            ca_bundle, ca_bundle_len,
                            signer_der, signer_len, key_der, key_der_len,
                            "19", csr_der, csr_der_len,
                            NULL, 0, out);

    WOLFCERT_XFREE(signer_der, heap);
    wc_ForceZero(key_der, (word32)key_der_len);
    WOLFCERT_XFREE(key_der, heap);
    return rc;
}

int wolfcert_scep_pkcs_req(const WolfCertServerCfg* srv,
                           const WolfCertScepCaps*  caps,
                           const uint8_t* ra_cert, size_t ra_cert_len,
                           const WolfCertKey*       new_key,
                           const uint8_t* csr_der, size_t csr_der_len,
                           WolfCertBuffer*          out_cert_pem)
{
    if (out_cert_pem == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    /* ra_cert doubles as the one-cert trust bundle. */
    WolfCertScepResult r = { 0 };
    int rc = wolfcert_scep_pkcs_req_ex(srv, caps, ra_cert, ra_cert_len,
                                       ra_cert, ra_cert_len,
                                       new_key, csr_der, csr_der_len, &r);
    if (rc != WOLFCERT_OK) {
        wolfcert_scep_result_free(&r);
        return rc;
    }

    if (r.status == WOLFCERT_SCEP_STATUS_SUCCESS) {
        *out_cert_pem = r.cert_pem;
        r.cert_pem.data = NULL;
        r.cert_pem.len = 0;
        wolfcert_scep_result_free(&r);
        return WOLFCERT_OK;
    }

    int err = r.status == WOLFCERT_SCEP_STATUS_PENDING
              ? WOLFCERT_ERR_PENDING : WOLFCERT_ERR_PROTOCOL;

    wolfcert_scep_result_free(&r);
    return err;
}

int wolfcert_scep_renewal_req_ex(const WolfCertServerCfg* srv,
                                 const WolfCertScepCaps*  caps,
                                 const uint8_t* ra_cert, size_t ra_cert_len,
                                 const uint8_t* ca_bundle, size_t ca_bundle_len,
                                 const uint8_t* current_cert, size_t current_cert_len,
                                 const WolfCertKey* current_key,
                                 const uint8_t* csr_der, size_t csr_der_len,
                                 WolfCertScepResult* out)
{
    if (out == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    memset(out, 0, sizeof(*out));
    out->fail_info = -1;

    if (srv == NULL || ra_cert == NULL || ra_cert_len == 0 ||
            ca_bundle == NULL || ca_bundle_len == 0 ||
            current_cert == NULL || current_cert_len == 0 ||
            current_key == NULL || csr_der == NULL || csr_der_len == 0)
        return WOLFCERT_ERR_BAD_ARG;

    if (current_key->type != WOLFCERT_KEY_RSA)
        return WOLFCERT_ERR(WOLFCERT_ERR_UNSUPPORTED, "scep",
            "SCEP (RFC 8894) requires an RSA signer for pkiMessage; "
            "Ed25519/Ed448/ML-DSA are not permitted");
    void* heap = srv->heap ? srv->heap : wolfcert_default_heap();
    int trc = scep_check_cfg(srv, heap);
    if (trc != WOLFCERT_OK)
        return trc;

    uint8_t* key_der = NULL;
    size_t key_der_len = 0;
    int rc = rsa_key_to_der(current_key, heap, &key_der, &key_der_len);
    if (rc != WOLFCERT_OK)
        return rc;

    rc = do_scep_round_trip(srv, caps, ra_cert, ra_cert_len,
                            ca_bundle, ca_bundle_len,
                            current_cert, current_cert_len,
                            key_der, key_der_len,
                            scep_renewal_msg_type(
                                srv->proto_opts.scep.renewal_msg_type),
                            csr_der, csr_der_len,
                            NULL, 0, out);

    wc_ForceZero(key_der, (word32)key_der_len);
    WOLFCERT_XFREE(key_der, heap);
    return rc;
}

int wolfcert_scep_renewal_req(const WolfCertServerCfg* srv,
                              const WolfCertScepCaps*  caps,
                              const uint8_t* ra_cert, size_t ra_cert_len,
                              const uint8_t* current_cert, size_t current_cert_len,
                              const WolfCertKey* current_key,
                              const uint8_t* csr_der, size_t csr_der_len,
                              WolfCertBuffer* out_cert_pem)
{
    if (out_cert_pem == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    /* ra_cert doubles as the one-cert trust bundle. */
    WolfCertScepResult r = { 0 };
    int rc = wolfcert_scep_renewal_req_ex(srv, caps, ra_cert, ra_cert_len,
                                          ra_cert, ra_cert_len,
                                          current_cert, current_cert_len,
                                          current_key,
                                          csr_der, csr_der_len, &r);

    if (rc != WOLFCERT_OK) {
        wolfcert_scep_result_free(&r);
        return rc;
    }

    if (r.status == WOLFCERT_SCEP_STATUS_SUCCESS) {
        *out_cert_pem = r.cert_pem;
        r.cert_pem.data = NULL;
        r.cert_pem.len = 0;
        wolfcert_scep_result_free(&r);
        return WOLFCERT_OK;
    }

    int err = r.status == WOLFCERT_SCEP_STATUS_PENDING
              ? WOLFCERT_ERR_PENDING : WOLFCERT_ERR_PROTOCOL;

    wolfcert_scep_result_free(&r);
    return err;
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
    if (out == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    memset(out, 0, sizeof(*out));
    out->fail_info = -1;

    if (srv == NULL || ra_cert == NULL || ra_cert_len == 0 ||
            ca_bundle == NULL || ca_bundle_len == 0 ||
            (signer_cert != NULL && signer_cert_len == 0) ||
            signer_key == NULL || csr_der == NULL || csr_der_len == 0 ||
            transaction_id == NULL || transaction_id_len == 0)
        return WOLFCERT_ERR_BAD_ARG;

    if (signer_key->type != WOLFCERT_KEY_RSA)
        return WOLFCERT_ERR(WOLFCERT_ERR_UNSUPPORTED, "scep",
            "SCEP (RFC 8894) requires an RSA signer for pkiMessage");
    void* heap = srv->heap ? srv->heap : wolfcert_default_heap();
    int trc = scep_check_cfg(srv, heap);
    if (trc != WOLFCERT_OK)
        return trc;


    WolfCertBuffer ias = { 0 };
    uint8_t* key_der = NULL;
    size_t key_der_len = 0;
    uint8_t* derived_signer = NULL;
    size_t derived_signer_len = 0;
    const uint8_t* eff_signer     = signer_cert;
    size_t         eff_signer_len = signer_cert_len;

    int rc = wolfcert_scep_issuer_and_subject(ra_cert, ra_cert_len,
                                              csr_der, csr_der_len, &ias, heap);

    if (rc == WOLFCERT_OK)
        rc = rsa_key_to_der(signer_key, heap, &key_der, &key_der_len);

    /* A pending PKCSReq has no signer cert; regenerate the transient
     * self-signed one that pkcs_req_ex used. */
    if (rc == WOLFCERT_OK && signer_cert == NULL) {
        rc = wolfcert_scep_self_signed_rsa((RsaKey*)signer_key->impl,
                                            csr_der, csr_der_len,
                                            &derived_signer, &derived_signer_len,
                                            heap);
        if (rc == WOLFCERT_OK) {
            eff_signer     = derived_signer;
            eff_signer_len = derived_signer_len;
        }
    }

    if (rc == WOLFCERT_OK)
        rc = do_scep_round_trip(srv, caps, ra_cert, ra_cert_len,
                                ca_bundle, ca_bundle_len,
                                eff_signer, eff_signer_len,
                                key_der, key_der_len,
                                "20", ias.data, ias.len,
                                transaction_id, transaction_id_len, out);

    wolfcert_buffer_free(&ias);
    if (key_der != NULL) {
        wc_ForceZero(key_der, (word32)key_der_len);
        WOLFCERT_XFREE(key_der, heap);
    }
    WOLFCERT_XFREE(derived_signer, heap);
    return rc;
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

int wolfcert_scep_get_cert(const WolfCertServerCfg* srv,
                           const WolfCertScepCaps* caps,
                           const uint8_t* ra_cert, size_t ra_cert_len,
                           const uint8_t* ca_bundle, size_t ca_bundle_len,
                           const uint8_t* signer_cert, size_t signer_cert_len,
                           const WolfCertKey* signer_key,
                           const uint8_t* serial, size_t serial_len,
                           WolfCertScepResult* out)
{
    if (out == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    memset(out, 0, sizeof(*out));
    out->fail_info = -1;

    if (srv == NULL || ra_cert == NULL || ra_cert_len == 0 ||
            ca_bundle == NULL || ca_bundle_len == 0 ||
            signer_cert == NULL || signer_cert_len == 0 || signer_key == NULL ||
            serial == NULL || serial_len == 0)
        return WOLFCERT_ERR_BAD_ARG;

    if (signer_key->type != WOLFCERT_KEY_RSA)
        return WOLFCERT_ERR(WOLFCERT_ERR_UNSUPPORTED, "scep",
            "SCEP (RFC 8894) requires an RSA signer for pkiMessage");
    void* heap = srv->heap ? srv->heap : wolfcert_default_heap();
    int trc = scep_check_cfg(srv, heap);
    if (trc != WOLFCERT_OK)
        return trc;

    WolfCertBuffer ias = { 0 };
    uint8_t* key_der = NULL;
    size_t   key_der_len = 0;
    const uint8_t* want_issuer = NULL;
    size_t         want_issuer_len = 0;
    const uint8_t* want_serial = NULL;
    size_t         want_serial_len = 0;

    int rc = wolfcert_scep_issuer_and_serial(ra_cert, ra_cert_len,
                                             serial, serial_len, &ias, heap);

    /* Match the response against the issuer and serial as sent on the wire. */
    if (rc == WOLFCERT_OK)
        rc = wolfcert_scep_parse_issuer_and_serial(ias.data, ias.len,
                                                   &want_issuer, &want_issuer_len,
                                                   &want_serial, &want_serial_len);

    if (rc == WOLFCERT_OK)
        rc = rsa_key_to_der(signer_key, heap, &key_der, &key_der_len);

    if (rc == WOLFCERT_OK)
        rc = do_scep_round_trip(srv, caps, ra_cert, ra_cert_len,
                                ca_bundle, ca_bundle_len,
                                signer_cert, signer_cert_len,
                                key_der, key_der_len,
                                "21", ias.data, ias.len, NULL, 0, out);

    if (rc == WOLFCERT_OK && out->status == WOLFCERT_SCEP_STATUS_SUCCESS) {
        int has = wolfcert_scep_pem_has_cert(out->cert_pem.data,
                                             out->cert_pem.len,
                                             want_issuer, want_issuer_len,
                                             want_serial, want_serial_len, heap);
        if (has != 1) {
            wolfcert_buffer_free(&out->cert_pem);
            out->status = WOLFCERT_SCEP_STATUS_UNSET;
            rc = (has < 0) ? has : WOLFCERT_ERR(WOLFCERT_ERR_PROTOCOL, "scep",
                "GetCert returned no certificate with the requested issuer and serial");
        }
    }

    wolfcert_buffer_free(&ias);
    if (key_der != NULL) {
        wc_ForceZero(key_der, (word32)key_der_len);
        WOLFCERT_XFREE(key_der, heap);
    }

    return rc;
}

int wolfcert_scep_get_next_ca_cert(const WolfCertServerCfg* srv,
                                   const uint8_t* current_ca_der,
                                   size_t current_ca_len,
                                   WolfCertBuffer* out_next_ca_pem)
{
    if (srv == NULL || srv->server_url == NULL ||
            current_ca_der == NULL || out_next_ca_pem == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    void* heap = srv->heap ? srv->heap : wolfcert_default_heap();
    int trc = scep_check_cfg(srv, heap);
    if (trc != WOLFCERT_OK)
        return trc;


    char* url = wolfcert_scep_build_getca_url(srv->server_url, "GetNextCACert",
                                              srv->proto_opts.scep.ca_id, heap);
    if (url == NULL)
        return WOLFCERT_ERR_MEMORY;

    WolfCertHttpRequest req = { .method = "GET", .url = url };
    fill_common(srv, &req);

    WolfCertHttpResponse resp = { 0 };
    int rc = wolfcert_http_request(&req, &resp);

    WOLFCERT_XFREE(url, heap);
    if (rc != WOLFCERT_OK)
        return rc;

    if (resp.status_code == 404) {
        wolfcert_http_response_free(&resp);
        return WOLFCERT_ERR_NOT_FOUND;
    }

    if (resp.status_code != 200) {
        wolfcert_http_response_free(&resp);
        return WOLFCERT_ERR_HTTP;
    }

    /* RFC 8894 section 4.7.1: the current CA signs a SignedData whose content
     * is a certs-only bundle holding the next CA cert. */
    rc = wolfcert_scep_verify_next_ca_response(resp.body, resp.body_len,
            current_ca_der, current_ca_len, out_next_ca_pem, heap);

    wolfcert_http_response_free(&resp);
    return rc;
}

/* The PKIOperation in the session's single in-flight slot. */
enum scep_session_op {
    SCEP_SESS_OP_PKCS_REQ = 0,
    SCEP_SESS_OP_RENEWAL,
    SCEP_SESS_OP_GET_CERT_INITIAL
};

struct WolfCertScepSession {
    WolfCertHttpSession*      http;
    char*                     server_url;     /* full SCEP endpoint URL, owned */
    void*                     heap;
    int                       nonblocking;    /* opened via _open_async */
    WolfCertScepTxidMode       txid_mode;
    WolfCertScepContentCipher  content_cipher;
    WolfCertScepRenewalMsgType renewal_msg_type;

    /* In-flight state of the single active round trip. */
    int                  in_active;
    int                  in_op;        /* enum scep_session_op, valid when in_active */
    char*                in_url;       /* owned request URL */
    WolfCertBuffer       in_pki;       /* built pkiMessage, owned (POST body) */
    WolfCertHttpRequest  in_req;
    WolfCertHttpResponse in_resp;

    uint8_t* in_ca_bundle;   size_t in_ca_bundle_len;    /* owned copy */
    uint8_t* in_signer;      size_t in_signer_len;       /* owned copy */
    uint8_t* in_signer_key;  size_t in_signer_key_len;   /* owned copy, zeroized */
    uint8_t* in_txid;        size_t in_txid_len;         /* owned, from scep_prepare */
    uint8_t  in_nonce[SCEP_NONCE_SZ];
    WolfCertScepResult* in_out;
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

static int scep_session_open_common(const WolfCertServerCfg* srv, int nonblocking,
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

    if (u.tls && !srv->verify_server) {
        wolfcert_http_url_free(&u);
        return WOLFCERT_ERR(WOLFCERT_ERR_TLS, "scep",
            "TLS SCEP endpoint requires server authentication: set verify_server "
            "or use a plaintext http:// URL");
    }

    char* origin = NULL;
    rc = wolfcert_http_url_origin(&u, heap, &origin);
    wolfcert_http_url_free(&u);
    if (rc != WOLFCERT_OK)
        return rc;

    WolfCertScepSession* s = (WolfCertScepSession*)WOLFCERT_XMALLOC(sizeof(*s), heap);
    if (s == NULL) {
        WOLFCERT_XFREE(origin, heap);
        return WOLFCERT_ERR_MEMORY;
    }

    memset(s, 0, sizeof(*s));
    s->heap           = heap;
    s->nonblocking    = nonblocking;
    s->txid_mode        = srv->proto_opts.scep.txid_mode;
    s->content_cipher   = srv->proto_opts.scep.content_cipher;
    s->renewal_msg_type = srv->proto_opts.scep.renewal_msg_type;
    s->server_url     = wolfcert_strdup(srv->server_url, heap);
    if (s->server_url == NULL) {
        WOLFCERT_XFREE(s, heap);
        WOLFCERT_XFREE(origin, heap);
        return WOLFCERT_ERR_MEMORY;
    }

    WolfCertHttpSessionCfg hcfg = {
        .base_url           = origin,
        .trust_anchors      = srv->trust_anchors,
        .trust_anchors_len  = srv->trust_anchors_len,
        .verify_server      = srv->verify_server,
        .timeout_ms         = srv->timeout_ms,
        .max_response_bytes = srv->max_response_bytes,
        .client_cert        = srv->client_cert,
        .client_cert_len    = srv->client_cert_len,
        .client_key         = srv->client_key,
        .client_key_len     = srv->client_key_len,
        .nonblocking        = nonblocking,
        .transport          = srv->transport,
        .heap               = heap,
    };
    rc = wolfcert_http_session_open(&hcfg, &s->http);

    WOLFCERT_XFREE(origin, heap);
    if (rc != WOLFCERT_OK) {
        WOLFCERT_XFREE(s->server_url, heap);
        WOLFCERT_XFREE(s, heap);
        return rc;
    }

    *out = s;
    return WOLFCERT_OK;
}

int wolfcert_scep_session_open(const WolfCertServerCfg* srv, WolfCertScepSession** out)
{
    return scep_session_open_common(srv, 0, out);
}

int wolfcert_scep_session_open_async(const WolfCertServerCfg* srv, WolfCertScepSession** out)
{
    return scep_session_open_common(srv, 1, out);
}

int wolfcert_scep_session_fd(const WolfCertScepSession* s)
{
    return s != NULL ? wolfcert_http_session_fd(s->http) : -1;
}

static void scep_async_reset(WolfCertScepSession* s)
{
    WOLFCERT_XFREE(s->in_url, s->heap);
    s->in_url = NULL;
    wolfcert_buffer_free(&s->in_pki);
    wolfcert_http_response_free(&s->in_resp);
    memset(&s->in_req,  0, sizeof(s->in_req));
    memset(&s->in_resp, 0, sizeof(s->in_resp));

    WOLFCERT_XFREE(s->in_ca_bundle, s->heap);
    s->in_ca_bundle = NULL;
    s->in_ca_bundle_len = 0;
    WOLFCERT_XFREE(s->in_signer, s->heap);
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
    s->in_out    = NULL;
    s->in_active = 0;
}

void wolfcert_scep_session_close(WolfCertScepSession* s)
{
    if (s == NULL)
        return;

    scep_async_reset(s);
    if (s->http)
        wolfcert_http_session_close(s->http);

    WOLFCERT_XFREE(s->server_url, s->heap);
    WOLFCERT_XFREE(s, s->heap);
}

/* Copies the finish-phase inputs so they outlive the pumps. */
static int scep_session_begin(WolfCertScepSession* s, const WolfCertScepCaps* caps,
    const uint8_t* ra_cert, size_t ra_cert_len,
    const uint8_t* ca_bundle, size_t ca_bundle_len,
    const uint8_t* signer_cert, size_t signer_cert_len,
    const uint8_t* signer_key, size_t signer_key_len,
    const char* msg_type, int op,
    const uint8_t* envelope_content, size_t envelope_content_len,
    const uint8_t* txid_override, size_t txid_override_len,
    WolfCertScepResult* out)
{
    void* heap = s->heap;
    out->heap = heap;
    out->fail_info = -1;

    /* dup_buf also returns NULL for a zero length, so reject empty inputs. */
    if (ca_bundle_len == 0 || signer_cert_len == 0 || signer_key_len == 0)
        return WOLFCERT_ERR(WOLFCERT_ERR_BAD_ARG, "scep",
            "ca_bundle, signer cert and signer key must be non-empty");

    s->in_ca_bundle     = dup_buf(ca_bundle, ca_bundle_len, heap);
    s->in_ca_bundle_len = ca_bundle_len;
    s->in_signer        = dup_buf(signer_cert, signer_cert_len, heap);
    s->in_signer_len    = signer_cert_len;
    s->in_signer_key    = dup_buf(signer_key, signer_key_len, heap);
    s->in_signer_key_len = signer_key_len;
    if (s->in_ca_bundle == NULL || s->in_signer == NULL || s->in_signer_key == NULL) {
        scep_async_reset(s);
        return WOLFCERT_ERR_MEMORY;
    }

    ScepTxidSel txid_sel = {
        .id = txid_override, .id_len = txid_override_len, .mode = s->txid_mode
    };

    WolfCertBuffer pki = { 0 };
    int rc = scep_prepare(heap, caps, ra_cert, ra_cert_len,
                          signer_cert, signer_cert_len, signer_key, signer_key_len,
                          msg_type, envelope_content, envelope_content_len,
                          &txid_sel, s->content_cipher,
                          &pki, &s->in_txid, &s->in_txid_len, s->in_nonce);
    if (rc != WOLFCERT_OK) {
        scep_async_reset(s);
        return rc;
    }

    char* url = NULL;
    int   use_post = 0;
    rc = scep_build_transport(s->server_url, caps, pki.data, pki.len, heap,
                              &url, &use_post);
    if (rc != WOLFCERT_OK) {
        wolfcert_buffer_free(&pki);
        scep_async_reset(s);
        return rc;
    }

    s->in_pki = pki;   /* ownership moves to the session */
    s->in_url = url;
    /* The session ignores a per-request max_response_bytes; it uses the cap
     * from WolfCertHttpSessionCfg. */
    s->in_req = (WolfCertHttpRequest){
        .method             = use_post ? "POST" : "GET",
        .url                = url,
        .heap               = heap,
    };
    if (use_post) {
        s->in_req.content_type = "application/x-pki-message";
        s->in_req.body         = s->in_pki.data;
        s->in_req.body_len     = s->in_pki.len;
    }
    s->in_out    = out;
    s->in_op     = op;
    s->in_active = 1;

    return WOLFCERT_OK;
}

/* `rc` is the transport result, already past any WANT_* handling. */
static int scep_session_finish(WolfCertScepSession* s, int rc)
{
    if (rc != WOLFCERT_OK) {
        scep_async_reset(s);
        return rc;
    }

    if (s->in_resp.status_code != 200) {
        scep_async_reset(s);
        return WOLFCERT_ERR_HTTP;
    }

    rc = scep_finish(s->heap, s->in_resp.body, s->in_resp.body_len,
                     s->in_ca_bundle, s->in_ca_bundle_len,
                     s->in_signer, s->in_signer_len,
                     s->in_signer_key, s->in_signer_key_len,
                     s->in_txid, s->in_txid_len, s->in_nonce, s->in_out);
    scep_async_reset(s);
    return rc;
}

static int scep_session_drive_sync(WolfCertScepSession* s)
{
    int rc = wolfcert_http_session_request(s->http, &s->in_req, &s->in_resp);
    return scep_session_finish(s, rc);
}

static int scep_session_drive_nb(WolfCertScepSession* s)
{
    int rc = wolfcert_http_session_request_nb(s->http, &s->in_req, &s->in_resp);
    if (rc == WOLFCERT_ERR_WANT_READ || rc == WOLFCERT_ERR_WANT_WRITE)
        return rc;
    return scep_session_finish(s, rc);
}

/* A resumed _nb poll must name the in-flight operation and result. */
static int scep_session_resume_check(const WolfCertScepSession* s, int expected_op,
                                     const WolfCertScepResult* out)
{
    if (s->in_op != expected_op)
        return WOLFCERT_ERR(WOLFCERT_ERR_BAD_ARG, "scep",
            "a different SCEP operation is already in flight on this session");
    if (out != s->in_out)
        return WOLFCERT_ERR(WOLFCERT_ERR_BAD_ARG, "scep",
            "result pointer differs from the in-flight request; pass the "
            "same WolfCertScepResult* to each poll call");
    return WOLFCERT_OK;
}

static int scep_session_begin_pkcs_req(WolfCertScepSession* s,
    const WolfCertScepCaps* caps,
    const uint8_t* ra_cert, size_t ra_cert_len,
    const uint8_t* ca_bundle, size_t ca_bundle_len,
    const WolfCertKey* new_key, const uint8_t* csr_der, size_t csr_der_len,
    WolfCertScepResult* out)
{
    if (new_key->type != WOLFCERT_KEY_RSA)
        return WOLFCERT_ERR(WOLFCERT_ERR_UNSUPPORTED, "scep",
            "SCEP (RFC 8894) requires an RSA signer for pkiMessage");

    void* heap = s->heap;
    uint8_t* signer_der = NULL;
    size_t   signer_len = 0;
    int rc = wolfcert_scep_self_signed_rsa((RsaKey*)new_key->impl,
                                            csr_der, csr_der_len,
                                            &signer_der, &signer_len, heap);
    if (rc != WOLFCERT_OK)
        return rc;

    uint8_t* key_der = NULL;
    size_t   key_der_len = 0;
    rc = rsa_key_to_der(new_key, heap, &key_der, &key_der_len);
    if (rc != WOLFCERT_OK) {
        WOLFCERT_XFREE(signer_der, heap);
        return rc;
    }

    rc = scep_session_begin(s, caps, ra_cert, ra_cert_len, ca_bundle, ca_bundle_len,
                            signer_der, signer_len, key_der, key_der_len,
                            "19", SCEP_SESS_OP_PKCS_REQ,
                            csr_der, csr_der_len, NULL, 0, out);

    WOLFCERT_XFREE(signer_der, heap);
    wc_ForceZero(key_der, (word32)key_der_len);
    WOLFCERT_XFREE(key_der, heap);
    return rc;
}

static int scep_session_begin_renewal(WolfCertScepSession* s,
    const WolfCertScepCaps* caps,
    const uint8_t* ra_cert, size_t ra_cert_len,
    const uint8_t* ca_bundle, size_t ca_bundle_len,
    const uint8_t* current_cert, size_t current_cert_len,
    const WolfCertKey* current_key, const uint8_t* csr_der, size_t csr_der_len,
    WolfCertScepResult* out)
{
    if (current_key->type != WOLFCERT_KEY_RSA)
        return WOLFCERT_ERR(WOLFCERT_ERR_UNSUPPORTED, "scep",
            "SCEP (RFC 8894) requires an RSA signer for pkiMessage");

    void* heap = s->heap;
    uint8_t* key_der = NULL;
    size_t   key_der_len = 0;
    int rc = rsa_key_to_der(current_key, heap, &key_der, &key_der_len);
    if (rc != WOLFCERT_OK)
        return rc;

    rc = scep_session_begin(s, caps, ra_cert, ra_cert_len, ca_bundle, ca_bundle_len,
                            current_cert, current_cert_len, key_der, key_der_len,
                            scep_renewal_msg_type(s->renewal_msg_type),
                            SCEP_SESS_OP_RENEWAL,
                            csr_der, csr_der_len, NULL, 0, out);

    wc_ForceZero(key_der, (word32)key_der_len);
    WOLFCERT_XFREE(key_der, heap);
    return rc;
}

static int scep_session_begin_get_cert_initial(WolfCertScepSession* s,
    const WolfCertScepCaps* caps,
    const uint8_t* ra_cert, size_t ra_cert_len,
    const uint8_t* ca_bundle, size_t ca_bundle_len,
    const uint8_t* signer_cert, size_t signer_cert_len,
    const WolfCertKey* signer_key,
    const uint8_t* csr_der, size_t csr_der_len,
    const uint8_t* transaction_id, size_t transaction_id_len,
    WolfCertScepResult* out)
{
    if (signer_key->type != WOLFCERT_KEY_RSA)
        return WOLFCERT_ERR(WOLFCERT_ERR_UNSUPPORTED, "scep",
            "SCEP (RFC 8894) requires an RSA signer for pkiMessage");

    void* heap = s->heap;
    WolfCertBuffer ias = { 0 };
    int rc = wolfcert_scep_issuer_and_subject(ra_cert, ra_cert_len,
                                               csr_der, csr_der_len, &ias, heap);
    if (rc != WOLFCERT_OK)
        return rc;

    uint8_t* key_der = NULL;
    size_t   key_der_len = 0;
    rc = rsa_key_to_der(signer_key, heap, &key_der, &key_der_len);
    if (rc != WOLFCERT_OK) {
        wolfcert_buffer_free(&ias);
        return rc;
    }

    /* A pending PKCSReq has no signer cert; regenerate the transient one. */
    uint8_t* derived = NULL;
    size_t   derived_len = 0;
    const uint8_t* eff     = signer_cert;
    size_t         eff_len = signer_cert_len;
    if (signer_cert == NULL) {
        rc = wolfcert_scep_self_signed_rsa((RsaKey*)signer_key->impl,
                                            csr_der, csr_der_len,
                                            &derived, &derived_len, heap);
        if (rc != WOLFCERT_OK) {
            wolfcert_buffer_free(&ias);
            wc_ForceZero(key_der, (word32)key_der_len);
            WOLFCERT_XFREE(key_der, heap);
            return rc;
        }
        eff     = derived;
        eff_len = derived_len;
    }

    rc = scep_session_begin(s, caps, ra_cert, ra_cert_len, ca_bundle, ca_bundle_len,
                            eff, eff_len, key_der, key_der_len,
                            "20", SCEP_SESS_OP_GET_CERT_INITIAL, ias.data, ias.len,
                            transaction_id, transaction_id_len, out);

    wolfcert_buffer_free(&ias);
    wc_ForceZero(key_der, (word32)key_der_len);
    WOLFCERT_XFREE(key_der, heap);
    WOLFCERT_XFREE(derived, heap);
    return rc;
}

int wolfcert_scep_session_pkcs_req_ex(WolfCertScepSession* s,
    const WolfCertScepCaps* caps,
    const uint8_t* ra_cert, size_t ra_cert_len,
    const uint8_t* ca_bundle, size_t ca_bundle_len,
    const WolfCertKey* new_key, const uint8_t* csr_der, size_t csr_der_len,
    WolfCertScepResult* out)
{
    if (out == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    /* Clearing the in-flight result would wipe the running request's. */
    if (s == NULL || !s->in_active || out != s->in_out) {
        memset(out, 0, sizeof(*out));
        out->fail_info = -1;
    }

    if (s == NULL || caps == NULL || ra_cert == NULL || ra_cert_len == 0 ||
            ca_bundle == NULL || ca_bundle_len == 0 || new_key == NULL ||
            csr_der == NULL || csr_der_len == 0)
        return WOLFCERT_ERR_BAD_ARG;

    if (s->nonblocking)
        return WOLFCERT_ERR(WOLFCERT_ERR_BAD_ARG, "scep",
            "blocking _ex call on an async session; use the _nb variant");

    int rc = scep_session_begin_pkcs_req(s, caps, ra_cert, ra_cert_len,
                                         ca_bundle, ca_bundle_len,
                                         new_key, csr_der, csr_der_len, out);
    if (rc != WOLFCERT_OK)
        return rc;
    return scep_session_drive_sync(s);
}

int wolfcert_scep_session_pkcs_req_nb(WolfCertScepSession* s,
    const WolfCertScepCaps* caps,
    const uint8_t* ra_cert, size_t ra_cert_len,
    const uint8_t* ca_bundle, size_t ca_bundle_len,
    const WolfCertKey* new_key, const uint8_t* csr_der, size_t csr_der_len,
    WolfCertScepResult* out)
{
    if (out == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    if (s == NULL || !s->in_active || out != s->in_out) {
        memset(out, 0, sizeof(*out));
        out->fail_info = -1;
    }

    if (s == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    if (!s->nonblocking)
        return WOLFCERT_ERR(WOLFCERT_ERR_BAD_ARG, "scep",
            "non-blocking _nb call on a blocking session; use the _ex variant");

    if (!s->in_active) {
        if (caps == NULL || ra_cert == NULL || ra_cert_len == 0 ||
                ca_bundle == NULL || ca_bundle_len == 0 || new_key == NULL ||
                csr_der == NULL || csr_der_len == 0)
            return WOLFCERT_ERR_BAD_ARG;
        int rc = scep_session_begin_pkcs_req(s, caps, ra_cert, ra_cert_len,
                                             ca_bundle, ca_bundle_len,
                                             new_key, csr_der, csr_der_len, out);
        if (rc != WOLFCERT_OK)
            return rc;
    }
    else {
        int rc = scep_session_resume_check(s, SCEP_SESS_OP_PKCS_REQ, out);
        if (rc != WOLFCERT_OK)
            return rc;
    }
    return scep_session_drive_nb(s);
}

int wolfcert_scep_session_renewal_req_ex(WolfCertScepSession* s,
    const WolfCertScepCaps* caps,
    const uint8_t* ra_cert, size_t ra_cert_len,
    const uint8_t* ca_bundle, size_t ca_bundle_len,
    const uint8_t* current_cert, size_t current_cert_len,
    const WolfCertKey* current_key, const uint8_t* csr_der, size_t csr_der_len,
    WolfCertScepResult* out)
{
    if (out == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    if (s == NULL || !s->in_active || out != s->in_out) {
        memset(out, 0, sizeof(*out));
        out->fail_info = -1;
    }

    if (s == NULL || caps == NULL || ra_cert == NULL || ra_cert_len == 0 ||
            ca_bundle == NULL || ca_bundle_len == 0 || current_cert == NULL ||
            current_cert_len == 0 || current_key == NULL || csr_der == NULL ||
            csr_der_len == 0)
        return WOLFCERT_ERR_BAD_ARG;

    if (s->nonblocking)
        return WOLFCERT_ERR(WOLFCERT_ERR_BAD_ARG, "scep",
            "blocking _ex call on an async session; use the _nb variant");

    int rc = scep_session_begin_renewal(s, caps, ra_cert, ra_cert_len,
                                        ca_bundle, ca_bundle_len,
                                        current_cert, current_cert_len,
                                        current_key, csr_der, csr_der_len, out);
    if (rc != WOLFCERT_OK)
        return rc;
    return scep_session_drive_sync(s);
}

int wolfcert_scep_session_renewal_req_nb(WolfCertScepSession* s,
    const WolfCertScepCaps* caps,
    const uint8_t* ra_cert, size_t ra_cert_len,
    const uint8_t* ca_bundle, size_t ca_bundle_len,
    const uint8_t* current_cert, size_t current_cert_len,
    const WolfCertKey* current_key, const uint8_t* csr_der, size_t csr_der_len,
    WolfCertScepResult* out)
{
    if (out == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    if (s == NULL || !s->in_active || out != s->in_out) {
        memset(out, 0, sizeof(*out));
        out->fail_info = -1;
    }

    if (s == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    if (!s->nonblocking)
        return WOLFCERT_ERR(WOLFCERT_ERR_BAD_ARG, "scep",
            "non-blocking _nb call on a blocking session; use the _ex variant");

    if (!s->in_active) {
        if (caps == NULL || ra_cert == NULL || ra_cert_len == 0 || ca_bundle == NULL ||
                ca_bundle_len == 0 || current_cert == NULL || current_cert_len == 0 ||
                current_key == NULL || csr_der == NULL || csr_der_len == 0)
            return WOLFCERT_ERR_BAD_ARG;
        int rc = scep_session_begin_renewal(s, caps, ra_cert, ra_cert_len,
                                            ca_bundle, ca_bundle_len,
                                            current_cert, current_cert_len,
                                            current_key, csr_der, csr_der_len, out);
        if (rc != WOLFCERT_OK)
            return rc;
    }
    else {
        int rc = scep_session_resume_check(s, SCEP_SESS_OP_RENEWAL, out);
        if (rc != WOLFCERT_OK)
            return rc;
    }
    return scep_session_drive_nb(s);
}

int wolfcert_scep_session_get_cert_initial_ex(WolfCertScepSession* s,
    const WolfCertScepCaps* caps,
    const uint8_t* ra_cert, size_t ra_cert_len,
    const uint8_t* ca_bundle, size_t ca_bundle_len,
    const uint8_t* signer_cert, size_t signer_cert_len,
    const WolfCertKey* signer_key,
    const uint8_t* csr_der, size_t csr_der_len,
    const uint8_t* transaction_id, size_t transaction_id_len,
    WolfCertScepResult* out)
{
    if (out == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    if (s == NULL || !s->in_active || out != s->in_out) {
        memset(out, 0, sizeof(*out));
        out->fail_info = -1;
    }

    if (s == NULL || caps == NULL || ra_cert == NULL || ra_cert_len == 0 ||
            ca_bundle == NULL || ca_bundle_len == 0 || signer_key == NULL ||
            csr_der == NULL || csr_der_len == 0 || transaction_id == NULL ||
            transaction_id_len == 0)
        return WOLFCERT_ERR_BAD_ARG;

    if (s->nonblocking)
        return WOLFCERT_ERR(WOLFCERT_ERR_BAD_ARG, "scep",
            "blocking _ex call on an async session; use the _nb variant");

    int rc = scep_session_begin_get_cert_initial(s, caps, ra_cert, ra_cert_len,
                ca_bundle, ca_bundle_len, signer_cert, signer_cert_len, signer_key,
                csr_der, csr_der_len, transaction_id, transaction_id_len, out);
    if (rc != WOLFCERT_OK)
        return rc;
    return scep_session_drive_sync(s);
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
    if (out == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    if (s == NULL || !s->in_active || out != s->in_out) {
        memset(out, 0, sizeof(*out));
        out->fail_info = -1;
    }

    if (s == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    if (!s->nonblocking)
        return WOLFCERT_ERR(WOLFCERT_ERR_BAD_ARG, "scep",
            "non-blocking _nb call on a blocking session; use the _ex variant");

    if (!s->in_active) {
        if (caps == NULL || ra_cert == NULL || ra_cert_len == 0 || ca_bundle == NULL ||
                ca_bundle_len == 0 || signer_key == NULL || csr_der == NULL ||
                csr_der_len == 0 || transaction_id == NULL || transaction_id_len == 0)
            return WOLFCERT_ERR_BAD_ARG;
        int rc = scep_session_begin_get_cert_initial(s, caps, ra_cert, ra_cert_len,
                    ca_bundle, ca_bundle_len, signer_cert, signer_cert_len, signer_key,
                    csr_der, csr_der_len, transaction_id, transaction_id_len, out);
        if (rc != WOLFCERT_OK)
            return rc;
    }
    else {
        int rc = scep_session_resume_check(s, SCEP_SESS_OP_GET_CERT_INITIAL, out);
        if (rc != WOLFCERT_OK)
            return rc;
    }
    return scep_session_drive_nb(s);
}
