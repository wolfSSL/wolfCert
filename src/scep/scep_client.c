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

#include <wolfssl/options.h>
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
#include <strings.h>

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

/* No HTTP Basic credentials here, unlike EST: RFC 8894 authenticates the
 * enrollment inside the pkiMessage - the CMS signature bound to the CA/RA
 * bundle plus the PKCS#9 challengePassword - and defines nothing at the HTTP
 * layer. */
static void fill_common(const WolfCertServerCfg* srv, WolfCertHttpRequest* req)
{
    req->trust_anchors      = srv->trust_anchors;
    req->trust_anchors_len  = srv->trust_anchors_len;
    req->verify_server      = srv->verify_server;
    req->timeout_ms         = srv->timeout_ms;
    req->max_response_bytes = srv->max_response_bytes;
    req->heap               = srv->heap;

    /* mTLS identity for the outer transport. RFC 8894 authenticates the
     * pkiMessage via its signed-data wrapper, but some deployments still
     * require mTLS on the outer HTTPS connection. */
    req->client_cert        = srv->client_cert;
    req->client_cert_len    = srv->client_cert_len;
    req->client_key         = srv->client_key;
    req->client_key_len     = srv->client_key_len;
    req->connect_cb         = srv->connect_cb;
    req->connect_ctx        = srv->connect_ctx;
}

/* ---- GetCACaps ---------------------------------------------------------- */

/* RFC 8894 section 3.5.2: GetCACaps is a newline-delimited list of exact
 * capability tokens. Match a whole line, not a substring, so an unknown
 * token that merely contains a known one is not mistaken for it. */
static int has_cap(const char* body, size_t len, const char* needle)
{
    size_t nl;
    size_t i = 0;

    /* Guard both pointers before dereferencing either: strlen(needle)
     * below and body[] indexing in the scan. `len` needs no separate
     * bound - every body[] access is gated by `i < len`, and the
     * strncasecmp only fires when the matched token length equals nl,
     * so it never reads past body + len. */
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

        if (tlen == nl && strncasecmp(body + start, needle, nl) == 0)
            return 1;

        if (i < len)
            ++i;
    }

    return 0;
}

/* Validate the config before it is used. The protocol check comes first: it
 * gates every read of proto_opts.scep below, which would otherwise reinterpret
 * an EST arm's storage as the CA identifier and the cipher selectors.
 *
 * SCEP itself does not require TLS: RFC 8894 authenticates at the pkiMessage
 * layer and plaintext http:// is legitimate. But an https:// endpoint must
 * still be authenticated, since verify_server is the sole peer-verification
 * switch and leaving it off would complete a silent, unauthenticated
 * handshake. The session open applies the same rules; this is the one-shot
 * half of it. */
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

    int is_p7 = resp.content_type != NULL &&
                strstr(resp.content_type, "x-x509-ca-ra-cert") != NULL;
    if (is_p7) {
        if (enc == WOLFCERT_ENCODING_DER) {
            rc = wolfcert_pkcs7_certs_to_der(resp.body, resp.body_len, out_ca, heap);
        }
        else {
            rc = wolfcert_pkcs7_certs_to_pem(resp.body, resp.body_len, out_ca, heap);
        }
    }
    else if (enc == WOLFCERT_ENCODING_DER) {
        /* Single CA cert; the body is already DER - hand back a copy the
         * caller owns. */
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
    /* SHA-512 (64 bytes) is the widest digest we produce. */
    uint8_t digest[64];
    size_t  digest_len = 0;
    int     rc = 0;

    if (ca_der == NULL || ca_der_len == 0 || expected == NULL || expected_len == 0)
        return WOLFCERT_ERR_BAD_ARG;

    /* AUTO: identify the algorithm from the supplied fingerprint length. This
     * is a legacy convenience; a 20-byte value maps to collision-weak SHA-1, so
     * callers that know the digest should pass it explicitly (see scep.h). */
    if (alg == WOLFCERT_SCEP_FP_AUTO) {
        switch (expected_len) {
            case 20: alg = WOLFCERT_SCEP_FP_SHA1;   break; /* SHA-1 (legacy) */
            case 32: alg = WOLFCERT_SCEP_FP_SHA256; break; /* SHA-256 */
            case 64: alg = WOLFCERT_SCEP_FP_SHA512; break; /* SHA-512 */
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

    /* An explicit algorithm with a mismatched length is a caller error. */
    if (expected_len != digest_len)
        return WOLFCERT_ERR(WOLFCERT_ERR_BAD_ARG, "scep",
            "expected fingerprint length does not match the digest size");

    if (wc_ConstantCompare(expected, digest, (int)digest_len) != 0)
        return WOLFCERT_ERR(WOLFCERT_ERR_AUTH, "scep",
            "CA certificate fingerprint mismatch");

    return WOLFCERT_OK;
}

/* ---- PKCSReq / RenewalReq ---------------------------------------------- */

static int pick_hash_oid(const WolfCertScepCaps* caps)
{
    if (caps == NULL)
        return SHA256h;
    if (caps->sha512)
        return SHA512h;
    if (caps->sha384)
        return SHA384h;

    return SHA256h;
}

/* Percent-encode `in` into a freshly allocated NUL-terminated string, escaping
 * every byte outside the RFC 3986 unreserved set so the base64 pkiMessage is
 * safe inside a URL query value. Returns NULL on allocation failure. */
static char* url_encode(const uint8_t* in, size_t in_len, void* heap)
{
    /* Worst case each byte expands to "%XX" (3 chars), plus the NUL. */
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
            /* RFC 3986 section 2.1: upper-case hex digits are the normal form. */
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

    /* RFC 8894 section 4.2/4.5: the `message` for GetCACert / GetCACaps is the
     * CA identifier, which the caller may omit entirely. */
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

/* Build the HTTP GET URL for a PKIOperation fallback (RFC 8894 section 4.1):
 *   base?operation=PKIOperation&message=<url-encoded base64 pkiMessage>
 * Returns WOLFCERT_OK with *out_url owned by the caller, WOLFCERT_ERR_MEMORY,
 * or WOLFCERT_ERR_UNSUPPORTED when the encoded URL would exceed
 * WOLFCERT_SCEP_MAX_GET_URL (message too large for GET). */
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

/* Decide the PKIOperation transport (RFC 8894 section 4.1) and build the
 * request URL: POST when the CA advertises POSTPKIOperation (assumed when caps
 * are unknown), otherwise a base64 GET carrying the message in the query. Sets
 * *out_url (owned by caller) and *out_use_post. Shared by the one-shot and
 * session clients. */
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

/* messageType for a renewal. The signer is the certificate being replaced
 * either way; only the attribute differs, so a CA that predates RenewalReq can
 * be given the messageType 19 it expects. */
static const char* scep_renewal_msg_type(WolfCertScepRenewalMsgType m)
{
    return (m == WOLFCERT_SCEP_RENEWAL_MSG_PKCS_REQ) ? "19" : "17";
}

/* Shared SCEP round-trip sizes. */
#define SCEP_NONCE_SZ 16
/* A random transactionID is 16 RNG bytes expanded to 32 hex characters. */
#define SCEP_TXID_RAND_SZ 16

/* Which transactionID one round trip carries. An `id` inherited from an earlier
 * request in the same transaction (the GetCertInitial poll that follows a
 * pending PKCSReq) always wins; otherwise the ID is derived per `mode`. */
typedef struct {
    const uint8_t*       id;      /* explicit transactionID, or NULL to derive */
    size_t               id_len;
    WolfCertScepTxidMode mode;    /* derivation used when `id` is NULL */
} ScepTxidSel;

/* Derive a transactionID from the signer's public key (RFC 8894 section 3.2.1):
 * SHA-256 over the subjectPublicKey BIT STRING contents, which is what
 * DecodedCert.publicKey spans, upper-case hex encoded (64 chars). That is the
 * same input wolfSSL's PKCS7.publicKey carries, so the value matches what a
 * wolfSCEP-based peer derives, and it is the key itself rather than the
 * enclosing SubjectPublicKeyInfo with its AlgorithmIdentifier. Retries of the
 * same key therefore reuse one transactionID. *out_txid is heap-allocated and
 * owned by the caller. */
static int derive_txid_pubkey(const uint8_t* signer_cert, size_t signer_cert_len,
                              uint8_t** out_txid, size_t* out_txid_len, void* heap)
{
    /* DecodedCert is a couple of KiB - more than an MCU task stack wants to
     * carry - so it goes on the heap-hint-aware heap like every other sizeable
     * wolfCert allocation. */
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

    /* Upper-case hex, per wolfSCEP. */
    wolfcert_hex_encode(digest, WC_SHA256_DIGEST_SIZE, 1, (char*)txid);
    *out_txid     = txid;
    *out_txid_len = hexlen;
    return WOLFCERT_OK;
}

/* Produce the transactionID for one round trip per `sel`: copy an inherited ID
 * verbatim, derive it from the signer public key, or draw a fresh random one.
 * Only that last path touches `rng`, so a caller whose selection is inherited
 * or pubkey-derived never spends RNG output. *out_txid is heap-allocated and
 * owned by the caller. */
static int scep_build_txid(const ScepTxidSel* sel,
                           const uint8_t* signer_cert, size_t signer_cert_len,
                           WC_RNG* rng, void* heap,
                           uint8_t** out_txid, size_t* out_txid_len)
{
    /* Hold the transactionID on the heap rather than in a fixed buffer: an
     * inherited ID is whatever the server chose for the earlier request (RFC
     * 8894 puts no length bound on it), and the pubkey-hash form is 64 hex
     * chars against the random form's 32. */
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
        /* A partially filled draw shares a frame with the senderNonce the same
         * generator just produced, so clear it here too, not only on success. */
        wc_ForceZero(rand_bytes, (word32)sizeof(rand_bytes));
        return WOLFCERT_ERR_WC(rng_rc, "scep",
                               "RNG failed generating transactionID");
    }

    size_t hexlen = sizeof(rand_bytes) * 2;
    uint8_t* txid = (uint8_t*)WOLFCERT_XMALLOC(hexlen, heap);
    if (txid != NULL)
        wolfcert_hex_encode(rand_bytes, sizeof(rand_bytes), 0, (char*)txid);

    /* Not a secret - the transactionID travels in the clear as a signed
     * attribute - but the raw draw has no reason to outlive its expansion. */
    wc_ForceZero(rand_bytes, (word32)sizeof(rand_bytes));
    if (txid == NULL)
        return WOLFCERT_ERR_MEMORY;

    *out_txid     = txid;
    *out_txid_len = hexlen;
    return WOLFCERT_OK;
}

/* Build the enveloped + signed pkiMessage for one SCEP round trip. Produces the
 * DER message in *out_pki, the effective transactionID in *out_txid (owned by
 * the caller, free with WOLFCERT_XFREE) and the senderNonce in out_nonce - both
 * retained by the caller to validate the CertRep after the transport completes.
 * `cipher` overrides the content-encryption algorithm; `txid_sel` picks the
 * transactionID. */
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

    /* An explicit content cipher overrides the caps-driven choice, so a caller
     * can talk to a peer that requires a particular algorithm (e.g. a wolfSCEP
     * deployment expecting AES-256). AUTO keeps the RFC 8894 default: the
     * GetCACaps "AES" keyword advertises AES-128-CBC; otherwise fall back to
     * the mandatory-to-implement triple DES-CBC. A wolfSSL built without 3DES
     * cannot serve 3DES, so reject that request/fallback with a clear error
     * instead of a cryptic encoder failure. */
    switch (cipher) {
        case WOLFCERT_SCEP_CIPHER_AES128:
#if !defined(WOLFSSL_AES_128) || !defined(HAVE_AES_CBC)
            return WOLFCERT_ERR(WOLFCERT_ERR_UNSUPPORTED, "scep",
                "AES-128-CBC content cipher requested but wolfSSL lacks it");
#else
            enc_oid = AES128CBCb;
            break;
#endif
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
            /* The "AES" capability names AES-128-CBC and nothing else, so a
             * wolfSSL that cannot do AES-128 has to take the 3DES path even
             * against an AES-advertising peer rather than silently substitute
             * a cipher the CA never offered. */
#if defined(WOLFSSL_AES_128) && defined(HAVE_AES_CBC)
            if (caps != NULL && caps->aes) {
                enc_oid = AES128CBCb;
            }
            else
#endif
            {
#ifdef NO_DES3
                return WOLFCERT_ERR(WOLFCERT_ERR_UNSUPPORTED, "scep",
                    "no usable content cipher: AES-128-CBC unavailable or "
                    "unadvertised, and wolfSSL lacks the 3DES fallback");
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

    /* The anti-replay senderNonce always comes from the RNG. Ignoring a failure
     * here would build the pkiMessage over uninitialized stack memory and
     * silently weaken replay protection, so surface any generation error
     * instead. Clearing out_nonce on the way out keeps the caller from
     * mistaking leftovers for a usable senderNonce. */
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

/* Validate and consume a CertRep response: require messageType 3 with the
 * transactionID we sent, bind the signer to the CA/RA bundle, check the
 * recipientNonce echoes our senderNonce, then fill `out` with SUCCESS (+ the
 * issued cert in cert_pem), PENDING, or FAILURE. Reads but does not free
 * `resp`; `txid`/`nonce` are the values scep_prepare produced. */
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

    /* RFC 8894: an enrollment response is a CertRep (messageType 3) whose
     * transactionID echoes the one we sent. Reject a response that claims a
     * different type or transaction before consuming it. */
    if (rc == WOLFCERT_OK) {
        rc = wolfcert_scep_check_cert_rep(resp_mt, rx_tid, rx_tid_len,
                                          txid, txid_len);
        if (rc != WOLFCERT_OK)
            rc = WOLFCERT_ERR(WOLFCERT_ERR_PROTOCOL, "scep",
                              "CertRep messageType or transactionID does not "
                              "match the request");
    }
    WOLFCERT_XFREE(resp_mt, heap);

    /* wolfcert_scep_parse_pki_message only verifies the CMS signature against
     * the cert embedded in the response, so a MITM on the (often plaintext)
     * SCEP transport could forge a fully signed CertRep. Authenticate the
     * response by requiring its signer to be one of the CA/RA certs from the
     * GetCACert bundle before trusting anything it carries. */
    if (rc == WOLFCERT_OK) {
        rc = wolfcert_scep_verify_rep_signer(rx_signer, rx_signer_len,
                                             ca_bundle, ca_bundle_len, heap);
        if (rc != WOLFCERT_OK)
            rc = WOLFCERT_ERR(WOLFCERT_ERR_AUTH, "scep",
                              "CertRep is not signed by the CA/RA certificate");
    }
    WOLFCERT_XFREE(rx_signer, heap);

    /* RFC 8894 section 3.2.1.2: the CertRep MUST carry a recipientNonce that
     * echoes the senderNonce we sent. An absent or mismatched recipientNonce
     * means the response cannot be tied to our request (stale / replayed /
     * cross-talk / cannot verify) -> reject. */
    if (rc == WOLFCERT_OK &&
        (rx_rn == NULL || rx_rn_len != SCEP_NONCE_SZ ||
         memcmp(rx_rn, nonce, SCEP_NONCE_SZ) != 0)) {
        rc = WOLFCERT_ERR(WOLFCERT_ERR_PROTOCOL, "scep",
                          "CertRep recipientNonce missing or does not echo "
                          "senderNonce");
    }
    WOLFCERT_XFREE(rx_rn, heap);

    if (rc == WOLFCERT_OK) {
        /* Echo the transactionID in the result so callers can poll later;
         * ownership of rx_tid moves to out. */
        out->transaction_id     = rx_tid;
        out->transaction_id_len = rx_tid_len;
        rx_tid = NULL;

        if (status != NULL && strcmp(status, "3") == 0) {
            out->status = WOLFCERT_SCEP_STATUS_PENDING;
        }
        else if (status == NULL || strcmp(status, "0") != 0) {
            out->status = WOLFCERT_SCEP_STATUS_FAILURE;
            /* RFC 8894 section 3.2.1.4: a FAILURE CertRep carries a failInfo
             * PrintableString of "0".."4". Surface it to the caller; leave the
             * default -1 when the server omitted the attribute. */
            if (fail_info != NULL &&
                fail_info[0] >= '0' && fail_info[0] <= '4' &&
                fail_info[1] == '\0') {
                out->fail_info = fail_info[0] - '0';
            }
        }
        else {
            /* status "0" is SUCCESS: de-envelop the CertRep and convert the
             * issued certificate(s) to PEM for the caller. */
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

/* One-shot SCEP round trip for PKCSReq / RenewalReq / GetCertInitial: build the
 * enveloped + signed pkiMessage (scep_prepare), POST or base64-GET it
 * (run_pki_op), then parse + verify the CertRep and fill `out` (scep_finish).
 * Caller retains ownership of `txid_override`; when NULL the transactionID is
 * derived per srv->proto_opts.scep.txid_mode. */
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

    /* The senderNonce is raw RNG output: not a secret (it is sent in the clear
     * in the pkiMessage) but not worth leaving on the stack either. The
     * transactionID is a plain identifier - scep_finish hands the echoed copy
     * straight back to the caller in out->transaction_id - so it is only
     * freed. The signer key DER belongs to the caller, which zeroizes it. */
    wc_ForceZero(nonce, (word32)sizeof(nonce));
    WOLFCERT_XFREE(txid, heap);

    return rc;
}

/* Serialize the private key half of a WolfCertKey to DER for PKCS#7 use.
 * SCEP requires RSA (RFC 8894), so the caller has already validated
 * key->type == WOLFCERT_KEY_RSA. */
static int rsa_key_to_der(const WolfCertKey* key, void* heap,
                          uint8_t** out_der, size_t* out_len)
{
    /* DER size grows with the modulus; give it head room. */
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
    if (srv == NULL || ra_cert == NULL || ca_bundle == NULL ||
        new_key == NULL || csr_der == NULL || out == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    if (new_key->type != WOLFCERT_KEY_RSA)
        return WOLFCERT_ERR(WOLFCERT_ERR_UNSUPPORTED, "scep",
            "SCEP (RFC 8894) requires an RSA signer for pkiMessage; "
            "Ed25519/Ed448/ML-DSA are not permitted");

    memset(out, 0, sizeof(*out));
    out->fail_info = -1;
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

    /* Single-cert form: the envelope target doubles as the one-cert trust
     * bundle. Callers with a CA/RA bundle should use the _ex form. */
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
    if (srv == NULL || ra_cert == NULL || ca_bundle == NULL ||
            current_cert == NULL || current_key == NULL || csr_der == NULL ||
            out == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    if (current_key->type != WOLFCERT_KEY_RSA)
        return WOLFCERT_ERR(WOLFCERT_ERR_UNSUPPORTED, "scep",
            "SCEP (RFC 8894) requires an RSA signer for pkiMessage; "
            "Ed25519/Ed448/ML-DSA are not permitted");

    memset(out, 0, sizeof(*out));
    out->fail_info = -1;
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

    /* Single-cert form: the envelope target doubles as the one-cert trust
     * bundle. Callers with a CA/RA bundle should use the _ex form. */
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
    if (srv == NULL || ra_cert == NULL || ca_bundle == NULL ||
            signer_key == NULL || csr_der == NULL ||
            transaction_id == NULL || transaction_id_len == 0 || out == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    if (signer_key->type != WOLFCERT_KEY_RSA)
        return WOLFCERT_ERR(WOLFCERT_ERR_UNSUPPORTED, "scep",
            "SCEP (RFC 8894) requires an RSA signer for pkiMessage");

    memset(out, 0, sizeof(*out));
    out->fail_info = -1;
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

    /* For a pending PKCSReq the caller has no long-lived cert carrying
     * signer_key's pubkey, so we regenerate the same transient
     * self-signed cert (subject copied from the CSR) that pkcs_req_ex
     * wraps the original request with. RenewalReq callers supply their
     * existing cert directly. */
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

    /* RFC 8894 section 4.6.1: the body is a SignedData signed by the current
     * CA whose content is a degenerate certs-only bundle carrying the next CA
     * certificate. Verify the signature, bind it to the trusted current CA,
     * then extract the certs from the signed content rather than the outer
     * signer certificate. */
    rc = wolfcert_scep_verify_next_ca_response(resp.body, resp.body_len,
            current_ca_der, current_ca_len, out_next_ca_pem, heap);

    wolfcert_http_response_free(&resp);
    return rc;
}

/* ---- keep-alive / async SCEP session ----------------------------------- */

/* Which PKIOperation occupies the session's single in-flight slot. Set when a
 * round trip begins; used to reject an async resume that names a different
 * operation than the one already in progress. */
enum scep_session_op {
    SCEP_SESS_OP_PKCS_REQ = 0,
    SCEP_SESS_OP_RENEWAL,
    SCEP_SESS_OP_GET_CERT_INITIAL
};

struct WolfCertScepSession {
    WolfCertHttpSession*      http;
    char*                     server_url;     /* full SCEP endpoint URL, owned */
    void*                     heap;
    int                       nonblocking;    /* opened via _open_async (_nb calls) vs _open (_ex) */
    WolfCertScepTxidMode       txid_mode;        /* captured from cfg at open */
    WolfCertScepContentCipher  content_cipher;   /* captured from cfg at open */
    WolfCertScepRenewalMsgType renewal_msg_type; /* captured from cfg at open */

    /* Async in-flight state: one round trip at a time. */
    int                  in_active;
    int                  in_op;        /* enum scep_session_op, valid when in_active */
    char*                in_url;       /* owned request URL */
    WolfCertBuffer       in_pki;       /* built pkiMessage, owned (POST body) */
    WolfCertHttpRequest  in_req;
    WolfCertHttpResponse in_resp;

    /* Captured at begin, consumed by the finish phase after the pumps: */
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

    /* The session copies proto_opts.scep below, so confirm the discriminator
     * before reading that arm. */
    int rc = wolfcert_cfg_require_proto(srv, WOLFCERT_PROTO_SCEP, "scep");
    if (rc != WOLFCERT_OK)
        return rc;

    /* Split the SCEP URL into scheme://host[:port] for the HTTP session vs the
     * path we keep for building per-operation query strings. Unlike EST there
     * is deliberately no TLS-required gate: RFC 8894 authenticates at the
     * pkiMessage layer and commonly runs over plaintext http://. */
    WolfCertUrl u;
    rc = wolfcert_http_url_parse(srv->server_url, &u, heap);
    if (rc != WOLFCERT_OK)
        return rc;

    /* SCEP does not require TLS, but if the caller did choose an https://
     * endpoint, refuse to run it unverified: verify_server is the sole peer-
     * verification switch, so opening with it off would perform a silent,
     * unauthenticated TLS handshake. Plaintext http:// stays allowed. */
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
        .connect_cb         = srv->connect_cb,
        .connect_ctx        = srv->connect_ctx,
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
    /* Like the one-shot path: the senderNonce is not a secret, but there is no
     * reason to keep RNG output in the session once the round trip is over. */
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

/* Build the request state for one round trip into the session. Copies the
 * finish-phase inputs (ca_bundle, signer cert/key) so they outlive the pumps,
 * prepares the pkiMessage, and picks POST/GET transport. */
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

    /* These three buffers are copied with dup_buf below, which returns NULL for
     * a zero length as well as for an allocation failure. Reject an empty one
     * up front so the NULL check that follows is unambiguously OOM. All internal
     * callers pass non-empty values (the pending-PKCSReq path derives a signer
     * cert rather than passing length 0), so this only fires on malformed input
     * such as a non-NULL signer cert with length 0. */
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
    /* Note: no max_response_bytes here - the HTTP session request path uses the
     * cap fixed at session open (WolfCertHttpSessionCfg.max_response_bytes), not
     * a per-request one, so setting it on in_req would be silently ignored. */
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

/* Run scep_finish on a completed transport result and clear the in-flight
 * state. `rc` is the transport return (already past any WANT_* handling). */
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

/* Validate a resumed async _nb poll: the operation must match the one captured
 * at begin and the result pointer must be the same object. Shared by the three
 * _nb entry points. */
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

/* ---- per-operation begin helpers (run only when starting a round trip) --- */

static int scep_session_begin_pkcs_req(WolfCertScepSession* s,
    const WolfCertScepCaps* caps,
    const uint8_t* ra_cert, size_t ra_cert_len,
    const uint8_t* ca_bundle, size_t ca_bundle_len,
    const WolfCertKey* new_key, const uint8_t* csr_der, size_t csr_der_len,
    WolfCertScepResult* out)
{
    /* Set the fail_info sentinel before the RSA-key check and the crypto below,
     * so an early error return carries -1 like the one-shot APIs (the entry
     * point only memset out to 0; scep_session_begin, which also sets -1, runs
     * after this crypto). */
    out->fail_info = -1;

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
    out->fail_info = -1;   /* sentinel before the crypto below (see pkcs_req) */

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
    out->fail_info = -1;   /* sentinel before the crypto below (see pkcs_req) */

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

    /* Pending PKCSReq: regenerate the same transient self-signed cert the
     * original request used. RenewalReq callers pass their existing cert. */
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

/* ---- session PKCSReq ---------------------------------------------------- */

int wolfcert_scep_session_pkcs_req_ex(WolfCertScepSession* s,
    const WolfCertScepCaps* caps,
    const uint8_t* ra_cert, size_t ra_cert_len,
    const uint8_t* ca_bundle, size_t ca_bundle_len,
    const WolfCertKey* new_key, const uint8_t* csr_der, size_t csr_der_len,
    WolfCertScepResult* out)
{
    if (s == NULL || caps == NULL || ra_cert == NULL || ra_cert_len == 0 ||
            ca_bundle == NULL || ca_bundle_len == 0 || new_key == NULL ||
            csr_der == NULL || csr_der_len == 0 || out == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    if (s->nonblocking)
        return WOLFCERT_ERR(WOLFCERT_ERR_BAD_ARG, "scep",
            "blocking _ex call on an async session; use the _nb variant");

    memset(out, 0, sizeof(*out));
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
    if (s == NULL || out == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    if (!s->nonblocking)
        return WOLFCERT_ERR(WOLFCERT_ERR_BAD_ARG, "scep",
            "non-blocking _nb call on a blocking session; use the _ex variant");

    if (!s->in_active) {
        if (caps == NULL || ra_cert == NULL || ra_cert_len == 0 ||
                ca_bundle == NULL || ca_bundle_len == 0 || new_key == NULL ||
                csr_der == NULL || csr_der_len == 0)
            return WOLFCERT_ERR_BAD_ARG;
        memset(out, 0, sizeof(*out));
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

/* ---- session RenewalReq ------------------------------------------------- */

int wolfcert_scep_session_renewal_req_ex(WolfCertScepSession* s,
    const WolfCertScepCaps* caps,
    const uint8_t* ra_cert, size_t ra_cert_len,
    const uint8_t* ca_bundle, size_t ca_bundle_len,
    const uint8_t* current_cert, size_t current_cert_len,
    const WolfCertKey* current_key, const uint8_t* csr_der, size_t csr_der_len,
    WolfCertScepResult* out)
{
    if (s == NULL || caps == NULL || ra_cert == NULL || ra_cert_len == 0 ||
            ca_bundle == NULL || ca_bundle_len == 0 || current_cert == NULL ||
            current_cert_len == 0 || current_key == NULL || csr_der == NULL ||
            csr_der_len == 0 || out == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    if (s->nonblocking)
        return WOLFCERT_ERR(WOLFCERT_ERR_BAD_ARG, "scep",
            "blocking _ex call on an async session; use the _nb variant");

    memset(out, 0, sizeof(*out));
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
    if (s == NULL || out == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    if (!s->nonblocking)
        return WOLFCERT_ERR(WOLFCERT_ERR_BAD_ARG, "scep",
            "non-blocking _nb call on a blocking session; use the _ex variant");

    if (!s->in_active) {
        if (caps == NULL || ra_cert == NULL || ra_cert_len == 0 || ca_bundle == NULL ||
                ca_bundle_len == 0 || current_cert == NULL || current_cert_len == 0 ||
                current_key == NULL || csr_der == NULL || csr_der_len == 0)
            return WOLFCERT_ERR_BAD_ARG;
        memset(out, 0, sizeof(*out));
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

/* ---- session GetCertInitial (poll) ------------------------------------- */

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
    if (s == NULL || caps == NULL || ra_cert == NULL || ra_cert_len == 0 ||
            ca_bundle == NULL || ca_bundle_len == 0 || signer_key == NULL ||
            csr_der == NULL || csr_der_len == 0 || transaction_id == NULL ||
            transaction_id_len == 0 || out == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    if (s->nonblocking)
        return WOLFCERT_ERR(WOLFCERT_ERR_BAD_ARG, "scep",
            "blocking _ex call on an async session; use the _nb variant");

    memset(out, 0, sizeof(*out));
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
    if (s == NULL || out == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    if (!s->nonblocking)
        return WOLFCERT_ERR(WOLFCERT_ERR_BAD_ARG, "scep",
            "non-blocking _nb call on a blocking session; use the _ex variant");

    if (!s->in_active) {
        if (caps == NULL || ra_cert == NULL || ra_cert_len == 0 || ca_bundle == NULL ||
                ca_bundle_len == 0 || signer_key == NULL || csr_der == NULL ||
                csr_der_len == 0 || transaction_id == NULL || transaction_id_len == 0)
            return WOLFCERT_ERR_BAD_ARG;
        memset(out, 0, sizeof(*out));
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
