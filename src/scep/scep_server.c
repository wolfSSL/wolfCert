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
 * Minimal SCEP (RFC 8894) test server. Shares the CA + issuance helpers
 * with the EST server via src/ca_issue.c.
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include <wolfcert/server.h>
#include <wolfcert/errors.h>
#include "../internal.h"

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/pkcs7.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/memory.h>

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <unistd.h>

/* Content-encryption cipher the CertRep EnvelopedData carries. Mirrors the
 * client's AUTO choice: RFC 8894 section 3.5.2's "AES" capability names
 * AES-128-CBC and nothing else, with the mandatory-to-implement triple DES-CBC
 * as the fallback for a wolfSSL that cannot do AES-128. */
#if defined(WOLFSSL_AES_128) && defined(HAVE_AES_CBC)
    #define SCEP_SRV_ENC_OID AES128CBCb
#elif !defined(NO_DES3)
    #define SCEP_SRV_ENC_OID DES3b
#else
    #error "wolfCert's SCEP test server needs AES-128-CBC or 3DES-CBC; rebuild wolfSSL with one of them, or configure without the test server"
#endif

typedef struct {
    /* rawbuf owns the request-line + header bytes read off the wire. It is
     * heap-allocated (REQ_BUF_SZ + QUERY_SZ) so an RFC 8894 GET PKIOperation,
     * whose base64 pkiMessage rides in the query string, never lands on the
     * stack. path and query point into it (NUL-terminated in place). */
    char*       rawbuf;
    const char* path;
    const char* query;
    uint8_t*    body;
    void*       heap;
    size_t      content_length;
    size_t      body_len;
    char        method[8];
    int         connection_close;
} ScepRequest;

/* Pending-queue entry: one per PKCSReq / RenewalReq held under
 * scep_require_approval. We copy the CSR + signer cert because the
 * request's body buffer is freed before the next poll arrives. */
typedef struct {
    uint8_t* transaction_id;
    size_t   transaction_id_len;
    uint8_t* csr_der;
    size_t   csr_len;
    uint8_t* signer_cert_der;
    size_t   signer_cert_len;
    int      polls;   /* #GetCertInitial seen for this txid */
} ScepPending;

typedef struct {
    ScepPending* items;
    size_t       count;
    size_t       cap;
    /* Optional rolled-over "next" CA, generated on first GetNextCACert
     * when WolfCertServerCfgSrv::scep_enable_next_ca is set. Signed and
     * self-contained; NOT installed as the active issuing CA. */
    WolfCertCa   next_ca;
    int          next_ca_ready;
#if defined(WOLFCERT_BUILD_TESTING)
    /* Client-side rejection tests: deliberately emit a non-compliant or forged
     * CertRep. Set via wolfcert_scep_server_set_faults; never present in a
     * production build. wrong_ca is a throwaway signer generated on first use. */
    int          fault_omit_recipient_nonce;
    int          fault_sign_with_wrong_key;
    int          fault_rng_fail;
    WolfCertCa   wrong_ca;
    int          wrong_ca_ready;
#endif
} ScepPriv;

#if defined(WOLFCERT_BUILD_TESTING)
WOLFCERT_TEST_VIS void wolfcert_scep_server_set_faults(WolfCertServer* s,
    int omit_recipient_nonce, int sign_with_wrong_key, int rng_fail)
{
    ScepPriv* p = (ScepPriv*)s->priv;

    p->fault_omit_recipient_nonce = omit_recipient_nonce;
    p->fault_sign_with_wrong_key  = sign_with_wrong_key;
    p->fault_rng_fail             = rng_fail;
}
#endif

static void free_req(ScepRequest* r)
{
    /* path/query point into rawbuf, so freeing rawbuf reclaims them too. */
    WOLFCERT_XFREE(r->body, r->heap);
    WOLFCERT_XFREE(r->rawbuf, r->heap);
    memset(r, 0, sizeof(*r));
}

static int read_line(const char** p, const char* end, char** ls, size_t* ll)
{
    const char* nl = memchr(*p, '\n', (size_t)(end - *p));
    if (nl == NULL)
        return -1;

    size_t len = (size_t)(nl - *p);
    if (len > 0 && (*p)[len - 1] == '\r')
        --len;

    *ls = (char*)*p;
    *ll = len;
    *p = nl + 1;

    return 0;
}

static int read_request(WolfCertServer* s, int fd, ScepRequest* out, void* heap)
{
    /* Large enough to hold the request line + headers, including a GET
     * PKIOperation whose base64 pkiMessage lives in the query string. Heap-
     * allocated (owned by free_req) to keep it off the request-handling stack;
     * path and query end up pointing into it. */
    size_t buf_sz = WOLFCERT_HTTP_REQ_BUF_SZ + WOLFCERT_HTTP_QUERY_SZ;
    char* buf;
    size_t n = 0;

    memset(out, 0, sizeof(*out));
    out->heap = heap;
    out->rawbuf = (char*)WOLFCERT_XMALLOC(buf_sz, heap);
    if (out->rawbuf == NULL)
        return WOLFCERT_ERR_MEMORY;
    buf = out->rawbuf;

    while (n < buf_sz - 1) {
        ssize_t r = wolfcert_io_recv(s, fd, buf + n, buf_sz - 1 - n);
        if (r <= 0)
            return WOLFCERT_ERR_IO;

        n += (size_t)r;
        buf[n] = '\0';
        if (strstr(buf, "\r\n\r\n") != NULL)
            break;
    }

    const char* p = buf;
    const char* end = buf + n;
    char* line;
    size_t llen;
    if (read_line(&p, end, &line, &llen) != 0)
        return WOLFCERT_ERR_PROTOCOL;

    char* sp1 = memchr(line, ' ', llen);
    if (sp1 == NULL)
        return WOLFCERT_ERR_PROTOCOL;

    size_t mlen = (size_t)(sp1 - line);
    if (mlen >= sizeof(out->method))
        return WOLFCERT_ERR_PROTOCOL;

    memcpy(out->method, line, mlen);
    out->method[mlen] = '\0';

    char* sp2 = memchr(sp1 + 1, ' ', llen - mlen - 1);
    if (sp2 == NULL)
        return WOLFCERT_ERR_PROTOCOL;

    /* Split the request-target in place: NUL the trailing space, then the '?'
     * (if any). path and query point into buf (== out->rawbuf), which lives
     * until free_req, so no copy and no large stack buffers are needed. */
    *sp2 = '\0';
    out->path = sp1 + 1;
    char* qs = strchr(sp1 + 1, '?');
    if (qs != NULL) {
        *qs = '\0';
        out->query = qs + 1;
    }
    else {
        out->query = sp2;   /* empty query string */
    }

    while (read_line(&p, end, &line, &llen) == 0 && llen > 0) {
        if (llen > 14 && strncasecmp(line, "Content-Length", 14) == 0) {
            char* c = memchr(line, ':', llen);
            if (c)
                out->content_length = (size_t)strtoul(c + 1, NULL, 10);
        }
        else if (llen > 10 && strncasecmp(line, "Connection", 10) == 0) {
            char* colon = memchr(line, ':', llen);
            if (colon != NULL) {
                const char* v = colon + 1;
                while (v < line + llen && (*v == ' ' || *v == '\t'))
                    ++v;
                size_t vlen = (size_t)(line + llen - v);
                if (vlen >= 5 && strncasecmp(v, "close", 5) == 0)
                    out->connection_close = 1;
            }
        }
    }

    size_t have = (size_t)(end - p);
    if (out->content_length > 0) {
        if (out->content_length > 1 * 1024 * 1024)
            return WOLFCERT_ERR_PROTOCOL;

        out->body = (uint8_t*)WOLFCERT_XMALLOC(out->content_length, heap);
        if (out->body == NULL)
            return WOLFCERT_ERR_MEMORY;

        size_t take = have > out->content_length ? out->content_length : have;
        memcpy(out->body, p, take);
        size_t left = out->content_length - take;
        while (left > 0) {
            ssize_t r = wolfcert_io_recv(s, fd,
                         out->body + (out->content_length - left), left);
            if (r <= 0) {
                WOLFCERT_XFREE(out->body, heap);
                out->body = NULL;
                return WOLFCERT_ERR_IO;
            }
            left -= (size_t)r;
        }
        out->body_len = out->content_length;
    }

    return WOLFCERT_OK;
}

static void send_all(WolfCertServer* s, int fd, const void* buf, size_t len)
{
    const uint8_t* p = buf;
    size_t n = 0;
    while (n < len) {
        ssize_t r = wolfcert_io_send(s, fd, p + n, len - n);
        if (r <= 0)
            break;
        n += (size_t)r;
    }
}

static const char* conn_hdr(const WolfCertServer* s)
{
    return s->keep_alive ? "keep-alive" : "close";
}

static void send_text(WolfCertServer* s, int fd, int status, const char* phrase,
                      const char* content_type, const char* body)
{
    size_t bl = body ? strlen(body) : 0;
    char hdr[256];
    int n = snprintf(hdr, sizeof(hdr),
        "HTTP/1.1 %d %s\r\nContent-Type: %s\r\nContent-Length: %zu\r\n"
        "Connection: %s\r\n\r\n",
        status, phrase, content_type, bl, conn_hdr(s));

    send_all(s, fd, hdr, (size_t)n);
    if (bl > 0)
        send_all(s, fd, body, bl);
}

static void send_bin(WolfCertServer* s, int fd, const char* content_type,
                     const uint8_t* body, size_t bl)
{
    char hdr[256];
    int n = snprintf(hdr, sizeof(hdr),
        "HTTP/1.1 200 OK\r\nContent-Type: %s\r\nContent-Length: %zu\r\n"
        "Connection: %s\r\n\r\n",
        content_type, bl, conn_hdr(s));

    send_all(s, fd, hdr, (size_t)n);
    send_all(s, fd, body, bl);
}

static void handle_get_ca_caps(WolfCertServer* s, int fd)
{
    if (s->cfg.scep_enable_next_ca) {
        send_text(s, fd, 200, "OK", "text/plain",
                  "POSTPKIOperation\r\nSHA-256\r\nAES\r\nRenewal\r\n"
                  "SCEPStandard\r\nGetNextCACert\r\n");
    }
    else {
        send_text(s, fd, 200, "OK", "text/plain",
                  "POSTPKIOperation\r\nSHA-256\r\nAES\r\nRenewal\r\nSCEPStandard\r\n");
    }
}

static void handle_get_ca_cert(WolfCertServer* s, int fd)
{
    send_bin(s, fd, "application/x-x509-ca-cert", s->ca.cert_der, s->ca.cert_der_len);
}

/* Materialize the rolled-over CA on first request and return it wrapped in a
 * SignedData signed by the current CA, per RFC 8894 section 4.6.1, so the
 * client can bind the rollover certificate to the CA it already trusts. */
static void handle_get_next_ca_cert(WolfCertServer* s, int fd)
{
    if (!s->cfg.scep_enable_next_ca) {
        send_text(s, fd, 404, "Not Found", "text/plain", "");
        return;
    }

    ScepPriv* p = (ScepPriv*)s->priv;
    if (!p->next_ca_ready) {
        WolfCertKeyType kt = s->cfg.ca_key_type ? s->cfg.ca_key_type : WOLFCERT_KEY_RSA;
        int kp = s->cfg.ca_key_param;
        if (wolfcert_ca_generate(&p->next_ca, kt, kp, s->heap) != WOLFCERT_OK) {
            send_text(s, fd, 500, "Server Error", "text/plain", "");
            return;
        }
        p->next_ca_ready = 1;
    }

    WolfCertBuffer p7 = { 0 };

    if (wolfcert_scep_build_next_ca_response(p->next_ca.cert_der,
                                             p->next_ca.cert_der_len,
                                             s->ca.cert_der, s->ca.cert_der_len,
                                             s->ca.key_der, s->ca.key_der_len,
                                             &p7, s->heap) != WOLFCERT_OK) {
        send_text(s, fd, 500, "Server Error", "text/plain", "");
        return;
    }

    send_bin(s, fd, "application/x-x509-next-ca-cert", p7.data, p7.len);
    wolfcert_buffer_free(&p7);
}

/* ---- pending queue ----------------------------------------------------- */

#define SCEP_PENDING_MAX 16

static ScepPending* pending_find(ScepPriv* p, const uint8_t* tid, size_t tid_len)
{
    for (size_t i = 0; i < p->count; ++i) {
        ScepPending* e = &p->items[i];
        if (e->transaction_id_len == tid_len &&
                memcmp(e->transaction_id, tid, tid_len) == 0)
            return e;
    }
    return NULL;
}

static int pending_add(ScepPriv* p, void* heap,
                       const uint8_t* tid, size_t tid_len,
                       const uint8_t* csr, size_t csr_len,
                       const uint8_t* signer, size_t signer_len)
{
    if (p->count >= SCEP_PENDING_MAX)
        return WOLFCERT_ERR_MEMORY;

    if (p->items == NULL) {
        p->items = (ScepPending*)WOLFCERT_XMALLOC(
            sizeof(ScepPending) * SCEP_PENDING_MAX, heap);
        if (p->items == NULL)
            return WOLFCERT_ERR_MEMORY;

        p->cap = SCEP_PENDING_MAX;
        memset(p->items, 0, sizeof(ScepPending) * SCEP_PENDING_MAX);
    }

    ScepPending* e     = &p->items[p->count];
    e->transaction_id  = (uint8_t*)WOLFCERT_XMALLOC(tid_len, heap);
    e->csr_der         = (uint8_t*)WOLFCERT_XMALLOC(csr_len, heap);
    e->signer_cert_der = (uint8_t*)WOLFCERT_XMALLOC(signer_len, heap);

    if (e->transaction_id == NULL || e->csr_der == NULL ||
            e->signer_cert_der == NULL) {
        WOLFCERT_XFREE(e->transaction_id, heap);
        WOLFCERT_XFREE(e->csr_der, heap);
        WOLFCERT_XFREE(e->signer_cert_der, heap);
        memset(e, 0, sizeof(*e));
        return WOLFCERT_ERR_MEMORY;
    }

    memcpy(e->transaction_id, tid, tid_len);
    memcpy(e->csr_der, csr, csr_len);
    memcpy(e->signer_cert_der, signer, signer_len);
    e->transaction_id_len = tid_len;
    e->csr_len            = csr_len;
    e->signer_cert_len    = signer_len;
    e->polls = 0;
    p->count++;

    return WOLFCERT_OK;
}

static void pending_remove(ScepPriv* p, void* heap, ScepPending* e)
{
    size_t idx = (size_t)(e - p->items);
    if (idx >= p->count)
        return;

    WOLFCERT_XFREE(e->transaction_id,  heap);
    WOLFCERT_XFREE(e->csr_der,         heap);
    WOLFCERT_XFREE(e->signer_cert_der, heap);

    /* swap-with-last to avoid memmove of the whole array */
    if (idx != p->count - 1)
        p->items[idx] = p->items[p->count - 1];

    memset(&p->items[p->count - 1], 0, sizeof(ScepPending));
    p->count--;
}

/* Verify the CSR's embedded PKCS#9 challengePassword (RFC 8894 section 2.9)
 * matches `expected`. Returns WOLFCERT_OK on match (or when no challenge
 * is configured), WOLFCERT_ERR_AUTH on mismatch / missing / parse failure.
 * Constant-time compare on the common-length prefix to avoid trivial
 * timing side channel. */
static int check_challenge(const uint8_t* csr_der, size_t csr_len,
                           const char* expected, void* heap)
{
    if (expected == NULL || expected[0] == '\0')
        return WOLFCERT_OK;

    DecodedCert dc;
    wc_InitDecodedCert(&dc, (byte*)csr_der, (word32)csr_len, heap);

    int rc = wc_ParseCert(&dc, CERTREQ_TYPE, NO_VERIFY, NULL);
    if (rc != 0) {
        wc_FreeDecodedCert(&dc);
        return WOLFCERT_ERR_AUTH;
    }

    size_t elen = strlen(expected);
    int ok = (dc.cPwd != NULL) && ((size_t)dc.cPwdLen == elen);
    if (ok)
        ok = (wc_ConstantCompare((const byte*)dc.cPwd,
                                 (const byte*)expected, (int)elen) == 0);

    wc_FreeDecodedCert(&dc);
    return ok ? WOLFCERT_OK : WOLFCERT_ERR_AUTH;
}

/* Ensure signer cert's SPKI matches the CSR's SPKI. Trust boundary: do
 * NOT issue a cert whose subject public key differs from the one that
 * the request was signed with. */
static int signer_matches_csr(const uint8_t* signer_der, size_t signer_len,
                              const uint8_t* csr_der, size_t csr_len,
                              void* heap)
{
    uint8_t* sa = NULL;
    size_t sa_len = 0;
    uint8_t* sb = NULL;
    size_t sb_len = 0;
    int rc = wolfcert_extract_spki(signer_der, signer_len, 0, &sa, &sa_len, heap);
    if (rc != WOLFCERT_OK)
        return rc;

    rc = wolfcert_extract_spki(csr_der, csr_len, 1, &sb, &sb_len, heap);
    if (rc != WOLFCERT_OK) {
        WOLFCERT_XFREE(sa, heap);
        return rc;
    }

    rc = (sa_len == sb_len && memcmp(sa, sb, sa_len) == 0) ?
            WOLFCERT_OK : WOLFCERT_ERR_AUTH;

    WOLFCERT_XFREE(sa, heap);
    WOLFCERT_XFREE(sb, heap);
    return rc;
}

/* Build + send a CertRep pkiMessage with the supplied pkiStatus.
 * When status==0 (success) the issued cert is enveloped for `env_target`;
 * when status==3 (pending) or status==2 (failure) the payload is empty. */
static int send_cert_rep(WolfCertServer* s, int fd,
                         const uint8_t* issued_cert, size_t issued_cert_len,
                         const uint8_t* env_target, size_t env_target_len,
                         const uint8_t* tid, size_t tid_len,
                         const uint8_t* snonce, size_t snonce_len,
                         const char* pki_status, const char* fail_info)
{
    int rc = WOLFCERT_OK;
    WolfCertBuffer resp_env = { 0 };

    if (strcmp(pki_status, "0") == 0) {
        const uint8_t* cs[1] = { issued_cert };
        size_t         cl[1] = { issued_cert_len };
        WolfCertBuffer p7 = { 0 };

        rc = wolfcert_pkcs7_build_certs_only(cs, cl, 1, &p7, s->heap);
        if (rc != WOLFCERT_OK) {
            send_text(s, fd, 500, "Server Error", "text/plain", "");
            return rc;
        }

        rc = wolfcert_scep_envelop(env_target, env_target_len,
                                    p7.data, p7.len, SCEP_SRV_ENC_OID, &resp_env,
                                    s->heap);

        wolfcert_buffer_free(&p7);
        if (rc != WOLFCERT_OK) {
            send_text(s, fd, 500, "Server Error", "text/plain", "");
            return rc;
        }
    }
    /* RFC 8894 section 3.2.2: a CertRep with pkiStatus PENDING ("3") or
     * FAILURE ("2") carries no enveloped messageData. resp_env is left empty
     * so the signed pkiMessage is built with an absent pkcsPKIEnvelope. */

    WC_RNG rng;
    if (wc_InitRng_ex(&rng, s->heap, WOLFCERT_DEVID_SOFTWARE) != 0) {
        wolfcert_buffer_free(&resp_env);
        send_text(s, fd, 500, "Server Error", "text/plain", "");
        return WOLFCERT_ERR_CRYPTO;
    }

    uint8_t my_nonce[16];
    int nonce_rc = wc_RNG_GenerateBlock(&rng, my_nonce, sizeof(my_nonce));
#if defined(WOLFCERT_BUILD_TESTING)
    if (((ScepPriv*)s->priv)->fault_rng_fail)
        nonce_rc = -1;
#endif
    if (nonce_rc != 0) {
        wc_FreeRng(&rng);
        wolfcert_buffer_free(&resp_env);
        send_text(s, fd, 500, "Server Error", "text/plain", "");
        return WOLFCERT_ERR_CRYPTO;
    }

    wc_FreeRng(&rng);

    /* RFC 8894 section 3.1: CertRep MUST carry messageType, pkiStatus,
     * transactionID, senderNonce, recipientNonce (plus failInfo on failure).
     * Alongside the three CMS auto-defaults (contentType, messageDigest,
     * signingTime) that is up to 9 signed attributes. wolfSSL's PKCS#7
     * encoder grows its signed-attribute array on the heap past the inline
     * MAX_SIGNED_ATTRIBS_SZ (default 7), so the full set encodes fine on any
     * malloc-enabled build. Only a WOLFSSL_NO_MALLOC build with the default
     * inline cap can't fit it; there we drop recipientNonce/failInfo unless
     * wolfSSL was rebuilt with -DMAX_SIGNED_ATTRIBS_SZ>=9. */
    WolfCertScepAttrs attrs = {
        .transaction_id     = tid, .transaction_id_len = tid_len,
        .sender_nonce       = my_nonce, .sender_nonce_len = sizeof(my_nonce),
        .message_type       = "3",
        .pki_status         = pki_status,
#if !defined(WOLFSSL_NO_MALLOC) || (MAX_SIGNED_ATTRIBS_SZ >= 9)
        .fail_info          = fail_info,
        .recipient_nonce    = snonce, .recipient_nonce_len = snonce_len,
#endif
    };
#if defined(WOLFSSL_NO_MALLOC) && (MAX_SIGNED_ATTRIBS_SZ < 9)
    (void)snonce;
    (void)snonce_len;
    (void)fail_info;
#endif
#if defined(WOLFCERT_BUILD_TESTING)
    ScepPriv* p = (ScepPriv*)s->priv;

    if (p->fault_omit_recipient_nonce) {
        attrs.recipient_nonce     = NULL;
        attrs.recipient_nonce_len = 0;
    }
#endif

    /* Sign with the CA key. The client-side signer-trust test can force a
     * throwaway key generated on first use to forge an untrusted signer. */
    const uint8_t* sign_cert     = s->ca.cert_der;
    size_t         sign_cert_len = s->ca.cert_der_len;
    const uint8_t* sign_key      = s->ca.key_der;
    size_t         sign_key_len  = s->ca.key_der_len;
#if defined(WOLFCERT_BUILD_TESTING)
    if (p->fault_sign_with_wrong_key) {
        if (!p->wrong_ca_ready) {
            WolfCertKeyType kt = s->cfg.ca_key_type ? s->cfg.ca_key_type
                                                    : WOLFCERT_KEY_RSA;
            rc = wolfcert_ca_generate(&p->wrong_ca, kt, s->cfg.ca_key_param,
                                      s->heap);
            if (rc != WOLFCERT_OK) {
                wolfcert_buffer_free(&resp_env);
                send_text(s, fd, 500, "Server Error", "text/plain", "");
                return rc;
            }
            p->wrong_ca_ready = 1;
        }
        sign_cert     = p->wrong_ca.cert_der;
        sign_cert_len = p->wrong_ca.cert_der_len;
        sign_key      = p->wrong_ca.key_der;
        sign_key_len  = p->wrong_ca.key_der_len;
    }
#endif

    WolfCertBuffer pki_out = { 0 };
    rc = wolfcert_scep_build_pki_message(resp_env.data, resp_env.len,
                                          sign_cert, sign_cert_len,
                                          sign_key,  sign_key_len,
                                          SHA256h, &attrs, &pki_out, s->heap);

    wolfcert_buffer_free(&resp_env);
    if (rc != WOLFCERT_OK) {
        send_text(s, fd, 500, "Server Error", "text/plain", "");
        return rc;
    }

    send_bin(s, fd, "application/x-pki-message", pki_out.data, pki_out.len);
    wolfcert_buffer_free(&pki_out);

    return WOLFCERT_OK;
}

/* Issue the cert and answer with a success CertRep. */
static int issue_and_reply(WolfCertServer* s, int fd,
                           const uint8_t* csr, size_t csr_len,
                           const uint8_t* env_target, size_t env_target_len,
                           const uint8_t* tid, size_t tid_len,
                           const uint8_t* snonce, size_t snonce_len)
{
    uint8_t* issued = NULL;
    size_t issued_len = 0;
    int rc = wolfcert_ca_issue(&s->ca, csr, csr_len, &issued, &issued_len);
    if (rc != WOLFCERT_OK) {
        send_text(s, fd, 400, "Bad CSR", "text/plain", "");
        return rc;
    }

    rc = send_cert_rep(s, fd, issued, issued_len,
                       env_target, env_target_len,
                       tid, tid_len, snonce, snonce_len, "0", NULL);

    WOLFCERT_XFREE(issued, s->heap);
    return rc;
}

/* Handle messageType=19 (PKCSReq) or 17 (RenewalReq) freshly arrived. */
static int handle_enroll(WolfCertServer* s, int fd, const char* mt,
                         const WolfCertBuffer* csr,
                         const uint8_t* signer_cert, size_t signer_cert_len,
                         const uint8_t* tid, size_t tid_len,
                         const uint8_t* snonce, size_t snonce_len)
{
    (void)mt;
    const uint8_t* env_target     = signer_cert ? signer_cert : s->ca.cert_der;
    size_t         env_target_len = signer_cert ? signer_cert_len : s->ca.cert_der_len;

    /* Enforce signer/CSR SPKI match. */
    if (signer_cert != NULL &&
            signer_matches_csr(signer_cert, signer_cert_len,
                               csr->data, csr->len, s->heap) != WOLFCERT_OK) {
        /* Report the failure as a CertRep, then close the connection. */
        s->keep_alive = 0;
        return send_cert_rep(s, fd, NULL, 0, env_target, env_target_len,
                             tid, tid_len, snonce, snonce_len,
                             "2", "2" /* badRequest */);
    }

    if (check_challenge(csr->data, csr->len, s->cfg_challenge,
                        s->heap) != WOLFCERT_OK) {
        /* Report the failure as a CertRep, then close the connection. */
        s->keep_alive = 0;
        return send_cert_rep(s, fd, NULL, 0, env_target, env_target_len,
                             tid, tid_len, snonce, snonce_len,
                             "2", "2" /* badRequest */);
    }

    if (s->cfg.scep_require_approval) {
        /* Defer issuance; return pkiStatus=3 (PENDING). The client polls
         * with GetCertInitial (messageType 20) referencing this txid. */
        ScepPriv* p = (ScepPriv*)s->priv;
        if (pending_find(p, tid, tid_len) == NULL) {
            int add = pending_add(p, s->heap, tid, tid_len,
                                  csr->data, csr->len,
                                  signer_cert ? signer_cert : s->ca.cert_der,
                                  signer_cert ? signer_cert_len : s->ca.cert_der_len);

            if (add != WOLFCERT_OK) {
                /* Queue full - fail rather than silently losing requests. */
                return send_cert_rep(s, fd, NULL, 0, env_target, env_target_len,
                                     tid, tid_len, snonce, snonce_len,
                                     "2", "2" /* badRequest */);
            }
        }

        return send_cert_rep(s, fd, NULL, 0, env_target, env_target_len,
                             tid, tid_len, snonce, snonce_len, "3", NULL);
    }

    return issue_and_reply(s, fd, csr->data, csr->len,
                           env_target, env_target_len,
                           tid, tid_len, snonce, snonce_len);
}

/* Handle messageType=20 (GetCertInitial): poll for a pending enrollment.
 * Test-server policy: the first poll for a known transactionID issues
 * the cert and drains the queue entry; subsequent polls for unknown
 * transactionIDs return pkiStatus=2 (FAILURE) rather than pretending
 * to be pending forever. */
static int handle_get_cert_initial(WolfCertServer* s, int fd,
                                   const uint8_t* tid, size_t tid_len,
                                   const uint8_t* snonce, size_t snonce_len,
                                   const uint8_t* signer_cert, size_t signer_cert_len)
{
    ScepPriv* p = (ScepPriv*)s->priv;
    ScepPending* e = pending_find(p, tid, tid_len);
    if (e == NULL) {
        const uint8_t* env_target     = signer_cert ? signer_cert : s->ca.cert_der;
        size_t         env_target_len = signer_cert ? signer_cert_len : s->ca.cert_der_len;

        return send_cert_rep(s, fd, NULL, 0, env_target, env_target_len,
                             tid, tid_len, snonce, snonce_len,
                             "2", "4" /* badCertId: no such transaction */);
    }

    /* Approve on first poll. A production implementation would hold
     * requests until an admin acts on a queue; for the test server a
     * single round trip through pending is enough to exercise the
     * RFC 8894 section 3.3.2 flow end-to-end. */
    e->polls++;
    uint8_t* csr_copy = (uint8_t*)WOLFCERT_XMALLOC(e->csr_len, s->heap);
    if (csr_copy == NULL) {
        send_text(s, fd, 500, "Server Error", "text/plain", "");
        return WOLFCERT_ERR_MEMORY;
    }

    memcpy(csr_copy, e->csr_der, e->csr_len);
    size_t   csr_len_local = e->csr_len;
    uint8_t* tgt = (uint8_t*)WOLFCERT_XMALLOC(e->signer_cert_len, s->heap);
    if (tgt == NULL) {
        WOLFCERT_XFREE(csr_copy, s->heap);
        send_text(s, fd, 500, "Server Error", "text/plain", "");
        return WOLFCERT_ERR_MEMORY;
    }

    memcpy(tgt, e->signer_cert_der, e->signer_cert_len);
    size_t tgt_len = e->signer_cert_len;

    pending_remove(p, s->heap, e);

    int rc = issue_and_reply(s, fd, csr_copy, csr_len_local,
                             tgt, tgt_len,
                             tid, tid_len, snonce, snonce_len);

    WOLFCERT_XFREE(csr_copy, s->heap);
    WOLFCERT_XFREE(tgt,      s->heap);
    return rc;
}

static int handle_pki_op(WolfCertServer* s, int fd, const ScepRequest* req)
{
    WolfCertBuffer env = { 0 };
    uint8_t* tid = NULL;
    size_t tid_len = 0;
    uint8_t* snonce = NULL;
    size_t snonce_len = 0;
    uint8_t* rnonce = NULL;
    size_t rnonce_len = 0;
    char* mt = NULL;
    char* ps = NULL;
    uint8_t* signer_cert = NULL;
    size_t signer_cert_len = 0;
    WolfCertBuffer csr = { 0 };

    int rc = wolfcert_scep_parse_pki_message(req->body, req->body_len, &env,
            &tid, &tid_len, &snonce, &snonce_len, &rnonce, &rnonce_len,
            &mt, &ps, &signer_cert, &signer_cert_len, NULL, s->heap);
    if (rc != WOLFCERT_OK) {
        send_text(s, fd, 400, "Bad Request", "text/plain", "");
        goto out;
    }

    if (mt == NULL) {
        send_text(s, fd, 400, "Bad Message", "text/plain", "");
        goto out;
    }

    if (tid == NULL || tid_len == 0 || snonce == NULL || snonce_len == 0) {
        s->keep_alive = 0;
        send_text(s, fd, 400, "Bad Message", "text/plain", "");
        rc = WOLFCERT_ERR_PROTOCOL;
        goto out;
    }

    rc = wolfcert_scep_deenvelop(s->ca.cert_der, s->ca.cert_der_len,
                                  s->ca.key_der,  s->ca.key_der_len,
                                  env.data, env.len, &csr, s->heap);
    if (rc != WOLFCERT_OK && strcmp(mt, "20") != 0) {
        /* Decryption matters for 19/17 (CSR inside); for 20 the payload
         * is IssuerAndSubject which the server matches by txid anyway. */
        send_text(s, fd, 400, "Cannot Decrypt", "text/plain", "");
        goto out;
    }

    if (strcmp(mt, "19") == 0 || strcmp(mt, "17") == 0) {
        rc = handle_enroll(s, fd, mt, &csr, signer_cert, signer_cert_len,
                           tid, tid_len, snonce, snonce_len);
    }
    else if (strcmp(mt, "20") == 0) {
        rc = handle_get_cert_initial(s, fd, tid, tid_len, snonce, snonce_len,
                                     signer_cert, signer_cert_len);
    }
    else {
        send_text(s, fd, 400, "Bad Message", "text/plain", "");
        rc = WOLFCERT_ERR_PROTOCOL;
    }

out:
    wolfcert_buffer_free(&csr);
    wolfcert_buffer_free(&env);
    WOLFCERT_XFREE(tid,    s->heap);
    WOLFCERT_XFREE(snonce, s->heap);
    WOLFCERT_XFREE(rnonce, s->heap);
    WOLFCERT_XFREE(mt,     s->heap);
    WOLFCERT_XFREE(ps,     s->heap);
    WOLFCERT_XFREE(signer_cert, s->heap);

    return rc;
}

static int hexval(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Return the value of query parameter `key` (the text just past "key="), or
 * NULL if absent. `key` is matched as a whole parameter name -- at the start of
 * the query or immediately after a '&' -- so "message" is not matched inside
 * "mymessage". The value runs to the next '&' or the end of the string. */
static const char* query_param(const char* query, const char* key)
{
    size_t key_len = strlen(key);
    const char* p = query;

    while (*p != '\0') {
        if (strncmp(p, key, key_len) == 0 && p[key_len] == '=')
            return p + key_len + 1;
        p = strchr(p, '&');
        if (p == NULL)
            break;
        ++p;
    }

    return NULL;
}

/* RFC 8894 section 4.1 GET PKIOperation: the pkiMessage is carried
 * base64-encoded and percent-escaped in the `message` query parameter. Decode
 * it into req->body (owned; freed by free_req) and dispatch exactly like a
 * POSTed pkiMessage. Sends its own 400 on a malformed message. */
static int handle_pki_op_get(WolfCertServer* s, int fd, ScepRequest* req)
{
    const char* m = query_param(req->query, "message");
    if (m == NULL) {
        send_text(s, fd, 400, "Bad Request", "text/plain", "");
        return WOLFCERT_ERR_PROTOCOL;
    }
    size_t enc_len = strcspn(m, "&");

    /* Percent-decoding never grows the input. */
    uint8_t* b64 = (uint8_t*)WOLFCERT_XMALLOC(enc_len + 1, req->heap);
    if (b64 == NULL) {
        send_text(s, fd, 500, "Server Error", "text/plain", "");
        return WOLFCERT_ERR_MEMORY;
    }

    size_t o = 0;
    for (size_t i = 0; i < enc_len; ) {
        if (m[i] == '%') {
            int hi = (i + 2 < enc_len) ? hexval((unsigned char)m[i + 1]) : -1;
            int lo = (i + 2 < enc_len) ? hexval((unsigned char)m[i + 2]) : -1;
            if (hi < 0 || lo < 0) {
                WOLFCERT_XFREE(b64, req->heap);
                send_text(s, fd, 400, "Bad Request", "text/plain", "");
                return WOLFCERT_ERR_PROTOCOL;
            }
            b64[o++] = (uint8_t)((hi << 4) | lo);
            i += 3;
        }
        else {
            b64[o++] = (uint8_t)m[i];
            i += 1;
        }
    }

    WolfCertBuffer der = { 0 };
    int rc = wolfcert_base64_decode(b64, o, &der, req->heap);
    WOLFCERT_XFREE(b64, req->heap);
    if (rc != WOLFCERT_OK) {
        send_text(s, fd, 400, "Bad Request", "text/plain", "");
        return rc;
    }

    /* A GET carries its pkiMessage in the query, not a body; free any body a
     * bogus Content-Length made read_request allocate before installing the
     * decoded message, so it is not leaked (XFREE(NULL) is a no-op). */
    WOLFCERT_XFREE(req->body, req->heap);
    req->body     = der.data;
    req->body_len = der.len;

    return handle_pki_op(s, fd, req);
}

static int handle_request(WolfCertServer* s, int fd)
{
    ScepRequest req = { 0 };
    int rc = read_request(s, fd, &req, s->heap);
    if (rc != WOLFCERT_OK) {
        s->keep_alive = 0;
        /* A heap allocation failure inside read_request is a server-side
         * fault, not a malformed request: map it to 500 so callers can tell
         * the two apart. Everything else (protocol/IO) stays a 400. */
        if (rc == WOLFCERT_ERR_MEMORY)
            send_text(s, fd, 500, "Server Error", "text/plain", "");
        else
            send_text(s, fd, 400, "Bad Request", "text/plain", "");
        free_req(&req);
        return rc;
    }

    if (req.connection_close)
        s->keep_alive = 0;

    const char* op = query_param(req.query, "operation");
    if (op == NULL) {
        send_text(s, fd,400, "Bad Request", "text/plain", "");
        free_req(&req);
        return WOLFCERT_ERR_PROTOCOL;
    }

    if (strncmp(op, "GetCACaps", 9) == 0 && strcmp(req.method, "GET") == 0) {
        handle_get_ca_caps(s, fd);
    }
    else if (strncmp(op, "GetNextCACert", 13) == 0 && strcmp(req.method, "GET") == 0) {
        handle_get_next_ca_cert(s, fd);
    }
    else if (strncmp(op, "GetCACert", 9) == 0 && strcmp(req.method, "GET") == 0) {
        handle_get_ca_cert(s, fd);
    }
    else if (strncmp(op, "PKIOperation", 12) == 0 && strcmp(req.method, "POST") == 0) {
        rc = handle_pki_op(s, fd, &req);
    }
    else if (strncmp(op, "PKIOperation", 12) == 0 && strcmp(req.method, "GET") == 0) {
        rc = handle_pki_op_get(s, fd, &req);
    }
    else {
        send_text(s, fd,404, "Not Found", "text/plain", "");
    }

    free_req(&req);
    return rc;
}

/* ---- vtable ------------------------------------------------------------ */

static int scep_start(const WolfCertServerCfgSrv* cfg, WolfCertServer* base)
{
    (void)cfg;
    ScepPriv* p = (ScepPriv*)WOLFCERT_XMALLOC(sizeof(*p), base->heap);
    if (p == NULL)
        return WOLFCERT_ERR_MEMORY;

    memset(p, 0, sizeof(*p));
    base->priv = p;

    return WOLFCERT_OK;
}

static int scep_serve_fd(WolfCertServer* srv, int fd)
{
    return handle_request(srv, fd);
}

static void scep_free_priv(WolfCertServer* srv)
{
    ScepPriv* p = (ScepPriv*)srv->priv;
    if (p == NULL)
        return;

    for (size_t i = 0; i < p->count; ++i) {
        WOLFCERT_XFREE(p->items[i].transaction_id,  srv->heap);
        WOLFCERT_XFREE(p->items[i].csr_der,         srv->heap);
        WOLFCERT_XFREE(p->items[i].signer_cert_der, srv->heap);
    }

    WOLFCERT_XFREE(p->items, srv->heap);
    if (p->next_ca_ready)
        wolfcert_ca_free(&p->next_ca);
#if defined(WOLFCERT_BUILD_TESTING)
    if (p->wrong_ca_ready)
        wolfcert_ca_free(&p->wrong_ca);
#endif
    WOLFCERT_XFREE(p, srv->heap);
    srv->priv = NULL;
}

static const WolfCertServerOps SCEP_OPS = {
    .start     = scep_start,
    .serve_fd  = scep_serve_fd,
    .free_priv = scep_free_priv,
};

const WolfCertServerOps* wolfcert_scep_server_ops(void)
{
    return &SCEP_OPS;
}
