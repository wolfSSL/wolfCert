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

/* Minimal SCEP (RFC 8894) test server. */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include <wolfcert/server.h>
#include <wolfcert/errors.h>
#include <wolfcert/csr.h>
#include "../internal.h"

#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/pkcs7.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/memory.h>

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* Content-encryption cipher for the CertRep and its GetCACaps tokens. RFC 8894
 * section 3.5.2: "AES" names AES128-CBC, and "SCEPStandard" implies "AES". */
#define SCEP_SRV_ENC_OID    AES128CBCb
#define SCEP_SRV_CIPHER_CAP "AES\r\n"
#define SCEP_SRV_STD_CAP    "SCEPStandard\r\n"

typedef struct {
    /* Owns the request line and headers; path and query point into it. */
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

/* A PKCSReq or RenewalReq held under scep_require_approval. It owns copies,
 * since the request body is freed before the next poll arrives. */
typedef struct {
    uint8_t* transaction_id;
    size_t   transaction_id_len;
    uint8_t* csr_der;
    size_t   csr_len;
    uint8_t* signer_cert_der;
    size_t   signer_cert_len;
    int      polls;   /* #GetCertInitial seen for this txid */
} ScepPending;

/* An issued certificate, kept so GetCert can fetch it by serial. */
typedef struct {
    uint8_t* cert_der;
    size_t   cert_len;
} ScepIssued;

typedef struct {
    ScepPending* items;
    size_t       count;
    size_t       cap;
    ScepIssued*  issued;
    size_t       issued_count;
    /* Rolled-over CA for GetNextCACert; never the active issuing CA. */
    WolfCertCa   next_ca;
    int          next_ca_ready;
    /* Split CA/RA identity and the GetCACert bundle naming it and the CA. */
    WolfCertCa   ra;
    WolfCertBuffer ca_ra_bundle;
#if defined(WOLFCERT_BUILD_TESTING)
    /* Fault injection for the client tests. */
    int          fault_omit_recipient_nonce;
    int          fault_sign_with_wrong_key;
    int          fault_rng_fail;
    int          fault_getcert_wrong_cert;
    int          fault_getcert_no_signer;
    int          fault_oom;
    int          fault_caps_status;
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

WOLFCERT_TEST_VIS void wolfcert_scep_server_set_getcert_fault(WolfCertServer* s,
                                                              int wrong_cert,
                                                              int no_signer)
{
    ScepPriv* p = (ScepPriv*)s->priv;

    p->fault_getcert_wrong_cert = wrong_cert;
    p->fault_getcert_no_signer  = no_signer;
}

WOLFCERT_TEST_VIS void wolfcert_scep_server_set_oom_fault(WolfCertServer* s,
                                                          int when)
{
    ((ScepPriv*)s->priv)->fault_oom = when;
}

WOLFCERT_TEST_VIS void wolfcert_scep_server_set_caps_fault(WolfCertServer* s,
                                                           int status)
{
    ((ScepPriv*)s->priv)->fault_caps_status = status;
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

    WolfCertReqFraming fr;
    wolfcert_server_framing_init(&fr, sp2 + 1, (size_t)(line + llen - sp2 - 1));

    /* Split the request-target in place inside rawbuf. */
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
        const char* v;
        size_t vlen;

        if (wolfcert_http_hdr_split(line, llen, &v, &vlen) != 0 ||
                wolfcert_server_framing_hdr(&fr, line, llen, v, vlen) < 0)
            return WOLFCERT_ERR_PROTOCOL;
    }

    out->content_length = fr.content_length;
    out->connection_close = wolfcert_server_framing_close(&fr);

    size_t have = (size_t)(end - p);
    if (fr.chunked) {
        return wolfcert_server_read_chunked(s, fd, p, have, 1 * 1024 * 1024,
                                            &out->body, &out->body_len, heap);
    }

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
#if defined(WOLFCERT_BUILD_TESTING)
    int fault = ((ScepPriv*)s->priv)->fault_caps_status;

    if (fault < 0) {
        s->keep_alive = 0;
        return;
    }
    if (fault != 0) {
        send_text(s, fd, fault, "Error", "text/plain", "");
        return;
    }
#endif
    if (s->cfg.scep_enable_next_ca) {
        send_text(s, fd, 200, "OK", "text/plain",
                  "POSTPKIOperation\r\nSHA-256\r\n" SCEP_SRV_CIPHER_CAP
                  "Renewal\r\n" SCEP_SRV_STD_CAP "GetNextCACert\r\n");
    }
    else {
        send_text(s, fd, 200, "OK", "text/plain",
                  "POSTPKIOperation\r\nSHA-256\r\n" SCEP_SRV_CIPHER_CAP
                  "Renewal\r\n" SCEP_SRV_STD_CAP);
    }
}

static void handle_get_ca_cert(WolfCertServer* s, int fd)
{
    ScepPriv* p = (ScepPriv*)s->priv;

    if (p->ca_ra_bundle.data != NULL) {
        send_bin(s, fd, "application/x-x509-ca-ra-cert", p->ca_ra_bundle.data,
                 p->ca_ra_bundle.len);
    }
    else {
        send_bin(s, fd, "application/x-x509-ca-cert", s->ca.cert_der,
                 s->ca.cert_der_len);
    }
}

/* The certificate and key that decrypt requests and sign CertReps. */
static void rep_identity(const WolfCertServer* s, const uint8_t** cert,
                         size_t* cert_len, const uint8_t** key, size_t* key_len)
{
    const ScepPriv* p = (const ScepPriv*)s->priv;

    const WolfCertCa* id = p->ra.cert_der != NULL ? &p->ra : &s->ca;

    *cert     = id->cert_der;
    *cert_len = id->cert_der_len;
    *key      = id->key_der;
    *key_len  = id->key_der_len;
}

/* RFC 8894 section 4.7.1: the current CA signs the next CA certificate. */
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

    if (idx != p->count - 1)
        p->items[idx] = p->items[p->count - 1];

    memset(&p->items[p->count - 1], 0, sizeof(ScepPending));
    p->count--;
}

/* RFC 8894 section 2.4 challengePassword check; an empty `expected` accepts
 * any request. */
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

/* The signer cert must carry the public key in `der`. */
static int signer_matches_key(const uint8_t* signer_der, size_t signer_len,
                              const uint8_t* der, size_t der_len,
                              int is_csr, void* heap)
{
    uint8_t* sa = NULL;
    size_t sa_len = 0;
    uint8_t* sb = NULL;
    size_t sb_len = 0;
    int rc = wolfcert_extract_spki(signer_der, signer_len, 0, &sa, &sa_len, heap);
    if (rc != WOLFCERT_OK)
        return rc;

    rc = wolfcert_extract_spki(der, der_len, is_csr, &sb, &sb_len, heap);
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

/* RFC 8894 section 2.3: a RenewalReq is signed by the certificate it renews. */
static int signer_issued_by_ca(WolfCertServer* s, const uint8_t* signer_der,
                               size_t signer_len)
{
    WOLFSSL_CERT_MANAGER* cm;
    int rc = WOLFCERT_ERR_AUTH;
    int wrc;

    if (signer_der == NULL)
        return WOLFCERT_ERR_AUTH;

    cm = wolfSSL_CertManagerNew_ex(s->heap);
    if (cm == NULL)
        return WOLFCERT_ERR_MEMORY;

    wrc = wolfSSL_CertManagerLoadCABuffer(cm, s->ca.cert_der,
                                          (long)s->ca.cert_der_len,
                                          WOLFSSL_FILETYPE_ASN1);
    if (wrc != WOLFSSL_SUCCESS) {
        rc = WOLFCERT_ERR(WOLFCERT_ERR_CRYPTO, "scep",
                          "cannot load the CA certificate (%d)", wrc);
    }
    else {
        wrc = wolfSSL_CertManagerVerifyBuffer(cm, signer_der, (long)signer_len,
                                              WOLFSSL_FILETYPE_ASN1);
        if (wrc == WOLFSSL_SUCCESS)
            rc = WOLFCERT_OK;
        else if (wrc == MEMORY_E)
            rc = WOLFCERT_ERR_MEMORY;
    }

    wolfSSL_CertManagerFree(cm);
    return rc;
}

/* Only pkiStatus "0" envelopes `issued_cert`, encrypted to `env_target`. */
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

    /* A CertRep has up to 9 signed attributes; WOLFSSL_NO_MALLOC with
     * MAX_SIGNED_ATTRIBS_SZ < 9 drops recipientNonce and failInfo. */
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

    /* A test fault can swap in a throwaway signer. */
    const uint8_t* sign_cert;
    size_t         sign_cert_len;
    const uint8_t* sign_key;
    size_t         sign_key_len;

    rep_identity(s, &sign_cert, &sign_cert_len, &sign_key, &sign_key_len);
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

#define SCEP_ISSUED_MAX 16

/* Record a copy of `cert`, evicting the oldest entry once full. */
static int issued_record(ScepPriv* p, void* heap,
                         const uint8_t* cert, size_t cert_len)
{
    if (p->issued == NULL) {
        p->issued = (ScepIssued*)WOLFCERT_XMALLOC(
            sizeof(ScepIssued) * SCEP_ISSUED_MAX, heap);
        if (p->issued == NULL)
            return WOLFCERT_ERR_MEMORY;

        memset(p->issued, 0, sizeof(ScepIssued) * SCEP_ISSUED_MAX);
    }

    uint8_t* copy = (uint8_t*)WOLFCERT_XMALLOC(cert_len, heap);
    if (copy == NULL)
        return WOLFCERT_ERR_MEMORY;

    memcpy(copy, cert, cert_len);

    if (p->issued_count == SCEP_ISSUED_MAX) {
        WOLFCERT_XFREE(p->issued[0].cert_der, heap);
        memmove(&p->issued[0], &p->issued[1],
                sizeof(ScepIssued) * (SCEP_ISSUED_MAX - 1));
        /* The memmove left the last slot aliasing its neighbour. */
        memset(&p->issued[SCEP_ISSUED_MAX - 1], 0, sizeof(ScepIssued));
        p->issued_count--;
    }

    p->issued[p->issued_count].cert_der = copy;
    p->issued[p->issued_count].cert_len = cert_len;
    p->issued_count++;

    return WOLFCERT_OK;
}

static const ScepIssued* issued_find(ScepPriv* p, void* heap,
                                     const uint8_t* serial, size_t serial_len)
{
    for (size_t i = 0; i < p->issued_count; ++i) {
        const ScepIssued* e = &p->issued[i];
        DecodedCert dc;
        int match;

        wc_InitDecodedCert(&dc, e->cert_der, (word32)e->cert_len, heap);
        if (wc_ParseCert(&dc, CERT_TYPE, NO_VERIFY, NULL) != 0) {
            wc_FreeDecodedCert(&dc);
            continue;
        }

        match = dc.serialSz > 0 && (size_t)dc.serialSz == serial_len &&
                memcmp(dc.serial, serial, serial_len) == 0;
        wc_FreeDecodedCert(&dc);

        if (match)
            return e;
    }

    return NULL;
}

static int send_pki_failure(WolfCertServer* s, int fd,
                            const uint8_t* tid, size_t tid_len,
                            const uint8_t* snonce, size_t snonce_len,
                            const char* fail_info)
{
    return send_cert_rep(s, fd, NULL, 0, NULL, 0,
                         tid, tid_len, snonce, snonce_len, "2", fail_info);
}

/* Issue the cert and answer with a success CertRep. *did_issue, when given, is
 * set once the CA has issued, whatever the reply's outcome. */
static int issue_and_reply(WolfCertServer* s, int fd,
                           const uint8_t* csr, size_t csr_len,
                           const uint8_t* env_target, size_t env_target_len,
                           const uint8_t* tid, size_t tid_len,
                           const uint8_t* snonce, size_t snonce_len,
                           int* did_issue)
{
    uint8_t* issued = NULL;
    size_t issued_len = 0;
    int rc = wolfcert_ca_issue(&s->ca, csr, csr_len, &issued, &issued_len);

    if (did_issue != NULL)
        *did_issue = 0;
#if defined(WOLFCERT_BUILD_TESTING)
    if (rc == WOLFCERT_OK && ((ScepPriv*)s->priv)->fault_oom == 1) {
        WOLFCERT_XFREE(issued, s->heap);
        issued = NULL;
        rc = WOLFCERT_ERR_MEMORY;
    }
#endif
    if (rc == WOLFCERT_ERR_MEMORY) {
        send_text(s, fd, 500, "Server Error", "text/plain", "");
        return rc;
    }
    if (rc != WOLFCERT_OK) {
        int send_rc;

        /* Closed by the non-OK return; the flag is for the header. */
        s->keep_alive = 0;
        send_rc = send_pki_failure(s, fd, tid, tid_len, snonce, snonce_len,
                                   "2" /* badRequest */);
        if (send_rc != WOLFCERT_OK)
            WOLFCERT_LOG_DBG("scep", "CertRep send failed: %d", send_rc);

        return rc;
    }

    if (did_issue != NULL)
        *did_issue = 1;

    if (s->cfg.scep_enable_get_cert) {
        int reg_rc = issued_record((ScepPriv*)s->priv, s->heap, issued,
                                   issued_len);
        if (reg_rc != WOLFCERT_OK)
            WOLFCERT_LOG_DBG("scep", "GetCert registry allocation failed: %d",
                             reg_rc);
    }

#if defined(WOLFCERT_BUILD_TESTING)
    if (((ScepPriv*)s->priv)->fault_oom == 2) {
        WOLFCERT_XFREE(issued, s->heap);
        send_text(s, fd, 500, "Server Error", "text/plain", "");
        return WOLFCERT_ERR_MEMORY;
    }
#endif

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
    const uint8_t* env_target     = signer_cert ? signer_cert : s->ca.cert_der;
    size_t         env_target_len = signer_cert ? signer_cert_len : s->ca.cert_der_len;
    int            mrc            = WOLFCERT_OK;

    /* A RenewalReq's CSR may carry a new key, unlike its signer cert. */
    if (strcmp(mt, "17") == 0) {
        mrc = signer_issued_by_ca(s, signer_cert, signer_cert_len);
    }
    else if (signer_cert != NULL) {
        mrc = signer_matches_key(signer_cert, signer_cert_len,
                                 csr->data, csr->len, 1, s->heap);
#if defined(WOLFCERT_BUILD_TESTING)
        if (mrc == WOLFCERT_OK && ((ScepPriv*)s->priv)->fault_oom == 3)
            mrc = WOLFCERT_ERR_MEMORY;
#endif
    }
    if (mrc == WOLFCERT_ERR_MEMORY || mrc == WOLFCERT_ERR_CRYPTO) {
        send_text(s, fd, 500, "Server Error", "text/plain", "");
        return mrc;
    }
    if (mrc != WOLFCERT_OK) {
        s->keep_alive = 0;
        return send_pki_failure(s, fd, tid, tid_len, snonce, snonce_len,
                                "2" /* badRequest */);
    }

    if (check_challenge(csr->data, csr->len, s->cfg_challenge,
                        s->heap) != WOLFCERT_OK) {
        s->keep_alive = 0;
        return send_pki_failure(s, fd, tid, tid_len, snonce, snonce_len,
                                "2" /* badRequest */);
    }

    if (s->cfg.scep_require_approval) {
        /* PENDING; the client polls with GetCertInitial (messageType 20). */
        ScepPriv* p = (ScepPriv*)s->priv;

        /* Refuse now a CSR that could never issue, rather than park it. */
        int vrc = wolfcert_csr_verify(csr->data, csr->len, s->heap);
        if (vrc == WOLFCERT_ERR_MEMORY) {
            send_text(s, fd, 500, "Server Error", "text/plain", "");
            return vrc;
        }
        if (vrc != WOLFCERT_OK) {
            s->keep_alive = 0;
            return send_pki_failure(s, fd, tid, tid_len, snonce, snonce_len,
                                    "2" /* badRequest */);
        }

        ScepPending* e = pending_find(p, tid, tid_len);
        if (e == NULL) {
            int add = pending_add(p, s->heap, tid, tid_len,
                                  csr->data, csr->len,
                                  signer_cert ? signer_cert : s->ca.cert_der,
                                  signer_cert ? signer_cert_len : s->ca.cert_der_len);

            if (add != WOLFCERT_OK) {
                return send_pki_failure(s, fd, tid, tid_len, snonce, snonce_len,
                                        "2" /* badRequest */);
            }
        }
        else {
            /* Only the signer that parked the request may resend it. */
            int krc = signer_cert == NULL ? WOLFCERT_ERR_AUTH :
                      signer_matches_key(signer_cert, signer_cert_len,
                                         e->signer_cert_der, e->signer_cert_len,
                                         0, s->heap);
            if (krc == WOLFCERT_OK &&
                    (csr->len != e->csr_len ||
                     memcmp(csr->data, e->csr_der, csr->len) != 0))
                krc = WOLFCERT_ERR_AUTH;
            if (krc == WOLFCERT_ERR_MEMORY) {
                send_text(s, fd, 500, "Server Error", "text/plain", "");
                return krc;
            }
            if (krc != WOLFCERT_OK) {
                s->keep_alive = 0;
                return send_pki_failure(s, fd, tid, tid_len, snonce, snonce_len,
                                        "2" /* badRequest */);
            }
        }

        return send_cert_rep(s, fd, NULL, 0, env_target, env_target_len,
                             tid, tid_len, snonce, snonce_len, "3", NULL);
    }

    return issue_and_reply(s, fd, csr->data, csr->len,
                           env_target, env_target_len,
                           tid, tid_len, snonce, snonce_len, NULL);
}

/* 1 when `name` holds the contents of the CSR's subject Name, 0 when not, or
 * WOLFCERT_ERR_MEMORY. */
static int csr_subject_is(const uint8_t* csr_der, size_t csr_len,
                          const uint8_t* name, size_t name_len, void* heap)
{
    DecodedCert dc;
    int match = 0;
    int wrc;

    wc_InitDecodedCert(&dc, (byte*)csr_der, (word32)csr_len, heap);
    wrc = wc_ParseCert(&dc, CERTREQ_TYPE, NO_VERIFY, NULL);
    if (wrc == MEMORY_E) {
        match = WOLFCERT_ERR_MEMORY;
    }
    else if (wrc == 0) {
        match = dc.subjectRaw != NULL &&
                (size_t)dc.subjectRawLen == name_len &&
                memcmp(dc.subjectRaw, name, name_len) == 0;
    }
    wc_FreeDecodedCert(&dc);

    return match;
}

/* GetCertInitial (20): the first accepted poll issues the cert; any other
 * poll fails and leaves the queue unchanged. */
static int handle_get_cert_initial(WolfCertServer* s, int fd,
                                   const WolfCertBuffer* ias,
                                   const uint8_t* signer_cert,
                                   size_t signer_cert_len,
                                   const uint8_t* tid, size_t tid_len,
                                   const uint8_t* snonce, size_t snonce_len)
{
    ScepPriv* p = (ScepPriv*)s->priv;
    const uint8_t* issuer = NULL;
    size_t issuer_len = 0;
    const uint8_t* subject = NULL;
    size_t subject_len = 0;
    ScepPending* e = pending_find(p, tid, tid_len);
    int named = 0;

    if (e != NULL &&
            wolfcert_scep_parse_issuer_and_subject(ias->data, ias->len,
                &issuer, &issuer_len, &subject, &subject_len) == WOLFCERT_OK) {
        named = wolfcert_scep_issuer_name_matches(s->ca.cert_der,
                    s->ca.cert_der_len, issuer, issuer_len, s->heap);
        if (named == 1)
            named = csr_subject_is(e->csr_der, e->csr_len, subject,
                                   subject_len, s->heap);
    }
#if defined(WOLFCERT_BUILD_TESTING)
    if (named == 1 && p->fault_oom == 4)
        named = WOLFCERT_ERR_MEMORY;
#endif
    if (named == WOLFCERT_ERR_MEMORY) {
        send_text(s, fd, 500, "Server Error", "text/plain", "");
        return named;
    }
    if (named != 1) {
        return send_pki_failure(s, fd, tid, tid_len, snonce, snonce_len,
                                "4" /* badCertId */);
    }

    /* Only the key that parked the request may release it. */
    int mrc = signer_cert == NULL ? WOLFCERT_ERR_AUTH :
              signer_matches_key(signer_cert, signer_cert_len,
                                 e->signer_cert_der, e->signer_cert_len,
                                 0, s->heap);
#if defined(WOLFCERT_BUILD_TESTING)
    if (mrc == WOLFCERT_OK && p->fault_oom == 3)
        mrc = WOLFCERT_ERR_MEMORY;
#endif
    if (mrc == WOLFCERT_ERR_MEMORY) {
        send_text(s, fd, 500, "Server Error", "text/plain", "");
        return mrc;
    }
    if (mrc != WOLFCERT_OK) {
        return send_pki_failure(s, fd, tid, tid_len, snonce, snonce_len,
                                "4" /* badCertId */);
    }

    e->polls++;
    int did_issue = 0;
    int rc = issue_and_reply(s, fd, e->csr_der, e->csr_len,
                             e->signer_cert_der, e->signer_cert_len,
                             tid, tid_len, snonce, snonce_len, &did_issue);

    /* Out of memory before issuing keeps the request for another poll. */
    if (rc != WOLFCERT_ERR_MEMORY || did_issue)
        pending_remove(p, s->heap, e);

    return rc;
}

/* RFC 8894 section 3.3.4 GetCert: the decrypted payload is an
 * IssuerAndSerialNumber naming a certificate this CA issued. */
static int handle_get_cert(WolfCertServer* s, int fd, const WolfCertBuffer* ias,
                           const uint8_t* env_target, size_t env_target_len,
                           const uint8_t* tid, size_t tid_len,
                           const uint8_t* snonce, size_t snonce_len)
{
    ScepPriv* p = (ScepPriv*)s->priv;
    const uint8_t* issuer = NULL;
    size_t issuer_len = 0;
    const uint8_t* serial = NULL;
    size_t serial_len = 0;
    const ScepIssued* hit = NULL;
    int named = 0;

    /* No CA-cert fallback as in handle_enroll: the requester could not decrypt
     * a reply enveloped to the CA's own key. */
    if (env_target == NULL || env_target_len == 0) {
        s->keep_alive = 0;
        return send_pki_failure(s, fd, tid, tid_len, snonce, snonce_len,
                                "2" /* badRequest */);
    }

    if (wolfcert_scep_parse_issuer_and_serial(ias->data, ias->len,
                                              &issuer, &issuer_len,
                                              &serial, &serial_len) == WOLFCERT_OK)
        named = wolfcert_scep_issuer_name_matches(s->ca.cert_der,
                    s->ca.cert_der_len, issuer, issuer_len, s->heap);
#if defined(WOLFCERT_BUILD_TESTING)
    if (named == 1 && p->fault_oom == 4)
        named = WOLFCERT_ERR_MEMORY;
#endif
    if (named == WOLFCERT_ERR_MEMORY) {
        send_text(s, fd, 500, "Server Error", "text/plain", "");
        return named;
    }
    if (named == 1)
        hit = issued_find(p, s->heap, serial, serial_len);

    if (hit == NULL) {
        return send_pki_failure(s, fd, tid, tid_len, snonce, snonce_len,
                                "4" /* badCertId */);
    }

    const uint8_t* reply     = hit->cert_der;
    size_t         reply_len  = hit->cert_len;

#if defined(WOLFCERT_BUILD_TESTING)
    if (p->fault_getcert_wrong_cert) {
        reply     = s->ca.cert_der;
        reply_len = s->ca.cert_der_len;
    }
#endif

    return send_cert_rep(s, fd, reply, reply_len,
                         env_target, env_target_len,
                         tid, tid_len, snonce, snonce_len, "0", NULL);
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
    int send_rc = WOLFCERT_OK;

    int rc = wolfcert_scep_parse_pki_message(req->body, req->body_len, &env,
            &tid, &tid_len, &snonce, &snonce_len, &rnonce, &rnonce_len,
            &mt, &ps, &signer_cert, &signer_cert_len, NULL, s->heap);
    if (rc == WOLFCERT_ERR_MEMORY) {
        send_text(s, fd, 500, "Server Error", "text/plain", "");
        goto out;
    }
    if (rc != WOLFCERT_OK) {
        send_text(s, fd, 400, "Bad Request", "text/plain", "");
        goto out;
    }

    /* RFC 8894 section 3.2.1: every message carries a PrintableString
     * transactionID, a messageType and a 16-byte senderNonce. */
    if (tid == NULL || tid_len == 0 ||
            !wolfcert_is_printable_string(tid, tid_len) ||
            snonce == NULL || snonce_len != SCEP_NONCE_SZ ||
            mt == NULL || mt[0] == '\0') {
        s->keep_alive = 0;
        send_text(s, fd, 400, "Bad Message", "text/plain", "");
        rc = WOLFCERT_ERR_PROTOCOL;
        goto out;
    }

    const uint8_t* rcpt_cert;
    size_t         rcpt_cert_len;
    const uint8_t* rcpt_key;
    size_t         rcpt_key_len;

    rep_identity(s, &rcpt_cert, &rcpt_cert_len, &rcpt_key, &rcpt_key_len);
    rc = wolfcert_scep_deenvelop(rcpt_cert, rcpt_cert_len, rcpt_key,
                                 rcpt_key_len, env.data, env.len, &csr,
                                 s->heap);
    if (rc != WOLFCERT_OK) {
        const char* fail_info = rc == WOLFCERT_ERR_UNSUPPORTED
                                    ? "0" /* badAlg */
                                    : "2" /* badRequest */;

        s->keep_alive = 0;
        send_rc = send_pki_failure(s, fd, tid, tid_len, snonce, snonce_len,
                                   fail_info);
        if (send_rc != WOLFCERT_OK)
            WOLFCERT_LOG_DBG("scep", "CertRep send failed: %d", send_rc);

        goto out;
    }

    if (strcmp(mt, "19") == 0 || strcmp(mt, "17") == 0) {
        rc = handle_enroll(s, fd, mt, &csr, signer_cert, signer_cert_len,
                           tid, tid_len, snonce, snonce_len);
    }
    else if (strcmp(mt, "20") == 0) {
        rc = handle_get_cert_initial(s, fd, &csr, signer_cert,
                                     signer_cert_len, tid, tid_len,
                                     snonce, snonce_len);
    }
    else if (strcmp(mt, "21") == 0 && s->cfg.scep_enable_get_cert) {
        const uint8_t* gc_signer     = signer_cert;
        size_t         gc_signer_len = signer_cert_len;
#if defined(WOLFCERT_BUILD_TESTING)
        /* Simulate a missing signer cert without dropping the owned pointer. */
        if (((ScepPriv*)s->priv)->fault_getcert_no_signer) {
            gc_signer     = NULL;
            gc_signer_len = 0;
        }
#endif
        rc = handle_get_cert(s, fd, &csr, gc_signer, gc_signer_len,
                             tid, tid_len, snonce, snonce_len);
    }
    else {
        s->keep_alive = 0;
        send_rc = send_pki_failure(s, fd, tid, tid_len, snonce, snonce_len,
                                   "2" /* badRequest */);
        if (send_rc != WOLFCERT_OK)
            WOLFCERT_LOG_DBG("scep", "CertRep send failed: %d", send_rc);

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

/* Value of query parameter `key`, matched as a whole name, or NULL. */
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

/* RFC 8894 section 4.1: a GET carries the base64 pkiMessage in `message`. */
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

    /* Free any body sent with a GET. */
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

/* Issue the RA identity from the CA and bundle it ahead of the CA. */
static int make_split_ra(WolfCertServer* s, ScepPriv* p)
{
    WolfCertKeyCfg kcfg = { .type = WOLFCERT_KEY_RSA, .param = 2048,
                            .dev_id = WOLFCERT_DEVID_SOFTWARE,
                            .heap = s->heap };
    WolfCertCertMeta meta = { .subject_dn = "CN=wolfCert Test RA,O=wolfCert" };
    WolfCertKey* key = NULL;
    WolfCertBuffer csr = { 0 };
    WolfCertBuffer kder = { 0 };
    const uint8_t* certs[2];
    size_t lens[2];
    int rc;

    rc = wolfcert_key_generate(&kcfg, &key);
    if (rc == WOLFCERT_OK)
        rc = wolfcert_csr_build(key, &meta, &csr);
    if (rc == WOLFCERT_OK)
        rc = wolfcert_key_to_der(key, &kder);
    if (rc == WOLFCERT_OK)
        rc = wolfcert_ca_issue(&s->ca, csr.data, csr.len, &p->ra.cert_der,
                               &p->ra.cert_der_len);
    if (rc == WOLFCERT_OK) {
        p->ra.type        = WOLFCERT_KEY_RSA;
        p->ra.heap        = s->heap;
        p->ra.impl        = key->impl;
        key->impl         = NULL;
        p->ra.key_der     = kder.data;
        p->ra.key_der_len = kder.len;
        kder.data         = NULL;
        certs[0] = p->ra.cert_der;
        lens[0]  = p->ra.cert_der_len;
        certs[1] = s->ca.cert_der;
        lens[1]  = s->ca.cert_der_len;
        rc = wolfcert_pkcs7_build_certs_only(certs, lens, 2, &p->ca_ra_bundle,
                                             s->heap);
    }

    wolfcert_buffer_free_secure(&kder);
    wolfcert_buffer_free(&csr);
    wolfcert_key_free(key);
    return rc;
}

static void free_split_ra(ScepPriv* p)
{
    wolfcert_ca_free(&p->ra);
    wolfcert_buffer_free(&p->ca_ra_bundle);
}

#if defined(WOLFCERT_BUILD_TESTING)
#define BUNDLE_CERT_CAP 4096
#define BUNDLE_CA       1
#define BUNDLE_EXPIRED  2

/* A certificate for `pub` under subject cn, or the CA's subject when cn is
 * NULL, signed by signer for issuer (self-signed if NULL), else by the CA. */
static int bundle_cert(WolfCertServer* s, int key_type, void* pub,
                       const char* cn, const char* ku, int flags,
                       RsaKey* signer, const uint8_t* issuer,
                       size_t issuer_len, uint8_t** der, size_t* len)
{
    static const byte not_before[] = { ASN_UTC_TIME, 13, '0', '0', '0', '1',
                                       '0', '1', '0', '0', '0', '0', '0', '0',
                                       'Z' };
    static const byte not_after[]  = { ASN_UTC_TIME, 13, '0', '1', '0', '1',
                                       '0', '1', '0', '0', '0', '0', '0', '0',
                                       'Z' };
    Cert* c = wc_CertNew(s->heap);
    WC_RNG rng;
    int rng_ok = 0;
    int sz = 0;
    int rc = WOLFCERT_OK;

    *der = NULL;
    if (c == NULL)
        return WOLFCERT_ERR_MEMORY;

    if (signer == NULL) {
        signer     = (RsaKey*)s->ca.impl;
        issuer     = s->ca.cert_der;
        issuer_len = s->ca.cert_der_len;
    }
    if (wc_InitCert_ex(c, s->heap, WOLFCERT_DEVID_SOFTWARE) != 0)
        rc = WOLFCERT_ERR_CRYPTO;
    if (rc == WOLFCERT_OK) {
        c->sigType    = CTC_SHA256wRSA;
        c->daysValid  = 30;
        c->isCA       = (flags & BUNDLE_CA) != 0;
        c->selfSigned = issuer == NULL;
        if ((flags & BUNDLE_EXPIRED) != 0) {
            memcpy(c->beforeDate, not_before, sizeof(not_before));
            memcpy(c->afterDate, not_after, sizeof(not_after));
            c->beforeDateSz = (int)sizeof(not_before);
            c->afterDateSz  = (int)sizeof(not_after);
        }
        if (cn != NULL)
            strncpy(c->subject.commonName, cn, CTC_NAME_SIZE - 1);
        else if (wc_SetSubjectBuffer(c, s->ca.cert_der,
                                     (int)s->ca.cert_der_len) != 0)
            rc = WOLFCERT_ERR_CRYPTO;
    }
    if (rc == WOLFCERT_OK && issuer != NULL &&
            wc_SetIssuerBuffer(c, issuer, (int)issuer_len) != 0)
        rc = WOLFCERT_ERR_CRYPTO;
    if (rc == WOLFCERT_OK && ku != NULL && wc_SetKeyUsage(c, ku) != 0)
        rc = WOLFCERT_ERR_CRYPTO;
    if (rc == WOLFCERT_OK) {
        *der = (uint8_t*)WOLFCERT_XMALLOC(BUNDLE_CERT_CAP, s->heap);
        if (*der == NULL)
            rc = WOLFCERT_ERR_MEMORY;
    }
    if (rc == WOLFCERT_OK) {
        if (wc_InitRng_ex(&rng, s->heap, WOLFCERT_DEVID_SOFTWARE) != 0)
            rc = WOLFCERT_ERR_CRYPTO;
        else
            rng_ok = 1;
    }
    if (rc == WOLFCERT_OK) {
        sz = wc_MakeCert_ex(c, *der, BUNDLE_CERT_CAP, key_type, pub, &rng);
        if (sz > 0)
            sz = wc_SignCert(c->bodySz, c->sigType, *der, BUNDLE_CERT_CAP,
                             signer, NULL, &rng);
        if (sz <= 0)
            rc = WOLFCERT_ERR_CRYPTO;
    }

    if (rng_ok)
        wc_FreeRng(&rng);
    wc_CertFree(c);
    if (rc == WOLFCERT_OK) {
        *len = (size_t)sz;
    }
    else {
        WOLFCERT_XFREE(*der, s->heap);
        *der = NULL;
    }
    return rc;
}

/* A root with its own key and keyEncipherment, and the CA reissued under it. */
static int bundle_root(WolfCertServer* s, uint8_t** root, size_t* root_len)
{
    WolfCertKeyCfg kcfg = { .type = WOLFCERT_KEY_RSA, .param = 2048,
                            .dev_id = WOLFCERT_DEVID_SOFTWARE,
                            .heap = s->heap };
    WolfCertKey* key = NULL;
    uint8_t* ca = NULL;
    size_t ca_len = 0;
    int rc;

    rc = wolfcert_key_generate(&kcfg, &key);
    if (rc == WOLFCERT_OK)
        rc = bundle_cert(s, RSA_TYPE, key->impl, "wolfCert Test Root",
                         "keyCertSign,cRLSign,keyEncipherment", BUNDLE_CA,
                         key->impl, NULL, 0, root, root_len);
    if (rc == WOLFCERT_OK)
        rc = bundle_cert(s, RSA_TYPE, s->ca.impl, NULL,
                         "keyCertSign,cRLSign,digitalSignature,"
                         "keyEncipherment", BUNDLE_CA, key->impl, *root,
                         *root_len, &ca, &ca_len);
    if (rc == WOLFCERT_OK) {
        WOLFCERT_XFREE(s->ca.cert_der, s->ca.heap);
        s->ca.cert_der     = ca;
        s->ca.cert_der_len = ca_len;
        s->ca.skid_copies  = wolfcert_ca_skid_copies(&s->ca);
    }

    wolfcert_key_free(key);
    return rc;
}

WOLFCERT_TEST_VIS int wolfcert_scep_server_set_bundle_fault(WolfCertServer* s,
                                                            int mode)
{
    ScepPriv* p = (ScepPriv*)s->priv;
    RsaKey* ca_key = (RsaKey*)s->ca.impl;
    WolfCertKeyCfg ecc = { .type = WOLFCERT_KEY_ECC, .param = 256,
                           .dev_id = WOLFCERT_DEVID_SOFTWARE,
                           .heap = s->heap };
    WolfCertKey* ecc_key = NULL;
    uint8_t* der[4] = { NULL, NULL, NULL, NULL };
    size_t len[4] = { 0, 0, 0, 0 };
    const uint8_t* certs[5];
    size_t lens[5];
    size_t n = 0;
    size_t i;
    WolfCertBuffer bundle = { 0 };
    int rc = WOLFCERT_OK;

    if (mode < 1 || mode > 5 || s->ca.type != WOLFCERT_KEY_RSA ||
            (mode == 2 || mode >= 4) != (p->ra.cert_der != NULL))
        return WOLFCERT_ERR_BAD_ARG;

    if (mode == 2) {
        rc = bundle_cert(s, RSA_TYPE, ca_key, "wolfCert Test Decoy", NULL, 0,
                         NULL, NULL, 0, &der[0], &len[0]);
        if (rc == WOLFCERT_OK)
            rc = bundle_cert(s, RSA_TYPE, ca_key, "wolfCert Test RA Signer",
                             "digitalSignature", 0, NULL, NULL, 0,
                             &der[1], &len[1]);
        if (rc == WOLFCERT_OK)
            rc = bundle_cert(s, RSA_TYPE, p->ra.impl, "wolfCert Test RA",
                             "digitalSignature,keyEncipherment", 0, NULL,
                             NULL, 0, &der[2], &len[2]);
    }
    if (mode == 4) {
        rc = bundle_cert(s, RSA_TYPE, ca_key, "wolfCert Test RA Twin",
                         "keyEncipherment", 0, NULL, NULL, 0, &der[0], &len[0]);
        if (rc == WOLFCERT_OK)
            rc = bundle_cert(s, RSA_TYPE, p->ra.impl, "wolfCert Test RA",
                             "keyEncipherment", 0, NULL, NULL, 0,
                             &der[2], &len[2]);
    }
    if (mode == 5)
        rc = bundle_cert(s, RSA_TYPE, p->ra.impl, "wolfCert Test RA",
                         "digitalSignature,keyEncipherment", BUNDLE_EXPIRED,
                         NULL, NULL, 0, &der[2], &len[2]);
    if (rc == WOLFCERT_OK && mode == 1)
        rc = bundle_root(s, &der[3], &len[3]);
    if (rc == WOLFCERT_OK && mode == 3) {
        rc = wolfcert_key_generate(&ecc, &ecc_key);
        if (rc == WOLFCERT_OK)
            rc = bundle_cert(s, ECC_TYPE, ecc_key->impl,
                             "wolfCert Test ECC Leaf", NULL, 0, NULL, NULL, 0,
                             &der[0], &len[0]);
    }

    if (rc == WOLFCERT_OK) {
        for (i = 0; i < 4; i++) {
            if (der[i] != NULL) {
                certs[n] = der[i];
                lens[n++] = len[i];
            }
        }
        certs[n] = s->ca.cert_der;
        lens[n++] = s->ca.cert_der_len;
        rc = wolfcert_pkcs7_build_certs_only(certs, lens, n, &bundle, s->heap);
    }
    if (rc == WOLFCERT_OK) {
        wolfcert_buffer_free(&p->ca_ra_bundle);
        p->ca_ra_bundle = bundle;
        if (der[2] != NULL) {
            WOLFCERT_XFREE(p->ra.cert_der, p->ra.heap);
            p->ra.cert_der     = der[2];
            p->ra.cert_der_len = len[2];
            der[2] = NULL;
        }
    }

    for (i = 0; i < 4; i++)
        WOLFCERT_XFREE(der[i], s->heap);
    wolfcert_key_free(ecc_key);
    return rc;
}
#endif

static int scep_start(const WolfCertServerCfgSrv* cfg, WolfCertServer* base)
{
    ScepPriv* p = (ScepPriv*)WOLFCERT_XMALLOC(sizeof(*p), base->heap);
    int rc = WOLFCERT_OK;

    if (p == NULL)
        return WOLFCERT_ERR_MEMORY;

    memset(p, 0, sizeof(*p));
    base->priv = p;

    if (cfg->scep_split_ra)
        rc = make_split_ra(base, p);

    return rc;
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

    for (size_t i = 0; i < p->issued_count; ++i)
        WOLFCERT_XFREE(p->issued[i].cert_der, srv->heap);

    WOLFCERT_XFREE(p->issued, srv->heap);
    free_split_ra(p);
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
