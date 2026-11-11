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

#include <wolfcert/est.h>
#include <wolfcert/http.h>
#include <wolfcert/errors.h>
#include "../internal.h"

#include <wolfssl/wolfcrypt/memory.h>

#include <string.h>

enum est_session_op {
    EST_OP_GET_CACERTS,
    EST_OP_GET_CSRATTRS,
    EST_OP_SIMPLE_ENROLL,
    EST_OP_SIMPLE_REENROLL
};

static const struct {
    const char* path;
    const char* accept;
} est_ops[] = {
    { "cacerts",        "application/pkcs7-mime" },
    { "csrattrs",       "application/csrattrs"   },
    { "simpleenroll",   "application/pkcs7-mime" },
    { "simplereenroll", "application/pkcs7-mime" }
};

static int est_is_enroll(enum est_session_op op)
{
    return op == EST_OP_SIMPLE_ENROLL || op == EST_OP_SIMPLE_REENROLL;
}

static char* join_path(const char* base, const char* suffix, void* heap)
{
    size_t bl = strlen(base);
    size_t sl = strlen(suffix);

    int trim = (bl > 0 && base[bl - 1] == '/') ? 1 : 0;
    char* out = (char*)WOLFCERT_XMALLOC(bl + sl + 2, heap);
    if (out == NULL)
        return NULL;

    memcpy(out, base, bl - trim);
    out[bl - trim] = '/';
    memcpy(out + bl - trim + 1, suffix, sl + 1);

    return out;
}

/* Parse the response to op into *out and free resp. res takes an enroll op's
 * status and is NULL for the other ops. */
static int est_finish(void* heap, WolfCertHttpResponse* resp,
                      enum est_session_op op,
                      WolfCertEncoding enc, WolfCertBuffer* out,
                      WolfCertEstResult* res)
{
    int rc = WOLFCERT_OK;
    int status = resp->status_code;
    int decoded = 0;
    WolfCertBuffer der = { 0 };

    /* RFC 7030 section 4.2.3: 202 Accepted = enrolment pending. */
    if (res != NULL && status == 202) {
        res->status          = WOLFCERT_EST_STATUS_PENDING;
        res->retry_after_sec = resp->retry_after_sec;
    }
    /* No CSR attributes (RFC 7030 section 4.5.2). */
    else if (op == EST_OP_GET_CSRATTRS &&
             (status == 204 || status == 404 || status == 405 ||
              status == 501 || (status == 200 && resp->body_len == 0))) {
        memset(out, 0, sizeof(*out));
    }
    else if (status != 200) {
        if (res != NULL)
            res->status = WOLFCERT_EST_STATUS_FAILURE;
        rc = WOLFCERT_ERR(status == 401 || status == 403 ? WOLFCERT_ERR_AUTH
                                                         : WOLFCERT_ERR_HTTP,
                          "est", "%s rejected: HTTP %d", est_ops[op].path,
                          status);
    }
    else if (resp->body_len == 0) {
        rc = WOLFCERT_ERR(WOLFCERT_ERR_HTTP, "est",
            "200 response carried no certificate");
    }
    else {
        rc = wolfcert_base64_decode(resp->body, resp->body_len, &der, heap);
        decoded = (rc == WOLFCERT_OK);
    }

    wolfcert_http_response_free(resp);

    if (decoded && op == EST_OP_GET_CSRATTRS) {
        *out = der;
        memset(&der, 0, sizeof(der));
    }
    else if (decoded && enc == WOLFCERT_ENCODING_DER) {
        rc = wolfcert_pkcs7_certs_to_der(der.data, der.len, out, heap);
    }
    else if (decoded) {
        rc = wolfcert_pkcs7_certs_to_pem(der.data, der.len, out, heap);
    }

    if (decoded && rc == WOLFCERT_OK && res != NULL)
        res->status = WOLFCERT_EST_STATUS_SUCCESS;

    wolfcert_buffer_free(&der);
    return rc;
}

void wolfcert_est_result_free(WolfCertEstResult* r)
{
    if (r == NULL)
        return;

    wolfcert_buffer_free(&r->cert_pem);
    r->status          = WOLFCERT_EST_STATUS_UNSET;
    r->retry_after_sec = 0;
    r->heap            = NULL;
}

struct WolfCertEstSession {
    WolfCertHttpSession* http;
    char*                base_url;     /* e.g. https://ca.example/.well-known/est */
    void*                heap;

    /* Copied at open so the cfg need not outlive the session; NULL if none. */
    char*                basic_user;
    char*                basic_pass;
    int                  has_client_identity;

    /* The request in flight, blocking or _nb; at most one at a time. */
    int                  in_active;
    char*                in_url;
    WolfCertBuffer       in_body;      /* base64-encoded CSR for POST, owned */
    WolfCertHttpRequest  in_req;
    WolfCertHttpResponse in_resp;
    const void*          in_out;       /* caller's output, checked on resume */
    enum est_session_op  in_op;
    WolfCertEncoding     in_enc;
};

static int est_session_open_dev(const WolfCertServerCfg* srv, int tls_dev_id,
                                WolfCertEstSession** out)
{
    if (srv == NULL || srv->server_url == NULL || out == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    void* heap = srv->heap ? srv->heap : wolfcert_default_heap();

    int rc = wolfcert_cfg_require_proto(srv, WOLFCERT_PROTO_EST, "est");
    if (rc != WOLFCERT_OK)
        return rc;

    WolfCertUrl u;
    rc = wolfcert_http_url_parse(srv->server_url, &u, heap);
    if (rc != WOLFCERT_OK)
        return rc;

    int tls = u.tls;
    wolfcert_http_url_free(&u);
    if (!tls)
        return WOLFCERT_ERR(WOLFCERT_ERR_TLS, "est",
            "EST requires TLS; refusing plaintext http:// URL (RFC 7030)");

    if (!srv->verify_server)
        return WOLFCERT_ERR(WOLFCERT_ERR_TLS, "est",
            "EST requires server authentication: set verify_server to verify "
            "the server certificate (RFC 7030)");

    WolfCertEstSession* s = (WolfCertEstSession*)WOLFCERT_XMALLOC(sizeof(*s), heap);
    if (s == NULL)
        return WOLFCERT_ERR_MEMORY;

    memset(s, 0, sizeof(*s));
    s->heap                = heap;
    s->has_client_identity = srv->client_cert != NULL &&
                             srv->client_key != NULL;
    s->base_url            = wolfcert_strdup(srv->server_url, heap);
    if (s->base_url == NULL) {
        wolfcert_est_session_close(s);
        return WOLFCERT_ERR_MEMORY;
    }

    const char* user = srv->proto_opts.est.username;
    const char* pass = srv->proto_opts.est.password;
    if (user != NULL)
        s->basic_user = wolfcert_strdup(user, heap);
    if (pass != NULL)
        s->basic_pass = wolfcert_strdup(pass, heap);
    if ((user != NULL && s->basic_user == NULL) ||
        (pass != NULL && s->basic_pass == NULL)) {
        wolfcert_est_session_close(s);
        return WOLFCERT_ERR_MEMORY;
    }

    WolfCertHttpSessionCfg hcfg = {
        .base_url                  = s->base_url,
        .trust_anchors             = srv->trust_anchors,
        .trust_anchors_len         = srv->trust_anchors_len,
        .verify_server             = srv->verify_server,
        .timeout_ms                = srv->timeout_ms,
        .max_response_bytes        = srv->max_response_bytes,
        .client_cert               = srv->client_cert,
        .client_cert_len           = srv->client_cert_len,
        .client_key                = srv->client_key,
        .client_key_len            = srv->client_key_len,
        .client_key_src            = srv->client_key_src,
        .client_key_dev_id         = srv->client_key_dev_id,
        .allow_post_handshake_auth = srv->proto_opts.est.allow_post_handshake_auth,
        .transport                 = srv->transport,
        .heap                      = heap,
    };
    rc = wolfcert_http_session_open_dev(&hcfg, tls_dev_id, &s->http);
    if (rc != WOLFCERT_OK) {
        /* Free with wolfcert_est_session_close() to zero s->basic_pass. */
        wolfcert_est_session_close(s);
        return rc;
    }

    *out = s;
    return WOLFCERT_OK;
}

int wolfcert_est_session_open(const WolfCertServerCfg* srv,
                              WolfCertEstSession** out)
{
    return est_session_open_dev(srv, wolfcert_default_dev_id(), out);
}

int wolfcert_est_session_fd(const WolfCertEstSession* s)
{
    return s != NULL ? wolfcert_http_session_fd(s->http) : -1;
}

/* Free the request in flight; its response stays for the parse. */
static void est_session_free_request(WolfCertEstSession* s)
{
    WOLFCERT_XFREE(s->in_url, s->heap);
    s->in_url = NULL;
    wolfcert_buffer_free(&s->in_body);
    memset(&s->in_req, 0, sizeof(s->in_req));
}

static void est_session_reset(WolfCertEstSession* s)
{
    est_session_free_request(s);
    wolfcert_http_response_free(&s->in_resp);
    memset(&s->in_resp, 0, sizeof(s->in_resp));
    s->in_out    = NULL;
    s->in_active = 0;
}

/* Refuse a resumed _nb call that does not match the request in flight. */
static int est_session_resume_check(const WolfCertEstSession* s,
                                    enum est_session_op op,
                                    WolfCertEncoding enc, const void* out)
{
    if (s->in_op != op)
        return WOLFCERT_ERR(WOLFCERT_ERR_BAD_ARG, "est",
            "a different EST operation is already in flight on this session");
    if (out != s->in_out)
        return WOLFCERT_ERR(WOLFCERT_ERR_BAD_ARG, "est",
            "output pointer differs from the in-flight request; pass the "
            "same pointer to each poll call");
    if (enc != s->in_enc)
        return WOLFCERT_ERR(WOLFCERT_ERR_BAD_ARG, "est",
            "encoding differs from the in-flight request");
    return WOLFCERT_OK;
}

void wolfcert_est_session_close(WolfCertEstSession* s)
{
    if (s == NULL)
        return;

    est_session_reset(s);
    if (s->http)
        wolfcert_http_session_close(s->http);

    WOLFCERT_XFREE(s->base_url, s->heap);

    if (s->basic_user != NULL)
        wc_ForceZero(s->basic_user, (word32)strlen(s->basic_user));
    WOLFCERT_XFREE(s->basic_user, s->heap);
    if (s->basic_pass != NULL)
        wc_ForceZero(s->basic_pass, (word32)strlen(s->basic_pass));
    WOLFCERT_XFREE(s->basic_pass, s->heap);
    WOLFCERT_XFREE(s, s->heap);
}

/* Clear the caller's output, unless it is the in-flight request's. */
static void est_call_clear(const WolfCertEstSession* s,
                           WolfCertBuffer* out, WolfCertEstResult* res)
{
    if (s != NULL && s->in_active && (const void*)out == s->in_out)
        return;

    if (res != NULL)
        memset(res, 0, sizeof(*res));
    else if (out != NULL)
        memset(out, 0, sizeof(*out));
}

static int est_call_check(enum est_session_op op,
                          const uint8_t* csr_der, size_t csr_der_len,
                          WolfCertEncoding enc, const WolfCertBuffer* out)
{
    if (out == NULL ||
        (enc != WOLFCERT_ENCODING_PEM && enc != WOLFCERT_ENCODING_DER) ||
        (est_is_enroll(op) && (csr_der == NULL || csr_der_len == 0)))
        return WOLFCERT_ERR_BAD_ARG;

    return WOLFCERT_OK;
}

/* Build the request for op into s->in_* and mark it in flight. */
static int est_session_begin(WolfCertEstSession* s, enum est_session_op op,
                             const uint8_t* csr_der, size_t csr_der_len,
                             WolfCertEncoding enc, const void* out)
{
    int rc = WOLFCERT_OK;

    s->in_url = join_path(s->base_url, est_ops[op].path, s->heap);
    if (s->in_url == NULL)
        rc = WOLFCERT_ERR_MEMORY;

    if (rc == WOLFCERT_OK && est_is_enroll(op)) {
        rc = wolfcert_base64_encode_mime(csr_der, csr_der_len, &s->in_body,
                                         s->heap);
    }

    if (rc == WOLFCERT_OK) {
        s->in_req = (WolfCertHttpRequest){
            .method     = "GET",
            .url        = s->in_url,
            .accept     = est_ops[op].accept,
            .basic_user = s->basic_user,
            .basic_pass = s->basic_pass,
            .heap       = s->heap,
        };
        if (est_is_enroll(op)) {
            s->in_req.method                    = "POST";
            s->in_req.content_type              = "application/pkcs10";
            s->in_req.content_transfer_encoding = "base64";
            s->in_req.body                      = s->in_body.data;
            s->in_req.body_len                  = s->in_body.len;
        }
        s->in_op     = op;
        s->in_enc    = enc;
        s->in_out    = out;
        s->in_active = 1;
    }
    else {
        est_session_reset(s);
    }

    return rc;
}

/* Run op on s, or continue the _nb request in flight, and parse the response
 * into *out and, for an enroll op, *res. *out also identifies the caller
 * across _nb calls. */
static int est_session_call(WolfCertEstSession* s, enum est_session_op op,
                            const uint8_t* csr_der, size_t csr_der_len,
                            WolfCertEncoding enc, WolfCertBuffer* out,
                            WolfCertEstResult* res, int nb)
{
    int rc;

    est_call_clear(s, out, res);
    if (s == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    if (s->in_active && !nb)
        return WOLFCERT_ERR(WOLFCERT_ERR_BAD_ARG, "est",
            "an EST request is in flight on this session; continue it with "
            "the _nb call");

    if (s->in_active) {
        rc = est_session_resume_check(s, op, enc, out);
    }
    else {
        rc = est_call_check(op, csr_der, csr_der_len, enc, out);
        if (rc == WOLFCERT_OK && op == EST_OP_SIMPLE_REENROLL &&
                !s->has_client_identity)
            rc = WOLFCERT_ERR(WOLFCERT_ERR_BAD_ARG, "est",
                "reenroll needs a session opened with the cert being renewed");
        if (rc == WOLFCERT_OK)
            rc = est_session_begin(s, op, csr_der, csr_der_len, enc, out);
    }
    if (rc != WOLFCERT_OK)
        return rc;

    if (nb)
        rc = wolfcert_http_session_request_nb(s->http, &s->in_req, &s->in_resp);
    else
        rc = wolfcert_http_session_request(s->http, &s->in_req, &s->in_resp);

    if (nb && (rc == WOLFCERT_ERR_WANT_READ || rc == WOLFCERT_ERR_WANT_WRITE))
        return rc;

    if (rc == WOLFCERT_OK) {
        est_session_free_request(s);
        if (res != NULL)
            res->heap = s->heap;
        rc = est_finish(s->heap, &s->in_resp, op, enc, out, res);
    }

    est_session_reset(s);
    return rc;
}

int wolfcert_est_session_get_cacerts(WolfCertEstSession* s,
                                     WolfCertEncoding enc,
                                     WolfCertBuffer* out_ca)
{
    return est_session_call(s, EST_OP_GET_CACERTS, NULL, 0, enc, out_ca,
                            NULL, 0);
}

int wolfcert_est_session_get_cacerts_nb(WolfCertEstSession* s,
                                        WolfCertEncoding enc,
                                        WolfCertBuffer* out_ca)
{
    return est_session_call(s, EST_OP_GET_CACERTS, NULL, 0, enc, out_ca,
                            NULL, 1);
}

int wolfcert_est_session_get_csr_attrs(WolfCertEstSession* s,
                                       WolfCertBuffer* out_attrs_der)
{
    return est_session_call(s, EST_OP_GET_CSRATTRS, NULL, 0,
                            WOLFCERT_ENCODING_DER, out_attrs_der, NULL, 0);
}

int wolfcert_est_session_get_csr_attrs_nb(WolfCertEstSession* s,
                                          WolfCertBuffer* out_attrs_der)
{
    return est_session_call(s, EST_OP_GET_CSRATTRS, NULL, 0,
                            WOLFCERT_ENCODING_DER, out_attrs_der, NULL, 1);
}

int wolfcert_est_session_simple_enroll(WolfCertEstSession* s,
                                       const uint8_t* csr_der,
                                       size_t csr_der_len,
                                       WolfCertEstResult* out)
{
    if (out == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    return est_session_call(s, EST_OP_SIMPLE_ENROLL, csr_der, csr_der_len,
                            WOLFCERT_ENCODING_PEM, &out->cert_pem, out, 0);
}

int wolfcert_est_session_simple_enroll_nb(WolfCertEstSession* s,
                                          const uint8_t* csr_der,
                                          size_t csr_der_len,
                                          WolfCertEstResult* out)
{
    if (out == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    return est_session_call(s, EST_OP_SIMPLE_ENROLL, csr_der, csr_der_len,
                            WOLFCERT_ENCODING_PEM, &out->cert_pem, out, 1);
}

int wolfcert_est_session_simple_reenroll(WolfCertEstSession* s,
                                         const uint8_t* csr_der,
                                         size_t csr_der_len,
                                         WolfCertEstResult* out)
{
    if (out == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    return est_session_call(s, EST_OP_SIMPLE_REENROLL, csr_der, csr_der_len,
                            WOLFCERT_ENCODING_PEM, &out->cert_pem, out, 0);
}

int wolfcert_est_session_simple_reenroll_nb(WolfCertEstSession* s,
                                            const uint8_t* csr_der,
                                            size_t csr_der_len,
                                            WolfCertEstResult* out)
{
    if (out == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    return est_session_call(s, EST_OP_SIMPLE_REENROLL, csr_der, csr_der_len,
                            WOLFCERT_ENCODING_PEM, &out->cert_pem, out, 1);
}

static int est_one_shot(const WolfCertServerCfg* srv, int tls_dev_id,
                        enum est_session_op op,
                        const uint8_t* csr_der, size_t csr_der_len,
                        WolfCertEncoding enc, WolfCertBuffer* out,
                        WolfCertEstResult* res)
{
    WolfCertEstSession* s = NULL;
    int rc;

    est_call_clear(NULL, out, res);
    rc = est_call_check(op, csr_der, csr_der_len, enc, out);
    if (rc == WOLFCERT_OK)
        rc = est_session_open_dev(srv, tls_dev_id, &s);
    if (rc == WOLFCERT_OK) {
        wolfcert_http_session_set_close(s->http);
        rc = est_session_call(s, op, csr_der, csr_der_len, enc, out, res, 0);
    }

    wolfcert_est_session_close(s);
    return rc;
}

int wolfcert_est_get_cacerts(const WolfCertServerCfg* srv, WolfCertEncoding enc,
                             WolfCertBuffer* out_ca)
{
    return est_one_shot(srv, wolfcert_default_dev_id(), EST_OP_GET_CACERTS,
                        NULL, 0, enc, out_ca, NULL);
}

int wolfcert_est_get_csr_attrs(const WolfCertServerCfg* srv,
                               WolfCertBuffer* out_attrs_der)
{
    return est_one_shot(srv, wolfcert_default_dev_id(), EST_OP_GET_CSRATTRS,
                        NULL, 0, WOLFCERT_ENCODING_DER, out_attrs_der, NULL);
}

int wolfcert_est_simple_enroll(const WolfCertServerCfg* srv,
                               const uint8_t* csr_der, size_t csr_der_len,
                               WolfCertEstResult* out)
{
    if (out == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    return est_one_shot(srv, wolfcert_default_dev_id(), EST_OP_SIMPLE_ENROLL,
                        csr_der, csr_der_len, WOLFCERT_ENCODING_PEM,
                        &out->cert_pem, out);
}

int wolfcert_est_simple_reenroll(const WolfCertServerCfg* srv,
                                 const uint8_t* current_cert, size_t current_cert_len,
                                 const WolfCertKey* current_key,
                                 const uint8_t* csr_der, size_t csr_der_len,
                                 WolfCertEstResult* out)
{
    WolfCertServerCfg cfg;
    WolfCertBuffer key_der = { 0 };
    int tls_dev_id;
    int rc = WOLFCERT_OK;

    if (out == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    est_call_clear(NULL, &out->cert_pem, out);

    if (srv == NULL || current_cert == NULL || current_cert_len == 0 ||
        current_key == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    /* The TLS identity is the cert being renewed. wolfSSL signs with a key
     * loaded from DER on the context's devId, so that is the key's device. */
    cfg = *srv;
    tls_dev_id = current_key->dev_id;
    cfg.client_cert       = current_cert;
    cfg.client_cert_len   = current_cert_len;
    if (current_key->id_len > 0) {
        cfg.client_key        = current_key->id;
        cfg.client_key_len    = current_key->id_len;
        cfg.client_key_src    = WOLFCERT_CLIENT_KEY_ID;
        cfg.client_key_dev_id = current_key->dev_id;
        tls_dev_id            = wolfcert_default_dev_id();
    }
    else {
        rc = wolfcert_key_to_der(current_key, &key_der);
        cfg.client_key     = key_der.data;
        cfg.client_key_len = key_der.len;
        cfg.client_key_src = WOLFCERT_CLIENT_KEY_BUFFER;
    }
    if (rc == WOLFCERT_OK)
        rc = est_one_shot(&cfg, tls_dev_id, EST_OP_SIMPLE_REENROLL,
                          csr_der, csr_der_len,
                          WOLFCERT_ENCODING_PEM, &out->cert_pem, out);

    wolfcert_buffer_free_secure(&key_der);
    return rc;
}
