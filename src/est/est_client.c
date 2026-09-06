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

#include <wolfcert/est.h>
#include <wolfcert/http.h>
#include <wolfcert/errors.h>
#include "../internal.h"

#include <wolfssl/wolfcrypt/memory.h>

#include <stdio.h>
#include <string.h>

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

static void fill_common(const WolfCertServerCfg* srv, WolfCertHttpRequest* req)
{
    req->basic_user        = srv->proto_opts.est.username;
    req->basic_pass        = srv->proto_opts.est.password;
    req->trust_anchors     = srv->trust_anchors;
    req->trust_anchors_len = srv->trust_anchors_len;
    req->verify_server     = srv->verify_server;
    req->timeout_ms        = srv->timeout_ms;
    req->max_response_bytes= srv->max_response_bytes;
    req->heap              = srv->heap;

    /* mTLS identity, if the caller supplied one. fill_common runs before
     * the per-endpoint overrides in post_enroll, so simplereenroll can
     * still fall back to the cert-being-renewed when cfg is silent. */
    req->client_cert       = srv->client_cert;
    req->client_cert_len   = srv->client_cert_len;
    req->client_key        = srv->client_key;
    req->client_key_len    = srv->client_key_len;
    req->connect_cb        = srv->connect_cb;
    req->connect_ctx       = srv->connect_ctx;
    req->transport         = srv->transport;
}

/* Validate the config before it is used. The protocol check comes first: it
 * gates every read of proto_opts.est below, which would otherwise reinterpret
 * a SCEP arm's storage as the HTTP Basic credentials.
 *
 * RFC 7030 then mandates EST over TLS *and* that the client authenticate the
 * server on every request. Reject an explicitly non-TLS (http://) server URL
 * first; a schemeless URL already defaults to TLS in wolfcert_http_url_parse(),
 * so only an explicit http:// scheme is refused. Then require server
 * authentication: verify_server is the sole switch for peer verification in
 * this transport (http.c installs WOLFSSL_VERIFY_PEER only when it is set), so
 * verify_server off always completes an unauthenticated handshake - a pinned
 * trust anchor is loaded but never enforced - which would leak the HTTP Basic
 * credentials and the CSR to a MITM. */
static int est_check_cfg(const WolfCertServerCfg* srv, void* heap)
{
    WolfCertUrl u;
    int rc = wolfcert_cfg_require_proto(srv, WOLFCERT_PROTO_EST, "est");
    if (rc != WOLFCERT_OK)
        return rc;

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

    return WOLFCERT_OK;
}

int wolfcert_est_get_cacerts(const WolfCertServerCfg* srv, WolfCertBuffer* out_ca_pem)
{
    return wolfcert_est_get_cacerts_enc(srv, WOLFCERT_ENCODING_PEM, out_ca_pem);
}

int wolfcert_est_get_cacerts_enc(const WolfCertServerCfg* srv, WolfCertEncoding enc,
                                 WolfCertBuffer* out_ca)
{
    if (srv == NULL || srv->server_url == NULL || out_ca == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    void* heap = srv->heap ? srv->heap : wolfcert_default_heap();
    int trc = est_check_cfg(srv, heap);
    if (trc != WOLFCERT_OK)
        return trc;

    char* url = join_path(srv->server_url, "cacerts", heap);
    if (url == NULL)
        return WOLFCERT_ERR_MEMORY;

    WolfCertHttpRequest req = { .method = "GET", .url = url,
                                .accept = "application/pkcs7-mime" };
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

    WolfCertBuffer p7 = { 0 };
    rc = wolfcert_base64_decode(resp.body, resp.body_len, &p7, heap);

    wolfcert_http_response_free(&resp);
    if (rc != WOLFCERT_OK)
        return rc;

    if (enc == WOLFCERT_ENCODING_DER)
        rc = wolfcert_pkcs7_certs_to_der(p7.data, p7.len, out_ca, heap);
    else
        rc = wolfcert_pkcs7_certs_to_pem(p7.data, p7.len, out_ca, heap);

    wolfcert_buffer_free(&p7);
    return rc;
}

/* Core round-trip for /simpleenroll and /simplereenroll, shared by the
 * simple-result `wolfcert_est_simple_enroll` / `_reenroll` (which flatten
 * 202 Accepted into WOLFCERT_ERR_PENDING and ignore Retry-After) and
 * the richer `_ex` variants (which expose the status + hint directly).
 * Returns WOLFCERT_OK for any HTTP round-trip the library understood -
 * the caller looks at `out->status` to distinguish SUCCESS / PENDING /
 * FAILURE. Transport / parse failures return a negative code. */
static int post_enroll_ex(const WolfCertServerCfg* srv,
                          const char* suffix,
                          const uint8_t* csr_der, size_t csr_der_len,
                          const uint8_t* fallback_cert_pem, size_t fallback_cert_len,
                          const uint8_t* fallback_key_pem,  size_t fallback_key_len,
                          WolfCertEstResult* out)
{
    void* heap = srv->heap ? srv->heap : wolfcert_default_heap();
    memset(out, 0, sizeof(*out));
    out->heap = heap;
    int trc = est_check_cfg(srv, heap);
    if (trc != WOLFCERT_OK)
        return trc;

    char* url = join_path(srv->server_url, suffix, heap);
    if (url == NULL)
        return WOLFCERT_ERR_MEMORY;

    /* RFC 7030 section 3.5 lets an EST client bind the proof-of-possession to
     * the TLS session by carrying the tls-unique channel binding (RFC 5929)
     * inside the CSR (typically the PKCS#9 challengePassword). This is an
     * optional measure and we currently do not implement it: the CSR is
     * built independently of the live TLS session and submitted as-is. If
     * channel binding is ever required, derive tls-unique from the TLS
     * connection and feed it to the CSR builder before this point. */

    WolfCertBuffer b64 = { 0 };
    int rc = wolfcert_base64_encode_mime(csr_der, csr_der_len, &b64, heap);
    if (rc != WOLFCERT_OK) {
        WOLFCERT_XFREE(url, heap);
        return rc;
    }

    WolfCertHttpRequest req = {
        .method                    = "POST",
        .url                       = url,
        .content_type              = "application/pkcs10",
        .content_transfer_encoding = "base64",
        .accept                    = "application/pkcs7-mime",
        .body                      = b64.data,
        .body_len                  = b64.len,
    };
    fill_common(srv, &req);

    /* Fallback: if the caller passed an endpoint-specific identity
     * (simplereenroll supplies the cert being renewed) and cfg itself is
     * silent on mTLS, use that. Explicit cfg identity takes precedence. */
    if (req.client_cert == NULL && fallback_cert_pem != NULL) {
        req.client_cert     = fallback_cert_pem;
        req.client_cert_len = fallback_cert_len;
        req.client_key      = fallback_key_pem;
        req.client_key_len  = fallback_key_len;
    }

    WolfCertHttpResponse resp = { 0 };
    rc = wolfcert_http_request(&req, &resp);

    WOLFCERT_XFREE(url, heap);
    wolfcert_buffer_free(&b64);
    if (rc != WOLFCERT_OK)
        return rc;

    /* RFC 7030 section 4.2.3: 202 Accepted = enrolment pending. The client is
     * expected to wait `Retry-After` seconds and re-POST the same CSR. */
    if (resp.status_code == 202) {
        out->status          = WOLFCERT_EST_STATUS_PENDING;
        out->retry_after_sec = resp.retry_after_sec;
        wolfcert_http_response_free(&resp);

        return WOLFCERT_OK;
    }

    if (resp.status_code != 200) {
        out->status = WOLFCERT_EST_STATUS_FAILURE;
        int mapped = resp.status_code == 401 || resp.status_code == 403
                     ? WOLFCERT_ERR_AUTH : WOLFCERT_ERR_HTTP;
        wolfcert_http_response_free(&resp);

        return mapped;
    }

    WolfCertBuffer p7 = { 0 };
    rc = wolfcert_base64_decode(resp.body, resp.body_len, &p7, heap);

    wolfcert_http_response_free(&resp);
    if (rc != WOLFCERT_OK)
        return rc;

    rc = wolfcert_pkcs7_certs_to_pem(p7.data, p7.len, &out->cert_pem, heap);

    wolfcert_buffer_free(&p7);
    if (rc != WOLFCERT_OK)
        return rc;

    out->status = WOLFCERT_EST_STATUS_SUCCESS;
    return WOLFCERT_OK;
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

int wolfcert_est_simple_enroll_ex(const WolfCertServerCfg* srv,
                                  const uint8_t* csr_der, size_t csr_der_len,
                                  WolfCertEstResult* out)
{
    if (srv == NULL || csr_der == NULL || csr_der_len == 0 || out == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    return post_enroll_ex(srv, "simpleenroll", csr_der, csr_der_len,
                          NULL, 0, NULL, 0, out);
}

int wolfcert_est_simple_reenroll_ex(const WolfCertServerCfg* srv,
                                    const uint8_t* current_cert, size_t current_cert_len,
                                    const WolfCertKey* current_key,
                                    const uint8_t* csr_der, size_t csr_der_len,
                                    WolfCertEstResult* out)
{
    if (srv == NULL || current_cert == NULL || current_key == NULL ||
        csr_der == NULL || out == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    WolfCertBuffer key_pem = { 0 };
    int rc = wolfcert_key_to_pem(current_key, &key_pem);
    if (rc != WOLFCERT_OK)
        return rc;

    rc = post_enroll_ex(srv, "simplereenroll", csr_der, csr_der_len,
                        current_cert, current_cert_len,
                        key_pem.data, key_pem.len, out);

    wc_ForceZero(key_pem.data, (word32)key_pem.len);
    wolfcert_buffer_free(&key_pem);
    return rc;
}

int wolfcert_est_simple_enroll(const WolfCertServerCfg* srv,
                               const uint8_t* csr_der, size_t csr_der_len,
                               WolfCertBuffer* out_cert_pem)
{
    if (srv == NULL || csr_der == NULL || csr_der_len == 0 || out_cert_pem == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    WolfCertEstResult r = { 0 };
    int rc = post_enroll_ex(srv, "simpleenroll", csr_der, csr_der_len,
                            NULL, 0, NULL, 0, &r);

    if (rc != WOLFCERT_OK) {
        wolfcert_est_result_free(&r);
        return rc;
    }

    if (r.status == WOLFCERT_EST_STATUS_PENDING) {
        wolfcert_est_result_free(&r);
        return WOLFCERT_ERR_PENDING;
    }

    if (r.status != WOLFCERT_EST_STATUS_SUCCESS) {
        wolfcert_est_result_free(&r);
        return WOLFCERT_ERR_PROTOCOL;
    }

    *out_cert_pem = r.cert_pem;
    r.cert_pem.data = NULL;
    r.cert_pem.len = 0;
    wolfcert_est_result_free(&r);

    return WOLFCERT_OK;
}

int wolfcert_est_simple_reenroll(const WolfCertServerCfg* srv,
                                 const uint8_t* current_cert, size_t current_cert_len,
                                 const WolfCertKey* current_key,
                                 const uint8_t* csr_der, size_t csr_der_len,
                                 WolfCertBuffer* out_cert_pem)
{
    if (srv == NULL || current_cert == NULL || current_key == NULL ||
        csr_der == NULL || out_cert_pem == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    WolfCertEstResult r = { 0 };
    int rc = wolfcert_est_simple_reenroll_ex(srv, current_cert, current_cert_len,
                                             current_key, csr_der, csr_der_len, &r);

    if (rc != WOLFCERT_OK) {
        wolfcert_est_result_free(&r);
        return rc;
    }

    if (r.status == WOLFCERT_EST_STATUS_PENDING) {
        wolfcert_est_result_free(&r);
        return WOLFCERT_ERR_PENDING;
    }

    if (r.status != WOLFCERT_EST_STATUS_SUCCESS) {
        wolfcert_est_result_free(&r);
        return WOLFCERT_ERR_PROTOCOL;
    }

    *out_cert_pem = r.cert_pem;
    r.cert_pem.data = NULL;
    r.cert_pem.len = 0;
    wolfcert_est_result_free(&r);

    return WOLFCERT_OK;
}

/* ---- keep-alive EST session -------------------------------------------- */

struct WolfCertEstSession {
    WolfCertHttpSession* http;
    char*                base_url;     /* e.g. https://ca.example/.well-known/est */
    size_t               max_body;
    void*                heap;

    /* HTTP Basic credentials, copied from the config at open (the caller's
     * WolfCertServerCfg need not outlive the session) and replayed on every
     * request the session issues. NULL when the caller supplied none. */
    char*                basic_user;
    char*                basic_pass;

    /* Async in-flight state: at most one request at a time. */
    int                  in_active;
    char*                in_url;
    WolfCertBuffer       in_body;      /* base64-encoded CSR for POST, owned */
    WolfCertHttpRequest  in_req;
    WolfCertHttpResponse in_resp;
    WolfCertBuffer*      in_out;
    enum { EST_OP_GET_CACERTS, EST_OP_SIMPLE_ENROLL } in_op;
};

static int est_session_open_common(const WolfCertServerCfg* srv, int nonblocking,
                                   WolfCertEstSession** out)
{
    if (srv == NULL || srv->server_url == NULL || out == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    void* heap = srv->heap ? srv->heap : wolfcert_default_heap();

    /* The session copies proto_opts.est below, so confirm the discriminator
     * before reading that arm. */
    int rc = wolfcert_cfg_require_proto(srv, WOLFCERT_PROTO_EST, "est");
    if (rc != WOLFCERT_OK)
        return rc;

    /* Split the base URL into scheme://host[:port] for the HTTP session
     * vs the path suffix, so per-endpoint joins still work. */
    WolfCertUrl u;
    rc = wolfcert_http_url_parse(srv->server_url, &u, heap);
    if (rc != WOLFCERT_OK)
        return rc;

    if (!u.tls) { /* RFC 7030: EST runs over TLS. */
        wolfcert_http_url_free(&u);
        return WOLFCERT_ERR(WOLFCERT_ERR_TLS, "est",
            "EST requires TLS; refusing plaintext http:// URL (RFC 7030)");
    }

    /* EST also requires authenticating the server (RFC 7030); refuse a session
     * that would run an unauthenticated (verify_server off) handshake, matching
     * the one-shot est_check_cfg() gate. */
    if (!srv->verify_server) {
        wolfcert_http_url_free(&u);
        return WOLFCERT_ERR(WOLFCERT_ERR_TLS, "est",
            "EST requires server authentication: set verify_server to verify "
            "the server certificate (RFC 7030)");
    }

    char* origin = NULL;
    rc = wolfcert_http_url_origin(&u, heap, &origin);
    wolfcert_http_url_free(&u);
    if (rc != WOLFCERT_OK)
        return rc;

    WolfCertEstSession* s = (WolfCertEstSession*)WOLFCERT_XMALLOC(sizeof(*s), heap);
    if (s == NULL) {
        WOLFCERT_XFREE(origin, heap);
        return WOLFCERT_ERR_MEMORY;
    }

    memset(s, 0, sizeof(*s));
    s->heap     = heap;
    s->base_url = wolfcert_strdup(srv->server_url, heap);
    s->max_body = srv->max_response_bytes;
    if (s->base_url == NULL) {
        WOLFCERT_XFREE(s, heap);
        WOLFCERT_XFREE(origin, heap);
        return WOLFCERT_ERR_MEMORY;
    }

    /* RFC 7030 section 3.2.3: HTTP Basic is one of the client authentication
     * mechanisms an EST server may demand, so the session has to carry the
     * credentials across every request on the connection, not just the first. */
    const char* user = srv->proto_opts.est.username;
    const char* pass = srv->proto_opts.est.password;
    if (user != NULL)
        s->basic_user = wolfcert_strdup(user, heap);
    if (pass != NULL)
        s->basic_pass = wolfcert_strdup(pass, heap);
    if ((user != NULL && s->basic_user == NULL) ||
        (pass != NULL && s->basic_pass == NULL)) {
        wolfcert_est_session_close(s);
        WOLFCERT_XFREE(origin, heap);
        return WOLFCERT_ERR_MEMORY;
    }

    WolfCertHttpSessionCfg hcfg = {
        .base_url                  = origin,
        .trust_anchors             = srv->trust_anchors,
        .trust_anchors_len         = srv->trust_anchors_len,
        .verify_server             = srv->verify_server,
        .timeout_ms                = srv->timeout_ms,
        .max_response_bytes        = srv->max_response_bytes,
        .client_cert               = srv->client_cert,
        .client_cert_len           = srv->client_cert_len,
        .client_key                = srv->client_key,
        .client_key_len            = srv->client_key_len,
        .allow_post_handshake_auth = srv->proto_opts.est.allow_post_handshake_auth,
        .nonblocking               = nonblocking,
        .connect_cb                = srv->connect_cb,
        .connect_ctx               = srv->connect_ctx,
        .transport                 = srv->transport,
        .heap                      = heap,
    };
    rc = wolfcert_http_session_open(&hcfg, &s->http);

    WOLFCERT_XFREE(origin, heap);
    if (rc != WOLFCERT_OK) {
        /* Tear down through the close helper rather than freeing by hand: it
         * is the one place that zeroizes the Basic password copy, and a dial
         * failure here (DNS, connect, or a rejected server certificate) is
         * routine enough that an enrolment retry loop would otherwise strand
         * one plaintext copy per attempt. s->http is NULL, so the helper's
         * `if (s->http)` guard makes it safe on a half-built session. */
        wolfcert_est_session_close(s);
        return rc;
    }

    *out = s;
    return WOLFCERT_OK;
}

int wolfcert_est_session_open(const WolfCertServerCfg* srv,
                              WolfCertEstSession** out)
{
    return est_session_open_common(srv, 0, out);
}

int wolfcert_est_session_open_async(const WolfCertServerCfg* srv,
                                    WolfCertEstSession** out)
{
    return est_session_open_common(srv, 1, out);
}

int wolfcert_est_session_fd(const WolfCertEstSession* s)
{
    return s != NULL ? wolfcert_http_session_fd(s->http) : -1;
}

static void est_async_reset(WolfCertEstSession* s)
{
    WOLFCERT_XFREE(s->in_url, s->heap);
    s->in_url = NULL;
    wolfcert_buffer_free(&s->in_body);
    wolfcert_http_response_free(&s->in_resp);
    memset(&s->in_req,  0, sizeof(s->in_req));
    memset(&s->in_resp, 0, sizeof(s->in_resp));
    s->in_out    = NULL;
    s->in_active = 0;
}

void wolfcert_est_session_close(WolfCertEstSession* s)
{
    if (s == NULL)
        return;

    est_async_reset(s);
    if (s->http)
        wolfcert_http_session_close(s->http);

    WOLFCERT_XFREE(s->base_url, s->heap);

    /* The credential pair has no reason to outlive the session; the user half
     * counts too, since half a credential still narrows an attacker's search. */
    if (s->basic_user != NULL)
        wc_ForceZero(s->basic_user, (word32)strlen(s->basic_user));
    WOLFCERT_XFREE(s->basic_user, s->heap);
    if (s->basic_pass != NULL)
        wc_ForceZero(s->basic_pass, (word32)strlen(s->basic_pass));
    WOLFCERT_XFREE(s->basic_pass, s->heap);
    WOLFCERT_XFREE(s, s->heap);
}

int wolfcert_est_session_get_cacerts_nb(WolfCertEstSession* s,
                                        WolfCertBuffer* out_ca_pem)
{
    if (s == NULL || out_ca_pem == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    if (!s->in_active) {
        s->in_url = join_path(s->base_url, "cacerts", s->heap);
        if (s->in_url == NULL)
            return WOLFCERT_ERR_MEMORY;

        s->in_req = (WolfCertHttpRequest){
            .method = "GET", .url = s->in_url,
            .accept = "application/pkcs7-mime",
            .basic_user = s->basic_user, .basic_pass = s->basic_pass,
            .max_response_bytes = s->max_body,
            .heap = s->heap,
        };
        s->in_out    = out_ca_pem;
        s->in_op     = EST_OP_GET_CACERTS;
        s->in_active = 1;
    }

    int rc = wolfcert_http_session_request_nb(s->http, &s->in_req, &s->in_resp);
    if (rc == WOLFCERT_ERR_WANT_READ || rc == WOLFCERT_ERR_WANT_WRITE)
        return rc;

    if (rc != WOLFCERT_OK) {
        est_async_reset(s);
        return rc;
    }

    if (s->in_resp.status_code != 200) {
        est_async_reset(s);
        return WOLFCERT_ERR_HTTP;
    }

    WolfCertBuffer p7 = { 0 };
    rc = wolfcert_base64_decode(s->in_resp.body, s->in_resp.body_len, &p7, s->heap);
    if (rc == WOLFCERT_OK) {
        rc = wolfcert_pkcs7_certs_to_pem(p7.data, p7.len, s->in_out, s->heap);
        wolfcert_buffer_free(&p7);
    }

    est_async_reset(s);
    return rc;
}

int wolfcert_est_session_simple_enroll_nb(WolfCertEstSession* s,
                                          const uint8_t* csr_der,
                                          size_t csr_der_len,
                                          WolfCertBuffer* out_cert_pem)
{
    if (s == NULL || csr_der == NULL || csr_der_len == 0 || out_cert_pem == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    if (!s->in_active) {
        s->in_url = join_path(s->base_url, "simpleenroll", s->heap);
        if (s->in_url == NULL)
            return WOLFCERT_ERR_MEMORY;

        int rc = wolfcert_base64_encode_mime(csr_der, csr_der_len, &s->in_body, s->heap);
        if (rc != WOLFCERT_OK) {
            WOLFCERT_XFREE(s->in_url, s->heap);
            s->in_url = NULL;
            return rc;
        }

        s->in_req = (WolfCertHttpRequest){
            .method                    = "POST",
            .url                       = s->in_url,
            .content_type              = "application/pkcs10",
            .content_transfer_encoding = "base64",
            .accept                    = "application/pkcs7-mime",
            .basic_user                = s->basic_user,
            .basic_pass                = s->basic_pass,
            .body                      = s->in_body.data,
            .body_len                  = s->in_body.len,
            .max_response_bytes        = s->max_body,
            .heap                      = s->heap,
        };
        s->in_out    = out_cert_pem;
        s->in_op     = EST_OP_SIMPLE_ENROLL;
        s->in_active = 1;
    }

    int rc = wolfcert_http_session_request_nb(s->http, &s->in_req, &s->in_resp);
    if (rc == WOLFCERT_ERR_WANT_READ || rc == WOLFCERT_ERR_WANT_WRITE)
        return rc;

    if (rc != WOLFCERT_OK) {
        est_async_reset(s);
        return rc;
    }

    if (s->in_resp.status_code != 200) {
        int mapped;
        if (s->in_resp.status_code == 202)
            mapped = WOLFCERT_ERR_PENDING;
        else if (s->in_resp.status_code == 401 || s->in_resp.status_code == 403)
            mapped = WOLFCERT_ERR_AUTH;
        else
            mapped = WOLFCERT_ERR_HTTP;
        est_async_reset(s);

        return mapped;
    }

    WolfCertBuffer p7 = { 0 };
    rc = wolfcert_base64_decode(s->in_resp.body, s->in_resp.body_len, &p7, s->heap);
    if (rc == WOLFCERT_OK) {
        rc = wolfcert_pkcs7_certs_to_pem(p7.data, p7.len, s->in_out, s->heap);
        wolfcert_buffer_free(&p7);
    }

    est_async_reset(s);
    return rc;
}

int wolfcert_est_session_get_cacerts(WolfCertEstSession* s,
                                     WolfCertBuffer* out_ca_pem)
{
    if (s == NULL || out_ca_pem == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    char* url = join_path(s->base_url, "cacerts", s->heap);
    if (url == NULL)
        return WOLFCERT_ERR_MEMORY;

    WolfCertHttpRequest req = { .method = "GET", .url = url,
                                .accept = "application/pkcs7-mime",
                                .basic_user = s->basic_user,
                                .basic_pass = s->basic_pass,
                                .max_response_bytes = s->max_body,
                                .heap = s->heap };
    WolfCertHttpResponse resp = { 0 };

    int rc = wolfcert_http_session_request(s->http, &req, &resp);

    WOLFCERT_XFREE(url, s->heap);
    if (rc != WOLFCERT_OK)
        return rc;

    if (resp.status_code != 200) {
        wolfcert_http_response_free(&resp);
        return WOLFCERT_ERR_HTTP;
    }

    WolfCertBuffer p7 = { 0 };
    rc = wolfcert_base64_decode(resp.body, resp.body_len, &p7, s->heap);

    wolfcert_http_response_free(&resp);
    if (rc != WOLFCERT_OK)
        return rc;

    rc = wolfcert_pkcs7_certs_to_pem(p7.data, p7.len, out_ca_pem, s->heap);

    wolfcert_buffer_free(&p7);
    return rc;
}

int wolfcert_est_session_simple_enroll(WolfCertEstSession* s,
                                       const uint8_t* csr_der, size_t csr_der_len,
                                       WolfCertBuffer* out_cert_pem)
{
    if (s == NULL || csr_der == NULL || csr_der_len == 0 || out_cert_pem == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    char* url = join_path(s->base_url, "simpleenroll", s->heap);
    if (url == NULL)
        return WOLFCERT_ERR_MEMORY;

    WolfCertBuffer b64 = { 0 };
    int rc = wolfcert_base64_encode_mime(csr_der, csr_der_len, &b64, s->heap);
    if (rc != WOLFCERT_OK) {
        WOLFCERT_XFREE(url, s->heap);
        return rc;
    }

    WolfCertHttpRequest req = {
        .method                    = "POST",
        .url                       = url,
        .content_type              = "application/pkcs10",
        .content_transfer_encoding = "base64",
        .accept                    = "application/pkcs7-mime",
        .basic_user                = s->basic_user,
        .basic_pass                = s->basic_pass,
        .body                      = b64.data,
        .body_len                  = b64.len,
        .max_response_bytes        = s->max_body,
        .heap                      = s->heap,
    };
    WolfCertHttpResponse resp = { 0 };
    rc = wolfcert_http_session_request(s->http, &req, &resp);

    WOLFCERT_XFREE(url, s->heap);
    wolfcert_buffer_free(&b64);
    if (rc != WOLFCERT_OK)
        return rc;

    if (resp.status_code != 200) {
        int mapped;
        if (resp.status_code == 202)
            mapped = WOLFCERT_ERR_PENDING;
        else if (resp.status_code == 401 || resp.status_code == 403)
            mapped = WOLFCERT_ERR_AUTH;
        else
            mapped = WOLFCERT_ERR_HTTP;
        wolfcert_http_response_free(&resp);

        return mapped;
    }

    WolfCertBuffer p7 = { 0 };
    rc = wolfcert_base64_decode(resp.body, resp.body_len, &p7, s->heap);

    wolfcert_http_response_free(&resp);
    if (rc != WOLFCERT_OK)
        return rc;

    rc = wolfcert_pkcs7_certs_to_pem(p7.data, p7.len, out_cert_pem, s->heap);

    wolfcert_buffer_free(&p7);
    return rc;
}

int wolfcert_est_get_csr_attrs(const WolfCertServerCfg* srv,
                               WolfCertBuffer* out_attrs_der)
{
    if (srv == NULL || srv->server_url == NULL || out_attrs_der == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    void* heap = srv->heap ? srv->heap : wolfcert_default_heap();
    memset(out_attrs_der, 0, sizeof(*out_attrs_der));
    out_attrs_der->heap = heap;
    int trc = est_check_cfg(srv, heap);
    if (trc != WOLFCERT_OK)
        return trc;

    char* url = join_path(srv->server_url, "csrattrs", heap);
    if (url == NULL)
        return WOLFCERT_ERR_MEMORY;

    WolfCertHttpRequest req = { .method = "GET", .url = url,
                                .accept = "application/csrattrs" };
    fill_common(srv, &req);

    WolfCertHttpResponse resp = { 0 };
    int rc = wolfcert_http_request(&req, &resp);

    WOLFCERT_XFREE(url, heap);
    if (rc != WOLFCERT_OK)
        return rc;

    /* RFC 7030 section 4.5.2: both 204 and 404 mean the server has no CSR
     * Attributes Response to offer; treat either (and an empty body) as a
     * normal "no attributes" result rather than a transport error. */
    if (resp.status_code == 204 || resp.status_code == 404 ||
        resp.body_len == 0) {
        wolfcert_http_response_free(&resp);
        return WOLFCERT_OK;
    }

    if (resp.status_code != 200) {
        wolfcert_http_response_free(&resp);
        return WOLFCERT_ERR_HTTP;
    }

    /* Body is base64-encoded per RFC 7030; decode. */
    WolfCertBuffer dec = { 0 };
    rc = wolfcert_base64_decode(resp.body, resp.body_len, &dec, heap);

    wolfcert_http_response_free(&resp);
    if (rc != WOLFCERT_OK)
        return rc;

    *out_attrs_der = dec;
    return WOLFCERT_OK;
}
