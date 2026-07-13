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
 * Minimal EST (RFC 7030) test server. Plaintext HTTP only; uses the
 * shared CA helpers for generation and issuance. Exposes a vtable to
 * src/server.c and a serve_fd entry point for integration with external
 * event loops.
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include <wolfcert/server.h>
#include <wolfcert/est.h>
#include <wolfcert/errors.h>
#include "../internal.h"

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/sha256.h>

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

/* ---- pending queue (RFC 7030 section 4.2.3, manual-approval mode) --------------
 *
 * The EST RFC has no explicit transaction identifier for async
 * enrollment - the client is expected to re-POST the identical CSR. We
 * key pending entries off the SHA-256 of the base64-encoded request
 * body so the second POST produces the same digest as the first, even
 * across reconnects. The queue is capped and intentionally shallow;
 * real deployments use a proper approval workflow. */
#define EST_PENDING_CAP 8

typedef struct {
    uint8_t  csr_hash[32];
    int      polls;
} EstPending;

typedef struct {
    EstPending items[EST_PENDING_CAP];
    size_t     count;
} EstPriv;

static void sha256_bytes(const uint8_t* in, size_t in_len, uint8_t out[32])
{
    wc_Sha256 h;
    wc_InitSha256(&h);
    wc_Sha256Update(&h, in, (word32)in_len);
    wc_Sha256Final(&h, out);
}

/* Returns index into items[] if present, -1 otherwise. */
static int pending_find(const EstPriv* p, const uint8_t hash[32])
{
    for (size_t i = 0; i < p->count; ++i) {
        if (memcmp(p->items[i].csr_hash, hash, 32) == 0)
            return (int)i;
    }
    return -1;
}

/* Append `hash` if there's room and it isn't already present. Returns 1 if
 * a new entry was added, 0 if the queue is full. */
static int pending_add(EstPriv* p, const uint8_t hash[32])
{
    if (p->count >= EST_PENDING_CAP)
        return 0;

    memcpy(p->items[p->count].csr_hash, hash, 32);
    p->items[p->count].polls = 0;
    ++p->count;

    return 1;
}

static void pending_remove(EstPriv* p, int idx)
{
    if (idx < 0 || (size_t)idx >= p->count)
        return;

    if ((size_t)idx < p->count - 1)
        p->items[idx] = p->items[p->count - 1];

    --p->count;
}

/* ---- HTTP request parser ----------------------------------------------- */

typedef struct {
    char   method[8];
    char   path[WOLFCERT_HTTP_PATH_SZ];
    char*  auth_header;
    size_t content_length;
    uint8_t* body;
    size_t body_len;
    int    connection_close;   /* 1 when client sent Connection: close */
    void*    heap;
} EstRequest;

static void free_req(EstRequest* r)
{
    WOLFCERT_XFREE(r->auth_header, r->heap);
    WOLFCERT_XFREE(r->body, r->heap);
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

static int parse_request(WolfCertServer* s, int fd, EstRequest* out, void* heap)
{
    memset(out, 0, sizeof(*out));
    out->heap = heap;
    char buf[WOLFCERT_HTTP_REQ_BUF_SZ];
    size_t n = 0;
    while (n < sizeof(buf) - 1) {
        ssize_t r = wolfcert_io_recv(s, fd, buf + n, sizeof(buf) - 1 - n);
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

    size_t plen = (size_t)(sp2 - sp1 - 1);
    if (plen >= sizeof(out->path))
        return WOLFCERT_ERR_PROTOCOL;

    memcpy(out->path, sp1 + 1, plen);
    out->path[plen] = '\0';

    int chunked = 0;
    while (read_line(&p, end, &line, &llen) == 0 && llen > 0) {
        if (llen > 14 && strncasecmp(line, "Content-Length", 14) == 0) {
            char* colon = memchr(line, ':', llen);
            if (colon != NULL)
                out->content_length = (size_t)strtoul(colon + 1, NULL, 10);
        }
        else if (llen > 17 && strncasecmp(line, "Transfer-Encoding", 17) == 0) {
            char* colon = memchr(line, ':', llen);
            if (colon != NULL) {
                const char* v = colon + 1;
                while (v < line + llen && (*v == ' ' || *v == '\t')) {
                    ++v;
                }

                size_t vlen = (size_t)(line + llen - v);
                if (vlen >= 7 && strncasecmp(v, "chunked", 7) == 0)
                    chunked = 1;
            }
        }
        else if (llen > 13 && strncasecmp(line, "Authorization", 13) == 0) {
            char* colon = memchr(line, ':', llen);
            if (colon != NULL) {
                char* val = colon + 1;
                while (*val == ' ' || *val == '\t') {
                    ++val;
                }

                size_t vlen = llen - (size_t)(val - line);
                out->auth_header = (char*)WOLFCERT_XMALLOC(vlen + 1, heap);
                if (out->auth_header) {
                    memcpy(out->auth_header, val, vlen);
                    out->auth_header[vlen] = '\0';
                }
            }
        }
        else if (llen > 10 && strncasecmp(line, "Connection", 10) == 0) {
            char* colon = memchr(line, ':', llen);
            if (colon != NULL) {
                const char* v = colon + 1;
                while (v < line + llen && (*v == ' ' || *v == '\t')) {
                    ++v;
                }

                size_t vlen = (size_t)(line + llen - v);
                if (vlen >= 5 && strncasecmp(v, "close", 5) == 0)
                    out->connection_close = 1;
            }
        }
    }

    size_t body_have = (size_t)(end - p);
    if (chunked) {
        /* Transfer-Encoding: chunked - accumulate the raw request tail
         * in a growable buffer, keep reading until we see a
         * zero-length chunk, then stream-decode into `out->body` in a
         * single pass. globalsign's estclient emits chunked
         * unconditionally, so the EST enrolment path needs this.
         * Hard-capped at 1 MiB to match the Content-Length branch. */
        static const size_t BODY_CAP = 1 * 1024 * 1024;
        uint8_t* raw = NULL;
        size_t raw_len = 0, raw_cap = 0;
        if (body_have > 0) {
            raw = (uint8_t*)WOLFCERT_XMALLOC(body_have, heap);
            if (raw == NULL)
                return WOLFCERT_ERR_MEMORY;

            memcpy(raw, p, body_have);
            raw_len = body_have;
            raw_cap = body_have;
        }

        int saw_end = 0;
        while (!saw_end) {
            /* Any "0\r\n" at a chunk-header position marks the end. */
            for (size_t i = 0; i + 2 < raw_len; ++i) {
                if (raw[i] == '0' && raw[i+1] == '\r' && raw[i+2] == '\n') {
                    /* Cheap heuristic: treat the last occurrence as the
                     * terminator. The decode pass below revalidates. */
                    saw_end = 1;
                }
            }

            if (saw_end)
                break;

            size_t grow = raw_len < 2048 ? 2048 : raw_len;
            if (raw_len + grow > BODY_CAP + 64 * 1024) {
                WOLFCERT_XFREE(raw, heap);
                return WOLFCERT_ERR_PROTOCOL;
            }

            uint8_t* nb = (uint8_t*)WOLFCERT_XREALLOC(raw, raw_len + grow, heap);
            if (nb == NULL) {
                WOLFCERT_XFREE(raw, heap);
                return WOLFCERT_ERR_MEMORY;
            }

            raw = nb;
            raw_cap = raw_len + grow;
            ssize_t r = wolfcert_io_recv(s, fd, raw + raw_len, raw_cap - raw_len);
            if (r <= 0) {
                WOLFCERT_XFREE(raw, heap);
                return WOLFCERT_ERR_IO;
            }

            raw_len += (size_t)r;
        }

        /* Decode pass: walk chunks, copy payloads into `body`. */
        uint8_t* body = (uint8_t*)WOLFCERT_XMALLOC(raw_len + 1, heap);
        if (body == NULL) {
            WOLFCERT_XFREE(raw, heap);
            return WOLFCERT_ERR_MEMORY;
        }

        size_t body_sz = 0, ri = 0;
        while (ri < raw_len) {
            /* Locate the end of the chunk-size line. */
            size_t he = ri;
            while (he + 1 < raw_len && !(raw[he] == '\r' && raw[he+1] == '\n')) {
                ++he;
            }

            if (he + 1 >= raw_len)
                break;

            unsigned long csz = 0;
            int parsed = 0;
            size_t hex_digits = 0;
            for (size_t k = ri; k < he; ++k) {
                char c = (char)raw[k];
                if (c == ';')
                    break; /* chunk-ext */

                int d = (c >= '0' && c <= '9') ? c - '0'
                      : (c >= 'a' && c <= 'f') ? c - 'a' + 10
                      : (c >= 'A' && c <= 'F') ? c - 'A' + 10 : -1;
                if (d < 0) {
                    parsed = -1;
                    break;
                }

                /* Cap the hex-digit count so a crafted long chunk-size
                 * line can't silently wrap `csz` to a small value that
                 * then sneaks past the `ri + csz > raw_len` check. 8
                 * digits cover every legitimate chunk we'd ever accept
                 * (BODY_CAP is 1 MiB). */
                if (++hex_digits > 8) {
                    parsed = -1;
                    break;
                }

                csz = (csz << 4) | (unsigned long)d;
                parsed = 1;
            }
            if (parsed <= 0) {
                WOLFCERT_XFREE(body, heap);
                WOLFCERT_XFREE(raw, heap);
                return WOLFCERT_ERR_PROTOCOL;
            }

            ri = he + 2;
            if (csz == 0)
                break;

            if (ri + csz > raw_len || body_sz + csz > BODY_CAP) {
                WOLFCERT_XFREE(body, heap);
                WOLFCERT_XFREE(raw, heap);
                return WOLFCERT_ERR_PROTOCOL;
            }

            memcpy(body + body_sz, raw + ri, csz);
            body_sz += csz;
            ri += csz;
            if (ri == raw_len)
                break; /* last chunk, no more framing */

            /* Every non-final chunk MUST end in CRLF - verify it before
             * consuming so framing corruption (missing trailer, stray
             * byte) is rejected as a protocol error rather than
             * silently tolerated. */
            if (ri + 2 > raw_len ||
                raw[ri] != '\r' || raw[ri + 1] != '\n') {
                WOLFCERT_XFREE(body, heap);
                WOLFCERT_XFREE(raw, heap);
                return WOLFCERT_ERR_PROTOCOL;
            }

            ri += 2;
        }

        body[body_sz] = '\0';
        WOLFCERT_XFREE(raw, heap);
        out->body = body;
        out->body_len = body_sz;

        return WOLFCERT_OK;
    }

    if (out->content_length > 0) {
        if (out->content_length > 1 * 1024 * 1024)
            return WOLFCERT_ERR_PROTOCOL;

        out->body = (uint8_t*)WOLFCERT_XMALLOC(out->content_length + 1, heap);
        if (out->body == NULL)
            return WOLFCERT_ERR_MEMORY;

        if (body_have > out->content_length)
            body_have = out->content_length;

        memcpy(out->body, p, body_have);
        size_t left = out->content_length - body_have;
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
        out->body[out->body_len] = '\0';
    }

    return WOLFCERT_OK;
}

/* ---- writers ----------------------------------------------------------- */

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

static void send_status(WolfCertServer* s, int fd, int status, const char* phrase)
{
    char line[128];
    int n = snprintf(line, sizeof(line),
        "HTTP/1.1 %d %s\r\nContent-Length: 0\r\nConnection: %s\r\n\r\n",
        status, phrase, conn_hdr(s));

    send_all(s, fd, line, (size_t)n);
}

static void send_pkcs7_b64(WolfCertServer* s, int fd, const uint8_t* b64, size_t b64_len)
{
    char hdr[256];
    int n = snprintf(hdr, sizeof(hdr),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/pkcs7-mime; smime-type=certs-only\r\n"
        "Content-Transfer-Encoding: base64\r\n"
        "Content-Length: %zu\r\n"
        "Connection: %s\r\n\r\n",
        b64_len, conn_hdr(s));

    send_all(s, fd, hdr, (size_t)n);
    send_all(s, fd, b64, b64_len);
}

/* RFC 7030 section 4.2.3: 202 Accepted with `Retry-After` tells the client the
 * enrolment is pending manual approval and can be retried. */
static void send_accepted_retry_after(WolfCertServer* s, int fd, int retry_after_sec)
{
    char hdr[192];
    int n = snprintf(hdr, sizeof(hdr),
        "HTTP/1.1 202 Accepted\r\n"
        "Retry-After: %d\r\n"
        "Content-Length: 0\r\n"
        "Connection: %s\r\n\r\n",
        retry_after_sec > 0 ? retry_after_sec : 1, conn_hdr(s));

    send_all(s, fd, hdr, (size_t)n);
}

/* HTTP Basic authentication scheme token, including its trailing space. */
#define EST_BASIC_AUTH_SCHEME     "Basic "
#define EST_BASIC_AUTH_SCHEME_LEN (sizeof(EST_BASIC_AUTH_SCHEME) - 1)

static int check_basic_auth(const WolfCertServer* s, const char* auth_header)
{
    if (s->cfg_basic_user == NULL)
        return 1;

    if (auth_header == NULL)
        return 0;

    if (strncasecmp(auth_header, EST_BASIC_AUTH_SCHEME,
                    EST_BASIC_AUTH_SCHEME_LEN) != 0)
        return 0;

    size_t ul = strlen(s->cfg_basic_user);
    size_t pl = s->cfg_basic_pass ? strlen(s->cfg_basic_pass) : 0;
    uint8_t raw[256];
    if (ul + 1 + pl >= sizeof(raw))
        return 0;

    memcpy(raw, s->cfg_basic_user, ul);
    raw[ul] = ':';
    if (pl > 0)
        memcpy(raw + ul + 1, s->cfg_basic_pass, pl);

    WolfCertBuffer enc = { 0 };
    if (wolfcert_base64_encode(raw, ul + 1 + pl, &enc, s->heap) != WOLFCERT_OK)
        return 0;

    /* Constant-time, full-length comparison of the base64 credential: reject
     * on a length mismatch, then accumulate byte differences so the timing
     * does not leak the length of the matching prefix. */
    const char* tok = auth_header + EST_BASIC_AUTH_SCHEME_LEN;
    int ok = (strlen(tok) == enc.len);
    if (ok) {
        unsigned acc = 0;
        for (size_t i = 0; i < enc.len; ++i)
            acc |= (unsigned)((unsigned char)tok[i] ^ enc.data[i]);
        ok = (acc == 0);
    }
    wolfcert_buffer_free(&enc);

    return ok;
}

/* ---- handlers ---------------------------------------------------------- */

/* RFC 7030 section 4.5.2: GET /.well-known/est/csrattrs.
 *   - 204 No Content   -> server has no attributes to advertise.
 *   - 200 OK           -> CsrAttrs DER, base64-encoded, content-type
 *                         application/csrattrs. */
static int handler_csr_attrs(WolfCertServer* s, int fd)
{
    if (s->cfg_csr_attrs == NULL || s->cfg_csr_attrs_len == 0) {
        send_status(s, fd, 204, "No Content");
        return WOLFCERT_OK;
    }

    WolfCertBuffer b64 = { 0 };
    int rc = wolfcert_base64_encode_mime(s->cfg_csr_attrs, s->cfg_csr_attrs_len,
                                     &b64, s->heap);
    if (rc != WOLFCERT_OK) {
        send_status(s, fd, 500, "Server Error");
        return rc;
    }

    char hdr[256];
    int n = snprintf(hdr, sizeof(hdr),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/csrattrs\r\n"
        "Content-Transfer-Encoding: base64\r\n"
        "Content-Length: %zu\r\n"
        "Connection: %s\r\n\r\n",
        b64.len, conn_hdr(s));

    send_all(s, fd, hdr, (size_t)n);
    send_all(s, fd, b64.data, b64.len);
    wolfcert_buffer_free(&b64);

    return WOLFCERT_OK;
}

static int handler_cacerts(WolfCertServer* s, int fd)
{
    const uint8_t* certs[1] = { s->ca.cert_der };
    size_t          clen[1]  = { s->ca.cert_der_len };
    WolfCertBuffer p7 = { 0 };

    int rc = wolfcert_pkcs7_build_certs_only(certs, clen, 1, &p7, s->heap);
    if (rc != WOLFCERT_OK) {
        send_status(s, fd,500, "Server Error");
        return rc;
    }

    WolfCertBuffer b64 = { 0 };
    rc = wolfcert_base64_encode_mime(p7.data, p7.len, &b64, s->heap);

    wolfcert_buffer_free(&p7);
    if (rc != WOLFCERT_OK) {
        send_status(s, fd,500, "Server Error");
        return rc;
    }

    send_pkcs7_b64(s, fd,b64.data, b64.len);
    wolfcert_buffer_free(&b64);

    return WOLFCERT_OK;
}

/* When the server is configured for TLS 1.3 post-handshake auth and the
 * connection has no peer cert yet, issue a CertificateRequest and wait
 * for the client's Certificate + CertificateVerify before treating this
 * as an authenticated call. Returns WOLFCERT_OK on successful PHA (or
 * when PHA is not configured / not needed); WOLFCERT_ERR_AUTH on any
 * TLS-layer failure (including the client declining to send a cert). */
static int ensure_post_handshake_auth(WolfCertServer* s)
{
#ifdef WOLFSSL_POST_HANDSHAKE_AUTH
    if (!s->cfg.tls_post_handshake_auth || s->tls_current == NULL)
        return WOLFCERT_OK;

    WOLFSSL_X509* peer = wolfSSL_get_peer_certificate(s->tls_current);
    if (peer != NULL) {
        wolfSSL_FreeX509(peer);
        return WOLFCERT_OK;
    }

    /* Queue CertificateRequest; wolfSSL pushes it to the wire on the
     * next write and processes the client's Certificate + CertVerify
     * inline on subsequent reads/writes. */
    if (wolfSSL_request_certificate(s->tls_current) != WOLFSSL_SUCCESS) {
        return WOLFCERT_ERR(WOLFCERT_ERR_AUTH, "est",
            "post-handshake: wolfSSL_request_certificate failed");
    }

    peer = wolfSSL_get_peer_certificate(s->tls_current);
    if (peer == NULL) {
        return WOLFCERT_ERR(WOLFCERT_ERR_AUTH, "est",
            "post-handshake: client did not present a certificate");
    }

    wolfSSL_FreeX509(peer);
    return WOLFCERT_OK;
#else
    (void)s;
    return WOLFCERT_OK;
#endif
}

/* ---- CSR attribute enforcement (est_require_csr_attributes) ---------- */

/* Read a DER TLV at `p`; on success fill `*tag`, `*len` (value length)
 * and `*hdr` (header size in bytes). Returns 0 on success, -1 on
 * truncation or malformed length encoding. Long-form lengths up to 4
 * bytes are supported, which is more than enough for a CSR (< 64 KiB). */
static int csr__take_tl(const uint8_t* p, size_t avail,
                        uint8_t* tag, size_t* len, size_t* hdr)
{
    if (avail < 2)
        return -1;

    *tag = p[0];
    size_t l, h;
    if ((p[1] & 0x80) == 0) {
        l = p[1];
        h = 2;
    }
    else {
        size_t n = p[1] & 0x7F;
        if (n == 0 || n > 4 || 2 + n > avail)
            return -1;

        l = 0;
        for (size_t i = 0; i < n; ++i) {
            l = (l << 8) | p[2 + i];
        }
        h = 2 + n;
    }

    if (h + l > avail)
        return -1;

    *len = l;
    *hdr = h;

    return 0;
}

/* Walk a PKCS#10 CertificationRequest DER down to the `attributes [0]`
 * field and check whether it contains an Attribute whose type OID
 * matches `oid`. Returns 1 if present, 0 if absent, -1 if the CSR
 * can't be parsed well enough to decide. */
static int csr__has_attr_oid(const uint8_t* csr, size_t csr_len,
                             const uint8_t* oid, size_t oid_len)
{
    uint8_t tag;
    size_t len, hdr;

    /* outer SEQUENCE (CertificationRequest). */
    if (csr__take_tl(csr, csr_len, &tag, &len, &hdr) != 0 || tag != 0x30)
        return -1;

    const uint8_t* p = csr + hdr;
    size_t avail = len;

    /* inner SEQUENCE (CertificationRequestInfo). */
    if (csr__take_tl(p, avail, &tag, &len, &hdr) != 0 || tag != 0x30)
        return -1;

    const uint8_t* info = p + hdr;
    size_t info_len = len;

    /* Skip version INTEGER. */
    if (csr__take_tl(info, info_len, &tag, &len, &hdr) != 0 || tag != 0x02)
        return -1;

    info += hdr + len;
    info_len -= hdr + len;

    /* Skip subject SEQUENCE. */
    if (csr__take_tl(info, info_len, &tag, &len, &hdr) != 0 || tag != 0x30)
        return -1;

    info += hdr + len;
    info_len -= hdr + len;

    /* Skip subjectPKInfo SEQUENCE. */
    if (csr__take_tl(info, info_len, &tag, &len, &hdr) != 0 || tag != 0x30)
        return -1;

    info += hdr + len;
    info_len -= hdr + len;

    /* attributes [0] IMPLICIT - tag 0xA0 (context-specific,
     * constructed, no. 0). Optional per PKCS#10; absent attributes
     * = no match. */
    if (info_len == 0)
        return 0;

    if (csr__take_tl(info, info_len, &tag, &len, &hdr) != 0 || tag != 0xA0)
        return 0;

    const uint8_t* attrs = info + hdr;
    size_t attrs_len = len;

    /* SET OF Attribute. Each Attribute is SEQUENCE { OID, SET OF vals }.
     * Walk and compare the type OID of each. */
    while (attrs_len > 0) {
        if (csr__take_tl(attrs, attrs_len, &tag, &len, &hdr) != 0 || tag != 0x30) {
            return -1;
        }

        const uint8_t* one  = attrs + hdr;
        size_t         onel = len;

        /* First TLV inside is the type OID. */
        uint8_t ot;
        size_t olen, ohdr;
        if (csr__take_tl(one, onel, &ot, &olen, &ohdr) != 0 || ot != 0x06)
            return -1;

        if (olen == oid_len && memcmp(one + ohdr, oid, oid_len) == 0) {
            return 1;
        }

        attrs     += hdr + len;
        attrs_len -= hdr + len;
    }

    return 0;
}

/* Enforce est_require_csr_attributes: every bare-OID policy item in
 * s->cfg_csr_attrs must appear as an attribute type OID in the CSR.
 * `err_oid_len` is a value-result parameter: on entry it holds the capacity
 * of the caller-provided `err_oid_buf`. It is reset to 0 up front and set
 * non-zero only on the missing-OID path (which copies the missing OID into
 * `err_oid_buf`), so the caller can treat `*err_oid_len > 0` as "an OID was
 * captured" without coupling to the exact return code. The OID is copied out
 * before the parsed policy is freed: the WolfCertCsrAttrs owns its OID
 * storage, so returning a pointer into it would dangle once the policy is
 * released. */
static int csr_attrs_enforce(const WolfCertServer* s,
                             const uint8_t* csr_der, size_t csr_len,
                             uint8_t* err_oid_buf, size_t* err_oid_len)
{
    /* Read the caller's buffer capacity, then default the out-length to 0 so
     * every non-missing return path reports "no OID captured". */
    size_t err_oid_cap = *err_oid_len;
    *err_oid_len = 0;

    if (!s->cfg.est_require_csr_attributes ||
            s->cfg_csr_attrs == NULL || s->cfg_csr_attrs_len == 0)
        return WOLFCERT_OK;

    WolfCertCsrAttrs policy;
    int rc = wolfcert_est_parse_csr_attrs(s->cfg_csr_attrs,
                                          s->cfg_csr_attrs_len, &policy);
    if (rc != WOLFCERT_OK)
        return rc;

    int missing = 0;
    for (size_t i = 0; i < policy.count; ++i) {
        /* Presence-only enforcement today: bare-OID items are required,
         * Attributes (with values) are advisory. Value-level comparison
         * is a future enhancement. */
        if (policy.items[i].kind != WOLFCERT_CSRATTR_BARE_OID)
            continue;

        int has = csr__has_attr_oid(csr_der, csr_len,
                                    policy.items[i].oid,
                                    policy.items[i].oid_len);
        if (has != 1) {
            size_t n = policy.items[i].oid_len;
            if (n > err_oid_cap)
                n = err_oid_cap;
            if (n > 0)
                memcpy(err_oid_buf, policy.items[i].oid, n);
            *err_oid_len = n;
            missing = 1;
            break;
        }
    }

    wolfcert_csr_attrs_free(&policy);

    return missing ? WOLFCERT_ERR_PROTOCOL : WOLFCERT_OK;
}

WOLFCERT_TEST_VIS size_t wolfcert_oid_to_dotted(const uint8_t* oid, size_t oid_len,
                                                char* out, size_t out_cap)
{
    size_t off = 0;

    /* Always leave a valid C string, even for an empty OID or zero capacity. */
    if (out_cap > 0)
        out[0] = '\0';

    if (oid_len >= 1) {
        /* First byte holds the first two arcs as 40*node1 + node2. node1 is
         * capped at 2, so for a first byte >= 80 node2 is the remainder above
         * 80 (node2 can exceed 40 only when node1 == 2). */
        unsigned first  = oid[0] < 80 ? oid[0] / 40 : 2;
        unsigned second = oid[0] < 80 ? oid[0] % 40 : oid[0] - 80u;
        off += (size_t)snprintf(out + off, out_cap - off, "%u.%u",
                                first, second);
    }

    unsigned long n = 0;
    for (size_t i = 1; i < oid_len && off + 16 < out_cap; ++i) {
        n = (n << 7) | (oid[i] & 0x7F);
        if ((oid[i] & 0x80) == 0) {
            off += (size_t)snprintf(out + off, out_cap - off, ".%lu", n);
            n = 0;
        }
    }

    return off;
}

/* Emit a 400 Bad Request whose body lists the missing OID in dotted
 * decimal. Helpful for humans debugging the round-trip. */
static void send_missing_oid(WolfCertServer* s, int fd,
                             const uint8_t* oid, size_t oid_len)
{
    char txt[128];
    wolfcert_oid_to_dotted(oid, oid_len, txt, sizeof(txt));

    char body[192];
    int bl = snprintf(body, sizeof(body),
                      "CSR missing required attribute OID %s\n", txt);
    char hdr[192];
    int hl = snprintf(hdr, sizeof(hdr),
                      "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\n"
                      "Content-Length: %d\r\nConnection: %s\r\n\r\n",
                      bl, conn_hdr(s));

    send_all(s, fd, hdr,  (size_t)hl);
    send_all(s, fd, body, (size_t)bl);
}

static int handler_enroll(WolfCertServer* s, int fd, const EstRequest* req)
{
    int pha = ensure_post_handshake_auth(s);
    if (pha != WOLFCERT_OK) {
        send_status(s, fd, 401, "Unauthorized");
        return pha;
    }

    if (req->body == NULL || req->body_len == 0) {
        send_status(s, fd,400, "Bad Request");
        return WOLFCERT_ERR_HTTP;
    }

    /* Manual-approval gate. First POST for a given CSR: park it and
     * return 202 + Retry-After. Second (matching) POST: drop the
     * pending entry and fall through to issuance. */
    if (s->cfg.est_require_approval && s->priv != NULL) {
        EstPriv* p = (EstPriv*)s->priv;
        uint8_t h[32];
        sha256_bytes(req->body, req->body_len, h);
        int idx = pending_find(p, h);
        if (idx < 0) {
            if (!pending_add(p, h)) {
                send_status(s, fd, 503, "Service Unavailable");
                return WOLFCERT_ERR_PROTOCOL;
            }
            send_accepted_retry_after(s, fd, s->cfg.est_retry_after_sec);
            return WOLFCERT_OK;
        }
        pending_remove(p, idx);
    }

    WolfCertBuffer csr = { 0 };
    int rc = wolfcert_base64_decode(req->body, req->body_len, &csr, s->heap);
    if (rc != WOLFCERT_OK) {
        send_status(s, fd,400, "Bad Request");
        return rc;
    }

    /* RFC 7030 section 3.5 lets an EST client bind the proof-of-possession to
     * the TLS session by carrying the tls-unique channel binding (RFC 5929)
     * inside the CSR (typically the PKCS#9 challengePassword), in which case
     * the server MUST verify it. We currently do not implement this: the CSR
     * is issued on its own merits without extracting any tls-unique value or
     * comparing it against this connection's TLS Finished data. If channel
     * binding is ever required, derive tls-unique from the TLS session here
     * and reject the request when the embedded binding does not match. */

    /* Policy enforcement: reject CSRs that don't carry every
     * bare-OID Attribute advertised via /csrattrs. Done before
     * wolfcert_ca_issue so an offending client can't walk away with a
     * cert even if the underlying issuance would have accepted it. */
    if (s->cfg.est_require_csr_attributes) {
        /* Room for the largest OID we would report; DER attribute-type OIDs
         * are far shorter than this in practice. */
        uint8_t missing_oid[64];
        size_t missing_len = sizeof(missing_oid);   /* in: cap, out: OID len */
        int erc = csr_attrs_enforce(s, csr.data, csr.len,
                                    missing_oid, &missing_len);
        if (erc != WOLFCERT_OK) {
            /* csr_attrs_enforce sets missing_len > 0 only when it captured a
             * missing required OID into missing_oid. Gate on that explicitly
             * (not on the return code alone) so no future error path can
             * render an unpopulated buffer into the response body. */
            if (erc == WOLFCERT_ERR_PROTOCOL && missing_len > 0)
                send_missing_oid(s, fd, missing_oid, missing_len);
            else
                send_status(s, fd, 400, "Bad Request");

            wolfcert_buffer_free(&csr);
            return erc;
        }
    }

    uint8_t* issued = NULL;
    size_t issued_len = 0;
    rc = wolfcert_ca_issue(&s->ca, csr.data, csr.len, &issued, &issued_len);

    wolfcert_buffer_free(&csr);
    if (rc != WOLFCERT_OK) {
        send_status(s, fd,400, "Bad CSR");
        return rc;
    }

    const uint8_t* certs[1] = { issued };
    size_t         clen[1]  = { issued_len };
    WolfCertBuffer p7 = { 0 };
    rc = wolfcert_pkcs7_build_certs_only(certs, clen, 1, &p7, s->heap);

    WOLFCERT_XFREE(issued, s->heap);
    if (rc != WOLFCERT_OK) {
        send_status(s, fd,500, "Server Error");
        return rc;
    }

    WolfCertBuffer b64 = { 0 };
    rc = wolfcert_base64_encode_mime(p7.data, p7.len, &b64, s->heap);

    wolfcert_buffer_free(&p7);
    if (rc != WOLFCERT_OK) {
        send_status(s, fd,500, "Server Error");
        return rc;
    }

    send_pkcs7_b64(s, fd,b64.data, b64.len);
    wolfcert_buffer_free(&b64);

    return WOLFCERT_OK;
}

static int handle_request(WolfCertServer* s, int fd)
{
    EstRequest req = { 0 };

    int rc = parse_request(s, fd, &req, s->heap);
    if (rc != WOLFCERT_OK) {
        /* No parseable request means the client hung up or sent
         * garbage; either way we're done with this connection. */
        s->keep_alive = 0;
        send_status(s, fd, 400, "Bad Request");
        free_req(&req);
        return rc;
    }

    if (req.connection_close)
        s->keep_alive = 0;

    const char* suffix = strstr(req.path, "/.well-known/est/");
    if (suffix != NULL)
        suffix += strlen("/.well-known/est/");
    else {
        const char* last = strrchr(req.path, '/');
        suffix = last ? last + 1 : req.path;
    }

    if (strcmp(req.method, "GET") == 0 && strcmp(suffix, "cacerts") == 0) {
        rc = handler_cacerts(s, fd);
    }
    else if (strcmp(req.method, "GET") == 0 && strcmp(suffix, "csrattrs") == 0) {
        rc = handler_csr_attrs(s, fd);
    }
    else if (strcmp(req.method, "POST") == 0 &&
             (strcmp(suffix, "simpleenroll") == 0 ||
              strcmp(suffix, "simplereenroll") == 0)) {
        if (!check_basic_auth(s, req.auth_header)) {
            send_status(s, fd,401, "Unauthorized");
            rc = WOLFCERT_ERR_AUTH;
        }
        else {
            rc = handler_enroll(s, fd, &req);
        }
    }
    else {
        send_status(s, fd,404, "Not Found");
        rc = WOLFCERT_ERR_NOT_FOUND;
    }

    free_req(&req);
    return rc;
}

/* ---- vtable ------------------------------------------------------------ */

static int est_start(const WolfCertServerCfgSrv* cfg, WolfCertServer* base)
{
    (void)cfg;

    /* Only allocate the pending queue when manual-approval is on; most
     * callers never touch it, so we avoid the ~300 byte state otherwise. */
    if (cfg->est_require_approval) {
        EstPriv* p = (EstPriv*)WOLFCERT_XMALLOC(sizeof(*p), base->heap);
        if (p == NULL)
            return WOLFCERT_ERR_MEMORY;

        memset(p, 0, sizeof(*p));
        base->priv = p;
    }

    return WOLFCERT_OK;
}

static int est_serve_fd(WolfCertServer* srv, int fd)
{
    return handle_request(srv, fd);
}

static void est_free_priv(WolfCertServer* srv)
{
    if (srv->priv != NULL) {
        WOLFCERT_XFREE(srv->priv, srv->heap);
        srv->priv = NULL;
    }
}

static const WolfCertServerOps EST_OPS = {
    .start     = est_start,
    .serve_fd  = est_serve_fd,
    .free_priv = est_free_priv,
};

const WolfCertServerOps* wolfcert_est_server_ops(void)
{
    return &EST_OPS;
}
