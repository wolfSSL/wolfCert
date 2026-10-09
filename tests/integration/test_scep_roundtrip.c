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
#define _DARWIN_C_SOURCE   /* expose memmem/strcasestr/INADDR_LOOPBACK on macOS */
#define _GNU_SOURCE

#include <wolfcert/wolfcert.h>
#include <wolfcert/scep.h>
#include <wolfcert/server.h>

#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/asn.h>          /* SHA256h */
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/pkcs7.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/rsa.h>

#include "internal.h"                       /* whitebox SCEP pkiMessage helpers */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define REQUIRE(cond) \
    do {                                                                    \
        if (!(cond)) {                                                      \
            fprintf(stderr, "FAIL %s:%d %s\n", __FILE__, __LINE__, #cond);  \
            return 1;                                                       \
        }                                                                   \
    } while (0)

static void* server_thread(void* arg)
{
    wolfcert_server_run((WolfCertServer*)arg);
    return NULL;
}

/* write() on a stream socket may return a short count. */
static int write_all_fd(int fd, const uint8_t* buf, size_t len)
{
    size_t off = 0;

    while (off < len) {
        ssize_t w = write(fd, buf + off, len - off);
        if (w <= 0)
            return -1;
        off += (size_t)w;
    }

    return 0;
}

/* Raw HTTP/1.1 request to the loopback SCEP server, for malformed-request
 * branches the client API cannot produce. out_body, when set, is caller-freed. */
static int raw_http_req(uint16_t port, const char* method, const char* target,
                        const char* content_type,
                        const uint8_t* body, size_t body_len, int persistent,
                        uint8_t** out_body, size_t* out_body_len)
{
    struct sockaddr_in addr;
    struct timeval tv;
    char hdr[512];
    uint8_t* resp = NULL;
    size_t resp_len = 0;
    size_t resp_cap = 0;
    const uint8_t* sep;
    int eof = 0;
    int fd;
    int n;
    ssize_t r;
    int status = -1;

    if (out_body != NULL && out_body_len != NULL) {
        *out_body = NULL;
        *out_body_len = 0;
    }

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;

    tv.tv_sec = 5;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        close(fd);
        return -1;
    }

    if (body != NULL)
        n = snprintf(hdr, sizeof(hdr),
                     "%s %s HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: %s\r\n"
                     "%s%s%sContent-Length: %zu\r\n\r\n",
                     method, target, persistent ? "keep-alive" : "close",
                     content_type != NULL ? "Content-Type: " : "",
                     content_type != NULL ? content_type : "",
                     content_type != NULL ? "\r\n" : "",
                     body_len);
    else
        n = snprintf(hdr, sizeof(hdr),
                     "%s %s HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: %s\r\n\r\n",
                     method, target, persistent ? "keep-alive" : "close");
    if (n < 0 || (size_t)n >= sizeof(hdr)) {
        close(fd);
        return -1;
    }
    if (write_all_fd(fd, (const uint8_t*)hdr, (size_t)n) != 0 ||
            (body_len > 0 && write_all_fd(fd, body, body_len) != 0)) {
        close(fd);
        return -1;
    }

    /* Read to EOF; a grow failure, read error or SO_RCVTIMEO expiry fails. */
    for (;;) {
        if (resp_len + 4096 + 1 > resp_cap) {
            size_t want = resp_cap == 0 ? 8192 : resp_cap * 2;
            uint8_t* grown = (uint8_t*)realloc(resp, want);
            if (grown == NULL)
                break;
            resp = grown;
            resp_cap = want;
        }
        r = read(fd, resp + resp_len, 4096);
        if (r < 0)
            break;
        if (r == 0) {
            eof = 1;
            break;
        }
        resp_len += (size_t)r;
    }
    close(fd);

    if (resp == NULL || !eof) {
        free(resp);
        return -1;
    }
    resp[resp_len] = '\0';

    if (resp_len > 9 && memcmp(resp, "HTTP/1.1 ", 9) == 0)
        status = atoi((const char*)resp + 9);

    sep = (const uint8_t*)memmem(resp, resp_len, "\r\n\r\n", 4);
    if (out_body != NULL && out_body_len != NULL && sep != NULL) {
        size_t off = (size_t)(sep - resp) + 4;
        size_t len = resp_len - off;
        uint8_t* b = (uint8_t*)malloc(len + 1);
        if (b != NULL) {
            memcpy(b, resp + off, len);
            b[len] = '\0';
            *out_body = b;
            *out_body_len = len;
        }
    }

    free(resp);
    return status;
}

/* Status code of the reply to a hand-written request, or -1 on no reply. */
static int raw_request_status(uint16_t port, const char* req)
{
    struct sockaddr_in addr;
    struct timeval tv = { 3, 0 };
    char resp[64];
    size_t n = 0;
    ssize_t r;
    int fd;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) != 0 ||
            write_all_fd(fd, (const uint8_t*)req, strlen(req)) != 0) {
        close(fd);
        return -1;
    }
    while (n < 12 && (r = read(fd, resp + n, sizeof(resp) - 1 - n)) > 0)
        n += (size_t)r;
    close(fd);
    resp[n] = '\0';

    return n >= 12 && memcmp(resp, "HTTP/1.1 ", 9) == 0 ? atoi(resp + 9) : -1;
}

static int raw_http_status(uint16_t port, const char* target, const char* body)
{
    return raw_http_req(port, "GET", target, NULL,
                        (const uint8_t*)body,
                        body != NULL ? strlen(body) : 0, 0, NULL, NULL);
}

/* Enrollment over the GET PKIOperation fallback (RFC 8894 section 4.1), with
 * the issued cert verified against the CA. */
static int check_get_fallback(const WolfCertServerCfg* cli,
                              const WolfCertScepCaps* caps,
                              const WolfCertKeyCfg* kcfg,
                              const uint8_t* ca_der_buf, size_t ca_der_len)
{
    WolfCertScepCaps      caps_get = *caps;
    WolfCertCertMeta      meta_get = { .subject_dn = "CN=device-scep-get" };
    WolfCertKey*          dkg = NULL;
    WolfCertBuffer        csr_get = { 0 };
    WolfCertBuffer        issued_get = { 0 };
    WOLFSSL_CERT_MANAGER* cm = NULL;
    DerBuffer*            issued_der = NULL;
    int rc;

    caps_get.post_pki_operation = 0;

    rc = wolfcert_key_generate(kcfg, &dkg);
    if (rc == WOLFCERT_OK)
        rc = wolfcert_csr_build(dkg, &meta_get, &csr_get);
    if (rc == WOLFCERT_OK)
        rc = wolfcert_scep_pkcs_req(cli, &caps_get, ca_der_buf, ca_der_len,
                                    dkg, csr_get.data, csr_get.len, &issued_get);

    if (rc == WOLFCERT_OK) {
        cm = wolfSSL_CertManagerNew();
        if (cm == NULL)
            rc = -1;
    }
    if (rc == WOLFCERT_OK &&
            wolfSSL_CertManagerLoadCABuffer(cm, ca_der_buf, (long)ca_der_len,
                WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS)
        rc = -1;
    if (rc == WOLFCERT_OK &&
            wc_PemToDer(issued_get.data, (long)issued_get.len, CERT_TYPE,
                &issued_der, NULL, NULL, NULL) != 0)
        rc = -1;
    if (rc == WOLFCERT_OK &&
            wolfSSL_CertManagerVerifyBuffer(cm, issued_der->buffer,
                (long)issued_der->length, WOLFSSL_FILETYPE_ASN1)
                    != WOLFSSL_SUCCESS)
        rc = -1;

    wc_FreeDer(&issued_der);
    if (cm != NULL)
        wolfSSL_CertManagerFree(cm);
    wolfcert_buffer_free(&issued_get);
    wolfcert_buffer_free(&csr_get);
    wolfcert_key_free(dkg);
    return rc;
}

static int check_rsa4096(const WolfCertServerCfg* cli,
                         const WolfCertScepCaps* caps,
                         const uint8_t* ca_der_buf, size_t ca_der_len)
{
    WolfCertKeyCfg        kcfg = { .type = WOLFCERT_KEY_RSA, .param = 4096,
                                   .dev_id = WOLFCERT_DEVID_SOFTWARE };
    WolfCertCertMeta      meta = { .subject_dn = "CN=device-scep-4096" };
    WolfCertKey*          key = NULL;
    WolfCertBuffer        csr = { 0 };
    WolfCertBuffer        issued = { 0 };
    WOLFSSL_CERT_MANAGER* cm = NULL;
    DerBuffer*            issued_der = NULL;
    int rc;

    rc = wolfcert_key_generate(&kcfg, &key);
    if (rc == WOLFCERT_OK)
        rc = wolfcert_csr_build(key, &meta, &csr);
    if (rc == WOLFCERT_OK)
        rc = wolfcert_scep_pkcs_req(cli, caps, ca_der_buf, ca_der_len,
                                    key, csr.data, csr.len, &issued);

    if (rc == WOLFCERT_OK) {
        cm = wolfSSL_CertManagerNew();
        if (cm == NULL)
            rc = -1;
    }
    if (rc == WOLFCERT_OK &&
            wolfSSL_CertManagerLoadCABuffer(cm, ca_der_buf, (long)ca_der_len,
                WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS)
        rc = -1;
    if (rc == WOLFCERT_OK &&
            wc_PemToDer(issued.data, (long)issued.len, CERT_TYPE,
                &issued_der, NULL, NULL, NULL) != 0)
        rc = -1;
    if (rc == WOLFCERT_OK &&
            wolfSSL_CertManagerVerifyBuffer(cm, issued_der->buffer,
                (long)issued_der->length, WOLFSSL_FILETYPE_ASN1)
                    != WOLFSSL_SUCCESS)
        rc = -1;

    wc_FreeDer(&issued_der);
    if (cm != NULL)
        wolfSSL_CertManagerFree(cm);
    wolfcert_buffer_free(&issued);
    wolfcert_buffer_free(&csr);
    wolfcert_key_free(key);
    return rc;
}

/* Two PKCSReqs of one key under txid_mode PUBKEY_HASH carry the same
 * transactionID, the upper-case hex SHA-256 of the CSR's SPKI. */
static int check_pubkey_txid(const WolfCertServerCfg* cli,
                             const WolfCertScepCaps* caps,
                             const WolfCertKeyCfg* kcfg,
                             const uint8_t* ca_der_buf, size_t ca_der_len)
{
    WolfCertServerCfg cli_ph = *cli;
    WolfCertCertMeta  meta = { .subject_dn = "CN=device-txid" };
    WolfCertKey*      key = NULL;
    WolfCertBuffer    csr = { 0 };
    WolfCertScepResult r1 = { 0 }, r2 = { 0 };
    int rc;

    cli_ph.proto_opts.scep.txid_mode = WOLFCERT_SCEP_TXID_PUBKEY_HASH;

    rc = wolfcert_key_generate(kcfg, &key);
    if (rc == WOLFCERT_OK)
        rc = wolfcert_csr_build(key, &meta, &csr);
    if (rc == WOLFCERT_OK)
        rc = wolfcert_scep_pkcs_req_ex(&cli_ph, caps, ca_der_buf, ca_der_len,
                                       ca_der_buf, ca_der_len, key,
                                       csr.data, csr.len, &r1);
    if (rc == WOLFCERT_OK && r1.status != WOLFCERT_SCEP_STATUS_SUCCESS)
        rc = -1;
    if (rc == WOLFCERT_OK && r1.transaction_id_len != 64)   /* SHA-256 hex */
        rc = -1;

    /* Recompute SHA-256(SPKI) from the CSR and compare, upper-case hex. */
    if (rc == WOLFCERT_OK) {
        DecodedCert dc;
        wc_InitDecodedCert(&dc, csr.data, (word32)csr.len, NULL);
        if (wc_ParseCert(&dc, CERTREQ_TYPE, NO_VERIFY, NULL) != 0) {
            rc = -1;
        }
        else {
            uint8_t digest[WC_SHA256_DIGEST_SIZE];
            if (wc_Sha256Hash(dc.publicKey, dc.pubKeySize, digest) != 0) {
                rc = -1;
            }
            else {
                static const char H[] = "0123456789ABCDEF";
                char hex[2 * WC_SHA256_DIGEST_SIZE];
                for (int i = 0; i < WC_SHA256_DIGEST_SIZE; i++) {
                    hex[i*2]   = H[digest[i] >> 4];
                    hex[i*2+1] = H[digest[i] & 0x0F];
                }
                if (memcmp(r1.transaction_id, hex, sizeof(hex)) != 0)
                    rc = -1;
            }
        }
        /* Freed on both branches: wc_ParseCert allocates before it can fail. */
        wc_FreeDecodedCert(&dc);
    }

    /* Deterministic: enrolling the same key again reuses the transactionID. */
    if (rc == WOLFCERT_OK)
        rc = wolfcert_scep_pkcs_req_ex(&cli_ph, caps, ca_der_buf, ca_der_len,
                                       ca_der_buf, ca_der_len, key,
                                       csr.data, csr.len, &r2);
    if (rc == WOLFCERT_OK &&
        (r2.transaction_id_len != r1.transaction_id_len ||
         memcmp(r1.transaction_id, r2.transaction_id, r1.transaction_id_len) != 0))
        rc = -1;

    wolfcert_scep_result_free(&r1);
    wolfcert_scep_result_free(&r2);
    wolfcert_buffer_free(&csr);
    wolfcert_key_free(key);
    return rc;
}

/* A CSR whose self-signature is broken gets past the SPKI and challenge checks
 * and is only refused at issuance, which must still answer with a CertRep. */
static int check_bad_csr_sig(const WolfCertServerCfg* cli,
                             const WolfCertScepCaps* caps,
                             const WolfCertKey* key,
                             const uint8_t* csr, size_t csr_len,
                             const uint8_t* ca_der_buf, size_t ca_der_len)
{
    WolfCertScepResult r = { 0 };
    uint8_t* bad = NULL;
    int rc = WOLFCERT_OK;

    bad = (uint8_t*)WOLFCERT_XMALLOC(csr_len, NULL);
    if (bad == NULL)
        rc = WOLFCERT_ERR_MEMORY;
    if (rc == WOLFCERT_OK) {
        memcpy(bad, csr, csr_len);
        bad[csr_len - 1] ^= 0x01;
        rc = wolfcert_scep_pkcs_req_ex(cli, caps, ca_der_buf, ca_der_len,
                                       ca_der_buf, ca_der_len, key,
                                       bad, csr_len, &r);
        if (rc != WOLFCERT_OK)
            fprintf(stderr, "bad CSR signature: rc=%d (%s)\n", rc,
                    wolfcert_strerror(rc));
    }
    if (rc == WOLFCERT_OK && (r.status != WOLFCERT_SCEP_STATUS_FAILURE ||
                              r.fail_info != 2))
        rc = -1;

    wolfcert_scep_result_free(&r);
    WOLFCERT_XFREE(bad, NULL);
    return rc;
}

/* Enrollment with an explicit proto_opts.scep.content_cipher. */
static int check_content_cipher(const WolfCertServerCfg* cli,
                                const WolfCertScepCaps* caps,
                                const WolfCertKeyCfg* kcfg,
                                const uint8_t* ca_der_buf, size_t ca_der_len,
                                WolfCertScepContentCipher cipher)
{
    WolfCertServerCfg c = *cli;
    WolfCertCertMeta  meta = { .subject_dn = "CN=device-cipher" };
    WolfCertKey*      key = NULL;
    WolfCertBuffer    csr = { 0 }, issued = { 0 };
    int rc;

    c.proto_opts.scep.content_cipher = cipher;

    rc = wolfcert_key_generate(kcfg, &key);
    if (rc == WOLFCERT_OK)
        rc = wolfcert_csr_build(key, &meta, &csr);
    if (rc == WOLFCERT_OK)
        rc = wolfcert_scep_pkcs_req(&c, caps, ca_der_buf, ca_der_len, key,
                                    csr.data, csr.len, &issued);
    if (rc == WOLFCERT_OK &&
            memmem(issued.data, issued.len, "BEGIN CERTIFICATE", 17) == NULL)
        rc = -1;

    wolfcert_buffer_free(&issued);
    wolfcert_buffer_free(&csr);
    wolfcert_key_free(key);
    return rc;
}

/* The listener canned_srv_thread() accepts on and the response it sends. */
struct canned_ctx {
    int            listen_fd;
    const char*    content_type;
    const uint8_t* body;
    size_t         body_len;
};

/* Bind a loopback listener and report its ephemeral port. */
static int listen_loopback(int* port)
{
    int ls = socket(AF_INET, SOCK_STREAM, 0);
    if (ls < 0)
        return -1;
    int yes = 1;
    setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    struct sockaddr_in sa = { .sin_family = AF_INET, .sin_port = htons(0),
                              .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    if (bind(ls, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
        close(ls);
        return -1;
    }
    if (listen(ls, 1) < 0) {
        close(ls);
        return -1;
    }
    socklen_t slen = sizeof(sa);
    if (getsockname(ls, (struct sockaddr*)&sa, &slen) < 0) {
        close(ls);
        return -1;
    }
    *port = ntohs(sa.sin_port);
    return ls;
}

/* Answers one request with canned_ctx's Content-Type and body. */
static void* canned_srv_thread(void* arg)
{
    struct canned_ctx* cc = (struct canned_ctx*)arg;
    int cs = accept(cc->listen_fd, NULL, NULL);
    close(cc->listen_fd);
    if (cs < 0)
        return NULL;

    char buf[1024];
    size_t n = 0;
    while (n < sizeof(buf) - 1) {
        ssize_t r = recv(cs, buf + n, sizeof(buf) - 1 - n, 0);
        if (r <= 0)
            break;
        n += (size_t)r;
        buf[n] = '\0';
        if (strstr(buf, "\r\n\r\n") != NULL)
            break;
    }

    char head[256];
    int hn = snprintf(head, sizeof(head),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n\r\n",
        cc->content_type, cc->body_len);
    if (hn > 0 && (size_t)hn < sizeof(head) &&
            write_all_fd(cs, (const uint8_t*)head, (size_t)hn) == 0)
        (void)write_all_fd(cs, cc->body, cc->body_len);
    shutdown(cs, SHUT_WR);
    close(cs);
    return NULL;
}

/* A GetCACaps body of Renewal-Extra and AESGCM sets neither renewal nor aes. */
static int test_caps_token_matching(void)
{
    const char* caps_body =
        "POSTPKIOperation\r\n"
        "Renewal-Extra\r\n"
        "AESGCM\r\n";
    struct canned_ctx cc = { .listen_fd = -1, .content_type = "text/plain",
                             .body = (const uint8_t*)caps_body,
                             .body_len = strlen(caps_body) };
    pthread_t tid;
    int port = 0;
    cc.listen_fd = listen_loopback(&port);
    REQUIRE(cc.listen_fd >= 0);
    REQUIRE(pthread_create(&tid, NULL, canned_srv_thread, &cc) == 0);

    char url[128];
    snprintf(url, sizeof(url), "http://127.0.0.1:%d/scep", port);
    WolfCertServerCfg cli = { .protocol = WOLFCERT_PROTO_SCEP, .server_url = url };
    WolfCertScepCaps caps = { 0 };
    REQUIRE(wolfcert_scep_get_ca_caps(&cli, &caps) == WOLFCERT_OK);
    pthread_join(tid, NULL);

    /* Exact token still matches; substring-only lines do not. */
    REQUIRE(caps.post_pki_operation == 1);
    REQUIRE(caps.renewal == 0);
    REQUIRE(caps.aes == 0);
    return 0;
}

static int test_caps_scep_standard(void)
{
    const char* caps_body = "SCEPStandard\r\n";
    struct canned_ctx cc = { .listen_fd = -1, .content_type = "text/plain",
                             .body = (const uint8_t*)caps_body,
                             .body_len = strlen(caps_body) };
    pthread_t tid;
    int port = 0;
    cc.listen_fd = listen_loopback(&port);
    REQUIRE(cc.listen_fd >= 0);
    REQUIRE(pthread_create(&tid, NULL, canned_srv_thread, &cc) == 0);

    char url[128];
    snprintf(url, sizeof(url), "http://127.0.0.1:%d/scep", port);
    WolfCertServerCfg cli = { .protocol = WOLFCERT_PROTO_SCEP, .server_url = url };
    WolfCertScepCaps caps = { 0 };
    int rc = wolfcert_scep_get_ca_caps(&cli, &caps);
    pthread_join(tid, NULL);
    REQUIRE(rc == WOLFCERT_OK);

    REQUIRE(caps.scep_standard == 1);
    REQUIRE(caps.post_pki_operation == 1);
    REQUIRE(caps.aes == 1);
    REQUIRE(caps.sha256 == 1);
    REQUIRE(caps.renewal == 0);
    REQUIRE(caps.sha384 == 0);
    REQUIRE(caps.sha512 == 0);
    REQUIRE(caps.get_next_ca_cert == 0);
    return 0;
}

/* Serve `body` once under `content_type` and fetch it with GetCACert. */
static int fetch_ca(const char* content_type, const uint8_t* body,
                    size_t body_len, WolfCertEncoding enc, WolfCertBuffer* out)
{
    struct canned_ctx cc = { .listen_fd = -1, .content_type = content_type,
                             .body = body, .body_len = body_len };
    pthread_t tid;
    int port = 0;
    cc.listen_fd = listen_loopback(&port);
    REQUIRE(cc.listen_fd >= 0);
    REQUIRE(pthread_create(&tid, NULL, canned_srv_thread, &cc) == 0);

    char url[128];
    snprintf(url, sizeof(url), "http://127.0.0.1:%d/scep", port);
    WolfCertServerCfg cli = { .protocol = WOLFCERT_PROTO_SCEP, .server_url = url };
    int rc = wolfcert_scep_get_ca_cert_enc(&cli, enc, out);
    pthread_join(tid, NULL);
    return rc;
}

/* The CA/RA media type (RFC 8894 section 4.2.1.2) matches case-insensitively
 * and with parameters (RFC 9110 section 8.3.1). */
static int check_getca_media_type(const uint8_t* ca_der_buf, size_t ca_der_len)
{
    const uint8_t* certs[1] = { ca_der_buf };
    size_t lens[1] = { ca_der_len };
    WolfCertBuffer p7 = { 0 };
    REQUIRE(wolfcert_pkcs7_build_certs_only(certs, lens, 1, &p7, NULL)
            == WOLFCERT_OK);

    /* Mixed case and whitespace before ';' still name the bundle type. */
    WolfCertBuffer pem = { 0 };
    REQUIRE(fetch_ca("Application/X-X509-CA-RA-Cert ; charset=binary",
                     p7.data, p7.len, WOLFCERT_ENCODING_PEM, &pem)
            == WOLFCERT_OK);
    DerBuffer* pem_der = NULL;
    REQUIRE(wc_PemToDer(pem.data, (long)pem.len, CERT_TYPE,
                        &pem_der, NULL, NULL, NULL) == 0);
    REQUIRE(pem_der->length == ca_der_len);
    REQUIRE(memcmp(pem_der->buffer, ca_der_buf, ca_der_len) == 0);
    wc_FreeDer(&pem_der);
    wolfcert_buffer_free(&pem);

    WolfCertBuffer der = { 0 };
    REQUIRE(fetch_ca("application/x-x509-ca-ra-cert", p7.data, p7.len,
                     WOLFCERT_ENCODING_DER, &der) == WOLFCERT_OK);
    REQUIRE(der.len == ca_der_len);
    REQUIRE(memcmp(der.data, ca_der_buf, ca_der_len) == 0);
    wolfcert_buffer_free(&der);

    /* A longer subtype is a different type: the bare cert comes back as is. */
    REQUIRE(fetch_ca("application/x-x509-ca-ra-certs", ca_der_buf, ca_der_len,
                     WOLFCERT_ENCODING_DER, &der) == WOLFCERT_OK);
    REQUIRE(der.len == ca_der_len);
    REQUIRE(memcmp(der.data, ca_der_buf, ca_der_len) == 0);
    wolfcert_buffer_free(&der);

    /* So is a different top-level type carrying the same subtype. */
    REQUIRE(fetch_ca("text/x-x509-ca-ra-cert", ca_der_buf, ca_der_len,
                     WOLFCERT_ENCODING_DER, &der) == WOLFCERT_OK);
    REQUIRE(der.len == ca_der_len);
    REQUIRE(memcmp(der.data, ca_der_buf, ca_der_len) == 0);
    wolfcert_buffer_free(&der);

    wolfcert_buffer_free(&p7);
    return 0;
}

static int get_ca_cert_empty(WolfCertEncoding enc)
{
    WolfCertBuffer ca = { 0 };
    int rc;
    int empty;

    rc = fetch_ca("text/plain", NULL, 0, enc, &ca);
    empty = (ca.data == NULL && ca.len == 0);
    wolfcert_buffer_free(&ca);
    REQUIRE(rc == WOLFCERT_ERR_HTTP);
    REQUIRE(empty);
    return 0;
}

static int test_get_ca_cert_empty_body(void)
{
    REQUIRE(get_ca_cert_empty(WOLFCERT_ENCODING_DER) == 0);
    REQUIRE(get_ca_cert_empty(WOLFCERT_ENCODING_PEM) == 0);
    return 0;
}

/* Captures one request and the pkiMessage fields it carried. Every instance
 * has an initializer, so the strings stay "" if the thread bails early. */
struct msgtype_ctx {
    int    listen_fd;
    char   seen[8];      /* the messageType attribute, or "" if not reached */
    char   reqline[256]; /* the HTTP request line, for the GET operations */
    size_t tid_len;      /* transactionID length, 0 if not reached */
    char   cipher[8];    /* content-encryption OID seen in the EnvelopedData */
    /* When reply is set, answer with a CertRep signed by rep_cert/rep_key that
     * carries rep_status and rep_fail_info; NULL leaves that attribute out. */
    const uint8_t* rep_cert;
    size_t         rep_cert_len;
    const uint8_t* rep_key;
    size_t         rep_key_len;
    const char*    rep_status;
    const char*    rep_fail_info;
    int            reply;
};

/* Send a CertRep echoing the request's transactionID and senderNonce. */
static void msgtype_send_cert_rep(const struct msgtype_ctx* mc, int cs,
                                  const uint8_t* tid, size_t tid_len,
                                  const uint8_t* snonce, size_t snonce_len)
{
    uint8_t my_nonce[16];
    memset(my_nonce, 0x3C, sizeof(my_nonce));
    WolfCertScepAttrs attrs = {
        .transaction_id  = tid,      .transaction_id_len  = tid_len,
        .sender_nonce    = my_nonce, .sender_nonce_len    = sizeof(my_nonce),
        .message_type    = "3",      .pki_status          = mc->rep_status,
        .recipient_nonce = snonce,   .recipient_nonce_len = snonce_len,
        .fail_info       = mc->rep_fail_info,
    };
    WolfCertBuffer rep = { 0 };
    if (wolfcert_scep_build_pki_message(NULL, 0, mc->rep_cert, mc->rep_cert_len,
                                        mc->rep_key, mc->rep_key_len, SHA256h,
                                        &attrs, &rep, NULL) != WOLFCERT_OK)
        return;

    char hdr[160];
    int hl = snprintf(hdr, sizeof(hdr),
                      "HTTP/1.1 200 OK\r\n"
                      "Content-Type: application/x-pki-message\r\n"
                      "Content-Length: %zu\r\n"
                      "Connection: close\r\n\r\n", rep.len);
    if (hl > 0 && (size_t)hl < sizeof(hdr) &&
        write_all_fd(cs, (const uint8_t*)hdr, (size_t)hl) == 0)
        (void)write_all_fd(cs, rep.data, rep.len);
    wolfcert_buffer_free(&rep);
}

static void* msgtype_srv_thread(void* arg)
{
    struct msgtype_ctx* mc = (struct msgtype_ctx*)arg;
    int cs = accept(mc->listen_fd, NULL, NULL);
    close(mc->listen_fd);
    if (cs < 0)
        return NULL;

    /* Bound the read so a client that never POSTs fails the assertion instead
     * of hanging until the ctest timeout. */
    struct timeval tv = { .tv_sec = 10, .tv_usec = 0 };
    setsockopt(cs, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    /* One byte is held back so the header block can be NUL-terminated. */
    uint8_t buf[16384];
    size_t n = 0;
    size_t hdr_end = 0, want = 0;
    while (n < sizeof(buf) - 1) {
        ssize_t r = recv(cs, buf + n, sizeof(buf) - 1 - n, 0);
        if (r <= 0)
            break;
        n += (size_t)r;
        if (hdr_end == 0) {
            for (size_t i = 3; i < n; i++) {
                if (memcmp(buf + i - 3, "\r\n\r\n", 4) == 0) {
                    hdr_end = i + 1;
                    break;
                }
            }
            if (hdr_end != 0) {
                buf[hdr_end - 1] = '\0';   /* terminate the header block only */
                const char* cl = strstr((const char*)buf, "Content-Length:");
                if (cl != NULL)
                    want = (size_t)strtoul(cl + 15, NULL, 10);
                buf[hdr_end - 1] = '\n';   /* restore; the body starts after */
            }
        }
        if (hdr_end != 0 && n >= hdr_end + want)
            break;
    }

    /* The request line, which is all a GET operation carries. */
    for (size_t i = 0; i < n && i < sizeof(mc->reqline) - 1; i++) {
        if (buf[i] == '\r' || buf[i] == '\n')
            break;
        mc->reqline[i] = (char)buf[i];
        mc->reqline[i + 1] = '\0';
    }

    if (hdr_end != 0 && want > 0 && n >= hdr_end + want) {
        char*    mt  = NULL;
        uint8_t* tid = NULL;
        size_t   tid_len = 0;
        uint8_t* sn  = NULL;
        size_t   sn_len = 0;
        WolfCertBuffer env = { 0 };
        if (wolfcert_scep_parse_pki_message(buf + hdr_end, want, &env,
                                            &tid, &tid_len,     /* txid      */
                                            &sn, &sn_len,       /* senderNonce */
                                            NULL, NULL,         /* recipNonce  */
                                            &mt,                /* messageType */
                                            NULL,               /* pkiStatus   */
                                            NULL, NULL,         /* signer cert */
                                            NULL,               /* failInfo    */
                                            NULL) == WOLFCERT_OK) {
            if (mt != NULL)
                snprintf(mc->seen, sizeof(mc->seen), "%s", mt);
            mc->tid_len = tid_len;

            /* The content-encryption OID inside the EnvelopedData. */
            static const uint8_t OID_AES128[] =
                { 0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x01,0x02 };
            static const uint8_t OID_AES256[] =
                { 0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x01,0x2a };
            static const uint8_t OID_DES3[] =
                { 0x06,0x08,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x03,0x07 };
            if (env.data != NULL) {
                if (memmem(env.data, env.len, OID_AES256, sizeof(OID_AES256)))
                    snprintf(mc->cipher, sizeof(mc->cipher), "aes256");
                else if (memmem(env.data, env.len, OID_AES128, sizeof(OID_AES128)))
                    snprintf(mc->cipher, sizeof(mc->cipher), "aes128");
                else if (memmem(env.data, env.len, OID_DES3, sizeof(OID_DES3)))
                    snprintf(mc->cipher, sizeof(mc->cipher), "des3");
            }

            if (mc->reply)
                msgtype_send_cert_rep(mc, cs, tid, tid_len, sn, sn_len);
        }
        /* Parser output comes from the wolfCert heap, not libc. */
        WOLFCERT_XFREE(mt, NULL);
        WOLFCERT_XFREE(tid, NULL);
        WOLFCERT_XFREE(sn, NULL);
        wolfcert_buffer_free(&env);
    }

    close(cs);
    return NULL;
}

/* The content_cipher override as seen in the request's EnvelopedData. */
static int check_content_cipher_wire(const WolfCertScepCaps* caps,
                                     const WolfCertKeyCfg* kcfg,
                                     const uint8_t* ca_der_buf, size_t ca_der_len,
                                     WolfCertScepContentCipher cipher,
                                     const char* expect)
{
    struct msgtype_ctx mc = { .listen_fd = -1 };
    pthread_t tid;
    int port = 0;
    mc.listen_fd = listen_loopback(&port);
    REQUIRE(mc.listen_fd >= 0);
    REQUIRE(pthread_create(&tid, NULL, msgtype_srv_thread, &mc) == 0);

    char url[128];
    snprintf(url, sizeof(url), "http://127.0.0.1:%d/scep", port);
    WolfCertServerCfg cli = {
        .protocol   = WOLFCERT_PROTO_SCEP,
        .server_url = url,
        .proto_opts.scep = { .content_cipher = cipher },
    };

    WolfCertCertMeta meta = { .subject_dn = "CN=device-cipher-wire" };
    WolfCertKey*     key = NULL;
    WolfCertBuffer   csr = { 0 }, issued = { 0 };
    REQUIRE(wolfcert_key_generate(kcfg, &key) == WOLFCERT_OK);
    REQUIRE(wolfcert_csr_build(key, &meta, &csr) == WOLFCERT_OK);

    /* The listener never answers, so the call fails. */
    (void)wolfcert_scep_pkcs_req(&cli, caps, ca_der_buf, ca_der_len, key,
                                 csr.data, csr.len, &issued);
    wolfcert_buffer_free(&issued);
    wolfcert_buffer_free(&csr);
    wolfcert_key_free(key);
    pthread_join(tid, NULL);

    REQUIRE(strcmp(mc.cipher, expect) == 0);
    return 0;
}

/* A renewal under renewal_msg_type mode carries messageType expect. */
static int check_renewal_msg_type(const WolfCertScepCaps* caps,
                                  const uint8_t* ca_der_buf, size_t ca_der_len,
                                  const uint8_t* cur_cert, size_t cur_cert_len,
                                  const WolfCertKey* cur_key,
                                  const uint8_t* csr, size_t csr_len,
                                  WolfCertScepRenewalMsgType mode,
                                  const char* expect)
{
    struct msgtype_ctx mc = { .listen_fd = -1 };
    pthread_t tid;
    int port = 0;
    mc.listen_fd = listen_loopback(&port);
    REQUIRE(mc.listen_fd >= 0);
    REQUIRE(pthread_create(&tid, NULL, msgtype_srv_thread, &mc) == 0);

    char url[128];
    snprintf(url, sizeof(url), "http://127.0.0.1:%d/scep", port);
    WolfCertServerCfg cli = {
        .protocol   = WOLFCERT_PROTO_SCEP,
        .server_url = url,
        .proto_opts.scep = { .renewal_msg_type = mode },
    };

    WolfCertScepResult r = { 0 };
    /* The capture server never answers, so the call fails. */
    (void)wolfcert_scep_renewal_req_ex(&cli, caps, ca_der_buf, ca_der_len,
                                       ca_der_buf, ca_der_len,
                                       cur_cert, cur_cert_len, cur_key,
                                       csr, csr_len, &r);
    wolfcert_scep_result_free(&r);
    pthread_join(tid, NULL);

    REQUIRE(strcmp(mc.seen, expect) == 0);
    return 0;
}

/* Answer a PKCSReq with an otherwise valid CertRep carrying the given
 * pkiStatus and failInfo (NULL omits either). */
static int check_pki_status(const WolfCertScepCaps* caps,
                            const uint8_t* signer_cert, size_t signer_cert_len,
                            const WolfCertKey* key,
                            const uint8_t* csr, size_t csr_len,
                            const char* status, const char* fail_info,
                            int expect_rc, WolfCertScepStatus expect_status,
                            int expect_fail)
{
    uint8_t key_der[4096];
    int kl = wc_RsaKeyToDer((RsaKey*)key->impl, key_der, sizeof(key_der));
    REQUIRE(kl > 0);

    struct msgtype_ctx mc = {
        .listen_fd    = -1,
        .rep_cert     = signer_cert, .rep_cert_len = signer_cert_len,
        .rep_key      = key_der,     .rep_key_len  = (size_t)kl,
        .rep_status   = status,
        .rep_fail_info = fail_info,
        .reply        = 1,
    };
    pthread_t tid;
    int port = 0;
    mc.listen_fd = listen_loopback(&port);
    REQUIRE(mc.listen_fd >= 0);
    REQUIRE(pthread_create(&tid, NULL, msgtype_srv_thread, &mc) == 0);

    char url[128];
    snprintf(url, sizeof(url), "http://127.0.0.1:%d/scep", port);
    WolfCertServerCfg cli = { .protocol = WOLFCERT_PROTO_SCEP, .server_url = url };

    WolfCertScepResult r = { 0 };
    int rc = wolfcert_scep_pkcs_req_ex(&cli, caps, signer_cert, signer_cert_len,
                                       signer_cert, signer_cert_len, key,
                                       csr, csr_len, &r);
    WolfCertScepStatus got = r.status;
    int got_tid  = r.transaction_id != NULL || r.transaction_id_len != 0;
    int got_cert = r.cert_pem.data != NULL || r.cert_pem.len != 0;
    int got_fail = r.fail_info;
    wolfcert_scep_result_free(&r);
    pthread_join(tid, NULL);
    wc_ForceZero(key_der, sizeof(key_der));

    REQUIRE(rc == expect_rc);
    REQUIRE(got == expect_status);
    /* Only an accepted CertRep hands back its transactionID. The reply never
     * carries a certificate. */
    REQUIRE(got_tid == (expect_rc == WOLFCERT_OK));
    REQUIRE(got_cert == 0);
    REQUIRE(got_fail == expect_fail);
    return 0;
}

/* A renewal on a session opened with RENEWAL_MSG_PKCS_REQ and PUBKEY_HASH
 * sends messageType 19 and a 64-character transactionID. */
static int check_session_opts_capture(const WolfCertScepCaps* caps,
                                      const uint8_t* ca_der_buf, size_t ca_der_len,
                                      const uint8_t* cur_cert, size_t cur_cert_len,
                                      const WolfCertKey* cur_key,
                                      const uint8_t* csr, size_t csr_len)
{
    struct msgtype_ctx mc = { .listen_fd = -1 };
    pthread_t tid;
    int port = 0;
    mc.listen_fd = listen_loopback(&port);
    REQUIRE(mc.listen_fd >= 0);
    REQUIRE(pthread_create(&tid, NULL, msgtype_srv_thread, &mc) == 0);

    char url[128];
    snprintf(url, sizeof(url), "http://127.0.0.1:%d/scep", port);
    WolfCertServerCfg cli = {
        .protocol   = WOLFCERT_PROTO_SCEP,
        .server_url = url,
        .proto_opts.scep = {
            .txid_mode        = WOLFCERT_SCEP_TXID_PUBKEY_HASH,
            .renewal_msg_type = WOLFCERT_SCEP_RENEWAL_MSG_PKCS_REQ,
        },
    };

    WolfCertScepSession* sess = NULL;
    REQUIRE(wolfcert_scep_session_open(&cli, &sess) == WOLFCERT_OK);

    WolfCertScepResult r = { 0 };
    /* The listener never answers, so this fails. */
    (void)wolfcert_scep_session_renewal_req_ex(sess, caps, ca_der_buf, ca_der_len,
                                               ca_der_buf, ca_der_len,
                                               cur_cert, cur_cert_len, cur_key,
                                               csr, csr_len, &r);
    wolfcert_scep_result_free(&r);
    wolfcert_scep_session_close(sess);
    pthread_join(tid, NULL);

    REQUIRE(strcmp(mc.seen, "19") == 0);   /* renewal_msg_type captured */
    REQUIRE(mc.tid_len == 64);             /* txid_mode captured        */
    return 0;
}

/* GetNextCACert carries the CA identifier as its message (RFC 8894 4.1). */
static int check_getnextca_ca_id(const uint8_t* ca_der_buf, size_t ca_der_len)
{
    struct msgtype_ctx mc = { .listen_fd = -1 };
    pthread_t tid;
    int port = 0;
    mc.listen_fd = listen_loopback(&port);
    REQUIRE(mc.listen_fd >= 0);
    REQUIRE(pthread_create(&tid, NULL, msgtype_srv_thread, &mc) == 0);

    char url[128];
    snprintf(url, sizeof(url), "http://127.0.0.1:%d/scep", port);
    WolfCertServerCfg cli = {
        .protocol   = WOLFCERT_PROTO_SCEP,
        .server_url = url,
        .proto_opts.scep = { .ca_id = "RolloverCA" },
    };

    WolfCertBuffer next = { 0 };
    (void)wolfcert_scep_get_next_ca_cert(&cli, ca_der_buf, ca_der_len, &next);
    wolfcert_buffer_free(&next);
    pthread_join(tid, NULL);

    REQUIRE(strstr(mc.reqline, "operation=GetNextCACert") != NULL);
    REQUIRE(strstr(mc.reqline, "message=RolloverCA") != NULL);
    return 0;
}

/* RFC 8894 section 3.2.1 requires transactionID and a fresh senderNonce in every
 * pkiMessage; the client always sends both, so POST hand-built ones instead. */
static int check_required_attrs(WolfCertServer* s, const WolfCertKeyCfg* kcfg,
                                const uint8_t* ca_der_buf, size_t ca_der_len)
{
    WolfCertCertMeta meta = { .subject_dn = "CN=scep-attrs" };
    WolfCertKey*   key  = NULL;
    WolfCertBuffer csr  = { 0 };
    WolfCertBuffer kder = { 0 };
    WolfCertBuffer env  = { 0 };
    uint8_t* signer = NULL;
    size_t   signer_len = 0;
    uint8_t  tid[16], snonce[16], snonce_long[17];
    size_t   i;
    int      rc;

    rc = wolfcert_key_generate(kcfg, &key);
    if (rc == WOLFCERT_OK)
        rc = wolfcert_csr_build(key, &meta, &csr);
    if (rc == WOLFCERT_OK)
        rc = wolfcert_key_to_der(key, &kder);
    if (rc == WOLFCERT_OK)
        rc = wolfcert_scep_self_signed_rsa((RsaKey*)key->impl, csr.data,
                                           csr.len, &signer, &signer_len, NULL);
    if (rc == WOLFCERT_OK)
        rc = wolfcert_scep_envelop(ca_der_buf, ca_der_len, csr.data, csr.len,
                                   AES128CBCb, &env, NULL);

    memset(tid,    'A', sizeof(tid));
    memset(snonce, 0x22, sizeof(snonce));
    memset(snonce_long, 0x33, sizeof(snonce_long));

    /* Each round omits or mis-sizes one required attribute; the last is the
     * control that reaches issuance. */
    for (i = 0; rc == WOLFCERT_OK && i < 9; ++i) {
        WolfCertScepAttrs a = { .message_type = i == 4 ? NULL :
                                                i == 5 ? ""   : "19" };
        WolfCertBuffer msg = { 0 };
        WolfCertBuffer renv = { 0 };
        uint8_t *r_tid = NULL, *r_sn = NULL, *r_rn = NULL, *r_sc = NULL;
        size_t   r_tidl = 0,   r_snl = 0,   r_rnl = 0,   r_scl = 0;
        char    *r_mt = NULL,  *r_st = NULL, *r_fi = NULL;
        uint8_t* rsp = NULL;
        size_t   rsp_len = 0;
        int      st;
        int      ok;

        if (i == 0) {                       /* no transactionID */
            a.sender_nonce = snonce;  a.sender_nonce_len = sizeof(snonce);
        }
        else if (i == 1) {                  /* zero-length transactionID */
            a.transaction_id = tid;   a.transaction_id_len = 0;
            a.sender_nonce = snonce;  a.sender_nonce_len = sizeof(snonce);
        }
        else if (i == 2) {                  /* no senderNonce */
            a.transaction_id = tid;   a.transaction_id_len = sizeof(tid);
        }
        else if (i == 3) {                  /* zero-length senderNonce */
            a.transaction_id = tid;   a.transaction_id_len = sizeof(tid);
            a.sender_nonce = snonce;  a.sender_nonce_len = 0;
        }
        else if (i == 4 || i == 5) {        /* no / zero-length messageType */
            a.transaction_id = tid;   a.transaction_id_len = sizeof(tid);
            a.sender_nonce = snonce;  a.sender_nonce_len = sizeof(snonce);
        }
        else if (i == 6) {                  /* short senderNonce */
            a.transaction_id = tid;   a.transaction_id_len = sizeof(tid);
            a.sender_nonce = snonce;  a.sender_nonce_len = 8;
        }
        else if (i == 7) {                  /* long senderNonce */
            a.transaction_id = tid;   a.transaction_id_len = sizeof(tid);
            a.sender_nonce = snonce_long;
            a.sender_nonce_len = sizeof(snonce_long);
        }
        else {                              /* control: all three present */
            a.transaction_id = tid;   a.transaction_id_len = sizeof(tid);
            a.sender_nonce = snonce;  a.sender_nonce_len = sizeof(snonce);
        }

        rc = wolfcert_scep_build_pki_message(env.data, env.len,
                    signer, signer_len, kder.data, kder.len,
                    SHA256h, &a, &msg, NULL);
        if (rc != WOLFCERT_OK)
            break;

        st = raw_http_req(wolfcert_server_port(s), "POST",
                          "/scep?operation=PKIOperation",
                          "application/x-pki-message",
                          msg.data, msg.len, 0, &rsp, &rsp_len);
        wolfcert_buffer_free(&msg);

        if (i < 8) {
            /* An absent, empty or missized attribute is not a pkiMessage. */
            ok = (st == 400);
        }
        else {
            ok = (st == 200 && rsp != NULL &&
                  wolfcert_scep_parse_pki_message(rsp, rsp_len, &renv,
                      &r_tid, &r_tidl, &r_sn, &r_snl, &r_rn, &r_rnl,
                      &r_mt, &r_st, &r_sc, &r_scl, &r_fi, NULL) == WOLFCERT_OK);

            ok = ok && r_tid != NULL && r_tidl == sizeof(tid) &&
                 memcmp(r_tid, tid, sizeof(tid)) == 0 &&
                 r_st != NULL && strcmp(r_st, "0") == 0 && renv.len > 0 &&
                 r_sn != NULL && r_snl == sizeof(snonce) &&
                 r_rn != NULL && r_rnl == sizeof(snonce) &&
                 memcmp(r_rn, snonce, sizeof(snonce)) == 0;

            WOLFCERT_XFREE(r_tid, NULL); WOLFCERT_XFREE(r_sn, NULL);
            WOLFCERT_XFREE(r_rn,  NULL); WOLFCERT_XFREE(r_sc, NULL);
            WOLFCERT_XFREE(r_mt,  NULL); WOLFCERT_XFREE(r_st, NULL);
            WOLFCERT_XFREE(r_fi,  NULL);
            wolfcert_buffer_free(&renv);
        }

        free(rsp);
        if (!ok) {
            fprintf(stderr, "FAIL %s:%d required-attrs round %zu (status %d)\n",
                    __FILE__, __LINE__, i, st);
            rc = -1;
        }
    }

    /* No messageType and no senderNonce on a keep-alive POST gets 400 and a
     * close; a socket left open reads as -1. */
    if (rc == WOLFCERT_OK) {
        WolfCertScepAttrs a = { .transaction_id = tid,
                                .transaction_id_len = sizeof(tid) };
        WolfCertBuffer msg = { 0 };

        rc = wolfcert_scep_build_pki_message(env.data, env.len,
                    signer, signer_len, kder.data, kder.len,
                    SHA256h, &a, &msg, NULL);
        if (rc == WOLFCERT_OK) {
            if (raw_http_req(wolfcert_server_port(s), "POST",
                             "/scep?operation=PKIOperation",
                             "application/x-pki-message",
                             msg.data, msg.len, 1, NULL, NULL) != 400) {
                fprintf(stderr, "FAIL %s:%d required-attrs did not reject "
                                "and close ahead of the messageType check\n",
                        __FILE__, __LINE__);
                rc = -1;
            }
            wolfcert_buffer_free(&msg);
        }
    }

    WOLFCERT_XFREE(signer, NULL);
    wolfcert_buffer_free(&env);
    wolfcert_buffer_free(&kder);
    wolfcert_buffer_free(&csr);
    wolfcert_key_free(key);

    return rc;
}

/* POST a signed PKCSReq whose transactionID `tid` is tagged PrintableString
 * whatever its bytes, which wolfcert_scep_build_pki_message will not encode. */
static int post_raw_tid(uint16_t port, const uint8_t* signer, size_t signer_len,
                        const WolfCertBuffer* kder, const char* tid)
{
    static const byte oid_msg_type[] =
        { 0x06,0x0A,0x60,0x86,0x48,0x01,0x86,0xF8,0x45,0x01,0x09,0x02 };
    static const byte oid_snonce[] =
        { 0x06,0x0A,0x60,0x86,0x48,0x01,0x86,0xF8,0x45,0x01,0x09,0x05 };
    static const byte oid_tid[] =
        { 0x06,0x0A,0x60,0x86,0x48,0x01,0x86,0xF8,0x45,0x01,0x09,0x07 };
    static const byte msg_type[] = { 0x13, 0x02, '1', '9' };
    static const byte junk[] = { 0x04, 0x02, 0xAB, 0xCD };
    byte        tid_val[2 + 16];
    byte        snonce[2 + 16];
    PKCS7Attrib attribs[3];
    PKCS7*      p7 = NULL;
    WC_RNG      rng;
    uint8_t*    buf = NULL;
    uint8_t*    rsp = NULL;
    size_t      rsp_len = 0;
    size_t      tid_len = strlen(tid);
    int         n = 0;
    int         st = -1;

    if (tid_len > 16 || wc_InitRng(&rng) != 0)
        return -1;

    tid_val[0] = 0x13;
    tid_val[1] = (byte)tid_len;
    memcpy(tid_val + 2, tid, tid_len);
    snonce[0] = 0x04;
    snonce[1] = 16;
    memset(snonce + 2, 0x22, 16);

    attribs[0].oid     = oid_msg_type;
    attribs[0].oidSz   = sizeof(oid_msg_type);
    attribs[0].value   = msg_type;
    attribs[0].valueSz = sizeof(msg_type);
    attribs[1].oid     = oid_tid;
    attribs[1].oidSz   = sizeof(oid_tid);
    attribs[1].value   = tid_val;
    attribs[1].valueSz = (word32)(2 + tid_len);
    attribs[2].oid     = oid_snonce;
    attribs[2].oidSz   = sizeof(oid_snonce);
    attribs[2].value   = snonce;
    attribs[2].valueSz = sizeof(snonce);

    p7 = wc_PKCS7_New(NULL, INVALID_DEVID);
    buf = (uint8_t*)malloc(8192);
    if (p7 != NULL && buf != NULL &&
            wc_PKCS7_InitWithCert(p7, (byte*)signer, (word32)signer_len) == 0) {
        p7->rng             = &rng;
        p7->privateKey      = kder->data;
        p7->privateKeySz    = (word32)kder->len;
        p7->encryptOID      = RSAk;
        p7->hashOID         = SHA256h;
        p7->content         = (byte*)junk;
        p7->contentSz       = sizeof(junk);
        p7->signedAttribs   = attribs;
        p7->signedAttribsSz = 3;
        n = wc_PKCS7_EncodeSignedData(p7, buf, 8192);
    }

    if (n > 0)
        st = raw_http_req(port, "POST", "/scep?operation=PKIOperation",
                          "application/x-pki-message", buf, (size_t)n, 0,
                          &rsp, &rsp_len);

    free(rsp);
    free(buf);
    if (p7 != NULL)
        wc_PKCS7_Free(p7);
    wc_FreeRng(&rng);
    return st;
}

/* A transactionID that is not a PrintableString gets 400. */
static int check_unprintable_tid(uint16_t port, const WolfCertKeyCfg* kcfg)
{
    WolfCertCertMeta meta = { .subject_dn = "CN=scep-tid" };
    WolfCertKey*   key  = NULL;
    WolfCertBuffer csr  = { 0 };
    WolfCertBuffer kder = { 0 };
    uint8_t* signer = NULL;
    size_t   signer_len = 0;
    int      st;
    int      rc;

    rc = wolfcert_key_generate(kcfg, &key);
    if (rc == WOLFCERT_OK)
        rc = wolfcert_csr_build(key, &meta, &csr);
    if (rc == WOLFCERT_OK)
        rc = wolfcert_key_to_der(key, &kder);
    if (rc == WOLFCERT_OK)
        rc = wolfcert_scep_self_signed_rsa((RsaKey*)key->impl, csr.data,
                                           csr.len, &signer, &signer_len, NULL);

    if (rc == WOLFCERT_OK) {
        st = post_raw_tid(port, signer, signer_len, &kder, "tid@1");
        if (st != 400) {
            fprintf(stderr, "FAIL %s:%d '@' transactionID got status %d\n",
                    __FILE__, __LINE__, st);
            rc = -1;
        }
    }

    /* The control reaches de-enveloping, which answers the junk content with
     * a signed FAILURE. */
    if (rc == WOLFCERT_OK) {
        st = post_raw_tid(port, signer, signer_len, &kder, "tid-1");
        if (st != 200) {
            fprintf(stderr, "FAIL %s:%d control transactionID got status %d\n",
                    __FILE__, __LINE__, st);
            rc = -1;
        }
    }

    WOLFCERT_XFREE(signer, NULL);
    wolfcert_buffer_free(&kder);
    wolfcert_buffer_free(&csr);
    wolfcert_key_free(key);

    return rc;
}

/* Junk content, messageType 99 and an unknown content cipher each get a
 * signed CertRep FAILURE (badRequest, badRequest, badAlg). */
static int check_malformed_dispatch(uint16_t port, const WolfCertKeyCfg* kcfg,
                                    const uint8_t* ca_der_buf, size_t ca_der_len)
{
    static const uint8_t junk[4] = { 0x04, 0x02, 0xAB, 0xCD };
    static const char* const msg_type[3] = { "19", "99", "19" };
    static const char* const want_fi[3]  = { "2",  "2",  "0"  };

    WolfCertCertMeta meta = { .subject_dn = "CN=scep-dispatch" };
    WolfCertKey*   key  = NULL;
    WolfCertBuffer csr  = { 0 };
    WolfCertBuffer kder = { 0 };
    WolfCertBuffer env  = { 0 };
    uint8_t* signer = NULL;
    size_t   signer_len = 0;
    uint8_t  tid[16], snonce[16];
    uint8_t  prev_sn[16];
    uint8_t* bad_env = NULL;
    int      have_prev = 0;
    char url[160];
    size_t i;
    int rc;

    memset(tid,    0x33, sizeof(tid));
    memset(snonce, 0x44, sizeof(snonce));
    snprintf(url, sizeof(url),
             "http://127.0.0.1:%u/scep?operation=PKIOperation", port);

    rc = wolfcert_key_generate(kcfg, &key);
    if (rc == WOLFCERT_OK)
        rc = wolfcert_csr_build(key, &meta, &csr);
    if (rc == WOLFCERT_OK)
        rc = wolfcert_key_to_der(key, &kder);
    if (rc == WOLFCERT_OK)
        rc = wolfcert_scep_self_signed_rsa((RsaKey*)key->impl, csr.data,
                                           csr.len, &signer, &signer_len, NULL);
    if (rc == WOLFCERT_OK)
        rc = wolfcert_scep_envelop(ca_der_buf, ca_der_len, csr.data, csr.len,
                                   AES128CBCb, &env, NULL);

    /* The last round needs a cipher the CA cannot run: copy the envelope and
     * point its algorithm at an unassigned OID under the same arc. */
    if (rc == WOLFCERT_OK) {
        static const uint8_t aes128_cbc[] =
            { 0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x01,0x02 };
        uint8_t* at = NULL;

        bad_env = (uint8_t*)WOLFCERT_XMALLOC(env.len, NULL);
        if (bad_env == NULL)
            rc = WOLFCERT_ERR_MEMORY;
        if (rc == WOLFCERT_OK) {
            memcpy(bad_env, env.data, env.len);
            at = (uint8_t*)memmem(bad_env, env.len, aes128_cbc,
                                  sizeof(aes128_cbc));
            if (at == NULL)
                rc = -1;
            else
                at[sizeof(aes128_cbc) - 1] = 0x63;
        }
    }

    for (i = 0; rc == WOLFCERT_OK && i < 3; ++i) {
        WolfCertScepAttrs a = {
            .transaction_id = tid,    .transaction_id_len = sizeof(tid),
            .sender_nonce   = snonce, .sender_nonce_len   = sizeof(snonce),
            .message_type   = msg_type[i],
        };
        /* Round 1 needs an envelope the CA can open, or it trips the
         * decrypt branch first; round 2 needs the unrunnable one. */
        const uint8_t* content     = i == 1 ? env.data :
                                     i == 2 ? bad_env  : junk;
        size_t         content_len = i >= 1 ? env.len  : sizeof(junk);
        WolfCertBuffer msg  = { 0 };
        WolfCertBuffer renv = { 0 };
        uint8_t *r_tid = NULL, *r_sn = NULL, *r_rn = NULL, *r_sc = NULL;
        size_t   r_tidl = 0,   r_snl = 0,   r_rnl = 0,   r_scl = 0;
        char    *r_mt = NULL,  *r_st = NULL, *r_fi = NULL;
        WolfCertHttpResponse resp = { 0 };

        rc = wolfcert_scep_build_pki_message(content, content_len,
                 signer, signer_len, kder.data, kder.len,
                 SHA256h, &a, &msg, NULL);
        if (rc == WOLFCERT_OK) {
            WolfCertHttpRequest req = {
                .method       = "POST",
                .url          = url,
                .content_type = "application/x-pki-message",
                .body         = msg.data,
                .body_len     = msg.len,
            };
            int ok = wolfcert_http_request(&req, &resp) == WOLFCERT_OK &&
                     resp.status_code == 200 && resp.body != NULL;

            ok = ok && wolfcert_scep_parse_pki_message(resp.body,
                           resp.body_len, &renv, &r_tid, &r_tidl, &r_sn,
                           &r_snl, &r_rn, &r_rnl, &r_mt, &r_st, &r_sc,
                           &r_scl, &r_fi, NULL) == WOLFCERT_OK;

            ok = ok && r_mt != NULL && strcmp(r_mt, "3") == 0 &&
                 r_st != NULL && strcmp(r_st, "2") == 0 &&
                 r_fi != NULL && strcmp(r_fi, want_fi[i]) == 0 &&
                 r_tid != NULL && r_tidl == sizeof(tid) &&
                 memcmp(r_tid, tid, sizeof(tid)) == 0 &&
                 r_rn != NULL && r_rnl == sizeof(snonce) &&
                 memcmp(r_rn, snonce, sizeof(snonce)) == 0 &&
                 renv.len == 0;

            /* Each reply carries a fresh senderNonce of its own. */
            ok = ok && r_sn != NULL && r_snl == sizeof(prev_sn) &&
                 (!have_prev ||
                  memcmp(r_sn, prev_sn, sizeof(prev_sn)) != 0);
            if (ok) {
                memcpy(prev_sn, r_sn, sizeof(prev_sn));
                have_prev = 1;
            }

            WOLFCERT_XFREE(r_tid, NULL); WOLFCERT_XFREE(r_sn, NULL);
            WOLFCERT_XFREE(r_rn,  NULL); WOLFCERT_XFREE(r_sc, NULL);
            WOLFCERT_XFREE(r_mt,  NULL); WOLFCERT_XFREE(r_st, NULL);
            WOLFCERT_XFREE(r_fi,  NULL);
            wolfcert_buffer_free(&renv);
            wolfcert_http_response_free(&resp);
            if (!ok)
                rc = -1;
        }

        wolfcert_buffer_free(&msg);
    }

    /* With keep-alive requested the CertRep comes back and the server hangs
     * up; a held-open socket would read as -1. */
    if (rc == WOLFCERT_OK) {
        WolfCertScepAttrs a = {
            .transaction_id = tid,    .transaction_id_len = sizeof(tid),
            .sender_nonce   = snonce, .sender_nonce_len   = sizeof(snonce),
            .message_type   = "99",
        };
        WolfCertBuffer msg = { 0 };

        rc = wolfcert_scep_build_pki_message(env.data, env.len, signer,
                 signer_len, kder.data, kder.len, SHA256h, &a, &msg, NULL);
        if (rc == WOLFCERT_OK) {
            if (raw_http_req(port, "POST", "/scep?operation=PKIOperation",
                             "application/x-pki-message",
                             msg.data, msg.len, 1, NULL, NULL) != 200) {
                fprintf(stderr, "FAIL %s:%d dispatch failure did not answer "
                                "and close\n", __FILE__, __LINE__);
                rc = -1;
            }
            wolfcert_buffer_free(&msg);
        }
    }

    WOLFCERT_XFREE(bad_env, NULL);
    WOLFCERT_XFREE(signer, NULL);
    wolfcert_buffer_free(&env);
    wolfcert_buffer_free(&kder);
    wolfcert_buffer_free(&csr);
    wolfcert_key_free(key);

    return rc;
}

int main(void)
{
    REQUIRE(wolfcert_init(NULL) == WOLFCERT_OK);

    if (test_caps_token_matching())
        return 1;
    if (test_caps_scep_standard())
        return 1;
    if (test_get_ca_cert_empty_body())
        return 1;

    WolfCertServerCfgSrv cfg = { .protocol = WOLFCERT_PROTO_SCEP,
                                 .bind_host = "127.0.0.1", .bind_port = 0 };
    WolfCertServer* s = NULL;
    REQUIRE(wolfcert_server_start(&cfg, &s) == WOLFCERT_OK);
    pthread_t tid;
    REQUIRE(pthread_create(&tid, NULL, server_thread, s) == 0);

    char url[128];
    snprintf(url, sizeof(url), "http://127.0.0.1:%u/scep", wolfcert_server_port(s));
    WolfCertServerCfg cli = { .protocol = WOLFCERT_PROTO_SCEP, .server_url = url };

    WolfCertScepCaps caps = { 0 };
    REQUIRE(wolfcert_scep_get_ca_caps(&cli, &caps) == WOLFCERT_OK);
    REQUIRE(caps.post_pki_operation);
    REQUIRE(caps.sha256);

    REQUIRE(caps.aes == 1);
    REQUIRE(caps.scep_standard == 1);
    REQUIRE(caps.renewal);

    WolfCertBuffer ca_pem = { 0 };
    REQUIRE(wolfcert_scep_get_ca_cert(&cli, &ca_pem) == WOLFCERT_OK);
    DerBuffer* ca_der = NULL;
    REQUIRE(wc_PemToDer(ca_pem.data, (long)ca_pem.len, CERT_TYPE,
                        &ca_der, NULL, NULL, NULL) == 0);

    /* A CA/RA bundle is recognised whatever the media type's case. */
    REQUIRE(check_getca_media_type(ca_der->buffer, ca_der->length) == 0);

    WolfCertKeyCfg kcfg = { .type = WOLFCERT_KEY_RSA, .param = 2048,
                            .dev_id = WOLFCERT_DEVID_SOFTWARE };
    WolfCertKey* dk = NULL;
    REQUIRE(wolfcert_key_generate(&kcfg, &dk) == WOLFCERT_OK);
    WolfCertCertMeta meta = { .subject_dn = "CN=device-scep-1" };
    WolfCertBuffer csr = { 0 };
    REQUIRE(wolfcert_csr_build(dk, &meta, &csr) == WOLFCERT_OK);

    WolfCertBuffer issued = { 0 };
    int rc = wolfcert_scep_pkcs_req(&cli, &caps, ca_der->buffer, ca_der->length,
                                    dk, csr.data, csr.len, &issued);
    if (rc != WOLFCERT_OK)
        fprintf(stderr, "SCEP rc=%d (%s)\n", rc, wolfcert_strerror(rc));
    REQUIRE(rc == WOLFCERT_OK);
    REQUIRE(memmem(issued.data, issued.len, "BEGIN CERTIFICATE", 17) != NULL);

    WOLFSSL_CERT_MANAGER* cm = wolfSSL_CertManagerNew();
    REQUIRE(cm != NULL);
    REQUIRE(wolfSSL_CertManagerLoadCABuffer(cm, ca_pem.data, (long)ca_pem.len,
                                            WOLFSSL_FILETYPE_PEM) == WOLFSSL_SUCCESS);
    DerBuffer* issued_der = NULL;
    REQUIRE(wc_PemToDer(issued.data, (long)issued.len, CERT_TYPE,
                        &issued_der, NULL, NULL, NULL) == 0);
    REQUIRE(wolfSSL_CertManagerVerifyBuffer(cm, issued_der->buffer,
                                            (long)issued_der->length,
                                            WOLFSSL_FILETYPE_ASN1) == WOLFSSL_SUCCESS);
    wolfSSL_CertManagerFree(cm);

    REQUIRE(check_get_fallback(&cli, &caps, &kcfg,
                               ca_der->buffer, ca_der->length) == WOLFCERT_OK);

    REQUIRE(check_pubkey_txid(&cli, &caps, &kcfg,
                              ca_der->buffer, ca_der->length) == WOLFCERT_OK);

    REQUIRE(check_bad_csr_sig(&cli, &caps, dk, csr.data, csr.len,
                              ca_der->buffer, ca_der->length) == WOLFCERT_OK);

    rc = check_rsa4096(&cli, &caps, ca_der->buffer, ca_der->length);
    if (rc != WOLFCERT_OK)
        fprintf(stderr, "SCEP rsa:4096 rc=%d (%s)\n", rc, wolfcert_strerror(rc));
    REQUIRE(rc == WOLFCERT_OK);

    /* A CA advertising SHA-512 or SHA-384 still enrolls within the digests
     * wolfSSL was built with. */
    WolfCertScepCaps caps_hash = caps;
    WolfCertBuffer   issued_hash = { 0 };

    caps_hash.sha512 = 1;
    REQUIRE(wolfcert_scep_pkcs_req(&cli, &caps_hash, ca_der->buffer,
                                   ca_der->length, dk, csr.data, csr.len,
                                   &issued_hash) == WOLFCERT_OK);
    wolfcert_buffer_free(&issued_hash);

    caps_hash.sha512 = 0;
    caps_hash.sha384 = 1;
    REQUIRE(wolfcert_scep_pkcs_req(&cli, &caps_hash, ca_der->buffer,
                                   ca_der->length, dk, csr.data, csr.len,
                                   &issued_hash) == WOLFCERT_OK);
    wolfcert_buffer_free(&issued_hash);

    /* Explicit AES-256 and AES-128 content ciphers both enroll. */
#if defined(WOLFSSL_AES_256)
    REQUIRE(check_content_cipher(&cli, &caps, &kcfg, ca_der->buffer,
                                 ca_der->length, WOLFCERT_SCEP_CIPHER_AES256)
            == WOLFCERT_OK);
#endif
    REQUIRE(check_content_cipher(&cli, &caps, &kcfg, ca_der->buffer,
                                 ca_der->length, WOLFCERT_SCEP_CIPHER_AES128)
            == WOLFCERT_OK);

    REQUIRE(check_renewal_msg_type(&caps, ca_der->buffer, ca_der->length,
                                   issued_der->buffer, issued_der->length, dk,
                                   csr.data, csr.len,
                                   WOLFCERT_SCEP_RENEWAL_MSG_RENEWAL_REQ,
                                   "17") == 0);
    REQUIRE(check_renewal_msg_type(&caps, ca_der->buffer, ca_der->length,
                                   issued_der->buffer, issued_der->length, dk,
                                   csr.data, csr.len,
                                   WOLFCERT_SCEP_RENEWAL_MSG_PKCS_REQ,
                                   "19") == 0);

    /* A pkiStatus outside RFC 8894's 0/2/3, or absent, is a protocol error;
     * the two "2" replies are the controls. */
    REQUIRE(check_pki_status(&caps, issued_der->buffer, issued_der->length,
                             dk, csr.data, csr.len, "2", "0", WOLFCERT_OK,
                             WOLFCERT_SCEP_STATUS_FAILURE, 0) == 0);
    REQUIRE(check_pki_status(&caps, issued_der->buffer, issued_der->length,
                             dk, csr.data, csr.len, "2", "4", WOLFCERT_OK,
                             WOLFCERT_SCEP_STATUS_FAILURE, 4) == 0);
    REQUIRE(check_pki_status(&caps, issued_der->buffer, issued_der->length,
                             dk, csr.data, csr.len, "1", NULL,
                             WOLFCERT_ERR_PROTOCOL,
                             WOLFCERT_SCEP_STATUS_UNSET, -1) == 0);
    REQUIRE(check_pki_status(&caps, issued_der->buffer, issued_der->length,
                             dk, csr.data, csr.len, NULL, NULL,
                             WOLFCERT_ERR_PROTOCOL,
                             WOLFCERT_SCEP_STATUS_UNSET, -1) == 0);
    /* A valid code as a prefix is not a match. */
    REQUIRE(check_pki_status(&caps, issued_der->buffer, issued_der->length,
                             dk, csr.data, csr.len, "30", NULL,
                             WOLFCERT_ERR_PROTOCOL,
                             WOLFCERT_SCEP_STATUS_UNSET, -1) == 0);
    REQUIRE(check_pki_status(&caps, issued_der->buffer, issued_der->length,
                             dk, csr.data, csr.len, "00", NULL,
                             WOLFCERT_ERR_PROTOCOL,
                             WOLFCERT_SCEP_STATUS_UNSET, -1) == 0);

    /* A FAILURE whose failInfo is outside 0..4, or absent, is also an error. */
    REQUIRE(check_pki_status(&caps, issued_der->buffer, issued_der->length,
                             dk, csr.data, csr.len, "2", "5",
                             WOLFCERT_ERR_PROTOCOL,
                             WOLFCERT_SCEP_STATUS_UNSET, -1) == 0);
    REQUIRE(check_pki_status(&caps, issued_der->buffer, issued_der->length,
                             dk, csr.data, csr.len, "2", "12",
                             WOLFCERT_ERR_PROTOCOL,
                             WOLFCERT_SCEP_STATUS_UNSET, -1) == 0);
    REQUIRE(check_pki_status(&caps, issued_der->buffer, issued_der->length,
                             dk, csr.data, csr.len, "2", NULL,
                             WOLFCERT_ERR_PROTOCOL,
                             WOLFCERT_SCEP_STATUS_UNSET, -1) == 0);
    REQUIRE(check_pki_status(&caps, issued_der->buffer, issued_der->length,
                             dk, csr.data, csr.len, "2", "",
                             WOLFCERT_ERR_PROTOCOL,
                             WOLFCERT_SCEP_STATUS_UNSET, -1) == 0);
    /* A failInfo on a non-FAILURE CertRep is ignored. */
    REQUIRE(check_pki_status(&caps, issued_der->buffer, issued_der->length,
                             dk, csr.data, csr.len, "3", "2", WOLFCERT_OK,
                             WOLFCERT_SCEP_STATUS_PENDING, -1) == 0);

    /* An explicit content_cipher shows up as that OID in the request. */
#if defined(WOLFSSL_AES_256)
    REQUIRE(check_content_cipher_wire(&caps, &kcfg, ca_der->buffer,
                                      ca_der->length,
                                      WOLFCERT_SCEP_CIPHER_AES256,
                                      "aes256") == 0);
#endif
    REQUIRE(check_content_cipher_wire(&caps, &kcfg, ca_der->buffer,
                                      ca_der->length,
                                      WOLFCERT_SCEP_CIPHER_AES128,
                                      "aes128") == 0);

    REQUIRE(check_session_opts_capture(&caps, ca_der->buffer, ca_der->length,
                                       issued_der->buffer, issued_der->length,
                                       dk, csr.data, csr.len) == 0);

    /* The CA identifier belongs on GetNextCACert as well (RFC 8894 4.1). */
    REQUIRE(check_getnextca_ca_id(ca_der->buffer, ca_der->length) == 0);

    /* GetCACaps and GetCACert to https:// with verify_server 0 get ERR_TLS. */
    {
        WolfCertServerCfg tls_cli = { .protocol = WOLFCERT_PROTO_SCEP,
                                      .server_url = "https://127.0.0.1:1/scep" };
        WolfCertScepCaps tls_caps = { 0 };
        WolfCertBuffer   tls_ca = { 0 };
        REQUIRE(wolfcert_scep_get_ca_caps(&tls_cli, &tls_caps) == WOLFCERT_ERR_TLS);
        REQUIRE(wolfcert_scep_get_ca_cert(&tls_cli, &tls_ca) == WOLFCERT_ERR_TLS);
        wolfcert_buffer_free(&tls_ca);

        /* With verify_server 1, GetCACaps to the closed port 1 fails with an
         * error other than ERR_TLS. */
        tls_cli.verify_server = 1;
        REQUIRE(wolfcert_scep_get_ca_caps(&tls_cli, &tls_caps) != WOLFCERT_ERR_TLS);
    }

    /* A longer field name that starts with Content-Length is not one. */
    REQUIRE(raw_request_status(wolfcert_server_port(s),
                "GET /scep?operation=GetCACaps HTTP/1.1\r\n"
                "Host: 127.0.0.1\r\nContent-Length-Foo: 4\r\n"
                "Connection: close\r\n\r\n") == 200);
    REQUIRE(raw_request_status(wolfcert_server_port(s),
                "GET /scep?operation=GetCACaps HTTP/1.1\r\n"
                "Host : 127.0.0.1\r\nConnection: close\r\n\r\n") == 400);

    /* Malformed GET PKIOperation requests get 400 (RFC 8894 section 4.1). */
    REQUIRE(raw_http_status(wolfcert_server_port(s),
                "/scep?operation=PKIOperation", NULL) == 400);              /* no message= */
    REQUIRE(raw_http_status(wolfcert_server_port(s),
                "/scep?operation=PKIOperation&message=%ZZ", NULL) == 400);  /* bad %-escape */
    REQUIRE(raw_http_status(wolfcert_server_port(s),
                "/scep?operation=PKIOperation&message=@@@@", NULL) == 400); /* bad base64  */

    /* A GET with valid base64 message=QUJD and a body "XYZ" gets 400; ASan
     * reports the body if the server leaks it. */
    REQUIRE(raw_http_status(wolfcert_server_port(s),
                "/scep?operation=PKIOperation&message=QUJD", "XYZ") == 400);

    REQUIRE(check_required_attrs(s, &kcfg, ca_der->buffer,
                                 ca_der->length) == WOLFCERT_OK);

    REQUIRE(check_unprintable_tid(wolfcert_server_port(s), &kcfg)
            == WOLFCERT_OK);

    REQUIRE(check_malformed_dispatch(wolfcert_server_port(s), &kcfg,
                                     ca_der->buffer, ca_der->length)
            == WOLFCERT_OK);

#ifdef WOLFCERT_HAVE_ED25519
    /* Ed25519 signer must be rejected cleanly (RFC 8894 requires RSA). */
    WolfCertKeyCfg edcfg = { .type = WOLFCERT_KEY_ED25519, .param = 0,
                             .dev_id = WOLFCERT_DEVID_SOFTWARE };
    WolfCertKey* edk = NULL;
    REQUIRE(wolfcert_key_generate(&edcfg, &edk) == WOLFCERT_OK);
    WolfCertCertMeta edmeta = { .subject_dn = "CN=ed-scep" };
    WolfCertBuffer edcsr = { 0 };
    REQUIRE(wolfcert_csr_build(edk, &edmeta, &edcsr) == WOLFCERT_OK);
    WolfCertBuffer edout = { 0 };
    REQUIRE(wolfcert_scep_pkcs_req(&cli, &caps, ca_der->buffer, ca_der->length,
                                   edk, edcsr.data, edcsr.len, &edout)
            == WOLFCERT_ERR_UNSUPPORTED);
    wolfcert_buffer_free(&edcsr);
    wolfcert_key_free(edk);
#endif

    wolfcert_server_stop(s);
    pthread_join(tid, NULL);
    wolfcert_server_free(s);

    /* Challenge password (RFC 8894 section 2.9). */
    WolfCertServerCfgSrv cfg2 = { .protocol = WOLFCERT_PROTO_SCEP,
                                  .bind_host = "127.0.0.1", .bind_port = 0,
                                  .challenge_password = "correct-horse" };
    WolfCertServer* s2 = NULL;
    REQUIRE(wolfcert_server_start(&cfg2, &s2) == WOLFCERT_OK);
    pthread_t tid2;
    REQUIRE(pthread_create(&tid2, NULL, server_thread, s2) == 0);

    char url2[128];
    snprintf(url2, sizeof(url2), "http://127.0.0.1:%u/scep", wolfcert_server_port(s2));
    WolfCertServerCfg cli2 = { .protocol = WOLFCERT_PROTO_SCEP, .server_url = url2 };

    WolfCertScepCaps caps2 = { 0 };
    REQUIRE(wolfcert_scep_get_ca_caps(&cli2, &caps2) == WOLFCERT_OK);
    WolfCertBuffer ca2_pem = { 0 };
    REQUIRE(wolfcert_scep_get_ca_cert(&cli2, &ca2_pem) == WOLFCERT_OK);
    DerBuffer* ca2_der = NULL;
    REQUIRE(wc_PemToDer(ca2_pem.data, (long)ca2_pem.len, CERT_TYPE,
                        &ca2_der, NULL, NULL, NULL) == 0);

    WolfCertKey* dk2 = NULL;
    REQUIRE(wolfcert_key_generate(&kcfg, &dk2) == WOLFCERT_OK);

    /* 1) no challenge -> signed CertRep FAILURE, surfaced as ERR_PROTOCOL;
     * a bare HTTP 4xx would read back as ERR_HTTP. */
    WolfCertCertMeta meta_none = { .subject_dn = "CN=chal-none" };
    WolfCertBuffer csr_none = { 0 };
    REQUIRE(wolfcert_csr_build(dk2, &meta_none, &csr_none) == WOLFCERT_OK);
    WolfCertBuffer out_none = { 0 };
    REQUIRE(wolfcert_scep_pkcs_req(&cli2, &caps2, ca2_der->buffer, ca2_der->length,
                                    dk2, csr_none.data, csr_none.len, &out_none)
            == WOLFCERT_ERR_PROTOCOL);
    wolfcert_buffer_free(&csr_none);

    /* 2) wrong challenge -> same CertRep FAILURE path */
    WolfCertCertMeta meta_bad = { .subject_dn = "CN=chal-bad",
                                  .challenge_password = "battery-staple" };
    WolfCertBuffer csr_bad = { 0 };
    REQUIRE(wolfcert_csr_build(dk2, &meta_bad, &csr_bad) == WOLFCERT_OK);
    WolfCertBuffer out_bad = { 0 };
    REQUIRE(wolfcert_scep_pkcs_req(&cli2, &caps2, ca2_der->buffer, ca2_der->length,
                                    dk2, csr_bad.data, csr_bad.len, &out_bad)
            == WOLFCERT_ERR_PROTOCOL);
    wolfcert_buffer_free(&csr_bad);

    /* 3) correct challenge -> issuance succeeds */
    WolfCertCertMeta meta_ok = { .subject_dn = "CN=chal-ok",
                                 .challenge_password = "correct-horse" };
    WolfCertBuffer csr_ok = { 0 };
    REQUIRE(wolfcert_csr_build(dk2, &meta_ok, &csr_ok) == WOLFCERT_OK);
    WolfCertBuffer out_ok = { 0 };
    REQUIRE(wolfcert_scep_pkcs_req(&cli2, &caps2, ca2_der->buffer, ca2_der->length,
                                    dk2, csr_ok.data, csr_ok.len, &out_ok)
            == WOLFCERT_OK);
    REQUIRE(memmem(out_ok.data, out_ok.len, "BEGIN CERTIFICATE", 17) != NULL);
    wolfcert_buffer_free(&csr_ok);
    wolfcert_buffer_free(&out_ok);

    wolfcert_server_stop(s2);
    pthread_join(tid2, NULL);
    wolfcert_server_free(s2);
    wc_FreeDer(&ca2_der);
    wolfcert_buffer_free(&ca2_pem);
    wolfcert_key_free(dk2);

    /* recipientNonce survives the encoder and parser (RFC 8894 3.2.1.2). */
    {
        WC_RNG rng;
        REQUIRE(wc_InitRng(&rng) == 0);
        RsaKey rsa;
        REQUIRE(wc_InitRsaKey(&rsa, NULL) == 0);
        REQUIRE(wc_MakeRsaKey(&rsa, 2048, 65537, &rng) == 0);

        Cert sc;
        REQUIRE(wc_InitCert(&sc) == 0);
        strncpy(sc.subject.commonName, "scep-nonce", CTC_NAME_SIZE - 1);
        sc.sigType = CTC_SHA256wRSA;
        uint8_t signer_cert[2048];
        int cl = wc_MakeSelfCert(&sc, signer_cert, sizeof(signer_cert), &rsa, &rng);
        REQUIRE(cl > 0);

        uint8_t signer_key[2048];
        int kl = wc_RsaKeyToDer(&rsa, signer_key, sizeof(signer_key));
        REQUIRE(kl > 0);

        const uint8_t content[] = { 0x04, 0x02, 0xAB, 0xCD }; /* arbitrary signed content */
        uint8_t snonce[16], rnonce[16];
        memset(snonce, 0x5A, sizeof(snonce));
        memset(rnonce, 0xA5, sizeof(rnonce));
        const uint8_t wtid[16] =
            { '0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F' };
        WolfCertScepAttrs wattrs = {
            .transaction_id  = wtid,   .transaction_id_len  = sizeof(wtid),
            .sender_nonce    = snonce, .sender_nonce_len    = sizeof(snonce),
            .message_type    = "3",    .pki_status          = "0",
            .recipient_nonce = rnonce, .recipient_nonce_len = sizeof(rnonce),
        };
        WolfCertBuffer wmsg = { 0 };
        REQUIRE(wolfcert_scep_build_pki_message(content, sizeof(content),
                    signer_cert, (size_t)cl, signer_key, (size_t)kl,
                    SHA256h, &wattrs, &wmsg, NULL) == WOLFCERT_OK);

        WolfCertBuffer wenv = { 0 };
        uint8_t *w_tid = NULL, *w_sn = NULL, *w_rn = NULL, *w_sc = NULL;
        size_t   w_tidl = 0,   w_snl = 0,   w_rnl = 0,   w_scl = 0;
        char    *w_mt = NULL,  *w_st = NULL;
        REQUIRE(wolfcert_scep_parse_pki_message(wmsg.data, wmsg.len, &wenv,
                    &w_tid, &w_tidl, &w_sn, &w_snl, &w_rn, &w_rnl,
                    &w_mt, &w_st, &w_sc, &w_scl, NULL, NULL) == WOLFCERT_OK);
        REQUIRE(w_rn != NULL);                              /* present */
        REQUIRE(w_rnl == sizeof(rnonce));
        REQUIRE(memcmp(w_rn, rnonce, sizeof(rnonce)) == 0); /* unchanged */

        WOLFCERT_XFREE(w_tid, NULL); WOLFCERT_XFREE(w_sn, NULL);
        WOLFCERT_XFREE(w_rn,  NULL); WOLFCERT_XFREE(w_sc, NULL);
        WOLFCERT_XFREE(w_mt,  NULL); WOLFCERT_XFREE(w_st, NULL);
        wolfcert_buffer_free(&wenv);
        wolfcert_buffer_free(&wmsg);
        wc_FreeRsaKey(&rsa);
        wc_FreeRng(&rng);
    }

    /* A CertRep with no recipientNonce is rejected (RFC 8894 3.2.1.2). */
    WolfCertServerCfgSrv cfg3 = { .protocol = WOLFCERT_PROTO_SCEP,
                                  .bind_host = "127.0.0.1", .bind_port = 0 };
    WolfCertServer* s3 = NULL;
    REQUIRE(wolfcert_server_start(&cfg3, &s3) == WOLFCERT_OK);
    wolfcert_scep_server_set_faults(s3, 1 /* omit recipientNonce */, 0, 0);
    pthread_t tid3;
    REQUIRE(pthread_create(&tid3, NULL, server_thread, s3) == 0);

    char url3[128];
    snprintf(url3, sizeof(url3), "http://127.0.0.1:%u/scep", wolfcert_server_port(s3));
    WolfCertServerCfg cli3 = { .protocol = WOLFCERT_PROTO_SCEP, .server_url = url3 };

    WolfCertScepCaps caps3 = { 0 };
    REQUIRE(wolfcert_scep_get_ca_caps(&cli3, &caps3) == WOLFCERT_OK);
    WolfCertBuffer ca3_pem = { 0 };
    REQUIRE(wolfcert_scep_get_ca_cert(&cli3, &ca3_pem) == WOLFCERT_OK);
    DerBuffer* ca3_der = NULL;
    REQUIRE(wc_PemToDer(ca3_pem.data, (long)ca3_pem.len, CERT_TYPE,
                        &ca3_der, NULL, NULL, NULL) == 0);

    WolfCertKey* dk3 = NULL;
    REQUIRE(wolfcert_key_generate(&kcfg, &dk3) == WOLFCERT_OK);
    WolfCertCertMeta meta3 = { .subject_dn = "CN=scep-no-rnonce" };
    WolfCertBuffer csr3 = { 0 };
    REQUIRE(wolfcert_csr_build(dk3, &meta3, &csr3) == WOLFCERT_OK);
    WolfCertBuffer out3 = { 0 };
    REQUIRE(wolfcert_scep_pkcs_req(&cli3, &caps3, ca3_der->buffer, ca3_der->length,
                                   dk3, csr3.data, csr3.len, &out3)
            == WOLFCERT_ERR_PROTOCOL);

    wolfcert_server_stop(s3);
    pthread_join(tid3, NULL);
    wolfcert_server_free(s3);
    wc_FreeDer(&ca3_der);
    wolfcert_buffer_free(&ca3_pem);
    wolfcert_buffer_free(&csr3);
    wolfcert_buffer_free(&out3);
    wolfcert_key_free(dk3);

    /* A CertRep signed by a key other than the CA's is rejected. */
    WolfCertServerCfgSrv cfg4 = { .protocol = WOLFCERT_PROTO_SCEP,
                                  .bind_host = "127.0.0.1", .bind_port = 0 };
    WolfCertServer* s4 = NULL;
    REQUIRE(wolfcert_server_start(&cfg4, &s4) == WOLFCERT_OK);
    wolfcert_scep_server_set_faults(s4, 0, 1 /* sign with wrong key */, 0);
    pthread_t tid4;
    REQUIRE(pthread_create(&tid4, NULL, server_thread, s4) == 0);

    char url4[128];
    snprintf(url4, sizeof(url4), "http://127.0.0.1:%u/scep", wolfcert_server_port(s4));
    WolfCertServerCfg cli4 = { .protocol = WOLFCERT_PROTO_SCEP, .server_url = url4 };

    WolfCertScepCaps caps4 = { 0 };
    REQUIRE(wolfcert_scep_get_ca_caps(&cli4, &caps4) == WOLFCERT_OK);
    WolfCertBuffer ca4_pem = { 0 };
    REQUIRE(wolfcert_scep_get_ca_cert(&cli4, &ca4_pem) == WOLFCERT_OK);
    DerBuffer* ca4_der = NULL;
    REQUIRE(wc_PemToDer(ca4_pem.data, (long)ca4_pem.len, CERT_TYPE,
                        &ca4_der, NULL, NULL, NULL) == 0);

    WolfCertKey* dk4 = NULL;
    REQUIRE(wolfcert_key_generate(&kcfg, &dk4) == WOLFCERT_OK);
    WolfCertCertMeta meta4 = { .subject_dn = "CN=scep-wrong-signer" };
    WolfCertBuffer csr4 = { 0 };
    REQUIRE(wolfcert_csr_build(dk4, &meta4, &csr4) == WOLFCERT_OK);
    WolfCertBuffer out4 = { 0 };
    REQUIRE(wolfcert_scep_pkcs_req(&cli4, &caps4, ca4_der->buffer, ca4_der->length,
                                   dk4, csr4.data, csr4.len, &out4)
            == WOLFCERT_ERR_AUTH);

    wolfcert_server_stop(s4);
    pthread_join(tid4, NULL);
    wolfcert_server_free(s4);
    wc_FreeDer(&ca4_der);
    wolfcert_buffer_free(&ca4_pem);
    wolfcert_buffer_free(&csr4);
    wolfcert_buffer_free(&out4);
    wolfcert_key_free(dk4);

    /* A failed senderNonce RNG draw on the server answers HTTP 500. */
    WolfCertServerCfgSrv cfg5 = { .protocol = WOLFCERT_PROTO_SCEP,
                                  .bind_host = "127.0.0.1", .bind_port = 0 };
    WolfCertServer* s5 = NULL;
    REQUIRE(wolfcert_server_start(&cfg5, &s5) == WOLFCERT_OK);
    wolfcert_scep_server_set_faults(s5, 0, 0, 1 /* RNG draw fails */);
    pthread_t tid5;
    REQUIRE(pthread_create(&tid5, NULL, server_thread, s5) == 0);

    char url5[128];
    snprintf(url5, sizeof(url5), "http://127.0.0.1:%u/scep", wolfcert_server_port(s5));
    WolfCertServerCfg cli5 = { .protocol = WOLFCERT_PROTO_SCEP, .server_url = url5 };

    WolfCertScepCaps caps5 = { 0 };
    REQUIRE(wolfcert_scep_get_ca_caps(&cli5, &caps5) == WOLFCERT_OK);
    WolfCertBuffer ca5_pem = { 0 };
    REQUIRE(wolfcert_scep_get_ca_cert(&cli5, &ca5_pem) == WOLFCERT_OK);
    DerBuffer* ca5_der = NULL;
    REQUIRE(wc_PemToDer(ca5_pem.data, (long)ca5_pem.len, CERT_TYPE,
                        &ca5_der, NULL, NULL, NULL) == 0);

    WolfCertKey* dk5 = NULL;
    REQUIRE(wolfcert_key_generate(&kcfg, &dk5) == WOLFCERT_OK);
    WolfCertCertMeta meta5 = { .subject_dn = "CN=scep-rng-fail" };
    WolfCertBuffer csr5 = { 0 };
    REQUIRE(wolfcert_csr_build(dk5, &meta5, &csr5) == WOLFCERT_OK);
    WolfCertBuffer out5 = { 0 };
    REQUIRE(wolfcert_scep_pkcs_req(&cli5, &caps5, ca5_der->buffer, ca5_der->length,
                                   dk5, csr5.data, csr5.len, &out5)
            == WOLFCERT_ERR_HTTP);

    wolfcert_server_stop(s5);
    pthread_join(tid5, NULL);
    wolfcert_server_free(s5);
    wc_FreeDer(&ca5_der);
    wolfcert_buffer_free(&ca5_pem);
    wolfcert_buffer_free(&csr5);
    wolfcert_buffer_free(&out5);
    wolfcert_key_free(dk5);

    wc_FreeDer(&ca_der);
    wc_FreeDer(&issued_der);
    wolfcert_buffer_free(&ca_pem);
    wolfcert_buffer_free(&csr);
    wolfcert_buffer_free(&issued);
    wolfcert_key_free(dk);
    wolfcert_cleanup();
    printf("OK\n");
    return 0;
}
