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

/* Raw HTTP/1.1 framing, HEAD and header cases against the EST server, plus a
 * SIGPIPE check on serve_fd(). */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#define _DARWIN_C_SOURCE   /* expose memmem/strcasestr/INADDR_LOOPBACK on macOS */
#define _GNU_SOURCE

#include <wolfcert/wolfcert.h>
#include <wolfcert/server.h>

#include "tls_test_util.h"

#include <wolfssl/wolfcrypt/coding.h>   /* Base64_Encode_NoNl */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define REQUIRE(cond) \
    do {                                                                    \
        if (!(cond)) {                                                      \
            fprintf(stderr, "FAIL %s:%d %s\n", __FILE__, __LINE__, #cond);  \
            return 1;                                                       \
        }                                                                   \
    } while (0)

/* The server's minted TLS identity, pinned by every client below. */
static uint8_t* g_tls_cert = NULL;
static size_t   g_tls_cert_len = 0;

static void* server_thread(void* arg)
{
    wolfcert_server_run((WolfCertServer*)arg);
    return NULL;
}

/* Send req over TLS and return the first line of the response. */
static int send_and_read_status(uint16_t port,
                                const void* req, size_t req_len,
                                char* status_line, size_t cap)
{
    TestTlsConn c;
    size_t n = 0;

    if (test_tls_connect(&c, port, g_tls_cert, g_tls_cert_len) != 0)
        return -1;

    if (test_tls_write(&c, req, req_len) != 0) {
        test_tls_close(&c);
        return -1;
    }

    while (n + 1 < cap) {
        int r = test_tls_read(&c, status_line + n, cap - 1 - n);
        if (r <= 0)
            break;
        n += (size_t)r;
        status_line[n] = '\0';
        if (memchr(status_line, '\n', n) != NULL)
            break;
    }
    test_tls_close(&c);
    status_line[n < cap ? n : cap - 1] = '\0';
    return (int)n;
}

static int fetch_whole(uint16_t port, const char* method, const char* op,
                       char* resp, size_t cap)
{
    TestTlsConn c;
    char req[160];
    size_t n = 0;
    int len;
    int r;

    len = snprintf(req, sizeof(req), "%s /.well-known/est/%s HTTP/1.1\r\n"
                   "Host: 127.0.0.1\r\nConnection: close\r\n\r\n",
                   method, op);
    REQUIRE(len > 0 && (size_t)len < sizeof(req));
    REQUIRE(test_tls_connect(&c, port, g_tls_cert, g_tls_cert_len) == 0);
    REQUIRE(test_tls_write(&c, req, (size_t)len) == 0);
    while (n + 1 < cap && (r = test_tls_read(&c, resp + n, cap - 1 - n)) > 0)
        n += (size_t)r;
    test_tls_close(&c);
    resp[n] = '\0';
    return 0;
}

/* HEAD returns GET's headers and no body. */
static int head_matches_get(uint16_t port, const char* op, const char* status)
{
    char get[4096];
    char head[4096];
    const char* eoh;

    REQUIRE(fetch_whole(port, "GET", op, get, sizeof(get)) == 0);
    REQUIRE(fetch_whole(port, "HEAD", op, head, sizeof(head)) == 0);
    if (strncmp(head, status, strlen(status)) != 0)
        fprintf(stderr, "HEAD %s: %.40s\n", op, head);
    REQUIRE(strncmp(head, status, strlen(status)) == 0);
    eoh = strstr(head, "\r\n\r\n");
    REQUIRE(eoh != NULL);
    REQUIRE(eoh[4] == '\0');
    REQUIRE(strncmp(get, head, (size_t)(eoh + 4 - head)) == 0);
    return 0;
}

static int reject_oversized_chunk_size(uint16_t port)
{
    const char* req =
        "POST /.well-known/est/simpleenroll HTTP/1.1\r\n"
        "Host: 127.0.0.1\r\n"
        "Content-Type: application/pkcs10\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        /* A 16-hex-digit chunk size, wider than the server accepts. */
        "FFFFFFFFFFFFFFFF\r\n"
        "ignored\r\n"
        "0\r\n\r\n";
    char status[128] = { 0 };
    send_and_read_status(port, req, strlen(req), status, sizeof(status));
    REQUIRE(strstr(status, "400") != NULL);
    return 0;
}

static int reject_corrupt_chunk_trailer(uint16_t port)
{
    const char req[] =
        "POST /.well-known/est/simpleenroll HTTP/1.1\r\n"
        "Host: 127.0.0.1\r\n"
        "Content-Type: application/pkcs10\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "4\r\n"
        "AAAA"
        "XX"            /* in place of the CRLF */
        "0\r\n\r\n";
    char status[128] = { 0 };
    send_and_read_status(port, req, sizeof(req) - 1, status, sizeof(status));
    REQUIRE(strstr(status, "400") != NULL);
    return 0;
}

/* A well-framed chunked body gets a response rather than a crash or hang. */
static int accept_wellformed_chunks(uint16_t port)
{
    const char req[] =
        "POST /.well-known/est/simpleenroll HTTP/1.1\r\n"
        "Host: 127.0.0.1\r\n"
        "Content-Type: application/pkcs10\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "4\r\nAAAA\r\n"
        "0\r\n\r\n";
    char status[128] = { 0 };
    send_and_read_status(port, req, sizeof(req) - 1, status, sizeof(status));
    REQUIRE(status[0] == 'H');
    return 0;
}

/* The chunk-size line "10\r\n" contains "0\r\n", so a framer that scans for
 * the terminator stops early and answers "Bad Request" instead of "Bad CSR". */
static int accept_multisegment_chunked_body(uint16_t port)
{
    const char* hdr =
        "POST /.well-known/est/simpleenroll HTTP/1.1\r\n"
        "Host: 127.0.0.1\r\n"
        "Content-Type: application/pkcs10\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n";
    const char* seg2 = "10\r\nAAAA";                /* size line + 4/16 bytes */
    const char* seg3 = "AAAAAAAAAAAA\r\n0\r\n\r\n"; /* last 12 bytes + terminator */
    TestTlsConn c;
    char status[128] = { 0 };
    size_t n = 0;

    REQUIRE(test_tls_connect(&c, port, g_tls_cert, g_tls_cert_len) == 0);

    REQUIRE(test_tls_write(&c, hdr, strlen(hdr)) == 0);
    /* TCP keeps no recv() boundaries, so the sleeps only make the split
     * likely. */
    test_sleep_ms(80);
    (void)test_tls_write(&c, seg2, strlen(seg2));
    test_sleep_ms(80);
    (void)test_tls_write(&c, seg3, strlen(seg3));

    while (n + 1 < sizeof(status)) {
        int r = test_tls_read(&c, status + n, sizeof(status) - 1 - n);
        if (r <= 0)
            break;
        n += (size_t)r;
        status[n] = '\0';
        if (memchr(status, '\n', n) != NULL)
            break;
    }
    test_tls_close(&c);

    REQUIRE(strstr(status, "Bad CSR") != NULL);
    return 0;
}

/* Authorization is a singleton field, so a second one is a malformed request. */
static int reject_duplicate_authorization(uint16_t port)
{
    const char* req =
        "GET /.well-known/est/cacerts HTTP/1.1\r\n"
        "Host: 127.0.0.1\r\n"
        "Authorization: Basic AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\r\n"
        "Authorization: Basic AA==\r\n"
        "Connection: close\r\n"
        "\r\n";
    /* A field that only starts with "Authorization" is a different field. */
    const char* other =
        "GET /.well-known/est/cacerts HTTP/1.1\r\n"
        "Host: 127.0.0.1\r\n"
        "Authorization-Foo: x\r\n"
        "Authorization: Basic AA==\r\n"
        "Connection: close\r\n"
        "\r\n";
    /* RFC 9112 section 5.1: whitespace before a colon is a 400. */
    const char* spaced =
        "GET /.well-known/est/cacerts HTTP/1.1\r\n"
        "Host: 127.0.0.1\r\n"
        "Content-Length : 0\r\n"
        "Connection: close\r\n"
        "\r\n";
    char status[128] = { 0 };
    send_and_read_status(port, req, strlen(req), status, sizeof(status));
    REQUIRE(strstr(status, "400") != NULL);
    memset(status, 0, sizeof(status));
    send_and_read_status(port, other, strlen(other), status, sizeof(status));
    REQUIRE(strstr(status, "200") != NULL);
    memset(status, 0, sizeof(status));
    send_and_read_status(port, spaced, strlen(spaced), status, sizeof(status));
    REQUIRE(strstr(status, "400") != NULL);
    return 0;
}

/* Chunked simpleenroll with a real CSR in one chunk: *head ends at the
 * last-chunk line "0\r\n" and *tail is the final CRLF. Caller frees both. */
static int build_split_enroll(char** head, size_t* head_len, char** tail)
{
    WolfCertKeyCfg kcfg = { .type = TEST_ENROLL_KEY_TYPE,
                            .param = TEST_ENROLL_KEY_PARAM,
                            .dev_id = WOLFCERT_DEVID_SOFTWARE };
    WolfCertCertMeta meta = { .subject_dn = "CN=keepalive-test" };
    WolfCertKey* key = NULL;
    WolfCertBuffer csr = { 0 };
    byte* b64 = NULL;
    word32 b64_len = 0;
    char* buf = NULL;
    char* trl = NULL;
    size_t hdr_len = 0;
    int rc;

    rc = wolfcert_key_generate(&kcfg, &key);
    if (rc == WOLFCERT_OK)
        rc = wolfcert_csr_build(key, &meta, &csr);

    if (rc == WOLFCERT_OK) {
        b64_len = (word32)(((csr.len + 2) / 3) * 4 + 4);
        b64 = (byte*)malloc(b64_len);
        if (b64 == NULL ||
            Base64_Encode_NoNl(csr.data, (word32)csr.len, b64, &b64_len) != 0)
            rc = WOLFCERT_ERR_CRYPTO;
    }

    if (rc == WOLFCERT_OK) {
        /* headers + chunk-size line + base64 body + CRLF + "0\r\n" */
        buf = (char*)malloc(512 + b64_len);
        trl = strdup("\r\n");
        if (buf == NULL || trl == NULL)
            rc = WOLFCERT_ERR_MEMORY;
    }

    if (rc == WOLFCERT_OK) {
        hdr_len = (size_t)snprintf(buf, 256,
            "POST /.well-known/est/simpleenroll HTTP/1.1\r\n"
            "Host: 127.0.0.1\r\n"
            "Content-Type: application/pkcs10\r\n"
            "Content-Transfer-Encoding: base64\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "%x\r\n", (unsigned)b64_len);
        memcpy(buf + hdr_len, b64, b64_len);
        hdr_len += b64_len;
        memcpy(buf + hdr_len, "\r\n0\r\n", 5); /* end chunk, last-chunk line */
        hdr_len += 5;

        *head = buf;
        *head_len = hdr_len;
        *tail = trl;
        buf = NULL;
        trl = NULL;
    }

    free(b64);
    free(buf);
    free(trl);
    wolfcert_buffer_free(&csr);
    wolfcert_key_free(key);
    return (rc == WOLFCERT_OK) ? 0 : 1;
}

/* A final CRLF left unread in its own segment turns the next keep-alive
 * request into "400 Bad Request". Request #1 enrolls a real CSR so the
 * connection stays alive. */
static int keepalive_after_split_trailer(uint16_t port)
{
    const char* req2 =
        "GET /.well-known/est/cacerts HTTP/1.1\r\n"
        "Host: 127.0.0.1\r\n"
        "Connection: close\r\n"
        "\r\n";
    TestTlsConn c;
    char* req1_head = NULL;
    char* req1_tail = NULL;
    size_t req1_head_len = 0;
    char resp[4096] = { 0 };
    size_t n = 0;

    REQUIRE(build_split_enroll(&req1_head, &req1_head_len, &req1_tail) == 0);

    REQUIRE(test_tls_connect(&c, port, g_tls_cert, g_tls_cert_len) == 0);

    REQUIRE(test_tls_write(&c, req1_head, req1_head_len) == 0);
    test_sleep_ms(80);
    REQUIRE(test_tls_write(&c, req1_tail, strlen(req1_tail)) == 0);

    while (n + 1 < sizeof(resp)) {
        int r = test_tls_read(&c, resp + n, sizeof(resp) - 1 - n);
        if (r <= 0)
            break;
        n += (size_t)r;
        resp[n] = '\0';
        if (strstr(resp, "\r\n\r\n") != NULL)
            break;
    }
    REQUIRE(strstr(resp, "200") != NULL);

    REQUIRE(test_tls_write(&c, req2, strlen(req2)) == 0);

    while (n + 1 < sizeof(resp)) {
        int r = test_tls_read(&c, resp + n, sizeof(resp) - 1 - n);
        if (r <= 0)
            break;
        n += (size_t)r;
        resp[n] = '\0';
    }
    test_tls_close(&c);
    free(req1_head);
    free(req1_tail);

    REQUIRE(strstr(resp, "Bad Request") == NULL);
    return 0;
}

static volatile sig_atomic_t g_sigpipe_raised;

static void note_sigpipe(int sig)
{
    (void)sig;
    g_sigpipe_raised = 1;
}

/* The handler's response write to a closed peer raises no SIGPIPE. */
static int no_sigpipe_on_response(void)
{
    static const char http_req[] =
        "GET /nope HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
    WolfCertServerCfgSrv cfg = {
        .protocol = WOLFCERT_PROTO_EST,
        .bind_host = "127.0.0.1", .bind_port = 0,
        .ca_store = test_ca_store(),
        .est_allow_anonymous_enroll = 1,
    };
    WolfCertServer*  srv = NULL;
    struct sigaction sa, old;
    uint8_t*         cert = NULL;
    uint8_t*         key = NULL;
    size_t           cert_len = 0;
    size_t           key_len = 0;
    int              sv[2];
    int              rc;

    /* EST requires a TLS identity even though serve_fd() stays plaintext. */
    REQUIRE(gen_server_identity(&cert, &cert_len, &key, &key_len) == 0);
    cfg.tls_cert_pem     = cert;
    cfg.tls_cert_pem_len = cert_len;
    cfg.tls_key_pem      = key;
    cfg.tls_key_pem_len  = key_len;

    REQUIRE(wolfcert_server_start(&cfg, &srv) == WOLFCERT_OK);
    REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    REQUIRE(write(sv[1], http_req, sizeof(http_req) - 1)
            == (ssize_t)(sizeof(http_req) - 1));
    close(sv[1]);

    /* A handler makes a raised SIGPIPE observable; main() ignores it. */
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = note_sigpipe;
    sigemptyset(&sa.sa_mask);
    REQUIRE(sigaction(SIGPIPE, &sa, &old) == 0);
    g_sigpipe_raised = 0;

    rc = wolfcert_server_serve_fd(srv, sv[0]);

    REQUIRE(sigaction(SIGPIPE, &old, NULL) == 0);
    close(sv[0]);
    wolfcert_server_free(srv);
    free(cert);
    free(key);

    REQUIRE(g_sigpipe_raised == 0);
    /* The 404 for GET /nope shows the handler reached its response write. */
    REQUIRE(rc == WOLFCERT_ERR_NOT_FOUND);

    return 0;
}

int main(void)
{
    /* The server may close while a client still writes later segments. */
    signal(SIGPIPE, SIG_IGN);

    REQUIRE(wolfcert_init(NULL) == WOLFCERT_OK);

    uint8_t* tls_key = NULL;
    size_t tls_key_len = 0;
    REQUIRE(gen_server_identity(&g_tls_cert, &g_tls_cert_len,
                                &tls_key, &tls_key_len) == 0);

    WolfCertServerCfgSrv cfg = {
        .protocol = WOLFCERT_PROTO_EST,
        .bind_host = "127.0.0.1", .bind_port = 0,
        .ca_store = test_ca_store(),
        .tls_cert_pem = g_tls_cert, .tls_cert_pem_len = g_tls_cert_len,
        .tls_key_pem  = tls_key,    .tls_key_pem_len  = tls_key_len,
        .est_allow_anonymous_enroll = 1,
    };
    WolfCertServer* srv = NULL;
    REQUIRE(wolfcert_server_start(&cfg, &srv) == WOLFCERT_OK);
    pthread_t tid;
    REQUIRE(pthread_create(&tid, NULL, server_thread, srv) == 0);

    uint16_t port = wolfcert_server_port(srv);

    int rc = head_matches_get(port, "nope", "HTTP/1.1 404");
    if (rc == 0)
        rc = head_matches_get(port, "cacerts", "HTTP/1.1 200");
    if (rc == 0)
        rc = head_matches_get(port, "csrattrs", "HTTP/1.1 204");
    if (rc == 0)
        rc = reject_oversized_chunk_size(port);
    if (rc == 0)
        rc = reject_corrupt_chunk_trailer(port);
    if (rc == 0)
        rc = accept_wellformed_chunks(port);
    if (rc == 0)
        rc = accept_multisegment_chunked_body(port);
    if (rc == 0)
        rc = keepalive_after_split_trailer(port);
    if (rc == 0)
        rc = reject_duplicate_authorization(port);
    if (rc == 0)
        rc = no_sigpipe_on_response();

    wolfcert_server_stop(srv);
    pthread_join(tid, NULL);
    wolfcert_server_free(srv);
    free(g_tls_cert);
    free(tls_key);
    if (rc != 0)
        return rc;

    test_ca_store_close();
    wolfcert_cleanup();
    printf("OK\n");
    return 0;
}
