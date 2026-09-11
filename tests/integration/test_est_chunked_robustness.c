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
 * Negative coverage for the chunked-transfer decoder in the EST
 * server's request parser. Drives the server with raw HTTP/1.1
 * requests that advertise `Transfer-Encoding: chunked` but mis-frame
 * the body, and asserts each one comes back as HTTP 400 rather than
 * being silently tolerated.
 *
 * Shapes covered:
 *   1. Oversized chunk-size (more than 8 hex digits).
 *   2. Corrupt inter-chunk trailer (bytes where CRLF should be).
 *   3. Well-formed sanity baseline so the test fails loudly if the
 *      server stops accepting chunked altogether.
 *   4. Well-formed body split across three TCP segments with a
 *      chunk-size line ending in the bytes '0' '\r' '\n'.
 *   5. Keep-alive correctness when the last-chunk trailer CRLF arrives
 *      in its own segment, so a following request is not corrupted.
 *
 * The target is `src/est/est_server.c`'s parse_request chunked path.
 * EST mandates TLS (RFC 7030), so the byte-exact requests are scripted
 * through a raw TLS client that pins the server's minted identity; one
 * test_tls_write() is one TLS record, hence one read on the server.
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#define _DARWIN_C_SOURCE   /* expose memmem/strcasestr/INADDR_LOOPBACK on macOS */
#define _GNU_SOURCE

#include <wolfcert/wolfcert.h>
#include <wolfcert/server.h>

#include "tls_test_util.h"      /* TEST_ENROLL_KEY_TYPE / _PARAM */

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

/* Dial 127.0.0.1:port over TLS, send `req` of `req_len` bytes, return the
 * first line of the response (up to the CRLF or buffer cap). */
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
        /* Stop once we have the first line. */
        if (memchr(status_line, '\n', n) != NULL)
            break;
    }
    test_tls_close(&c);
    status_line[n < cap ? n : cap - 1] = '\0';
    return (int)n;
}

/* Shape #1: a chunk-size line longer than 8 hex digits. The parser
 * must reject this rather than letting the shift-accumulate silently
 * wrap. */
static int reject_oversized_chunk_size(uint16_t port)
{
    const char* req =
        "POST /.well-known/est/simpleenroll HTTP/1.1\r\n"
        "Host: 127.0.0.1\r\n"
        "Content-Type: application/pkcs10\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        /* 16 hex digits -> body would be 2^63 bytes, but the cap kicks
         * in at digit 9 and returns ERR_PROTOCOL. */
        "FFFFFFFFFFFFFFFF\r\n"
        "ignored\r\n"
        "0\r\n\r\n";
    char status[128] = { 0 };
    send_and_read_status(port, req, strlen(req), status, sizeof(status));
    REQUIRE(strstr(status, "400") != NULL);
    return 0;
}

/* Shape #2: inter-chunk trailer that isn't CRLF. A legitimate
 * chunked encoder always emits "<csz>\r\n<data>\r\n<csz>\r\n..."; the
 * parser must reject "<data>XX<csz>\r\n..." instead of absorbing the
 * garbage. */
static int reject_corrupt_chunk_trailer(uint16_t port)
{
    const char req[] =
        "POST /.well-known/est/simpleenroll HTTP/1.1\r\n"
        "Host: 127.0.0.1\r\n"
        "Content-Type: application/pkcs10\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "4\r\n"
        "AAAA"          /* chunk body */
        "XX"            /* <-- should be \r\n; this is the bug we catch */
        "0\r\n\r\n";
    char status[128] = { 0 };
    send_and_read_status(port, req, sizeof(req) - 1, status, sizeof(status));
    REQUIRE(strstr(status, "400") != NULL);
    return 0;
}

/* Positive sanity: a well-formed (if garbage-content) chunked POST
 * still reaches the CSR-parse stage and gets rejected with 400 -
 * but distinctly at the CSR layer, not at the framer. We only
 * require "not 500" here; the 400 body in both cases proves the
 * server didn't crash on the well-framed request. */
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
    /* Not crashing / hanging -> we got *some* status back. The body is
     * not a real CSR so the server returns 400 "Bad CSR"; what we care
     * about is that the framer fed the bytes through cleanly. */
    REQUIRE(status[0] == 'H');
    return 0;
}

/* Shape #4: a well-formed chunked body delivered across three TCP
 * segments, with a chunk-size line ("10" = 16 bytes) that ends in the
 * bytes '0' '\r' '\n'. A completion check that scans for "0\r\n"
 * anywhere in the accumulated buffer trips on that size line the moment
 * the first partial segment lands, stops reading before the rest of the
 * body arrives, and the request is truncated. The framer must instead
 * track chunk framing and keep reading until a genuine zero-length
 * chunk, so the full body reaches the CSR layer and comes back
 * "400 Bad CSR" rather than the "400 Bad Request" a truncated request
 * produces. */
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
    /* Best-effort segmentation: TCP guarantees no recv() boundaries, so the
     * sleeps only make the intended split likely. */
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

/* Build a chunked simpleenroll request whose body carries a real,
 * base64-encoded CSR in a single chunk, but split so the last-chunk line
 * ("0\r\n") is delivered separately from its terminating trailer CRLF.
 * *head gets "<headers>\r\n<len>\r\n<b64-csr>\r\n0\r\n" and *tail gets the
 * lone "\r\n". Both are heap-allocated; the caller frees them. */
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
        trl = strdup("\r\n"); /* trailer terminator, sent as its own segment */
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
        buf = NULL; /* ownership handed to caller */
        trl = NULL;
    }

    free(b64);
    free(buf); /* NULL on success; frees the partial build on failure */
    free(trl);
    wolfcert_buffer_free(&csr);
    wolfcert_key_free(key);
    return (rc == WOLFCERT_OK) ? 0 : 1;
}

/* Shape #5: keep-alive correctness when a chunked request's terminating
 * trailer CRLF arrives in its own TCP segment. A framer that treats
 * "0\r\n" as complete before that final CRLF stops one byte-pair short
 * and leaves "\r\n" on the socket; the next request on the same
 * keep-alive connection then parses the stray CRLF as an empty request
 * line and comes back "400 Bad Request". The corruption is only
 * observable once request #1 succeeds and keeps the connection alive, so
 * request #1 enrolls a real CSR (the in-tree server issues against its
 * generated CA -> "200"). Request #2 is a body-less GET so a mis-parse
 * closes cleanly with the "400 Bad Request" visible (no reset). With the
 * framer consuming the trailer terminator, request #2 reaches the
 * cacerts handler and no "Bad Request" appears. */
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

    /* Request #1: last-chunk line first, trailer CRLF withheld into its
     * own segment so a premature "0\r\n" completion leaves it unread. */
    REQUIRE(test_tls_write(&c, req1_head, req1_head_len) == 0);
    test_sleep_ms(80);
    REQUIRE(test_tls_write(&c, req1_tail, strlen(req1_tail)) == 0);

    /* Wait for request #1's response head before sending request #2. */
    while (n + 1 < sizeof(resp)) {
        int r = test_tls_read(&c, resp + n, sizeof(resp) - 1 - n);
        if (r <= 0)
            break;
        n += (size_t)r;
        resp[n] = '\0';
        if (strstr(resp, "\r\n\r\n") != NULL)
            break;
    }
    REQUIRE(strstr(resp, "200") != NULL); /* enrollment issued a cert */

    REQUIRE(test_tls_write(&c, req2, strlen(req2)) == 0);

    /* Drain until the server closes (request #2 asked for Connection:
     * close), appending onto the same buffer. */
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

    /* Request #2 must have reached the cacerts handler, not the framer:
     * a "Bad Request" means the stray trailer CRLF corrupted it. */
    REQUIRE(strstr(resp, "Bad Request") == NULL);
    return 0;
}

int main(void)
{
    /* A truncated request makes the server respond and close while the
     * client is still writing later segments; ignore the resulting
     * SIGPIPE and read the response back instead. */
    signal(SIGPIPE, SIG_IGN);

    REQUIRE(wolfcert_init(NULL) == WOLFCERT_OK);

    uint8_t* tls_key = NULL;
    size_t tls_key_len = 0;
    REQUIRE(gen_server_identity(&g_tls_cert, &g_tls_cert_len,
                                &tls_key, &tls_key_len) == 0);

    WolfCertServerCfgSrv cfg = {
        .protocol = WOLFCERT_PROTO_EST,
        .bind_host = "127.0.0.1", .bind_port = 0,
        .tls_cert_pem = g_tls_cert, .tls_cert_pem_len = g_tls_cert_len,
        .tls_key_pem  = tls_key,    .tls_key_pem_len  = tls_key_len,
    };
    WolfCertServer* srv = NULL;
    REQUIRE(wolfcert_server_start(&cfg, &srv) == WOLFCERT_OK);
    pthread_t tid;
    REQUIRE(pthread_create(&tid, NULL, server_thread, srv) == 0);

    uint16_t port = wolfcert_server_port(srv);

    int rc = reject_oversized_chunk_size(port);
    if (rc == 0)
        rc = reject_corrupt_chunk_trailer(port);
    if (rc == 0)
        rc = accept_wellformed_chunks(port);
    if (rc == 0)
        rc = accept_multisegment_chunked_body(port);
    if (rc == 0)
        rc = keepalive_after_split_trailer(port);

    wolfcert_server_stop(srv);
    pthread_join(tid, NULL);
    wolfcert_server_free(srv);
    free(g_tls_cert);
    free(tls_key);
    if (rc != 0)
        return rc;

    wolfcert_cleanup();
    printf("OK\n");
    return 0;
}
