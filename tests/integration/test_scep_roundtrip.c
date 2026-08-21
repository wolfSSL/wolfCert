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

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/asn.h>          /* SHA256h */
#include <wolfssl/wolfcrypt/asn_public.h>
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

/* Send a raw HTTP/1.1 GET to the plain-HTTP SCEP server on the loopback port
 * and return the numeric response status (or -1 on transport failure). An
 * optional body (with a matching Content-Length) is sent when `body` is
 * non-NULL. Used to exercise the server's malformed-GET rejection branches and
 * the GET-with-body free path, which the client API cannot produce. */
static int raw_http_status(uint16_t port, const char* target, const char* body)
{
    struct sockaddr_in addr;
    struct timeval tv;
    char req[512];
    char resp[128];
    size_t body_len = body != NULL ? strlen(body) : 0;
    int fd;
    int n;
    ssize_t r;
    int status = -1;

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

    if (body_len > 0)
        n = snprintf(req, sizeof(req),
                     "GET %s HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n"
                     "Content-Length: %zu\r\n\r\n%s",
                     target, body_len, body);
    else
        n = snprintf(req, sizeof(req),
                     "GET %s HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
                     target);
    if (n < 0 || (size_t)n >= sizeof(req)) {
        close(fd);
        return -1;
    }
    if (write(fd, req, (size_t)n) != (ssize_t)n) {
        close(fd);
        return -1;
    }

    r = read(fd, resp, sizeof(resp) - 1);
    if (r > 0) {
        resp[r] = '\0';
        if (strncmp(resp, "HTTP/1.1 ", 9) == 0)
            status = atoi(resp + 9);
    }

    close(fd);
    return status;
}

/* Exercise the HTTP GET PKIOperation fallback (RFC 8894 section 4.1): with a
 * caps set that does not advertise POSTPKIOperation the client carries the
 * pkiMessage base64-encoded in a GET query and the server decodes and issues
 * exactly as for POST. The issued cert is verified to chain to the CA that
 * answered the GET - the same trust check the POST path runs in main, not just
 * a PEM-marker match. The device key, CSR, issued buffer, cert manager and
 * decoded DER are owned here and freed on every return path, so a failing check
 * cannot leak them. Returns WOLFCERT_OK on success, a negative wolfCert error,
 * or -1 on a content/verification mismatch. */
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

    /* The issued cert must chain to the CA that answered the GET, not merely
     * look like a PEM certificate. */
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

/* proto_opts.scep.txid_mode = PUBKEY_HASH: the transactionID must be the
 * 64-char upper-case hex SHA-256 of the enrollee public keyInfo, must
 * match a value recomputed from the CSR, and must be deterministic (a second
 * enrollment of the same key reuses it). Owns and frees everything it makes. */
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

/* The content-cipher checks force an AES-CBC cipher, so they only exist when
 * wolfSSL can supply one. */
#if defined(HAVE_AES_CBC) && \
        (defined(WOLFSSL_AES_128) || defined(WOLFSSL_AES_256))
#define WOLFCERT_TEST_HAVE_CIPHER_OVERRIDE
#endif

#ifdef WOLFCERT_TEST_HAVE_CIPHER_OVERRIDE
/* proto_opts.scep.content_cipher override: enrolling with an explicit
 * cipher must still issue a cert - the server de-envelops whatever OID the
 * request carries - proving AES-256 (and explicit AES-128) interoperate. */
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
#endif /* WOLFCERT_TEST_HAVE_CIPHER_OVERRIDE */

/* Minimal single-shot HTTP responder that answers any request with a
 * caller-supplied GetCACaps body, so a test can drive capability parsing
 * with a body the real server would never emit. */
struct caps_ctx { int listen_fd; const char* body; };

/* Bind a loopback listener and report the ephemeral port it landed on.
 * Callers run this before spawning the responder thread, so the port never
 * has to travel back across the thread boundary. */
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

static void* caps_srv_thread(void* arg)
{
    struct caps_ctx* cc = (struct caps_ctx*)arg;
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

    char resp[512];
    int rn = snprintf(resp, sizeof(resp),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/plain\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n\r\n%s",
        strlen(cc->body), cc->body);
    if (rn > 0)
        send(cs, resp, (size_t)rn, 0);
    shutdown(cs, SHUT_WR);
    close(cs);
    return NULL;
}

/* RFC 8894 section 3.5.2: GetCACaps is a newline-delimited list of exact
 * tokens. A future token that merely contains a known one as a substring
 * (Renewal-Extra, AESGCM) must not be read as advertising that capability. */
static int test_caps_token_matching(void)
{
    const char* caps_body =
        "POSTPKIOperation\r\n"
        "Renewal-Extra\r\n"
        "AESGCM\r\n";
    struct caps_ctx cc = { .listen_fd = -1, .body = caps_body };
    pthread_t tid;
    int port = 0;
    cc.listen_fd = listen_loopback(&port);
    REQUIRE(cc.listen_fd >= 0);
    REQUIRE(pthread_create(&tid, NULL, caps_srv_thread, &cc) == 0);

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

/* Captures one POSTed pkiMessage and reports the messageType it carried. The
 * in-tree server routes 19 and 17 through the same handler, so only a look at
 * the wire can tell the two renewal shapes apart.
 *
 * Every declaration below initializes .listen_fd, which zero-fills the rest of
 * the struct (C99 6.7.9p19), so the char buffers are empty strings even when
 * the thread bails out before parsing and the assertions compare cleanly. */
struct msgtype_ctx {
    int    listen_fd;
    char   seen[8];      /* the messageType attribute, or "" if not reached */
    char   reqline[256]; /* the HTTP request line, for the GET operations */
    size_t tid_len;      /* transactionID length, 0 if not reached */
    char   cipher[8];    /* content-encryption OID seen in the EnvelopedData */
};

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

    /* Read headers, find Content-Length, then the body that follows. One byte
     * is held back so the header scan below can NUL-terminate what arrived:
     * recv() does not, and strstr must not run off the end. */
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
        WolfCertBuffer env = { 0 };
        if (wolfcert_scep_parse_pki_message(buf + hdr_end, want, &env,
                                            &tid, &tid_len,     /* txid      */
                                            NULL, NULL,         /* senderNonce */
                                            NULL, NULL,         /* recipNonce  */
                                            &mt,                /* messageType */
                                            NULL,               /* pkiStatus   */
                                            NULL, NULL,         /* signer cert */
                                            NULL,               /* failInfo    */
                                            NULL) == WOLFCERT_OK) {
            if (mt != NULL)
                snprintf(mc->seen, sizeof(mc->seen), "%s", mt);
            mc->tid_len = tid_len;

            /* The content-encryption AlgorithmIdentifier inside the
             * EnvelopedData: the option is only honoured if this changes. */
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
        }
        /* Parser output comes from the wolfCert heap, not libc. */
        WOLFCERT_XFREE(mt, NULL);
        WOLFCERT_XFREE(tid, NULL);
        wolfcert_buffer_free(&env);
    }

    /* The client's round trip fails from here; the request is all we wanted. */
    close(cs);
    return NULL;
}

#ifdef WOLFCERT_TEST_HAVE_CIPHER_OVERRIDE
/* The end-to-end cipher check above only proves the server de-enveloped
 * whatever arrived, which it does for any OID, so it would pass even if the
 * override were ignored. Read the algorithm off the wire instead. */
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

    /* The listener never answers, so the call fails; the request is the point. */
    (void)wolfcert_scep_pkcs_req(&cli, caps, ca_der_buf, ca_der_len, key,
                                 csr.data, csr.len, &issued);
    wolfcert_buffer_free(&issued);
    wolfcert_buffer_free(&csr);
    wolfcert_key_free(key);
    pthread_join(tid, NULL);

    REQUIRE(strcmp(mc.cipher, expect) == 0);
    return 0;
}
#endif /* WOLFCERT_TEST_HAVE_CIPHER_OVERRIDE */

/* proto_opts.scep.renewal_msg_type picks the messageType a renewal carries,
 * while the signer stays the certificate being replaced either way. Default is
 * RFC 8894's RenewalReq (17); PKCS_REQ sends 19 for a CA that predates it. */
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
    /* The capture server never answers, so the call fails; the assertion is
     * about what it put on the wire before that. */
    (void)wolfcert_scep_renewal_req_ex(&cli, caps, ca_der_buf, ca_der_len,
                                       ca_der_buf, ca_der_len,
                                       cur_cert, cur_cert_len, cur_key,
                                       csr, csr_len, &r);
    wolfcert_scep_result_free(&r);
    pthread_join(tid, NULL);

    REQUIRE(strcmp(mc.seen, expect) == 0);
    return 0;
}

/* The session captures the SCEP options at open rather than reading the config
 * per request, so the capture has its own coverage: drive a session renewal
 * against the recording listener and check both the messageType it chose and
 * the transactionID form it derived. */
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
    /* The listener never answers, so this fails; the request is the assertion. */
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

/* RFC 8894 section 4.6.1: GetNextCACert takes the CA identifier too, so a
 * multi-CA responder can be told which rollover certificate is wanted. */
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

/* handle_pki_op's dispatch failures answer with a signed CertRep FAILURE, not
 * a bare HTTP error. The client cannot produce these messages, so POST
 * hand-built ones. Owns and frees everything it makes. */
static int check_malformed_dispatch(uint16_t port, const WolfCertKeyCfg* kcfg,
                                    const uint8_t* ca_der_buf, size_t ca_der_len)
{
    static const uint8_t junk[4] = { 0x04, 0x02, 0xAB, 0xCD };
    static const char* const msg_type[4] = { NULL, "19", "99", NULL };

    WolfCertCertMeta meta = { .subject_dn = "CN=scep-dispatch" };
    WolfCertKey*   key  = NULL;
    WolfCertBuffer csr  = { 0 };
    WolfCertBuffer kder = { 0 };
    WolfCertBuffer env  = { 0 };
    uint8_t* signer = NULL;
    size_t   signer_len = 0;
    uint8_t  tid[16], snonce[16];
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

    for (i = 0; rc == WOLFCERT_OK && i < 4; ++i) {
        /* The last round omits the transactionID, which no CertRep can echo. */
        WolfCertScepAttrs a = {
            .transaction_id = i == 3 ? NULL : tid,
            .transaction_id_len = i == 3 ? 0 : sizeof(tid),
            .sender_nonce   = snonce, .sender_nonce_len   = sizeof(snonce),
            .message_type   = msg_type[i],
        };
        /* Round 2 needs an envelope the CA can open, or it trips the
         * decrypt branch first. */
        const uint8_t* content     = i == 2 ? env.data : junk;
        size_t         content_len = i == 2 ? env.len  : sizeof(junk);
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
            int ok = wolfcert_http_request(&req, &resp) == WOLFCERT_OK;

            if (i == 3) {
                ok = ok && resp.status_code == 400 && resp.body_len == 0;
            }
            else {
                ok = ok && resp.status_code == 200 && resp.body != NULL;

                ok = ok && wolfcert_scep_parse_pki_message(resp.body,
                               resp.body_len, &renv, &r_tid, &r_tidl, &r_sn,
                               &r_snl, &r_rn, &r_rnl, &r_mt, &r_st, &r_sc,
                               &r_scl, &r_fi, NULL) == WOLFCERT_OK;

                ok = ok && r_mt != NULL && strcmp(r_mt, "3") == 0 &&
                     r_st != NULL && strcmp(r_st, "2") == 0 &&
                     r_fi != NULL && strcmp(r_fi, "2") == 0 &&
                     r_tid != NULL && r_tidl == sizeof(tid) &&
                     memcmp(r_tid, tid, sizeof(tid)) == 0 &&
                     r_rn != NULL && r_rnl == sizeof(snonce) &&
                     memcmp(r_rn, snonce, sizeof(snonce)) == 0 &&
                     renv.len == 0;
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

    WolfCertBuffer ca_pem = { 0 };
    REQUIRE(wolfcert_scep_get_ca_cert(&cli, &ca_pem) == WOLFCERT_OK);
    DerBuffer* ca_der = NULL;
    REQUIRE(wc_PemToDer(ca_pem.data, (long)ca_pem.len, CERT_TYPE,
                        &ca_der, NULL, NULL, NULL) == 0);

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

    /* ---- HTTP GET PKIOperation fallback (RFC 8894 section 4.1) ------------
     * Driven from a helper that owns and frees the device key, CSR and issued
     * buffer so a failing assertion cannot leak them. */
    REQUIRE(check_get_fallback(&cli, &caps, &kcfg,
                               ca_der->buffer, ca_der->length) == WOLFCERT_OK);

    /* ---- Public-key-hash transactionID (RFC 8894 section 3.2.1) ----------- */
    REQUIRE(check_pubkey_txid(&cli, &caps, &kcfg,
                              ca_der->buffer, ca_der->length) == WOLFCERT_OK);

    /* ---- Content-cipher override: explicit AES-256 and AES-128 both enroll.
     * Each half needs the cipher wolfSSL was actually built with; scep_prepare
     * returns WOLFCERT_ERR_UNSUPPORTED for one the library cannot do. */
#if defined(WOLFSSL_AES_256) && defined(HAVE_AES_CBC)
    REQUIRE(check_content_cipher(&cli, &caps, &kcfg, ca_der->buffer,
                                 ca_der->length, WOLFCERT_SCEP_CIPHER_AES256)
            == WOLFCERT_OK);
#endif
#if defined(WOLFSSL_AES_128) && defined(HAVE_AES_CBC)
    REQUIRE(check_content_cipher(&cli, &caps, &kcfg, ca_der->buffer,
                                 ca_der->length, WOLFCERT_SCEP_CIPHER_AES128)
            == WOLFCERT_OK);
#endif

    /* ---- Renewal messageType. The signer is the certificate being replaced
     * in both cases; only the attribute changes, and the in-tree server routes
     * 19 and 17 through one handler, so this reads the value off the wire. */
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

    /* ...and the same options read off the wire, since the server de-envelops
     * any OID and so cannot tell an honoured override from an ignored one. */
#if defined(WOLFSSL_AES_256) && defined(HAVE_AES_CBC)
    REQUIRE(check_content_cipher_wire(&caps, &kcfg, ca_der->buffer,
                                      ca_der->length,
                                      WOLFCERT_SCEP_CIPHER_AES256,
                                      "aes256") == 0);
#endif
#if defined(WOLFSSL_AES_128) && defined(HAVE_AES_CBC)
    REQUIRE(check_content_cipher_wire(&caps, &kcfg, ca_der->buffer,
                                      ca_der->length,
                                      WOLFCERT_SCEP_CIPHER_AES128,
                                      "aes128") == 0);
#endif

    /* The session captures the SCEP options at open, so that path needs its own
     * check rather than inheriting the one-shot coverage above. */
    REQUIRE(check_session_opts_capture(&caps, ca_der->buffer, ca_der->length,
                                       issued_der->buffer, issued_der->length,
                                       dk, csr.data, csr.len) == 0);

    /* The CA identifier belongs on GetNextCACert as well (RFC 8894 4.6.1). */
    REQUIRE(check_getnextca_ca_id(ca_der->buffer, ca_der->length) == 0);

    REQUIRE(check_malformed_dispatch(wolfcert_server_port(s), &kcfg,
                                     ca_der->buffer, ca_der->length)
            == WOLFCERT_OK);

    /* One-shot SCEP over https:// must refuse to run unverified, the same rule
     * the session open applies: verify_server is the only peer-verification
     * switch, so leaving it off would complete a silent anonymous handshake. */
    {
        WolfCertServerCfg tls_cli = { .protocol = WOLFCERT_PROTO_SCEP,
                                      .server_url = "https://127.0.0.1:1/scep" };
        WolfCertScepCaps tls_caps = { 0 };
        WolfCertBuffer   tls_ca = { 0 };
        REQUIRE(wolfcert_scep_get_ca_caps(&tls_cli, &tls_caps) == WOLFCERT_ERR_TLS);
        REQUIRE(wolfcert_scep_get_ca_cert(&tls_cli, &tls_ca) == WOLFCERT_ERR_TLS);
        wolfcert_buffer_free(&tls_ca);

        /* With verification on it must get past the gate and fail on the
         * network instead, so the check cannot be firing indiscriminately. */
        tls_cli.verify_server = 1;
        REQUIRE(wolfcert_scep_get_ca_caps(&tls_cli, &tls_caps) != WOLFCERT_ERR_TLS);
    }

    /* Negative GET PKIOperation branches (RFC 8894 section 4.1): the server must
     * reject each malformed request with 400. These cannot be produced by the
     * client API, so drive the running server over a raw socket. */
    REQUIRE(raw_http_status(wolfcert_server_port(s),
                "/scep?operation=PKIOperation", NULL) == 400);              /* no message= */
    REQUIRE(raw_http_status(wolfcert_server_port(s),
                "/scep?operation=PKIOperation&message=%ZZ", NULL) == 400);  /* bad %-escape */
    REQUIRE(raw_http_status(wolfcert_server_port(s),
                "/scep?operation=PKIOperation&message=@@@@", NULL) == 400); /* bad base64  */

    /* A GET carrying a spurious Content-Length body: read_request allocates
     * req->body for it, and handle_pki_op_get must free that before installing
     * the decoded message or it leaks (caught under ASan). "QUJD" is valid
     * base64 so the decode succeeds and the free path runs; the payload is not a
     * real pkiMessage, so the request is rejected with 400. */
    REQUIRE(raw_http_status(wolfcert_server_port(s),
                "/scep?operation=PKIOperation&message=QUJD", "XYZ") == 400); /* body freed */

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

    /* ---- Challenge password (RFC 8894 section 2.9) -------------------------
     * Fresh server configured to require a challenge. Enrolling without
     * it or with the wrong value must fail; the correct value must issue. */
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

    /* 1) no challenge in CSR -> server answers with a signed CertRep FAILURE
     * (RFC 8894 pkiStatus=2), which the client surfaces as ERR_PROTOCOL.
     * A plain HTTP 4xx here would instead read back as ERR_HTTP. */
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

    /* ---- recipientNonce round-trips (RFC 8894 section 3.2.1.2) ------------
     * The SCEP server now always emits recipientNonce in its CertRep (on any
     * malloc-enabled wolfSSL), and the client rejects a CertRep whose
     * recipientNonce fails to echo the senderNonce it sent (exercised by the
     * successful enrollments above). This whitebox check asserts the encoder
     * actually puts the nonce on the wire and the parser recovers it intact. */
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
        const uint8_t wtid[16] = { 0 };
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

    /* ---- Absent recipientNonce in a CertRep must be rejected -------------
     * RFC 8894 section 3.2.1.2 requires the sender to verify the CertRep's
     * recipientNonce echoes the senderNonce it sent. A CertRep that carries
     * no recipientNonce cannot be verified, so the client must reject it.
     * Drive a server that deliberately omits the nonce and confirm the
     * enrollment fails instead of accepting the reply. */
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

    /* ---- CertRep signed by a non-CA key must be rejected ----------------
     * RFC 8894 authenticates the CertRep through its CMS signature. A reply
     * signed by a key other than the trusted CA (a rogue server or a man in
     * the middle) must be rejected. Drive a server that signs with a throwaway
     * key and confirm the enrollment fails with an auth error rather than
     * accepting the attacker-controlled certificate. */
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

    /* ---- senderNonce RNG failure must abort, not leak stack -------------
     * If the RNG draw for the CertRep senderNonce fails, the server must not
     * build a CertRep over an uninitialized buffer. It frees its scratch,
     * answers HTTP 500, and returns an error, which the client sees as a
     * transport failure. Drive a server whose nonce draw is forced to fail
     * and confirm the enrollment does not succeed. This also exercises the
     * error-path cleanup under the sanitizer builds. */
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
