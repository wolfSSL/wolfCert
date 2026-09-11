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
 * Shared integration-test helper: mint self-signed identities (cert + key,
 * PEM) with an iPAddress SAN for 127.0.0.1, used to stand up the in-tree test
 * server behind TLS. EST mandates TLS (RFC 7030), so the EST integration tests
 * run over HTTPS and pin a freshly-minted cert as their bootstrap trust
 * anchor. The signing algorithm follows whatever the wolfSSL build provides
 * (RSA when present, else ECC P-256), so the helpers work under reduced
 * key-algorithm configurations.
 */

#ifndef WOLFCERT_TLS_TEST_UTIL_H
#define WOLFCERT_TLS_TEST_UTIL_H

#include <wolfcert/wolfcert.h>

#include <sys/types.h>   /* pid_t, referenced by wolfssl/wolfcrypt/random.h */

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/ecc.h>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static inline void test_sleep_ms(long ms)
{
    struct timespec ts;

    ts.tv_sec  = ms / 1000;
    ts.tv_nsec = (ms % 1000) * 1000000L;
    nanosleep(&ts, NULL);
}

/* A key algorithm + parameter the current build supports, for client
 * enrollments where the algorithm is incidental to what the test verifies. */
#if defined(WOLFCERT_HAVE_ECC)
    #define TEST_ENROLL_KEY_TYPE  WOLFCERT_KEY_ECC
    #define TEST_ENROLL_KEY_PARAM 256
#elif defined(WOLFCERT_HAVE_RSA)
    #define TEST_ENROLL_KEY_TYPE  WOLFCERT_KEY_RSA
    #define TEST_ENROLL_KEY_PARAM 2048
#elif defined(WOLFCERT_HAVE_ED25519)
    #define TEST_ENROLL_KEY_TYPE  WOLFCERT_KEY_ED25519
    #define TEST_ENROLL_KEY_PARAM 0
#elif defined(WOLFCERT_HAVE_ED448)
    #define TEST_ENROLL_KEY_TYPE  WOLFCERT_KEY_ED448
    #define TEST_ENROLL_KEY_PARAM 0
#else
    #error "tls_test_util: no supported enrollment key algorithm"
#endif

/* The tests self-sign their identities with whatever signature-capable key
 * algorithm the wolfSSL build provides: RSA when present, else ECC P-256.
 * (A wolfCert build always has at least one of the two.) */
#if !defined(NO_RSA)
    typedef RsaKey            test_signkey;
    #define TEST_CERT_SIGTYPE CTC_SHA256wRSA
    #define TEST_KEY_PEM_TYPE PRIVATEKEY_TYPE
#elif defined(HAVE_ECC)
    typedef ecc_key           test_signkey;
    #define TEST_CERT_SIGTYPE CTC_SHA256wECDSA
    #define TEST_KEY_PEM_TYPE ECC_PRIVATEKEY_TYPE
#else
    #error "tls_test_util: tests need RSA or ECC for a signing identity"
#endif

/* Init + generate a signing key. Returns 0 on success (free with
 * test_signkey_free); non-zero on failure (nothing to free). */
static inline int test_signkey_make(test_signkey* key, WC_RNG* rng)
{
#if !defined(NO_RSA)
    if (wc_InitRsaKey(key, NULL) != 0)
        return -1;
    if (wc_MakeRsaKey(key, 2048, WC_RSA_EXPONENT, rng) != 0) {
        wc_FreeRsaKey(key);
        return -1;
    }
#else
    if (wc_ecc_init(key) != 0)
        return -1;
    if (wc_ecc_make_key(rng, 32, key) != 0) {
        wc_ecc_free(key);
        return -1;
    }
#endif
    return 0;
}

static inline void test_signkey_free(test_signkey* key)
{
#if !defined(NO_RSA)
    wc_FreeRsaKey(key);
#else
    wc_ecc_free(key);
#endif
}

/* Self-sign the (already populated) Cert into `der`. Returns the signed DER
 * length, or <= 0 on error. */
static inline int test_sign_selfcert(Cert* cert, uint8_t* der, int der_sz,
                                     test_signkey* key, WC_RNG* rng)
{
#if !defined(NO_RSA)
    return wc_MakeSelfCert(cert, der, (word32)der_sz, key, rng);
#else
    /* No ECC form of wc_MakeSelfCert; make the body self-issued and sign it. */
    cert->issuer = cert->subject;
    if (wc_MakeCert(cert, der, (word32)der_sz, NULL, key, rng) <= 0)
        return -1;
    return wc_SignCert(cert->bodySz, cert->sigType, der, (word32)der_sz,
                       NULL, key, rng);
#endif
}

/* Sign the (already populated) CSR into `der`. Returns the signed DER length,
 * or <= 0 on error. */
static inline int test_sign_certreq(Cert* req, uint8_t* der, int der_sz,
                                    test_signkey* key, WC_RNG* rng)
{
#if !defined(NO_RSA)
    if (wc_MakeCertReq(req, der, (word32)der_sz, key, NULL) <= 0)
        return -1;
    return wc_SignCert(req->bodySz, req->sigType, der, (word32)der_sz,
                       key, NULL, rng);
#else
    if (wc_MakeCertReq(req, der, (word32)der_sz, NULL, key) <= 0)
        return -1;
    return wc_SignCert(req->bodySz, req->sigType, der, (word32)der_sz,
                       NULL, key, rng);
#endif
}

/* Serialize the private key to DER. Returns DER length, or <= 0 on error. */
static inline int test_signkey_to_der(test_signkey* key, uint8_t* der,
                                      int der_sz)
{
#if !defined(NO_RSA)
    return wc_RsaKeyToDer(key, der, (word32)der_sz);
#else
    return wc_EccKeyToDer(key, der, (word32)der_sz);
#endif
}

/* Mint a self-signed cert + key (PEM) for common name `cn`. With is_ca == 0
 * the cert carries an iPAddress SAN for 127.0.0.1 (a usable TLS leaf); with
 * is_ca != 0 it is marked CA and carries no SAN. Returns 0 on success; the
 * caller frees *cert_pem / *key_pem with free(). */
static inline int mint_self_id(const char* cn, int is_ca,
                               uint8_t** cert_pem, size_t* cert_pem_len,
                               uint8_t** key_pem,  size_t* key_pem_len)
{
    static const uint8_t san_seq[] = { 0x30, 0x06, 0x87, 0x04, 127, 0, 0, 1 };
    test_signkey key;
    WC_RNG rng;
    Cert cert;
    uint8_t cder[8192];
    uint8_t cpem[16384];
    uint8_t kder[8192];
    uint8_t kpem[16384];
    int cs, cp, ks, kp;

    if (wc_InitRng(&rng) != 0)
        return -1;
    if (test_signkey_make(&key, &rng) != 0) {
        wc_FreeRng(&rng);
        return -1;
    }

    wc_InitCert(&cert);
    strcpy(cert.subject.commonName, cn);
    cert.selfSigned = 1;
    cert.sigType = TEST_CERT_SIGTYPE;
    cert.daysValid = 1;
    cert.isCA = is_ca ? 1 : 0;
    if (!is_ca) {
        memcpy(cert.altNames, san_seq, sizeof(san_seq));
        cert.altNamesSz = (int)sizeof(san_seq);
    }

    cs = test_sign_selfcert(&cert, cder, (int)sizeof(cder), &key, &rng);
    if (cs <= 0)
        goto fail;
    cp = wc_DerToPem(cder, (word32)cs, cpem, sizeof(cpem), CERT_TYPE);
    if (cp <= 0)
        goto fail;

    ks = test_signkey_to_der(&key, kder, (int)sizeof(kder));
    if (ks <= 0)
        goto fail;
    kp = wc_DerToPem(kder, (word32)ks, kpem, sizeof(kpem), TEST_KEY_PEM_TYPE);
    if (kp <= 0)
        goto fail;

    *cert_pem = (uint8_t*)malloc((size_t)cp);
    memcpy(*cert_pem, cpem, (size_t)cp);
    *cert_pem_len = (size_t)cp;
    *key_pem  = (uint8_t*)malloc((size_t)kp);
    memcpy(*key_pem,  kpem, (size_t)kp);
    *key_pem_len  = (size_t)kp;
    test_signkey_free(&key);
    wc_FreeRng(&rng);
    return 0;
fail:
    test_signkey_free(&key);
    wc_FreeRng(&rng);
    return -1;
}

/* Self-signed TLS server identity (cert + key, PEM) for 127.0.0.1. */
static inline int gen_server_identity(uint8_t** cert_pem, size_t* cert_pem_len,
                                      uint8_t** key_pem,  size_t* key_pem_len)
{
    return mint_self_id("127.0.0.1", 0, cert_pem, cert_pem_len,
                        key_pem, key_pem_len);
}

/* A raw TLS client against the in-tree test server, for the tests that need
 * to script byte-exact HTTP rather than go through wolfcert_est_*. Each
 * test_tls_write() becomes one TLS record and so one wolfSSL_read() on the
 * server, which is what the segmentation-sensitive framing tests rely on. */
typedef struct {
    WOLFSSL_CTX* ctx;
    WOLFSSL*     ssl;
    int          fd;
} TestTlsConn;

static inline void test_tls_close(TestTlsConn* c)
{
    if (c->ssl != NULL) {
        wolfSSL_shutdown(c->ssl);
        wolfSSL_free(c->ssl);
        c->ssl = NULL;
    }
    if (c->ctx != NULL) {
        wolfSSL_CTX_free(c->ctx);
        c->ctx = NULL;
    }
    if (c->fd >= 0) {
        close(c->fd);
        c->fd = -1;
    }
}

/* Everything up to the handshake: TCP is connected and the WOLFSSL is bound to
 * the socket, with `ca_pem` pinned as the sole trust anchor. */
static inline int test_tls_setup(TestTlsConn* c, uint16_t port,
                                 const uint8_t* ca_pem, size_t ca_pem_len)
{
    struct sockaddr_in sa = { 0 };

    memset(c, 0, sizeof(*c));
    c->fd = -1;

    c->ctx = wolfSSL_CTX_new(wolfTLS_client_method());
    if (c->ctx == NULL)
        return -1;

    if (wolfSSL_CTX_load_verify_buffer(c->ctx, ca_pem, (long)ca_pem_len,
                                       WOLFSSL_FILETYPE_PEM)
            != WOLFSSL_SUCCESS)
        goto fail;

    wolfSSL_CTX_set_verify(c->ctx, WOLFSSL_VERIFY_PEER, NULL);

    c->fd = socket(AF_INET, SOCK_STREAM, 0);
    if (c->fd < 0)
        goto fail;

    sa.sin_family = AF_INET;
    sa.sin_port   = htons(port);
    if (inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr) != 1)
        goto fail;
    if (connect(c->fd, (struct sockaddr*)&sa, sizeof(sa)) < 0)
        goto fail;

    c->ssl = wolfSSL_new(c->ctx);
    if (c->ssl == NULL)
        goto fail;

    if (wolfSSL_set_fd(c->ssl, c->fd) != WOLFSSL_SUCCESS)
        goto fail;

    return 0;
fail:
    test_tls_close(c);
    return -1;
}

/* Connect to 127.0.0.1:port and handshake, pinning `ca_pem` as the sole trust
 * anchor. Returns 0 on success; the caller closes with test_tls_close(). */
static inline int test_tls_connect(TestTlsConn* c, uint16_t port,
                                   const uint8_t* ca_pem, size_t ca_pem_len)
{
    if (test_tls_setup(c, port, ca_pem, ca_pem_len) != 0)
        return -1;

    if (wolfSSL_connect(c->ssl) != WOLFSSL_SUCCESS) {
        test_tls_close(c);
        return -1;
    }

    return 0;
}

/* Send the ClientHello and stop there, returning once the server's flight has
 * arrived -- proof that the server is inside wolfSSL_accept() awaiting the
 * rest of the handshake. Returns 0 on success, -1 on error or `timeout_ms`. */
static inline int test_tls_connect_partial(TestTlsConn* c, uint16_t port,
                                           const uint8_t* ca_pem,
                                           size_t ca_pem_len, int timeout_ms)
{
    struct pollfd pfd;
    int flags;
    int ret;

    if (test_tls_setup(c, port, ca_pem, ca_pem_len) != 0)
        return -1;

    flags = fcntl(c->fd, F_GETFL, 0);
    if (flags < 0 || fcntl(c->fd, F_SETFL, flags | O_NONBLOCK) < 0)
        goto fail;

    ret = wolfSSL_connect(c->ssl);
    if (ret == WOLFSSL_SUCCESS ||
            wolfSSL_get_error(c->ssl, ret) != WOLFSSL_ERROR_WANT_READ)
        goto fail;

    pfd.fd     = c->fd;
    pfd.events = POLLIN;
    if (poll(&pfd, 1, timeout_ms) != 1 || (pfd.revents & POLLIN) == 0)
        goto fail;

    return 0;
fail:
    test_tls_close(c);
    return -1;
}

/* Write `len` bytes as a single TLS record. Returns 0 on success. */
static inline int test_tls_write(TestTlsConn* c, const void* buf, size_t len)
{
    return wolfSSL_write(c->ssl, buf, (int)len) == (int)len ? 0 : -1;
}

/* One wolfSSL_read(). Returns the byte count, or <= 0 at close/error. */
static inline int test_tls_read(TestTlsConn* c, void* buf, size_t len)
{
    return wolfSSL_read(c->ssl, buf, (int)len);
}

#endif /* WOLFCERT_TLS_TEST_UTIL_H */
