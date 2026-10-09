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

/* SCEP pkiMessage build, parse and signer checks (RFC 8894). */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#define _DARWIN_C_SOURCE   /* expose memmem on macOS */
#define _GNU_SOURCE

#include <wolfcert/wolfcert.h>
#include "../test_static_mem.h"
#include "internal.h"

#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/pkcs7.h>
#include <wolfssl/wolfcrypt/rsa.h>
#ifdef HAVE_ECC
#include <wolfssl/wolfcrypt/ecc.h>
#endif
#include <wolfssl/wolfcrypt/random.h>
#ifndef NO_SHA
#include <wolfssl/wolfcrypt/sha.h>
#endif
#include <wolfssl/wolfcrypt/sha256.h>
#ifdef WOLFSSL_SHA512
#include <wolfssl/wolfcrypt/sha512.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define REQUIRE(cond) \
    do {                                                                    \
        if (!(cond)) {                                                      \
            fprintf(stderr, "FAIL %s:%d %s\n", __FILE__, __LINE__, #cond);  \
            return 1;                                                       \
        }                                                                   \
    } while (0)

/* Throwaway self-signed RSA CA cert and key, both DER; free with free(). */
static int make_ca(uint8_t** cert_out, size_t* cert_out_len,
                   uint8_t** key_out, size_t* key_out_len)
{
    RsaKey   key;
    WC_RNG   rng;
    Cert*    cert = NULL;
    uint8_t* cert_der = NULL;
    uint8_t* key_der  = NULL;
    int      ret  = 0;
    int      key_n = 0;
    int      cert_n = 0;

    if (wc_InitRng(&rng) != 0)
        return -1;
    if (wc_InitRsaKey(&key, NULL) != 0) {
        wc_FreeRng(&rng);
        return -1;
    }

    if (ret == 0 && wc_MakeRsaKey(&key, 2048, WC_RSA_EXPONENT, &rng) != 0)
        ret = -1;

    if (ret == 0) {
        key_der  = (uint8_t*)malloc(2048);
        cert_der = (uint8_t*)malloc(4096);
        if (key_der == NULL || cert_der == NULL)
            ret = -1;
    }

    if (ret == 0) {
        key_n = wc_RsaKeyToDer(&key, key_der, 2048);
        if (key_n <= 0)
            ret = -1;
    }

    if (ret == 0) {
        cert = wc_CertNew(NULL);
        if (cert == NULL)
            ret = -1;
    }

    if (ret == 0) {
        wc_InitCert_ex(cert, NULL, INVALID_DEVID);
        strncpy(cert->subject.commonName, "wolfCert Test CA", CTC_NAME_SIZE - 1);
        cert->subject.commonName[CTC_NAME_SIZE - 1] = '\0';
        cert->isCA       = 1;
        cert->selfSigned = 1;
        cert->sigType    = CTC_SHA256wRSA;
        cert->daysValid  = 2;

        cert_n = wc_MakeSelfCert(cert, cert_der, 4096, &key, &rng);
        if (cert_n <= 0)
            ret = -1;
    }

    if (ret == 0) {
        *key_out      = key_der;
        *key_out_len  = (size_t)key_n;
        *cert_out     = cert_der;
        *cert_out_len = (size_t)cert_n;
        key_der  = NULL;   /* ownership transferred */
        cert_der = NULL;
    }

    if (cert != NULL)
        wc_CertFree(cert);
    free(key_der);
    free(cert_der);
    wc_FreeRsaKey(&key);
    wc_FreeRng(&rng);
    return ret;
}

/* Issues a cert from the make_ca CA; `with_bc` 0 omits basic constraints.
 * Free *cert_out with free(). */
static int make_signed_cert(const uint8_t* ca_der, size_t ca_der_len,
                            const uint8_t* ca_key_der, size_t ca_key_len,
                            const char* cn, int is_ca, int with_bc,
                            uint8_t** cert_out, size_t* cert_out_len)
{
    RsaKey   ca_key;
    RsaKey   sub_key;
    WC_RNG   rng;
    Cert*    cert = NULL;
    uint8_t* der  = NULL;
    word32   idx  = 0;
    int      ret  = 0;
    int      body_n = 0;
    int      sign_n = 0;

    if (wc_InitRng(&rng) != 0)
        return -1;
    if (wc_InitRsaKey(&ca_key, NULL) != 0) {
        wc_FreeRng(&rng);
        return -1;
    }
    if (wc_InitRsaKey(&sub_key, NULL) != 0) {
        wc_FreeRsaKey(&ca_key);
        wc_FreeRng(&rng);
        return -1;
    }

    if (wc_RsaPrivateKeyDecode(ca_key_der, &idx, &ca_key,
                               (word32)ca_key_len) != 0)
        ret = -1;

    if (ret == 0 && wc_MakeRsaKey(&sub_key, 2048, WC_RSA_EXPONENT, &rng) != 0)
        ret = -1;

    if (ret == 0) {
        der = (uint8_t*)malloc(4096);
        if (der == NULL)
            ret = -1;
    }

    if (ret == 0) {
        cert = wc_CertNew(NULL);
        if (cert == NULL)
            ret = -1;
    }

    if (ret == 0) {
        wc_InitCert_ex(cert, NULL, INVALID_DEVID);
        strncpy(cert->subject.commonName, cn, CTC_NAME_SIZE - 1);
        cert->subject.commonName[CTC_NAME_SIZE - 1] = '\0';
        cert->isCA          = is_ca;
        cert->basicConstSet = with_bc;   /* CA:FALSE when is_ca is 0 */
        cert->selfSigned    = 0;
        cert->sigType    = CTC_SHA256wRSA;
        cert->daysValid  = 2;

        if (wc_SetIssuerBuffer(cert, ca_der, (int)ca_der_len) != 0)
            ret = -1;
    }

    if (ret == 0) {
        body_n = wc_MakeCert(cert, der, 4096, &sub_key, NULL, &rng);
        if (body_n <= 0)
            ret = -1;
    }

    if (ret == 0) {
        sign_n = wc_SignCert(cert->bodySz, cert->sigType, der, 4096, &ca_key,
                             NULL, &rng);
        if (sign_n <= 0)
            ret = -1;
    }

    if (ret == 0) {
        *cert_out     = der;
        *cert_out_len = (size_t)sign_n;
        der = NULL;   /* ownership transferred */
    }

    if (cert != NULL)
        wc_CertFree(cert);
    free(der);
    wc_FreeRsaKey(&sub_key);
    wc_FreeRsaKey(&ca_key);
    wc_FreeRng(&rng);
    return ret;
}

#ifdef HAVE_ECC
/* Throwaway self-signed ECC P-256 CA cert, DER; free with free(). */
static int make_ecc_ca(uint8_t** cert_out, size_t* cert_out_len)
{
    ecc_key  key;
    WC_RNG   rng;
    Cert*    cert = NULL;
    uint8_t* cert_der = NULL;
    int      ret = 0;
    int      body_n = 0;
    int      cert_n = 0;

    if (wc_InitRng(&rng) != 0)
        return -1;
    if (wc_ecc_init(&key) != 0) {
        wc_FreeRng(&rng);
        return -1;
    }

    if (ret == 0 && wc_ecc_make_key(&rng, 32, &key) != 0)   /* 32 bytes = P-256 */
        ret = -1;

    if (ret == 0) {
        cert_der = (uint8_t*)malloc(4096);
        if (cert_der == NULL)
            ret = -1;
    }

    if (ret == 0) {
        cert = wc_CertNew(NULL);
        if (cert == NULL)
            ret = -1;
    }

    if (ret == 0) {
        wc_InitCert_ex(cert, NULL, INVALID_DEVID);
        strncpy(cert->subject.commonName, "wolfCert Test ECC CA",
                CTC_NAME_SIZE - 1);
        cert->subject.commonName[CTC_NAME_SIZE - 1] = '\0';
        cert->isCA       = 1;
        cert->selfSigned = 1;
        cert->sigType    = CTC_SHA256wECDSA;
        cert->daysValid  = 2;

        body_n = wc_MakeCert(cert, cert_der, 4096, NULL, &key, &rng);
        if (body_n <= 0)
            ret = -1;
    }

    if (ret == 0) {
        cert_n = wc_SignCert(cert->bodySz, cert->sigType, cert_der, 4096,
                             NULL, &key, &rng);
        if (cert_n <= 0)
            ret = -1;
    }

    if (ret == 0) {
        *cert_out     = cert_der;
        *cert_out_len = (size_t)cert_n;
        cert_der = NULL;   /* ownership transferred */
    }

    if (cert != NULL)
        wc_CertFree(cert);
    free(cert_der);
    wc_ecc_free(&key);
    wc_FreeRng(&rng);
    return ret;
}

/* RFC 8894 is RSA-only, so an ECC RA cert gives WOLFCERT_ERR_UNSUPPORTED. */
static int test_envelop_rejects_ecc_ra(void)
{
    static const uint8_t payload[] = { 0x30, 0x03, 0x02, 0x01, 0x00 };
    uint8_t* ecc_ca      = NULL;
    size_t   ecc_ca_len  = 0;
    uint8_t* rsa_ca      = NULL;
    size_t   rsa_ca_len  = 0;
    uint8_t* rsa_key     = NULL;
    size_t   rsa_key_len = 0;
    WolfCertBuffer ecc_env = { 0 };
    WolfCertBuffer rsa_env = { 0 };
    int made_ecc, made_rsa;
    int ecc_rc = 0, rsa_rc = 0;
    int ecc_env_empty = 0, rsa_env_ok = 0;

    made_ecc = make_ecc_ca(&ecc_ca, &ecc_ca_len);
    made_rsa = make_ca(&rsa_ca, &rsa_ca_len, &rsa_key, &rsa_key_len);

    if (made_ecc == 0) {
        ecc_rc = wolfcert_scep_envelop(ecc_ca, ecc_ca_len, payload,
                                       sizeof(payload), AES128CBCb, &ecc_env,
                                       NULL);
        ecc_env_empty = (ecc_env.data == NULL);
    }
    if (made_rsa == 0) {
        rsa_rc = wolfcert_scep_envelop(rsa_ca, rsa_ca_len, payload,
                                       sizeof(payload), AES128CBCb, &rsa_env,
                                       NULL);
        rsa_env_ok = (rsa_env.data != NULL && rsa_env.len > 0);
    }

    /* Free everything before asserting so a failed REQUIRE cannot leak. */
    wolfcert_buffer_free(&ecc_env);
    wolfcert_buffer_free(&rsa_env);
    free(ecc_ca);
    free(rsa_ca);
    free(rsa_key);

    REQUIRE(made_ecc == 0);
    REQUIRE(made_rsa == 0);
    REQUIRE(ecc_rc == WOLFCERT_ERR_UNSUPPORTED);
    REQUIRE(ecc_env_empty);
    REQUIRE(rsa_rc == WOLFCERT_OK);
    REQUIRE(rsa_env_ok);
    return 0;
}
#endif /* HAVE_ECC */

/* A FAILURE CertRep signed with hash_oid has no pkcsPKIEnvelope. */
static int check_no_envelope(const uint8_t* ca_der, size_t ca_len,
                             const uint8_t* key_der, size_t key_len,
                             int hash_oid)
{
    /* pkcs7-envelopedData, OID 1.2.840.113549.1.7.3 */
    static const uint8_t ENVELOPED_OID[] =
        { 0x06,0x09,0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x07,0x03 };
    static const uint8_t tid[16] =
        { '0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F' };
    uint8_t sn[16];
    uint8_t rn[16];

    WolfCertScepAttrs attrs;
    WolfCertBuffer    pki = { 0 };
    WolfCertBuffer    env = { 0 };
    char*    status = NULL;
    char*    mt     = NULL;
    char*    rx_fi  = NULL;
    uint8_t* rx_tid = NULL;
    size_t   rx_tid_len = 0;
    uint8_t* rx_sn  = NULL;
    size_t   rx_sn_len = 0;
    uint8_t* rx_rn  = NULL;
    size_t   rx_rn_len = 0;
    int      prc;
    int      env_ok, status_ok, mt_ok, fi_ok;

    memset(sn, 0xA5, sizeof(sn));
    memset(rn, 0x5A, sizeof(rn));

    memset(&attrs, 0, sizeof(attrs));
    attrs.transaction_id     = tid;
    attrs.transaction_id_len = sizeof(tid);
    attrs.sender_nonce       = sn;
    attrs.sender_nonce_len   = sizeof(sn);
    attrs.recipient_nonce    = rn;
    attrs.recipient_nonce_len = sizeof(rn);
    attrs.message_type       = "3";
    attrs.pki_status         = "2";
    attrs.fail_info          = "2";

    REQUIRE(wolfcert_scep_build_pki_message(NULL, 0, ca_der, ca_len,
                                            key_der, key_len, hash_oid,
                                            &attrs, &pki, NULL) == WOLFCERT_OK);

    REQUIRE(memmem(pki.data, pki.len, ENVELOPED_OID,
                   sizeof(ENVELOPED_OID)) == NULL);

    prc = wolfcert_scep_parse_pki_message(pki.data, pki.len, &env,
            &rx_tid, &rx_tid_len, &rx_sn, &rx_sn_len, &rx_rn, &rx_rn_len,
            &mt, &status, NULL, NULL, &rx_fi, NULL);
    /* Free the parsed outputs before the REQUIREs so a failure cannot leak. */
    env_ok    = (env.len == 0 && env.data == NULL);
    status_ok = (status != NULL && strcmp(status, "2") == 0);
    mt_ok     = (mt != NULL && strcmp(mt, "3") == 0);
    fi_ok     = (rx_fi != NULL && strcmp(rx_fi, "2") == 0);

    wolfcert_buffer_free(&env);
    wolfcert_buffer_free(&pki);
    WOLFCERT_XFREE(status, NULL);
    WOLFCERT_XFREE(mt, NULL);
    WOLFCERT_XFREE(rx_fi, NULL);
    WOLFCERT_XFREE(rx_tid, NULL);
    WOLFCERT_XFREE(rx_sn, NULL);
    WOLFCERT_XFREE(rx_rn, NULL);

    REQUIRE(prc == WOLFCERT_OK);
    REQUIRE(env_ok);
    REQUIRE(status_ok);
    REQUIRE(mt_ok);
    REQUIRE(fi_ok);
    return 0;
}

static int test_non_success_has_no_envelope(void)
{
    uint8_t* ca_der  = NULL;
    size_t   ca_len  = 0;
    uint8_t* key_der = NULL;
    size_t   key_len = 0;
    int      rc;

    REQUIRE(make_ca(&ca_der, &ca_len, &key_der, &key_len) == 0);

    /* Signer digests SHA-256 and, where built, SHA-512. */
    rc = check_no_envelope(ca_der, ca_len, key_der, key_len, SHA256h);
#ifdef WOLFSSL_SHA512
    if (rc == 0)
        rc = check_no_envelope(ca_der, ca_len, key_der, key_len, SHA512h);
#endif

    free(ca_der);
    free(key_der);
    return rc;
}

/* RFC 8894 puts no length bound on transactionID, so 200 bytes round-trip. */
static int test_long_transaction_id(void)
{
    uint8_t* ca_der  = NULL;
    size_t   ca_len  = 0;
    uint8_t* key_der = NULL;
    size_t   key_len = 0;
    uint8_t  tid[200];
    uint8_t  sn[16];

    WolfCertScepAttrs attrs;
    WolfCertBuffer    pki = { 0 };
    WolfCertBuffer    env = { 0 };
    char*    status = NULL;
    char*    mt     = NULL;
    uint8_t* rx_tid = NULL;
    size_t   rx_tid_len = 0;
    uint8_t* rx_sn  = NULL;
    size_t   rx_sn_len = 0;
    int      prc, brc, tid_ok;

    REQUIRE(make_ca(&ca_der, &ca_len, &key_der, &key_len) == 0);

    /* Varying PrintableString characters so a truncated copy cannot match. */
    for (size_t i = 0; i < sizeof(tid); ++i)
        tid[i] = (uint8_t)('A' + (i % 26));
    memset(sn, 0xA5, sizeof(sn));

    memset(&attrs, 0, sizeof(attrs));
    attrs.transaction_id     = tid;
    attrs.transaction_id_len = sizeof(tid);
    attrs.sender_nonce       = sn;
    attrs.sender_nonce_len   = sizeof(sn);
    attrs.message_type       = "19";

    brc = wolfcert_scep_build_pki_message(NULL, 0, ca_der, ca_len,
                                          key_der, key_len, SHA256h,
                                          &attrs, &pki, NULL);
    if (brc == WOLFCERT_OK)
        prc = wolfcert_scep_parse_pki_message(pki.data, pki.len, &env,
                &rx_tid, &rx_tid_len, &rx_sn, &rx_sn_len, NULL, NULL,
                &mt, &status, NULL, NULL, NULL, NULL);
    else
        prc = brc;

    tid_ok = (rx_tid != NULL && rx_tid_len == sizeof(tid) &&
              memcmp(rx_tid, tid, sizeof(tid)) == 0);

    wolfcert_buffer_free(&env);
    wolfcert_buffer_free(&pki);
    WOLFCERT_XFREE(status, NULL);
    WOLFCERT_XFREE(mt, NULL);
    WOLFCERT_XFREE(rx_tid, NULL);
    WOLFCERT_XFREE(rx_sn, NULL);
    free(ca_der);
    free(key_der);

    REQUIRE(brc == WOLFCERT_OK);
    REQUIRE(prc == WOLFCERT_OK);
    REQUIRE(tid_ok);
    return 0;
}

/* Signed PKCS#10 CSR with a multi-RDN subject, DER; free with free(). */
static int make_csr(RsaKey* key, WC_RNG* rng, const char* cn, const char* org,
                    uint8_t** csr_out, size_t* csr_out_len)
{
    Cert*    req = NULL;
    uint8_t* der = NULL;
    int      ret = 0;
    int      body_n = 0;
    int      sign_n = 0;

    req = wc_CertNew(NULL);
    if (req == NULL)
        return -1;

    wc_InitCert_ex(req, NULL, INVALID_DEVID);
    strncpy(req->subject.commonName, cn, CTC_NAME_SIZE - 1);
    req->subject.commonName[CTC_NAME_SIZE - 1] = '\0';
    strncpy(req->subject.org, org, CTC_NAME_SIZE - 1);
    req->subject.org[CTC_NAME_SIZE - 1] = '\0';
    req->sigType = CTC_SHA256wRSA;

    der = (uint8_t*)malloc(4096);
    if (der == NULL)
        ret = -1;

    if (ret == 0) {
        body_n = wc_MakeCertReq(req, der, 4096, key, NULL);
        if (body_n <= 0)
            ret = -1;
    }

    if (ret == 0) {
        sign_n = wc_SignCert(body_n, CTC_SHA256wRSA, der, 4096, key, NULL, rng);
        if (sign_n <= 0)
            ret = -1;
    }

    if (ret == 0) {
        *csr_out     = der;
        *csr_out_len = (size_t)sign_n;
        der = NULL;   /* ownership transferred */
    }

    if (req != NULL)
        wc_CertFree(req);
    free(der);
    return ret;
}

/* RFC 8894 section 2.3: the signer cert's subject equals the CSR's. */
static int test_signer_subject_matches_csr(void)
{
    RsaKey      key;
    WC_RNG      rng;
    uint8_t*    csr_der    = NULL;
    size_t      csr_len    = 0;
    uint8_t*    signer_der = NULL;
    size_t      signer_len = 0;
    DecodedCert csr_dc;
    DecodedCert sgn_dc;
    int         rc = 0;

    REQUIRE(wc_InitRng(&rng) == 0);
    REQUIRE(wc_InitRsaKey(&key, NULL) == 0);
    REQUIRE(wc_MakeRsaKey(&key, 2048, WC_RSA_EXPONENT, &rng) == 0);

    REQUIRE(make_csr(&key, &rng, "device-4711.example.org", "Widgets Inc",
                     &csr_der, &csr_len) == 0);

    REQUIRE(wolfcert_scep_self_signed_rsa(&key, csr_der, csr_len,
                                          &signer_der, &signer_len, NULL)
            == WOLFCERT_OK);

    wc_InitDecodedCert(&csr_dc, csr_der, (word32)csr_len, NULL);
    REQUIRE(wc_ParseCert(&csr_dc, CERTREQ_TYPE, NO_VERIFY, NULL) == 0);

    wc_InitDecodedCert(&sgn_dc, signer_der, (word32)signer_len, NULL);
    REQUIRE(wc_ParseCert(&sgn_dc, CERT_TYPE, NO_VERIFY, NULL) == 0);

    if (sgn_dc.subjectRaw == NULL || csr_dc.subjectRaw == NULL ||
            sgn_dc.subjectRawLen != csr_dc.subjectRawLen ||
            memcmp(sgn_dc.subjectRaw, csr_dc.subjectRaw,
                   (size_t)csr_dc.subjectRawLen) != 0) {
        rc = 1;
    }

    wc_FreeDecodedCert(&csr_dc);
    wc_FreeDecodedCert(&sgn_dc);
    WOLFCERT_XFREE(signer_der, NULL);
    free(csr_der);
    wc_FreeRsaKey(&key);
    wc_FreeRng(&rng);

    REQUIRE(rc == 0);
    return 0;
}

/* RFC 8894 section 1: the transient self-signed signer certificate must carry a
 * keyUsage extension asserting digitalSignature and keyEncipherment. */
static int test_signer_key_usage(void)
{
    RsaKey      key;
    WC_RNG      rng;
    uint8_t*    csr_der    = NULL;
    size_t      csr_len    = 0;
    uint8_t*    signer_der = NULL;
    size_t      signer_len = 0;
    DecodedCert dc;
    int         rc = 0;

    REQUIRE(wc_InitRng(&rng) == 0);
    REQUIRE(wc_InitRsaKey(&key, NULL) == 0);
    REQUIRE(wc_MakeRsaKey(&key, 2048, WC_RSA_EXPONENT, &rng) == 0);

    REQUIRE(make_csr(&key, &rng, "device-9799.example.org", "Widgets Inc",
                     &csr_der, &csr_len) == 0);

    REQUIRE(wolfcert_scep_self_signed_rsa(&key, csr_der, csr_len,
                                          &signer_der, &signer_len, NULL)
            == WOLFCERT_OK);

    wc_InitDecodedCert(&dc, signer_der, (word32)signer_len, NULL);
    REQUIRE(wc_ParseCert(&dc, CERT_TYPE, NO_VERIFY, NULL) == 0);

    if (dc.extKeyUsageSet == 0 ||
            (dc.extKeyUsage & KEYUSE_DIGITAL_SIG) == 0 ||
            (dc.extKeyUsage & KEYUSE_KEY_ENCIPHER) == 0) {
        rc = 1;
    }

    wc_FreeDecodedCert(&dc);
    WOLFCERT_XFREE(signer_der, NULL);
    free(csr_der);
    wc_FreeRsaKey(&key);
    wc_FreeRng(&rng);

    REQUIRE(rc == 0);
    return 0;
}

/* Content of the DER SEQUENCE at `p`, or NULL when it is not one or does not
 * fit in `len`. `content_len` and `total` receive the content and TLV sizes. */
static const uint8_t* seq_content(const uint8_t* p, size_t len,
                                  size_t* content_len, size_t* total)
{
    size_t hdr;
    size_t clen;
    size_t nb;
    size_t i;

    if (len < 2 || p[0] != 0x30)
        return NULL;

    if ((p[1] & 0x80) == 0) {
        hdr  = 2;
        clen = p[1];
    }
    else {
        nb = (size_t)(p[1] & 0x7F);
        if (nb == 0 || nb > 4 || len < 2 + nb)
            return NULL;

        clen = 0;
        for (i = 0; i < nb; i++)
            clen = (clen << 8) | p[2 + i];
        hdr = 2 + nb;
    }

    if (clen > len - hdr)
        return NULL;

    *content_len = clen;
    *total       = hdr + clen;
    return p + hdr;
}

/* The IssuerAndSubject for `ra_der` names `name_der`'s subject as issuer
 * and the CSR's subject as subject. */
static int check_issuer_and_subject(const uint8_t* ra_der, size_t ra_len,
                                    const uint8_t* name_der, size_t name_len,
                                    const uint8_t* csr_der, size_t csr_len)
{
    WolfCertBuffer ias = { 0 };
    DecodedCert    nc;
    DecodedCert    sc;
    const uint8_t* outer = NULL;
    const uint8_t* dn    = NULL;
    size_t         outer_len = 0;
    size_t         dn_len    = 0;
    size_t         total     = 0;
    size_t         total2    = 0;
    int            rc  = 0;

    if (wolfcert_scep_issuer_and_subject(ra_der, ra_len, csr_der, csr_len,
                                         &ias, NULL) != WOLFCERT_OK)
        return 1;

    wc_InitDecodedCert(&nc, name_der, (word32)name_len, NULL);
    wc_InitDecodedCert(&sc, csr_der, (word32)csr_len, NULL);

    if (wc_ParseCert(&nc, CERT_TYPE, NO_VERIFY, NULL) != 0 ||
            wc_ParseCert(&sc, CERTREQ_TYPE, NO_VERIFY, NULL) != 0)
        rc = 1;

    if (rc == 0 && (nc.subjectRaw == NULL || nc.subjectRawLen <= 0 ||
                    sc.subjectRaw == NULL || sc.subjectRawLen <= 0))
        rc = 1;

    /* SEQUENCE { issuer Name, subject Name }, nothing before or after. */
    if (rc == 0) {
        outer = seq_content(ias.data, ias.len, &outer_len, &total);
        if (outer == NULL || total != ias.len)
            rc = 1;
    }

    if (rc == 0) {
        dn = seq_content(outer, outer_len, &dn_len, &total);
        if (dn == NULL || dn_len != (size_t)nc.subjectRawLen ||
                memcmp(dn, nc.subjectRaw, dn_len) != 0)
            rc = 1;
    }

    if (rc == 0) {
        dn = seq_content(outer + total, outer_len - total, &dn_len, &total2);
        if (dn == NULL || dn_len != (size_t)sc.subjectRawLen ||
                memcmp(dn, sc.subjectRaw, dn_len) != 0)
            rc = 1;
        else if (total + total2 != outer_len)
            rc = 1;
    }

    wc_FreeDecodedCert(&nc);
    wc_FreeDecodedCert(&sc);
    wolfcert_buffer_free(&ias);
    return rc;
}

/* rc is BAD_ARG and r is UNSET with no cert, no tid, fail_info -1 and a
 * NULL heap. */
static int check_result_defined(const char* what, int rc, const WolfCertScepResult* r)
{
    if (rc != WOLFCERT_ERR_BAD_ARG) {
        fprintf(stderr, "FAIL %s: expected BAD_ARG, got %d\n", what, rc);
        return 1;
    }
    if (r->status != WOLFCERT_SCEP_STATUS_UNSET || r->cert_pem.data != NULL ||
            r->cert_pem.len != 0 || r->transaction_id != NULL ||
            r->transaction_id_len != 0 || r->fail_info != -1 || r->heap != NULL) {
        fprintf(stderr, "FAIL %s: result left indeterminate\n", what);
        return 1;
    }
    return 0;
}

/* OPENSSL_EXTRA's GetCertName reports a failed X509_NAME allocation as
 * ASN_PARSE_E, indistinguishable from a bad certificate. */
#if defined(USE_WOLFSSL_MEMORY) && !defined(WOLFSSL_STATIC_MEMORY) && \
    !defined(WOLFSSL_DEBUG_MEMORY) && !defined(OPENSSL_EXTRA) && \
    !defined(OPENSSL_EXTRA_X509_SMALL)
#define TEST_ALLOC_FAILURES
#endif

#ifdef TEST_ALLOC_FAILURES
/* Allocations left before failing_malloc() returns NULL; -1 never fails. */
static int g_allocs_left = -1;

static void* failing_malloc(size_t sz)
{
    if (g_allocs_left == 0)
        return NULL;
    if (g_allocs_left > 0)
        g_allocs_left--;
    return malloc(sz);
}

static void failing_free(void* ptr)
{
    free(ptr);
}

static void* failing_realloc(void* ptr, size_t sz)
{
    if (g_allocs_left == 0)
        return NULL;
    if (g_allocs_left > 0)
        g_allocs_left--;
    return realloc(ptr, sz);
}

/* Failing each allocation in turn must give WOLFCERT_ERR_MEMORY or a match. */
static int pem_has_cert_reports_oom(const char* pem, size_t pem_len,
                                    const DecodedCert* lc)
{
    wolfSSL_Malloc_cb  mf;
    wolfSSL_Free_cb    ff;
    wolfSSL_Realloc_cb rf;
    int fails;
    int rc = 0;

    REQUIRE(wolfSSL_GetAllocators(&mf, &ff, &rf) == 0);
    for (fails = 0; rc != 1; fails++) {
        g_allocs_left = fails;
        REQUIRE(wolfSSL_SetAllocators(failing_malloc, failing_free,
                                      failing_realloc) == 0);
        rc = wolfcert_scep_pem_has_cert((const uint8_t*)pem, pem_len,
                                        lc->issuerRaw,
                                        (size_t)lc->issuerRawLen, lc->serial,
                                        (size_t)lc->serialSz, NULL);
        REQUIRE(wolfSSL_SetAllocators(mf, ff, rf) == 0);
        g_allocs_left = -1;
        if (rc != 1 && rc != WOLFCERT_ERR_MEMORY) {
            fprintf(stderr, "FAIL pem_has_cert with allocation %d failing: "
                    "%d\n", fails, rc);
            return 1;
        }
    }
    REQUIRE(fails > 1);
    return 0;
}

static int rep_signer_reports_oom(const uint8_t* signer, size_t signer_len,
                                  const uint8_t* bundle, size_t bundle_len)
{
    wolfSSL_Malloc_cb  mf;
    wolfSSL_Free_cb    ff;
    wolfSSL_Realloc_cb rf;
    int fails;
    int rc = WOLFCERT_ERR_MEMORY;

    REQUIRE(wolfSSL_GetAllocators(&mf, &ff, &rf) == 0);
    for (fails = 0; rc != WOLFCERT_OK; fails++) {
        g_allocs_left = fails;
        REQUIRE(wolfSSL_SetAllocators(failing_malloc, failing_free,
                                      failing_realloc) == 0);
        rc = wolfcert_scep_verify_rep_signer(signer, signer_len, bundle,
                                             bundle_len, NULL);
        REQUIRE(wolfSSL_SetAllocators(mf, ff, rf) == 0);
        g_allocs_left = -1;
        if (rc != WOLFCERT_OK && rc != WOLFCERT_ERR_MEMORY) {
            fprintf(stderr, "FAIL verify_rep_signer with allocation %d "
                    "failing: %d\n", fails, rc);
            return 1;
        }
    }
    REQUIRE(fails > 1);
    return 0;
}
#endif

/* A leaf's issuer and serial give 1 against its PEM, also behind a junk
 * entry; a wrong serial or issuer, or a NULL or truncated input, give 0. */
static int test_pem_has_cert(void)
{
    uint8_t* ca_der     = NULL;
    size_t   ca_len     = 0;
    uint8_t* ca_key_der = NULL;
    size_t   ca_key_len = 0;
    uint8_t* leaf_der   = NULL;
    size_t   leaf_len   = 0;
    static const char JUNK[] =
        "-----BEGIN CERTIFICATE-----\nZZZZ not base64 at all\n"
        "-----END CERTIFICATE-----\n";
    static char pem[8192];
    static char bundle[16384];
    int n;

    REQUIRE(make_ca(&ca_der, &ca_len, &ca_key_der, &ca_key_len) == 0);
    REQUIRE(make_signed_cert(ca_der, ca_len, ca_key_der, ca_key_len,
                             "leaf-pem-has-cert", 0, 1, &leaf_der, &leaf_len) == 0);

    DecodedCert lc;
    wc_InitDecodedCert(&lc, leaf_der, (word32)leaf_len, NULL);
    REQUIRE(wc_ParseCert(&lc, CERT_TYPE, NO_VERIFY, NULL) == 0);
    REQUIRE(lc.serialSz > 0 && lc.issuerRawLen > 0);

    n = wc_DerToPem(leaf_der, (word32)leaf_len, (byte*)pem, sizeof(pem), CERT_TYPE);
    REQUIRE(n > 0);

    REQUIRE(wolfcert_scep_pem_has_cert((const uint8_t*)pem, (size_t)n,
                                       lc.issuerRaw, (size_t)lc.issuerRawLen,
                                       lc.serial, (size_t)lc.serialSz, NULL) == 1);
#ifdef TEST_ALLOC_FAILURES
    REQUIRE(pem_has_cert_reports_oom(pem, (size_t)n, &lc) == 0);
#endif

    /* Behind an unparseable entry it must still be found. */
    REQUIRE((size_t)n + sizeof(JUNK) < sizeof(bundle));
    memcpy(bundle, JUNK, sizeof(JUNK) - 1);
    memcpy(bundle + sizeof(JUNK) - 1, pem, (size_t)n);
    REQUIRE(wolfcert_scep_pem_has_cert((const uint8_t*)bundle,
                                       sizeof(JUNK) - 1 + (size_t)n,
                                       lc.issuerRaw, (size_t)lc.issuerRawLen,
                                       lc.serial, (size_t)lc.serialSz, NULL) == 1);

    /* A wrong serial and a wrong issuer each fail to match. */
    {
        uint8_t bad_serial[32];
        uint8_t bad_issuer[512];

        REQUIRE((size_t)lc.serialSz <= sizeof(bad_serial));
        memcpy(bad_serial, lc.serial, (size_t)lc.serialSz);
        bad_serial[lc.serialSz - 1] ^= 0xFF;
        REQUIRE(wolfcert_scep_pem_has_cert((const uint8_t*)pem, (size_t)n,
                                           lc.issuerRaw, (size_t)lc.issuerRawLen,
                                           bad_serial, (size_t)lc.serialSz,
                                           NULL) == 0);

        REQUIRE((size_t)lc.issuerRawLen <= sizeof(bad_issuer));
        memcpy(bad_issuer, lc.issuerRaw, (size_t)lc.issuerRawLen);
        bad_issuer[lc.issuerRawLen - 1] ^= 0xFF;
        REQUIRE(wolfcert_scep_pem_has_cert((const uint8_t*)pem, (size_t)n,
                                           bad_issuer, (size_t)lc.issuerRawLen,
                                           lc.serial, (size_t)lc.serialSz,
                                           NULL) == 0);
    }

    /* Degenerate inputs are refused without forming a pointer past the end. */
    REQUIRE(wolfcert_scep_pem_has_cert(NULL, 0, lc.issuerRaw,
                                       (size_t)lc.issuerRawLen, lc.serial,
                                       (size_t)lc.serialSz, NULL) == 0);
    REQUIRE(wolfcert_scep_pem_has_cert((const uint8_t*)pem, 4, lc.issuerRaw,
                                       (size_t)lc.issuerRawLen, lc.serial,
                                       (size_t)lc.serialSz, NULL) == 0);
    REQUIRE(wolfcert_scep_pem_has_cert((const uint8_t*)pem, (size_t)n, NULL, 0,
                                       lc.serial, (size_t)lc.serialSz,
                                       NULL) == 0);

    wc_FreeDecodedCert(&lc);
    free(ca_der);
    free(ca_key_der);
    free(leaf_der);
    return 0;
}

static int test_zero_length_args_rejected(void)
{
    WolfCertScepResult r;
    WolfCertScepCaps   caps = { 0 };
    WolfCertServerCfg  srv  = { .protocol = WOLFCERT_PROTO_SCEP,
                                .server_url = "http://127.0.0.1:1/scep" };
    uint8_t            blob[4] = { 1, 2, 3, 4 };
    WolfCertKey*       key = NULL;
    WolfCertKeyCfg     kcfg = { .type = WOLFCERT_KEY_RSA, .param = 2048,
                                .dev_id = WOLFCERT_DEVID_SOFTWARE };

    REQUIRE(wolfcert_key_generate(&kcfg, &key) == WOLFCERT_OK);

#define REJECTS(what, call)                                \
    do {                                                   \
        if ((call) != WOLFCERT_ERR_BAD_ARG) {              \
            printf("FAIL %s: zero length accepted\n", what); \
            wolfcert_key_free(key);                        \
            return 1;                                      \
        }                                                  \
        wolfcert_scep_result_free(&r);                     \
    } while (0)

    REJECTS("pkcs_req_ex ra_cert_len",
        wolfcert_scep_pkcs_req_ex(&srv, &caps, blob, 0,
                                  blob, sizeof(blob), key, blob, sizeof(blob), &r));
    REJECTS("pkcs_req_ex ca_bundle_len",
        wolfcert_scep_pkcs_req_ex(&srv, &caps, blob, sizeof(blob),
                                  blob, 0, key, blob, sizeof(blob), &r));
    REJECTS("pkcs_req_ex csr_der_len",
        wolfcert_scep_pkcs_req_ex(&srv, &caps, blob, sizeof(blob),
                                  blob, sizeof(blob), key, blob, 0, &r));

    REJECTS("renewal_req_ex ra_cert_len",
        wolfcert_scep_renewal_req_ex(&srv, &caps, blob, 0,
                                     blob, sizeof(blob), blob, sizeof(blob),
                                     key, blob, sizeof(blob), &r));
    REJECTS("renewal_req_ex ca_bundle_len",
        wolfcert_scep_renewal_req_ex(&srv, &caps, blob, sizeof(blob),
                                     blob, 0, blob, sizeof(blob),
                                     key, blob, sizeof(blob), &r));
    REJECTS("renewal_req_ex current_cert_len",
        wolfcert_scep_renewal_req_ex(&srv, &caps, blob, sizeof(blob),
                                     blob, sizeof(blob), blob, 0,
                                     key, blob, sizeof(blob), &r));
    REJECTS("renewal_req_ex csr_der_len",
        wolfcert_scep_renewal_req_ex(&srv, &caps, blob, sizeof(blob),
                                     blob, sizeof(blob), blob, sizeof(blob),
                                     key, blob, 0, &r));

    REJECTS("get_cert_initial ra_cert_len",
        wolfcert_scep_get_cert_initial(&srv, &caps, blob, 0,
                                       blob, sizeof(blob), blob, sizeof(blob),
                                       key, blob, sizeof(blob),
                                       blob, sizeof(blob), &r));
    REJECTS("get_cert_initial ca_bundle_len",
        wolfcert_scep_get_cert_initial(&srv, &caps, blob, sizeof(blob),
                                       blob, 0, blob, sizeof(blob),
                                       key, blob, sizeof(blob),
                                       blob, sizeof(blob), &r));
    REJECTS("get_cert_initial csr_der_len",
        wolfcert_scep_get_cert_initial(&srv, &caps, blob, sizeof(blob),
                                       blob, sizeof(blob), blob, sizeof(blob),
                                       key, blob, 0,
                                       blob, sizeof(blob), &r));
    /* signer_cert stays optional, but a non-NULL one must carry bytes. */
    REJECTS("get_cert_initial signer_cert_len",
        wolfcert_scep_get_cert_initial(&srv, &caps, blob, sizeof(blob),
                                       blob, sizeof(blob), blob, 0,
                                       key, blob, sizeof(blob),
                                       blob, sizeof(blob), &r));
#undef REJECTS

    wolfcert_key_free(key);
    return 0;
}

static int test_result_defined_on_early_return(void)
{
    WolfCertScepResult r;
    WolfCertScepCaps   caps = { 0 };
    uint8_t            blob[4] = { 1, 2, 3, 4 };
    WolfCertKey*       key = NULL;
    WolfCertKeyCfg     kcfg = { .type = WOLFCERT_KEY_RSA, .param = 2048,
                                .dev_id = WOLFCERT_DEVID_SOFTWARE };

    REQUIRE(wolfcert_key_generate(&kcfg, &key) == WOLFCERT_OK);

#define POISON_AND_CALL(what, call)                        \
    do {                                                   \
        memset(&r, 0xA5, sizeof(r));                       \
        if (check_result_defined(what, (call), &r)) {      \
            wolfcert_key_free(key);                        \
            return 1;                                      \
        }                                                  \
        wolfcert_scep_result_free(&r);                     \
    } while (0)

    /* One-shot entry points with a NULL srv. */
    POISON_AND_CALL("pkcs_req_ex",
        wolfcert_scep_pkcs_req_ex(NULL, &caps, blob, sizeof(blob),
                                  blob, sizeof(blob), key, blob, sizeof(blob), &r));
    POISON_AND_CALL("renewal_req_ex",
        wolfcert_scep_renewal_req_ex(NULL, &caps, blob, sizeof(blob),
                                     blob, sizeof(blob), blob, sizeof(blob),
                                     key, blob, sizeof(blob), &r));
    POISON_AND_CALL("get_cert_initial",
        wolfcert_scep_get_cert_initial(NULL, &caps, blob, sizeof(blob),
                                       blob, sizeof(blob), blob, sizeof(blob),
                                       key, blob, sizeof(blob),
                                       blob, sizeof(blob), &r));
    POISON_AND_CALL("get_cert",
        wolfcert_scep_get_cert(NULL, &caps, blob, sizeof(blob),
                               blob, sizeof(blob), blob, sizeof(blob),
                               key, blob, sizeof(blob), &r));

    /* Session entry points with a NULL session. */
    POISON_AND_CALL("session_pkcs_req_ex",
        wolfcert_scep_session_pkcs_req_ex(NULL, &caps, blob, sizeof(blob),
                                          blob, sizeof(blob), key,
                                          blob, sizeof(blob), &r));
    POISON_AND_CALL("session_pkcs_req_nb",
        wolfcert_scep_session_pkcs_req_nb(NULL, &caps, blob, sizeof(blob),
                                          blob, sizeof(blob), key,
                                          blob, sizeof(blob), &r));
    POISON_AND_CALL("session_renewal_req_ex",
        wolfcert_scep_session_renewal_req_ex(NULL, &caps, blob, sizeof(blob),
                                             blob, sizeof(blob), blob, sizeof(blob),
                                             key, blob, sizeof(blob), &r));
    POISON_AND_CALL("session_renewal_req_nb",
        wolfcert_scep_session_renewal_req_nb(NULL, &caps, blob, sizeof(blob),
                                             blob, sizeof(blob), blob, sizeof(blob),
                                             key, blob, sizeof(blob), &r));
    POISON_AND_CALL("session_get_cert_initial_ex",
        wolfcert_scep_session_get_cert_initial_ex(NULL, &caps, blob, sizeof(blob),
                                                  blob, sizeof(blob), blob, sizeof(blob),
                                                  key, blob, sizeof(blob),
                                                  blob, sizeof(blob), &r));
    POISON_AND_CALL("session_get_cert_initial_nb",
        wolfcert_scep_session_get_cert_initial_nb(NULL, &caps, blob, sizeof(blob),
                                                  blob, sizeof(blob), blob, sizeof(blob),
                                                  key, blob, sizeof(blob),
                                                  blob, sizeof(blob), &r));
#undef POISON_AND_CALL

    /* A NULL result is still rejected without a dereference. */
    REQUIRE(wolfcert_scep_get_cert(NULL, &caps, blob, sizeof(blob),
                                   blob, sizeof(blob), blob, sizeof(blob),
                                   key, blob, sizeof(blob),
                                   NULL) == WOLFCERT_ERR_BAD_ARG);

    wolfcert_key_free(key);
    return 0;
}

/* IssuerAndSerialNumber round trip for a leaf, high-bit and padded serial;
 * truncated or trailing bytes fail to parse. */
static int test_issuer_and_serial(void)
{
    uint8_t* ca_der     = NULL;
    size_t   ca_len     = 0;
    uint8_t* ca_key_der = NULL;
    size_t   ca_key_len = 0;
    uint8_t* leaf_der   = NULL;
    size_t   leaf_len   = 0;
    uint8_t* other_der  = NULL;
    size_t   other_len  = 0;

    REQUIRE(make_ca(&ca_der, &ca_len, &ca_key_der, &ca_key_len) == 0);
    /* make_ca gives every CA the same DN, so a distinct name needs its own CN. */
    REQUIRE(make_signed_cert(ca_der, ca_len, ca_key_der, ca_key_len,
                             "unrelated-ca", 1, 1, &other_der, &other_len) == 0);
    REQUIRE(make_signed_cert(ca_der, ca_len, ca_key_der, ca_key_len,
                             "leaf-getcert", 0, 1, &leaf_der, &leaf_len) == 0);

    DecodedCert lc;
    wc_InitDecodedCert(&lc, leaf_der, (word32)leaf_len, NULL);
    REQUIRE(wc_ParseCert(&lc, CERT_TYPE, NO_VERIFY, NULL) == 0);
    REQUIRE(lc.serialSz > 0);

    DecodedCert cc;
    wc_InitDecodedCert(&cc, ca_der, (word32)ca_len, NULL);
    REQUIRE(wc_ParseCert(&cc, CERT_TYPE, NO_VERIFY, NULL) == 0);

    WolfCertBuffer ias = { 0 };
    REQUIRE(wolfcert_scep_issuer_and_serial(ca_der, ca_len,
                                            lc.serial, (size_t)lc.serialSz,
                                            &ias, NULL) == WOLFCERT_OK);

    /* SEQUENCE { issuer Name, serialNumber }, nothing before or after. */
    size_t outer_len = 0;
    size_t total     = 0;
    const uint8_t* outer = seq_content(ias.data, ias.len, &outer_len, &total);
    REQUIRE(outer != NULL);
    REQUIRE(total == ias.len);

    size_t dn_len = 0;
    const uint8_t* dn = seq_content(outer, outer_len, &dn_len, &total);
    REQUIRE(dn != NULL);
    REQUIRE(dn_len == (size_t)cc.subjectRawLen);
    REQUIRE(memcmp(dn, cc.subjectRaw, dn_len) == 0);

    /* A DER INTEGER serial, sign-padded if bit 8 is set, ends the SEQUENCE. */
    size_t pad = (lc.serial[0] & 0x80) ? 1 : 0;
    REQUIRE(outer[total] == 0x02);
    REQUIRE(outer[total + 1] == (uint8_t)((size_t)lc.serialSz + pad));
    if (pad)
        REQUIRE(outer[total + 2] == 0x00);
    REQUIRE(memcmp(outer + total + 2 + pad, lc.serial, (size_t)lc.serialSz) == 0);
    REQUIRE(total + 2 + pad + (size_t)lc.serialSz == outer_len);

    const uint8_t* got = NULL;
    size_t got_len = 0;
    const uint8_t* got_iss = NULL;
    size_t got_iss_len = 0;
    REQUIRE(wolfcert_scep_parse_issuer_and_serial(ias.data, ias.len,
                                                  &got_iss, &got_iss_len,
                                                  &got, &got_len) == WOLFCERT_OK);
    REQUIRE(got_len == (size_t)lc.serialSz);
    REQUIRE(memcmp(got, lc.serial, got_len) == 0);

    /* The issuer Name comes back too, and is the CA's own. */
    REQUIRE(got_iss_len == (size_t)cc.subjectRawLen);
    REQUIRE(memcmp(got_iss, cc.subjectRaw, got_iss_len) == 0);
    REQUIRE(wolfcert_scep_issuer_name_matches(ca_der, ca_len, got_iss,
                                              got_iss_len, NULL));
    /* The leaf names the same CA as issuer; only the unrelated CA fails. */
    REQUIRE(wolfcert_scep_issuer_name_matches(leaf_der, leaf_len, got_iss,
                                              got_iss_len, NULL));
    REQUIRE(!wolfcert_scep_issuer_name_matches(other_der, other_len, got_iss,
                                               got_iss_len, NULL));

    /* A truncated encoding is rejected rather than read past the end. */
    REQUIRE(wolfcert_scep_parse_issuer_and_serial(ias.data, ias.len - 1,
                                                  &got_iss, &got_iss_len,
                                                  &got, &got_len) != WOLFCERT_OK);
    REQUIRE(wolfcert_scep_issuer_and_serial(ca_der, ca_len, lc.serial, 0,
                                            &ias, NULL) == WOLFCERT_ERR_BAD_ARG);

    /* Hand-built, since wolfSSL never generates a high-bit serial. The sign
     * pad is not in DecodedCert.serial, so 8A 01 02 must re-encode with 00. */
    static const uint8_t high_bit[3] = { 0x8A, 0x01, 0x02 };
    WolfCertBuffer hb = { 0 };
    REQUIRE(wolfcert_scep_issuer_and_serial(ca_der, ca_len, high_bit,
                                            sizeof(high_bit), &hb,
                                            NULL) == WOLFCERT_OK);
    REQUIRE(wolfcert_scep_parse_issuer_and_serial(hb.data, hb.len,
                                                  &got_iss, &got_iss_len,
                                                  &got, &got_len) == WOLFCERT_OK);
    REQUIRE(got_len == sizeof(high_bit));
    REQUIRE(memcmp(got, high_bit, got_len) == 0);
    REQUIRE(got[-1] == 0x00);
    REQUIRE(got[-2] == (uint8_t)(sizeof(high_bit) + 1));

    /* Anything after the serialNumber means this is not an IssuerAndSerial. */
    uint8_t* trailing = (uint8_t*)malloc(hb.len + 2);
    REQUIRE(trailing != NULL);
    memcpy(trailing, hb.data, hb.len);
    trailing[hb.len]     = 0x05;   /* a NULL element the structure has no room for */
    trailing[hb.len + 1] = 0x00;
    trailing[1] = (uint8_t)(trailing[1] + 2);   /* widen the outer SEQUENCE */
    REQUIRE(wolfcert_scep_parse_issuer_and_serial(trailing, hb.len + 2,
                                                  &got_iss, &got_iss_len,
                                                  &got, &got_len) != WOLFCERT_OK);
    /* And so are bytes past the end the outer SEQUENCE's own length names. */
    trailing[1] = (uint8_t)(trailing[1] - 2);
    REQUIRE(wolfcert_scep_parse_issuer_and_serial(trailing, hb.len + 2,
                                                  &got_iss, &got_iss_len,
                                                  &got, &got_len) != WOLFCERT_OK);
    free(trailing);

    /* The padded wire form of a serial encodes the same as its magnitude. */
    static const uint8_t padded[4] = { 0x00, 0x8A, 0x01, 0x02 };
    WolfCertBuffer pb = { 0 };
    REQUIRE(wolfcert_scep_issuer_and_serial(ca_der, ca_len, padded,
                                            sizeof(padded), &pb,
                                            NULL) == WOLFCERT_OK);
    REQUIRE(pb.len == hb.len);
    REQUIRE(memcmp(pb.data, hb.data, pb.len) == 0);
    wolfcert_buffer_free(&pb);
    wolfcert_buffer_free(&hb);

    wolfcert_buffer_free(&ias);
    wc_FreeDecodedCert(&lc);
    wc_FreeDecodedCert(&cc);
    free(ca_der);
    free(ca_key_der);
    free(leaf_der);
    free(other_der);
    return 0;
}

/* IssuerAndSubject issuer for an RA, a self-signed CA, a sub-CA and a cert
 * without basic constraints names the issuing CA; NULL args get BAD_ARG. */
static int test_issuer_and_subject_issuer_name(void)
{
    RsaKey   key;
    WC_RNG   rng;
    uint8_t* ca_der     = NULL;
    size_t   ca_len     = 0;
    uint8_t* ca_key_der = NULL;
    size_t   ca_key_len = 0;
    uint8_t* ra_der     = NULL;
    size_t   ra_len     = 0;
    uint8_t* sub_der    = NULL;
    size_t   sub_len    = 0;
    uint8_t* nobc_der   = NULL;
    size_t   nobc_len   = 0;
    uint8_t* csr_der    = NULL;
    size_t   csr_len    = 0;
    WolfCertBuffer bad  = { 0 };
    int      rc = 0;

    REQUIRE(wc_InitRng(&rng) == 0);
    REQUIRE(wc_InitRsaKey(&key, NULL) == 0);
    REQUIRE(wc_MakeRsaKey(&key, 2048, WC_RSA_EXPONENT, &rng) == 0);

    REQUIRE(make_ca(&ca_der, &ca_len, &ca_key_der, &ca_key_len) == 0);
    REQUIRE(make_signed_cert(ca_der, ca_len, ca_key_der, ca_key_len,
                             "wolfCert Test RA Encryption", 0, 1,
                             &ra_der, &ra_len) == 0);
    REQUIRE(make_signed_cert(ca_der, ca_len, ca_key_der, ca_key_len,
                             "wolfCert Test Sub CA", 1, 1,
                             &sub_der, &sub_len) == 0);
    REQUIRE(make_signed_cert(ca_der, ca_len, ca_key_der, ca_key_len,
                             "wolfCert Test No BC", 0, 0,
                             &nobc_der, &nobc_len) == 0);
    REQUIRE(make_csr(&key, &rng, "device-4711.example.org", "Widgets Inc",
                     &csr_der, &csr_len) == 0);

    /* Split RA/CA: the RA is an end entity, so its issuer names the CA. */
    rc = check_issuer_and_subject(ra_der, ra_len, ca_der, ca_len,
                                  csr_der, csr_len);

    /* Single self-signed CA as the envelope target. */
    if (rc == 0)
        rc = check_issuer_and_subject(ca_der, ca_len, ca_der, ca_len,
                                      csr_der, csr_len);

    /* Sub-CA with no RA: it issues, so it names itself. */
    if (rc == 0)
        rc = check_issuer_and_subject(sub_der, sub_len, sub_der, sub_len,
                                      csr_der, csr_len);

    /* No basic constraints counts as an end entity, so its issuer is used. */
    if (rc == 0)
        rc = check_issuer_and_subject(nobc_der, nobc_len, ca_der, ca_len,
                                      csr_der, csr_len);

    /* Each NULL argument is refused before any parsing. */
    if (rc == 0 && wolfcert_scep_issuer_and_subject(NULL, ra_len, csr_der,
            csr_len, &bad, NULL) != WOLFCERT_ERR_BAD_ARG)
        rc = 1;
    if (rc == 0 && wolfcert_scep_issuer_and_subject(ra_der, ra_len, NULL,
            csr_len, &bad, NULL) != WOLFCERT_ERR_BAD_ARG)
        rc = 1;
    if (rc == 0 && wolfcert_scep_issuer_and_subject(ra_der, ra_len, csr_der,
            csr_len, NULL, NULL) != WOLFCERT_ERR_BAD_ARG)
        rc = 1;

    wolfcert_buffer_free(&bad);
    free(csr_der);
    free(nobc_der);
    free(sub_der);
    free(ra_der);
    free(ca_key_der);
    free(ca_der);
    wc_FreeRsaKey(&key);
    wc_FreeRng(&rng);

    REQUIRE(rc == 0);
    return 0;
}

/* A CertRep signer with a key other than the RA cert's fails; the RA passes. */
static int test_cert_rep_signer_trust(void)
{
    uint8_t* ra_der  = NULL;
    size_t   ra_len  = 0;
    uint8_t* ra_key  = NULL;
    size_t   ra_key_len = 0;
    uint8_t* att_der = NULL;
    size_t   att_len = 0;
    uint8_t* att_key = NULL;
    size_t   att_key_len = 0;

    REQUIRE(make_ca(&ra_der,  &ra_len,  &ra_key,  &ra_key_len)  == 0);
    REQUIRE(make_ca(&att_der, &att_len, &att_key, &att_key_len) == 0);

    REQUIRE(wolfcert_scep_verify_rep_signer(att_der, att_len,
                                            ra_der, ra_len, NULL)
            != WOLFCERT_OK);

    REQUIRE(wolfcert_scep_verify_rep_signer(ra_der, ra_len,
                                            ra_der, ra_len, NULL)
            == WOLFCERT_OK);

    free(ra_der);
    free(ra_key);
    free(att_der);
    free(att_key);
    return 0;
}

static int test_cert_rep_txid_and_type(void)
{
    static const uint8_t sent[8]  = { 'a','b','c','d','e','f','0','1' };
    static const uint8_t other[8] = { 'a','b','c','d','e','f','0','2' };

    /* Correct messageType with an echoed transactionID is accepted. */
    REQUIRE(wolfcert_scep_check_cert_rep("3", sent, sizeof(sent),
                                         sent, sizeof(sent)) == WOLFCERT_OK);

    /* A transactionID that does not echo the request is rejected. */
    REQUIRE(wolfcert_scep_check_cert_rep("3", other, sizeof(other),
                                         sent, sizeof(sent)) != WOLFCERT_OK);

    /* A transactionID of a different length is rejected. */
    REQUIRE(wolfcert_scep_check_cert_rep("3", sent, sizeof(sent) - 1,
                                         sent, sizeof(sent)) != WOLFCERT_OK);

    /* A messageType other than CertRep ("3") is rejected. */
    REQUIRE(wolfcert_scep_check_cert_rep("19", sent, sizeof(sent),
                                         sent, sizeof(sent)) != WOLFCERT_OK);

    /* A missing messageType is rejected. */
    REQUIRE(wolfcert_scep_check_cert_rep(NULL, sent, sizeof(sent),
                                         sent, sizeof(sent)) != WOLFCERT_OK);

    return 0;
}

/* A built GetNextCACert reply parses as signed data holding the next CA. */
static int test_next_ca_response_is_signed(void)
{
    uint8_t* ca_der   = NULL;
    size_t   ca_len   = 0;
    uint8_t* ca_key   = NULL;
    size_t   ca_key_len = 0;
    uint8_t* next_der = NULL;
    size_t   next_len = 0;
    uint8_t* next_key = NULL;
    size_t   next_key_len = 0;
    WolfCertBuffer resp     = { 0 };
    WolfCertBuffer content  = { 0 };
    WolfCertBuffer next_pem = { 0 };
    int rc;

    REQUIRE(make_ca(&ca_der,   &ca_len,   &ca_key,   &ca_key_len)   == 0);
    REQUIRE(make_ca(&next_der, &next_len, &next_key, &next_key_len) == 0);

    REQUIRE(wolfcert_scep_build_next_ca_response(next_der, next_len,
                                                 ca_der, ca_len,
                                                 ca_key, ca_key_len,
                                                 &resp, NULL) == WOLFCERT_OK);

    /* OK proves a signature; the parser refuses degenerate SignedData. */
    rc = wolfcert_scep_parse_pki_message(resp.data, resp.len, &content,
            NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    REQUIRE(rc == WOLFCERT_OK);
    REQUIRE(content.data != NULL && content.len > 0);

    /* The signed content carries the next CA certificate. */
    REQUIRE(wolfcert_pkcs7_certs_to_pem(content.data, content.len,
                                        &next_pem, NULL) == WOLFCERT_OK);
    REQUIRE(next_pem.len > 0);

    wolfcert_buffer_free(&content);
    wolfcert_buffer_free(&next_pem);
    wolfcert_buffer_free(&resp);
    free(ca_der);
    free(ca_key);
    free(next_der);
    free(next_key);
    return 0;
}

/* A roll-over reply verifies against the CA that signed it; another CA fails
 * and a NULL CA gets BAD_ARG. */
static int test_next_ca_response_signer_trust(void)
{
    uint8_t* ca_der   = NULL;
    size_t   ca_len   = 0;
    uint8_t* ca_key   = NULL;
    size_t   ca_key_len = 0;
    uint8_t* att_der  = NULL;
    size_t   att_len  = 0;
    uint8_t* att_key  = NULL;
    size_t   att_key_len = 0;
    uint8_t* next_der = NULL;
    size_t   next_len = 0;
    uint8_t* next_key = NULL;
    size_t   next_key_len = 0;
    WolfCertBuffer resp = { 0 };
    WolfCertBuffer pem  = { 0 };

    REQUIRE(make_ca(&ca_der,   &ca_len,   &ca_key,   &ca_key_len)   == 0);
    REQUIRE(make_ca(&att_der,  &att_len,  &att_key,  &att_key_len)  == 0);
    REQUIRE(make_ca(&next_der, &next_len, &next_key, &next_key_len) == 0);

    /* Roll-over response signed by the genuine current CA. */
    REQUIRE(wolfcert_scep_build_next_ca_response(next_der, next_len,
                                                 ca_der, ca_len,
                                                 ca_key, ca_key_len,
                                                 &resp, NULL) == WOLFCERT_OK);

    /* Accepted when bound to the CA that actually signed it. */
    REQUIRE(wolfcert_scep_verify_next_ca_response(resp.data, resp.len,
                                                  ca_der, ca_len,
                                                  &pem, NULL) == WOLFCERT_OK);
    REQUIRE(pem.len > 0);
    wolfcert_buffer_free(&pem);

    /* Rejected when bound to a different CA. */
    REQUIRE(wolfcert_scep_verify_next_ca_response(resp.data, resp.len,
                                                  att_der, att_len,
                                                  &pem, NULL) != WOLFCERT_OK);
    wolfcert_buffer_free(&pem);

    /* A NULL current CA is rejected. */
    REQUIRE(wolfcert_scep_verify_next_ca_response(resp.data, resp.len,
                                                  NULL, 0, &pem, NULL)
            == WOLFCERT_ERR_BAD_ARG);
    wolfcert_buffer_free(&pem);

    wolfcert_buffer_free(&resp);
    free(ca_der);
    free(ca_key);
    free(att_der);
    free(att_key);
    free(next_der);
    free(next_key);
    return 0;
}

/* SignedData signed by signer_cert with extra_cert prepended as cert[0];
 * free *out with free(). */
static int make_two_cert_signed(const uint8_t* signer_cert, size_t signer_cert_len,
                                const uint8_t* signer_key, size_t signer_key_len,
                                const uint8_t* extra_cert, size_t extra_cert_len,
                                uint8_t** out, size_t* out_len)
{
    static const uint8_t content[3] = { 0xDE, 0xAD, 0xBE };
    PKCS7*   p7 = NULL;
    WC_RNG   rng;
    uint8_t* buf = NULL;
    int      have_rng = 0;
    int      ret = 0;
    int      n = 0;

    if (wc_InitRng(&rng) != 0)
        return -1;
    have_rng = 1;

    p7 = wc_PKCS7_New(NULL, INVALID_DEVID);
    if (p7 == NULL)
        ret = -1;

    if (ret == 0 &&
            wc_PKCS7_InitWithCert(p7, (byte*)signer_cert, (word32)signer_cert_len) != 0)
        ret = -1;

    /* Prepend a second certificate so the signer is no longer cert[0]. */
    if (ret == 0 &&
            wc_PKCS7_AddCertificate(p7, (byte*)extra_cert, (word32)extra_cert_len) != 0)
        ret = -1;

    if (ret == 0) {
        buf = (uint8_t*)malloc(8192);
        if (buf == NULL)
            ret = -1;
    }

    if (ret == 0) {
        p7->rng          = &rng;
        p7->privateKey   = (byte*)signer_key;
        p7->privateKeySz = (word32)signer_key_len;
        p7->encryptOID   = RSAk;
        p7->hashOID      = SHA256h;
        p7->content      = (byte*)content;
        p7->contentSz    = sizeof(content);

        n = wc_PKCS7_EncodeSignedData(p7, buf, 8192);
        if (n <= 0)
            ret = -1;
    }

    if (ret == 0) {
        *out     = buf;
        *out_len = (size_t)n;
        buf = NULL;
    }

    free(buf);
    if (p7 != NULL)
        wc_PKCS7_Free(p7);
    if (have_rng)
        wc_FreeRng(&rng);
    return ret;
}

/* The signer is the cert the SignerInfo names, which need not be cert[0]. */
static int test_signer_is_verified_cert(void)
{
    uint8_t* ca_der   = NULL;
    size_t   ca_len   = 0;
    uint8_t* ca_key   = NULL;
    size_t   ca_key_len = 0;
    uint8_t* att_der  = NULL;
    size_t   att_len  = 0;
    uint8_t* att_key  = NULL;
    size_t   att_key_len = 0;
    uint8_t* msg      = NULL;
    size_t   msg_len  = 0;
    WolfCertBuffer env = { 0 };
    uint8_t* signer   = NULL;
    size_t   signer_len = 0;

    REQUIRE(make_ca(&ca_der,  &ca_len,  &ca_key,  &ca_key_len)  == 0);
    REQUIRE(make_ca(&att_der, &att_len, &att_key, &att_key_len) == 0);

    /* Signed by the attacker key, but the trusted CA cert is cert[0]. */
    REQUIRE(make_two_cert_signed(att_der, att_len, att_key, att_key_len,
                                 ca_der, ca_len, &msg, &msg_len) == 0);

    REQUIRE(wolfcert_scep_parse_pki_message(msg, msg_len, &env,
            NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
            &signer, &signer_len, NULL, NULL) == WOLFCERT_OK);

    /* The parser reports the cert that signed. */
    REQUIRE(signer != NULL);
    REQUIRE(signer_len == att_len && memcmp(signer, att_der, att_len) == 0);

    /* That signer does not verify against the trusted CA. */
    REQUIRE(wolfcert_scep_verify_rep_signer(signer, signer_len,
                                            ca_der, ca_len, NULL) != WOLFCERT_OK);

    WOLFCERT_XFREE(signer, NULL);
    wolfcert_buffer_free(&env);
    free(msg);
    free(ca_der);
    free(ca_key);
    free(att_der);
    free(att_key);
    return 0;
}

/* Signers A and B pass against an [A, B] bundle; an unrelated one fails. */
static int test_signer_matches_any_bundle_cert(void)
{
    uint8_t* a_der  = NULL;
    size_t   a_len  = 0;
    uint8_t* a_key  = NULL;
    size_t   a_key_len = 0;
    uint8_t* b_der  = NULL;
    size_t   b_len  = 0;
    uint8_t* b_key  = NULL;
    size_t   b_key_len = 0;
    uint8_t* u_der  = NULL;
    size_t   u_len  = 0;
    uint8_t* u_key  = NULL;
    size_t   u_key_len = 0;
    uint8_t* bundle = NULL;
    size_t   bundle_len;

    REQUIRE(make_ca(&a_der, &a_len, &a_key, &a_key_len) == 0);
    REQUIRE(make_ca(&b_der, &b_len, &b_key, &b_key_len) == 0);
    REQUIRE(make_ca(&u_der, &u_len, &u_key, &u_key_len) == 0);

    /* Concatenated-DER bundle: [cert A, cert B]. */
    bundle_len = a_len + b_len;
    bundle = (uint8_t*)malloc(bundle_len);
    REQUIRE(bundle != NULL);
    memcpy(bundle, a_der, a_len);
    memcpy(bundle + a_len, b_der, b_len);

    /* Signer matching the second bundle cert is accepted... */
    REQUIRE(wolfcert_scep_verify_rep_signer(b_der, b_len,
                                            bundle, bundle_len, NULL)
            == WOLFCERT_OK);
    /* ...the first too... */
    REQUIRE(wolfcert_scep_verify_rep_signer(a_der, a_len,
                                            bundle, bundle_len, NULL)
            == WOLFCERT_OK);
    /* ...and a signer in neither is rejected. */
    REQUIRE(wolfcert_scep_verify_rep_signer(u_der, u_len,
                                            bundle, bundle_len, NULL)
            != WOLFCERT_OK);
#ifdef TEST_ALLOC_FAILURES
    REQUIRE(rep_signer_reports_oom(b_der, b_len, bundle, bundle_len) == 0);
#endif

    free(bundle);
    free(a_der);
    free(a_key);
    free(b_der);
    free(b_key);
    free(u_der);
    free(u_key);
    return 0;
}

/* An empty CSR subject (DER 30 00) gives the signer the literal CN
 * "SCEP Enrollee". */
static int test_signer_subject_fallback(void)
{
    RsaKey      key;
    WC_RNG      rng;
    uint8_t*    csr = NULL;
    size_t      csr_len = 0;
    uint8_t*    signer = NULL;
    size_t      signer_len = 0;
    DecodedCert dc;

    REQUIRE(wc_InitRng(&rng) == 0);
    REQUIRE(wc_InitRsaKey(&key, NULL) == 0);
    REQUIRE(wc_MakeRsaKey(&key, 2048, WC_RSA_EXPONENT, &rng) == 0);

    REQUIRE(make_csr(&key, &rng, "", "", &csr, &csr_len) == 0);

    REQUIRE(wolfcert_scep_self_signed_rsa(&key, csr, csr_len,
                                          &signer, &signer_len, NULL)
            == WOLFCERT_OK);

    wc_InitDecodedCert(&dc, signer, (word32)signer_len, NULL);
    REQUIRE(wc_ParseCert(&dc, CERT_TYPE, NO_VERIFY, NULL) == 0);
    REQUIRE(dc.subjectCN != NULL && dc.subjectCNLen == 13 &&
            memcmp(dc.subjectCN, "SCEP Enrollee", 13) == 0);

    wc_FreeDecodedCert(&dc);
    WOLFCERT_XFREE(signer, NULL);
    free(csr);
    wc_FreeRsaKey(&key);
    wc_FreeRng(&rng);
    return 0;
}

/* Fingerprint cases for ca_der, which test_ca_fingerprint frees after. */
static int check_ca_fingerprint(const uint8_t* ca_der, size_t ca_len)
{
    uint8_t sha256[WC_SHA256_DIGEST_SIZE];
    uint8_t tampered[WC_SHA256_DIGEST_SIZE];
#ifndef NO_SHA
    uint8_t sha1[WC_SHA_DIGEST_SIZE];
#else
    uint8_t sha1_absent[20];    /* SHA-1 digest length; algorithm not compiled in */
#endif
#ifdef WOLFSSL_SHA512
    uint8_t sha512[WC_SHA512_DIGEST_SIZE];
#else
    uint8_t sha512_absent[64];  /* SHA-512 digest length; algorithm not compiled in */
#endif

    REQUIRE(wc_Sha256Hash(ca_der, (word32)ca_len, sha256) == 0);

    /* Explicit SHA-256 and AUTO (by length) both accept the real digest. */
    REQUIRE(wolfcert_scep_verify_ca_fingerprint(ca_der, ca_len, sha256,
                sizeof(sha256), WOLFCERT_SCEP_FP_SHA256) == WOLFCERT_OK);
    REQUIRE(wolfcert_scep_verify_ca_fingerprint(ca_der, ca_len, sha256,
                sizeof(sha256), WOLFCERT_SCEP_FP_AUTO) == WOLFCERT_OK);

    /* A single flipped bit must be rejected as a mismatch. */
    memcpy(tampered, sha256, sizeof(tampered));
    tampered[0] ^= 0x01;
    REQUIRE(wolfcert_scep_verify_ca_fingerprint(ca_der, ca_len, tampered,
                sizeof(tampered), WOLFCERT_SCEP_FP_SHA256) == WOLFCERT_ERR_AUTH);

    /* Explicit algorithm with a length that doesn't match the digest -> BAD_ARG. */
    REQUIRE(wolfcert_scep_verify_ca_fingerprint(ca_der, ca_len, sha256, 20,
                WOLFCERT_SCEP_FP_SHA256) == WOLFCERT_ERR_BAD_ARG);
    /* AUTO with an unrecognized length -> BAD_ARG. */
    REQUIRE(wolfcert_scep_verify_ca_fingerprint(ca_der, ca_len, sha256, 33,
                WOLFCERT_SCEP_FP_AUTO) == WOLFCERT_ERR_BAD_ARG);
    /* NULL / zero inputs -> BAD_ARG. */
    REQUIRE(wolfcert_scep_verify_ca_fingerprint(NULL, 0, sha256, sizeof(sha256),
                WOLFCERT_SCEP_FP_SHA256) == WOLFCERT_ERR_BAD_ARG);

#ifndef NO_SHA
    REQUIRE(wc_ShaHash(ca_der, (word32)ca_len, sha1) == 0);
    REQUIRE(wolfcert_scep_verify_ca_fingerprint(ca_der, ca_len, sha1,
                sizeof(sha1), WOLFCERT_SCEP_FP_SHA1) == WOLFCERT_OK);
    REQUIRE(wolfcert_scep_verify_ca_fingerprint(ca_der, ca_len, sha1,
                sizeof(sha1), WOLFCERT_SCEP_FP_AUTO) == WOLFCERT_OK);
    /* A single flipped bit must be rejected on the SHA-1 path too. */
    sha1[0] ^= 0x01;
    REQUIRE(wolfcert_scep_verify_ca_fingerprint(ca_der, ca_len, sha1,
                sizeof(sha1), WOLFCERT_SCEP_FP_SHA1) == WOLFCERT_ERR_AUTH);
#else
    /* SHA-1 absent: both requests report UNSUPPORTED before any compare. */
    memset(sha1_absent, 0, sizeof(sha1_absent));
    REQUIRE(wolfcert_scep_verify_ca_fingerprint(ca_der, ca_len, sha1_absent,
                sizeof(sha1_absent), WOLFCERT_SCEP_FP_SHA1)
            == WOLFCERT_ERR_UNSUPPORTED);
    REQUIRE(wolfcert_scep_verify_ca_fingerprint(ca_der, ca_len, sha1_absent,
                sizeof(sha1_absent), WOLFCERT_SCEP_FP_AUTO)
            == WOLFCERT_ERR_UNSUPPORTED);
#endif

#ifdef WOLFSSL_SHA512
    REQUIRE(wc_Sha512Hash(ca_der, (word32)ca_len, sha512) == 0);
    REQUIRE(wolfcert_scep_verify_ca_fingerprint(ca_der, ca_len, sha512,
                sizeof(sha512), WOLFCERT_SCEP_FP_SHA512) == WOLFCERT_OK);
    REQUIRE(wolfcert_scep_verify_ca_fingerprint(ca_der, ca_len, sha512,
                sizeof(sha512), WOLFCERT_SCEP_FP_AUTO) == WOLFCERT_OK);
    /* A single flipped bit must be rejected on the SHA-512 path too. */
    sha512[0] ^= 0x01;
    REQUIRE(wolfcert_scep_verify_ca_fingerprint(ca_der, ca_len, sha512,
                sizeof(sha512), WOLFCERT_SCEP_FP_SHA512) == WOLFCERT_ERR_AUTH);
#else
    /* SHA-512 absent: same as the SHA-1 case for the 64-byte path. */
    memset(sha512_absent, 0, sizeof(sha512_absent));
    REQUIRE(wolfcert_scep_verify_ca_fingerprint(ca_der, ca_len, sha512_absent,
                sizeof(sha512_absent), WOLFCERT_SCEP_FP_SHA512)
            == WOLFCERT_ERR_UNSUPPORTED);
    REQUIRE(wolfcert_scep_verify_ca_fingerprint(ca_der, ca_len, sha512_absent,
                sizeof(sha512_absent), WOLFCERT_SCEP_FP_AUTO)
            == WOLFCERT_ERR_UNSUPPORTED);
#endif

    return 0;
}

static int test_ca_fingerprint(void)
{
    uint8_t* ca_der  = NULL;
    uint8_t* key_der = NULL;
    size_t   ca_len  = 0, key_len = 0;
    int      rc;

    REQUIRE(make_ca(&ca_der, &ca_len, &key_der, &key_len) == 0);

    rc = check_ca_fingerprint(ca_der, ca_len);

    free(ca_der);
    free(key_der);
    return rc;
}

/* Map one hex digit to its nibble value, or -1 if it is not a hex digit. */
static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    return -1;
}

/* Decodes %XX escapes in `in` into `out`, which holds strlen(in) bytes.
 * Returns the decoded length, or -1 on a malformed escape. */
static int percent_decode(const char* in, uint8_t* out)
{
    int    hi, lo;
    size_t i = 0, o = 0;

    while (in[i] != '\0') {
        if (in[i] == '%') {
            if (in[i + 1] == '\0' || in[i + 2] == '\0')
                return -1;
            hi = hex_nibble(in[i + 1]);
            lo = hex_nibble(in[i + 2]);
            if (hi < 0 || lo < 0)
                return -1;
            out[o++] = (uint8_t)((hi << 4) | lo);
            i += 3;
        }
        else {
            out[o++] = (uint8_t)in[i];
            i += 1;
        }
    }
    return (int)o;
}

static int test_pki_get_url(void)
{
    const char* base = "http://ca.example/scep";
    const char* pfx  = "http://ca.example/scep?operation=PKIOperation&message=";
    int         prefix_ok, msg_ok = 0, rc;

    uint8_t small[64];
    for (size_t i = 0; i < sizeof(small); i++)
        small[i] = (uint8_t)(i * 7 + 3);   /* spans bytes that must be escaped */

    char* url = NULL;
    REQUIRE(wolfcert_scep_build_pki_get_url(base, small, sizeof(small), NULL, &url)
            == WOLFCERT_OK);
    REQUIRE(url != NULL);
    /* Free url before the REQUIREs so a failing check cannot leak it. */
    prefix_ok = (strncmp(url, pfx, strlen(pfx)) == 0);
    /* message= must percent- and base64-decode back to the original bytes. */
    if (prefix_ok) {
        uint8_t        decoded_b64[sizeof(small) * 2];  /* holds the ~88-char b64 */
        WolfCertBuffer raw = { 0 };
        int            declen = percent_decode(url + strlen(pfx), decoded_b64);
        if (declen > 0 && wolfcert_base64_decode(decoded_b64, (size_t)declen,
                                                 &raw, NULL) == WOLFCERT_OK) {
            msg_ok = (raw.len == sizeof(small) &&
                      memcmp(raw.data, small, sizeof(small)) == 0);
        }
        wolfcert_buffer_free(&raw);
    }
    WOLFCERT_XFREE(url, NULL);   /* url is from the wolfCert heap */
    REQUIRE(prefix_ok);
    REQUIRE(msg_ok);

    /* A pkiMessage too large for a GET must be refused so the caller POSTs. */
    size_t big_len = WOLFCERT_SCEP_MAX_GET_URL;   /* base64 alone exceeds the cap */
    uint8_t* big = (uint8_t*)malloc(big_len);
    REQUIRE(big != NULL);
    memset(big, 0xA5, big_len);
    char* url2 = NULL;
    rc = wolfcert_scep_build_pki_get_url(base, big, big_len, NULL, &url2);
    free(big);
    WOLFCERT_XFREE(url2, NULL);   /* NULL on the expected UNSUPPORTED path */
    REQUIRE(rc == WOLFCERT_ERR_UNSUPPORTED);

    return 0;
}

static int test_getca_url(void)
{
    /* The URLs come from the wolfCert heap, a static pool under
     * WOLFSSL_NO_MALLOC, so they go back through WOLFCERT_XFREE. */
    char* u;

    u = wolfcert_scep_build_getca_url("http://ca.example/scep", "GetCACert", NULL, NULL);
    REQUIRE(u != NULL);
    REQUIRE(strcmp(u, "http://ca.example/scep?operation=GetCACert") == 0);
    WOLFCERT_XFREE(u, NULL);

    /* An empty identifier is treated as unset. */
    u = wolfcert_scep_build_getca_url("http://ca.example/scep", "GetCACaps", "", NULL);
    REQUIRE(u != NULL);
    REQUIRE(strcmp(u, "http://ca.example/scep?operation=GetCACaps") == 0);
    WOLFCERT_XFREE(u, NULL);

    u = wolfcert_scep_build_getca_url("http://ca.example/scep", "GetCACert", "MyCA", NULL);
    REQUIRE(u != NULL);
    REQUIRE(strcmp(u, "http://ca.example/scep?operation=GetCACert&message=MyCA") == 0);
    WOLFCERT_XFREE(u, NULL);

    /* Reserved characters in the identifier must be percent-encoded. */
    u = wolfcert_scep_build_getca_url("http://ca.example/scep", "GetCACert", "a b/c", NULL);
    REQUIRE(u != NULL);
    REQUIRE(strcmp(u,
        "http://ca.example/scep?operation=GetCACert&message=a%20b%2Fc") == 0);
    WOLFCERT_XFREE(u, NULL);

    return 0;
}

/* An EST config with Basic credentials gets BAD_ARG from the SCEP GetCA*
 * calls and both session opens. */
static int test_scep_rejects_est_cfg(void)
{
    static const uint8_t dummy_ca[] = { 0x30, 0x03, 0x02, 0x01, 0x00 };
    WolfCertServerCfg srv = {
        .protocol      = WOLFCERT_PROTO_EST,
        .server_url    = "http://127.0.0.1:1/scep",
        .verify_server = 0,
        .proto_opts.est = { .username = "alice", .password = "hunter2" }
    };
    WolfCertScepCaps caps = { 0 };
    WolfCertBuffer out = { 0 };
    WolfCertScepSession* sess = NULL;

    REQUIRE(wolfcert_scep_get_ca_caps(&srv, &caps) == WOLFCERT_ERR_BAD_ARG);
    REQUIRE(wolfcert_scep_get_ca_cert(&srv, &out) == WOLFCERT_ERR_BAD_ARG);
    REQUIRE(wolfcert_scep_get_ca_cert_enc(&srv, WOLFCERT_ENCODING_DER, &out)
            == WOLFCERT_ERR_BAD_ARG);
    REQUIRE(wolfcert_scep_get_next_ca_cert(&srv, dummy_ca, sizeof(dummy_ca),
                                           &out) == WOLFCERT_ERR_BAD_ARG);

    REQUIRE(wolfcert_scep_session_open(&srv, &sess) == WOLFCERT_ERR_BAD_ARG);
    REQUIRE(sess == NULL);
    REQUIRE(wolfcert_scep_session_open_async(&srv, &sess) == WOLFCERT_ERR_BAD_ARG);
    REQUIRE(sess == NULL);

    /* protocol = 0 is refused too. */
    srv.protocol = (WolfCertProtocol)0;
    REQUIRE(wolfcert_scep_get_ca_caps(&srv, &caps) == WOLFCERT_ERR_BAD_ARG);
    REQUIRE(wolfcert_scep_session_open(&srv, &sess) == WOLFCERT_ERR_BAD_ARG);

    return 0;
}

/* AES256CBCb / AES128CBCb put the matching AES-CBC OID on the wire. */
static int test_envelop_cipher_oid(void)
{
#if defined(WOLFSSL_AES_256)
    static const uint8_t OID_AES256[] =
        { 0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x01,0x2a };
#endif
    static const uint8_t OID_AES128[] =
        { 0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x01,0x02 };
    const uint8_t payload[] = "content-encryption OID probe";

    uint8_t* ca_der  = NULL;
    uint8_t* key_der = NULL;
    size_t   ca_len  = 0, key_len = 0;
    REQUIRE(make_ca(&ca_der, &ca_len, &key_der, &key_len) == 0);

#if defined(WOLFSSL_AES_256)
    WolfCertBuffer env256 = { 0 };
    REQUIRE(wolfcert_scep_envelop(ca_der, ca_len, payload, sizeof(payload),
                                  AES256CBCb, &env256, NULL) == WOLFCERT_OK);
    REQUIRE(memmem(env256.data, env256.len, OID_AES256, sizeof(OID_AES256)) != NULL);
    REQUIRE(memmem(env256.data, env256.len, OID_AES128, sizeof(OID_AES128)) == NULL);
    wolfcert_buffer_free(&env256);
#endif

    WolfCertBuffer env128 = { 0 };
    REQUIRE(wolfcert_scep_envelop(ca_der, ca_len, payload, sizeof(payload),
                                  AES128CBCb, &env128, NULL) == WOLFCERT_OK);
    REQUIRE(memmem(env128.data, env128.len, OID_AES128, sizeof(OID_AES128)) != NULL);
    wolfcert_buffer_free(&env128);

    free(ca_der);
    free(key_der);
    return 0;
}

static const byte scep_oid_msg_type[] =
    { 0x06,0x0A,0x60,0x86,0x48,0x01,0x86,0xF8,0x45,0x01,0x09,0x02 };
static const byte scep_oid_trans_id[] =
    { 0x06,0x0A,0x60,0x86,0x48,0x01,0x86,0xF8,0x45,0x01,0x09,0x07 };
static const byte scep_oid_pki_status[] =
    { 0x06,0x0A,0x60,0x86,0x48,0x01,0x86,0xF8,0x45,0x01,0x09,0x03 };
static const byte scep_oid_fail_info[] =
    { 0x06,0x0A,0x60,0x86,0x48,0x01,0x86,0xF8,0x45,0x01,0x09,0x04 };

/* Signs fixed content with raw caller attributes, so a test can build sets
 * wolfCert never emits. The caller frees *out. */
static int make_signed_with_attribs(const uint8_t* signer_cert,
                                    size_t signer_cert_len,
                                    const uint8_t* signer_key,
                                    size_t signer_key_len,
                                    PKCS7Attrib* attribs, int attribs_sz,
                                    uint8_t** out, size_t* out_len)
{
    static const uint8_t content[3] = { 0xDE, 0xAD, 0xBE };
    PKCS7*   p7 = NULL;
    WC_RNG   rng;
    uint8_t* buf = NULL;
    int      have_rng = 0;
    int      ret = 0;
    int      n = 0;

    if (wc_InitRng(&rng) != 0)
        return -1;
    have_rng = 1;

    p7 = wc_PKCS7_New(NULL, INVALID_DEVID);
    if (p7 == NULL)
        ret = -1;

    if (ret == 0 &&
            wc_PKCS7_InitWithCert(p7, (byte*)signer_cert, (word32)signer_cert_len) != 0)
        ret = -1;

    if (ret == 0) {
        buf = (uint8_t*)malloc(8192);
        if (buf == NULL)
            ret = -1;
    }

    if (ret == 0) {
        p7->rng             = &rng;
        p7->privateKey      = (byte*)signer_key;
        p7->privateKeySz    = (word32)signer_key_len;
        p7->encryptOID      = RSAk;
        p7->hashOID         = SHA256h;
        p7->content         = (byte*)content;
        p7->contentSz       = sizeof(content);
        p7->signedAttribs   = attribs;
        p7->signedAttribsSz = (word32)attribs_sz;

        n = wc_PKCS7_EncodeSignedData(p7, buf, 8192);
        if (n <= 0)
            ret = -1;
    }

    if (ret == 0) {
        *out     = buf;
        *out_len = (size_t)n;
        buf = NULL;
    }

    free(buf);
    if (p7 != NULL)
        wc_PKCS7_Free(p7);
    if (have_rng)
        wc_FreeRng(&rng);
    return ret;
}

/* A messageType attribute plus two transactionID attributes whose values
 * differ, each in its own Attribute SEQUENCE. */
static int make_dup_tid_signed(const uint8_t* signer_cert, size_t signer_cert_len,
                               const uint8_t* signer_key, size_t signer_key_len,
                               uint8_t** out, size_t* out_len)
{
    static const byte msg_type[] = { 0x13, 0x02, '1', '9' };
    static const byte tid_a[] = { 0x13, 0x01, 'A' };
    static const byte tid_b[] = { 0x13, 0x01, 'B' };
    PKCS7Attrib attribs[3];

    attribs[0].oid     = scep_oid_msg_type;
    attribs[0].oidSz   = sizeof(scep_oid_msg_type);
    attribs[0].value   = msg_type;
    attribs[0].valueSz = sizeof(msg_type);
    attribs[1].oid     = scep_oid_trans_id;
    attribs[1].oidSz   = sizeof(scep_oid_trans_id);
    attribs[1].value   = tid_a;
    attribs[1].valueSz = sizeof(tid_a);
    attribs[2].oid     = scep_oid_trans_id;
    attribs[2].oidSz   = sizeof(scep_oid_trans_id);
    attribs[2].value   = tid_b;
    attribs[2].valueSz = sizeof(tid_b);

    return make_signed_with_attribs(signer_cert, signer_cert_len,
                                    signer_key, signer_key_len,
                                    attribs, 3, out, out_len);
}

/* One transactionID Attribute whose value SET holds "A" and "B". */
static int make_multi_value_tid_signed(const uint8_t* signer_cert,
                                       size_t signer_cert_len,
                                       const uint8_t* signer_key,
                                       size_t signer_key_len,
                                       uint8_t** out, size_t* out_len)
{
    static const byte msg_type[] = { 0x13, 0x02, '1', '9' };
    static const byte tid_two[] = { 0x13, 0x01, 'A', 0x13, 0x01, 'B' };
    PKCS7Attrib attribs[2];

    attribs[0].oid     = scep_oid_msg_type;
    attribs[0].oidSz   = sizeof(scep_oid_msg_type);
    attribs[0].value   = msg_type;
    attribs[0].valueSz = sizeof(msg_type);
    attribs[1].oid     = scep_oid_trans_id;
    attribs[1].oidSz   = sizeof(scep_oid_trans_id);
    attribs[1].value   = tid_two;
    attribs[1].valueSz = sizeof(tid_two);

    return make_signed_with_attribs(signer_cert, signer_cert_len,
                                    signer_key, signer_key_len,
                                    attribs, 2, out, out_len);
}

/* Two transactionID attributes are rejected (RFC 8894: one value each). */
static int test_duplicate_signed_attrib(void)
{
    uint8_t* ca_der  = NULL;
    size_t   ca_len  = 0;
    uint8_t* ca_key  = NULL;
    size_t   ca_key_len = 0;
    uint8_t* msg     = NULL;
    size_t   msg_len = 0;
    WolfCertBuffer env = { 0 };
    uint8_t* tid     = NULL;
    size_t   tid_len = 0;
    uint8_t* snonce  = NULL;
    size_t   snonce_len = 0;
    uint8_t* rnonce  = NULL;
    size_t   rnonce_len = 0;
    char*    mt      = NULL;
    char*    ps      = NULL;
    char*    fi      = NULL;
    uint8_t* signer  = NULL;
    size_t   signer_len = 0;
    int      rc;
    int      tid_ok, snonce_ok, rnonce_ok, signer_ok, str_ok, env_ok;

    REQUIRE(make_ca(&ca_der, &ca_len, &ca_key, &ca_key_len) == 0);
    REQUIRE(make_dup_tid_signed(ca_der, ca_len, ca_key, ca_key_len,
                                &msg, &msg_len) == 0);

    /* Every output is requested so each can be checked after the reject. */
    rc = wolfcert_scep_parse_pki_message(msg, msg_len, &env,
            &tid, &tid_len, &snonce, &snonce_len, &rnonce, &rnonce_len,
            &mt, &ps, &signer, &signer_len, &fi, NULL);
    if (rc != WOLFCERT_ERR_PROTOCOL) {
        fprintf(stderr, "duplicate transactionID accepted: rc=%d tid=%.*s\n",
                rc, (int)tid_len, tid == NULL ? "" : (const char*)tid);
    }

    /* Capture every check, then free unconditionally so nothing leaks. */
    tid_ok    = (tid == NULL && tid_len == 0);
    snonce_ok = (snonce == NULL && snonce_len == 0);
    rnonce_ok = (rnonce == NULL && rnonce_len == 0);
    signer_ok = (signer == NULL && signer_len == 0);
    str_ok    = (mt == NULL && ps == NULL && fi == NULL);
    env_ok    = (env.data == NULL && env.len == 0);

    WOLFCERT_XFREE(tid, NULL);
    WOLFCERT_XFREE(snonce, NULL);
    WOLFCERT_XFREE(rnonce, NULL);
    WOLFCERT_XFREE(signer, NULL);
    WOLFCERT_XFREE(mt, NULL);
    WOLFCERT_XFREE(ps, NULL);
    WOLFCERT_XFREE(fi, NULL);
    wolfcert_buffer_free(&env);
    free(msg);
    free(ca_der);
    free(ca_key);

    REQUIRE(rc == WOLFCERT_ERR_PROTOCOL);
    REQUIRE(tid_ok);
    REQUIRE(snonce_ok);
    REQUIRE(rnonce_ok);
    REQUIRE(signer_ok);
    REQUIRE(str_ok);
    REQUIRE(env_ok);
    return 0;
}

/* One transactionID Attribute whose SET carries two values. */
static int test_multi_value_signed_attrib(void)
{
    uint8_t* ca_der  = NULL;
    size_t   ca_len  = 0;
    uint8_t* ca_key  = NULL;
    size_t   ca_key_len = 0;
    uint8_t* msg     = NULL;
    size_t   msg_len = 0;
    WolfCertBuffer env = { 0 };
    uint8_t* tid     = NULL;
    size_t   tid_len = 0;
    uint8_t* snonce  = NULL;
    size_t   snonce_len = 0;
    uint8_t* rnonce  = NULL;
    size_t   rnonce_len = 0;
    char*    mt      = NULL;
    char*    ps      = NULL;
    char*    fi      = NULL;
    uint8_t* signer  = NULL;
    size_t   signer_len = 0;
    int      rc;
    int      tid_ok, snonce_ok, rnonce_ok, signer_ok, str_ok, env_ok;

    REQUIRE(make_ca(&ca_der, &ca_len, &ca_key, &ca_key_len) == 0);
    REQUIRE(make_multi_value_tid_signed(ca_der, ca_len, ca_key, ca_key_len,
                                        &msg, &msg_len) == 0);

    rc = wolfcert_scep_parse_pki_message(msg, msg_len, &env,
            &tid, &tid_len, &snonce, &snonce_len, &rnonce, &rnonce_len,
            &mt, &ps, &signer, &signer_len, &fi, NULL);
    if (rc != WOLFCERT_ERR_PROTOCOL) {
        fprintf(stderr, "multi-valued transactionID accepted: rc=%d tid=%.*s\n",
                rc, (int)tid_len, tid == NULL ? "" : (const char*)tid);
    }

    tid_ok    = (tid == NULL && tid_len == 0);
    snonce_ok = (snonce == NULL && snonce_len == 0);
    rnonce_ok = (rnonce == NULL && rnonce_len == 0);
    signer_ok = (signer == NULL && signer_len == 0);
    str_ok    = (mt == NULL && ps == NULL && fi == NULL);
    env_ok    = (env.data == NULL && env.len == 0);

    WOLFCERT_XFREE(tid, NULL);
    WOLFCERT_XFREE(snonce, NULL);
    WOLFCERT_XFREE(rnonce, NULL);
    WOLFCERT_XFREE(signer, NULL);
    WOLFCERT_XFREE(mt, NULL);
    WOLFCERT_XFREE(ps, NULL);
    WOLFCERT_XFREE(fi, NULL);
    wolfcert_buffer_free(&env);
    free(msg);
    free(ca_der);
    free(ca_key);

    REQUIRE(rc == WOLFCERT_ERR_PROTOCOL);
    REQUIRE(tid_ok);
    REQUIRE(snonce_ok);
    REQUIRE(rnonce_ok);
    REQUIRE(signer_ok);
    REQUIRE(str_ok);
    REQUIRE(env_ok);
    return 0;
}

/* Sign one text attribute with raw value bytes and parse it back. On success
 * the parsed string must equal `expect`; on rejection nothing may be left. */
static int check_text_attrib(const uint8_t* ca_der, size_t ca_len,
                             const uint8_t* ca_key, size_t ca_key_len,
                             const byte* oid, word32 oid_sz,
                             const byte* value, word32 value_sz,
                             int expect_rc, const char* expect)
{
    PKCS7Attrib    attrib;
    uint8_t*       msg     = NULL;
    size_t         msg_len = 0;
    WolfCertBuffer env     = { 0 };
    char*          mt      = NULL;
    char*          ps      = NULL;
    char*          fi      = NULL;
    const char*    got;
    int            rc;
    int            str_ok;

    attrib.oid     = oid;
    attrib.oidSz   = oid_sz;
    attrib.value   = value;
    attrib.valueSz = value_sz;
    REQUIRE(make_signed_with_attribs(ca_der, ca_len, ca_key, ca_key_len,
                                     &attrib, 1, &msg, &msg_len) == 0);

    rc = wolfcert_scep_parse_pki_message(msg, msg_len, &env,
            NULL, NULL, NULL, NULL, NULL, NULL,
            &mt, &ps, NULL, NULL, &fi, NULL);

    got = mt != NULL ? mt : (ps != NULL ? ps : fi);
    if (expect_rc == WOLFCERT_OK)
        str_ok = got != NULL && strcmp(got, expect) == 0;
    else
        str_ok = mt == NULL && ps == NULL && fi == NULL;

    WOLFCERT_XFREE(mt, NULL);
    WOLFCERT_XFREE(ps, NULL);
    WOLFCERT_XFREE(fi, NULL);
    wolfcert_buffer_free(&env);
    free(msg);

    REQUIRE(rc == expect_rc);
    REQUIRE(str_ok);
    return 0;
}

/* RFC 8894 section 3.2.1 text attributes must be NUL-free PrintableStrings. */
static int test_text_attrib_printable(void)
{
    static const byte ps_ok[]   = { 0x13, 0x01, '2' };
    static const byte ps_nul[]  = { 0x13, 0x02, '2', 0x00 };
    static const byte fi_nul[]  = { 0x13, 0x03, '0', 0x00, 'x' };
    static const byte mt_utf8[] = { 0x0C, 0x01, '3' };
    uint8_t* ca_der  = NULL;
    size_t   ca_len  = 0;
    uint8_t* ca_key  = NULL;
    size_t   ca_key_len = 0;
    int      ret = 0;

    REQUIRE(make_ca(&ca_der, &ca_len, &ca_key, &ca_key_len) == 0);

    if (check_text_attrib(ca_der, ca_len, ca_key, ca_key_len,
                          scep_oid_pki_status, sizeof(scep_oid_pki_status),
                          ps_ok, sizeof(ps_ok), WOLFCERT_OK, "2") != 0 ||
        check_text_attrib(ca_der, ca_len, ca_key, ca_key_len,
                          scep_oid_pki_status, sizeof(scep_oid_pki_status),
                          ps_nul, sizeof(ps_nul),
                          WOLFCERT_ERR_PROTOCOL, NULL) != 0 ||
        check_text_attrib(ca_der, ca_len, ca_key, ca_key_len,
                          scep_oid_fail_info, sizeof(scep_oid_fail_info),
                          fi_nul, sizeof(fi_nul),
                          WOLFCERT_ERR_PROTOCOL, NULL) != 0 ||
        check_text_attrib(ca_der, ca_len, ca_key, ca_key_len,
                          scep_oid_msg_type, sizeof(scep_oid_msg_type),
                          mt_utf8, sizeof(mt_utf8),
                          WOLFCERT_ERR_PROTOCOL, NULL) != 0) {
        ret = 1;
    }

    free(ca_der);
    free(ca_key);
    return ret;
}

int main(void)
{
    REQUIRE(test_static_mem_init() == 0);
    REQUIRE(wolfcert_init(test_heap_hint()) == WOLFCERT_OK);
    if (test_getca_url())
        return 1;
    if (test_scep_rejects_est_cfg())
        return 1;
    if (test_envelop_cipher_oid())
        return 1;
    if (test_ca_fingerprint())
        return 1;
    if (test_pki_get_url())
        return 1;
    if (test_non_success_has_no_envelope())
        return 1;
    if (test_signer_subject_fallback())
        return 1;
    if (test_signer_subject_matches_csr())
        return 1;
    if (test_signer_key_usage())
        return 1;
    if (test_issuer_and_subject_issuer_name())
        return 1;
    if (test_issuer_and_serial())
        return 1;
    if (test_pem_has_cert())
        return 1;
    if (test_result_defined_on_early_return())
        return 1;
    if (test_zero_length_args_rejected())
        return 1;
    if (test_cert_rep_signer_trust())
        return 1;
    if (test_cert_rep_txid_and_type())
        return 1;
    if (test_long_transaction_id())
        return 1;
    if (test_next_ca_response_is_signed())
        return 1;
    if (test_next_ca_response_signer_trust())
        return 1;
    if (test_signer_is_verified_cert())
        return 1;
    if (test_signer_matches_any_bundle_cert())
        return 1;
    if (test_duplicate_signed_attrib())
        return 1;
    if (test_multi_value_signed_attrib())
        return 1;
    if (test_text_attrib_printable())
        return 1;
#ifdef HAVE_ECC
    if (test_envelop_rejects_ecc_ra())
        return 1;
#endif
    wolfcert_cleanup();
    printf("OK\n");
    return 0;
}
