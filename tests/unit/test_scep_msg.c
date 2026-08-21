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
 * SCEP pkiMessage structural tests.
 *
 * RFC 8894 section 3.2.2: a CertRep whose pkiStatus is PENDING ("3") or
 * FAILURE ("2") carries no pkcsPKIEnvelope, so the signed pkiMessage must
 * encode with an absent SignedData eContent. This exercises the build/parse
 * pair directly: a non-success pkiMessage built with no envelope must contain
 * no EnvelopedData and must round-trip through the parser with an empty
 * envelope and the expected signed attributes.
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#define _DARWIN_C_SOURCE   /* expose memmem on macOS */
#define _GNU_SOURCE

#include <wolfcert/wolfcert.h>
#include "../test_static_mem.h"
#include "internal.h"

#include <wolfssl/options.h>
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

/* Generate a throwaway self-signed RSA CA cert and its private key, both DER.
 * Ownership of the returned buffers passes to the caller (free with free()). */
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

#ifdef HAVE_ECC
/* Generate a throwaway self-signed ECC (P-256) CA cert, DER. Ownership of the
 * returned buffer passes to the caller (free with free()). */
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

/* wolfcert_scep_envelop must reject a non-RSA RA certificate up front with a
 * clear WOLFCERT_ERR_UNSUPPORTED, not fail deep in the PKCS#7 encoder with
 * BAD_KEYWRAP_ALG_E - RFC 8894 is RSA-only. An RSA RA cert still succeeds. */
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

    /* enc_oid is irrelevant for the ECC case: the recipient is rejected up
     * front, before it is used. The RSA cert is the contrast that must still
     * envelop. */
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

/* Build a FAILURE CertRep signed with hash_oid and confirm it carries no
 * pkcsPKIEnvelope and still round-trips through the parser - which must
 * discover the signer's digest rather than assume one. */
static int check_no_envelope(const uint8_t* ca_der, size_t ca_len,
                             const uint8_t* key_der, size_t key_len,
                             int hash_oid)
{
    /* pkcs7-envelopedData OID 1.2.840.113549.1.7.3 - present whenever a
     * pkcsPKIEnvelope is emitted, and what must be absent here. */
    static const uint8_t ENVELOPED_OID[] =
        { 0x06,0x09,0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x07,0x03 };
    static const uint8_t tid[16] =
        { 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15 };
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

    /* Build a FAILURE CertRep with no enveloped messageData. */
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

    /* The pkcsPKIEnvelope must be genuinely absent: no EnvelopedData. */
    REQUIRE(memmem(pki.data, pki.len, ENVELOPED_OID,
                   sizeof(ENVELOPED_OID)) == NULL);

    /* The message must still verify and parse, returning an empty envelope. */
    prc = wolfcert_scep_parse_pki_message(pki.data, pki.len, &env,
            &rx_tid, &rx_tid_len, &rx_sn, &rx_sn_len, &rx_rn, &rx_rn_len,
            &mt, &status, NULL, NULL, &rx_fi, NULL);
    /* Capture every assertion, then free the parsed outputs before the REQUIREs
     * so a failing check cannot leak them (same pattern as test_pki_get_url). */
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

    /* SHA-256 is the common case. SHA-512 covers a signer that chose a
     * different digest: the parser must not assume the algorithm. */
    rc = check_no_envelope(ca_der, ca_len, key_der, key_len, SHA256h);
#ifdef WOLFSSL_SHA512
    if (rc == 0)
        rc = check_no_envelope(ca_der, ca_len, key_der, key_len, SHA512h);
#endif

    free(ca_der);
    free(key_der);
    return rc;
}

/* A transactionID longer than the generated 32-hex one must survive a
 * build -> parse round trip byte for byte. RFC 8894 puts no length bound on the
 * attribute, and a client that silently truncated it would send an identifier
 * naming a different transaction than the one it is polling for. */
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

    /* Printable-string bytes so the value is a legal PrintableString, and
     * varying so a truncated copy cannot compare equal by accident. */
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

/* Build a PKCS#10 CSR with a distinctive multi-RDN subject, DER-encoded and
 * signed with `key`. Ownership of *csr_out passes to the caller (free with
 * free()). */
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

/* RFC 8894 section 2.3: the transient self-signed certificate that signs a
 * PKCSReq must carry the same subject name as the enclosed PKCS#10 request.
 * Build a CSR with a distinctive subject, generate the signer cert from it,
 * and require the signer's subject DN to match the CSR's byte for byte. */
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

    /* The signer certificate subject DN must equal the CSR subject DN. */
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

/* RFC 8894: a CertRep must be signed by the CA/RA certificate the client
 * fetched via GetCACert. A response signed by any other certificate, as a
 * MITM or rogue server would forge, must be rejected before the client
 * trusts the enclosed certificate. */
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

    /* Signer whose key differs from the RA cert must be rejected. */
    REQUIRE(wolfcert_scep_verify_rep_signer(att_der, att_len,
                                            ra_der, ra_len, NULL)
            != WOLFCERT_OK);

    /* The genuine CA/RA signer is accepted. */
    REQUIRE(wolfcert_scep_verify_rep_signer(ra_der, ra_len,
                                            ra_der, ra_len, NULL)
            == WOLFCERT_OK);

    free(ra_der);
    free(ra_key);
    free(att_der);
    free(att_key);
    return 0;
}

/* RFC 8894: an enrollment response must be a CertRep (messageType "3") whose
 * transactionID echoes the request. A mismatched transactionID or a wrong
 * messageType must be rejected so a follow-up poll cannot run under the wrong
 * transaction. */
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

/* RFC 8894 section 4.6.1: the GetNextCACert response must be a SignedData
 * signed by the current CA, not an unsigned degenerate certs-only bundle. A
 * signed message verifies through the pkiMessage parser (which rejects
 * degenerate SignedData); the signed content must in turn yield the next CA
 * certificate. */
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

    /* A signed SignedData verifies here; an unsigned degenerate bundle does
     * not, because the parser rejects degenerate SignedData. */
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

/* RFC 8894 section 4.6.1: the client must bind the GetNextCACert response to
 * the current CA it already trusts. A response validated against a different
 * (attacker) CA must be rejected, while the genuine current CA is accepted. */
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

    /* Rejected when bound to a different CA: the signer is not trusted. */
    REQUIRE(wolfcert_scep_verify_next_ca_response(resp.data, resp.len,
                                                  att_der, att_len,
                                                  &pem, NULL) != WOLFCERT_OK);
    wolfcert_buffer_free(&pem);

    /* Binding is mandatory: a NULL current CA must be rejected, not silently
     * skipped. */
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

/* Build a SignedData signed by signer_cert/signer_key, but prepend extra_cert
 * so the bundle carries it as the first certificate while the SignerInfo still
 * identifies signer_cert. Ownership of *out passes to the caller (free()). */
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

/* A SignedData verifier trusts the certificate that actually produced the
 * signature, which wolfSSL matches by SignerInfo identity, not the first cert
 * in the bundle. A message signed by an attacker key but carrying a trusted
 * cert first must surface the attacker cert as the signer so the trust check
 * against the trusted CA rejects it. */
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

    /* The parser must surface the cert that signed, not cert[0]. */
    REQUIRE(signer != NULL);
    REQUIRE(signer_len == att_len && memcmp(signer, att_der, att_len) == 0);

    /* Binding that real signer to the trusted CA must therefore fail. */
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

/* RFC 8894 / split CA-RA: the response signer is trusted when it matches any
 * certificate in the fingerprint-verified GetCACert bundle, not only the first
 * one. Verify a signer matching the second cert of a two-cert bundle (e.g. an
 * RA encryption cert followed by the CA signer) is accepted, and one in neither
 * is rejected. */
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

    free(bundle);
    free(a_der);
    free(a_key);
    free(b_der);
    free(b_key);
    free(u_der);
    free(u_key);
    return 0;
}

/* When the CSR subject cannot be copied verbatim, wolfcert_scep_self_signed_rsa
 * falls back to a common name. An empty subject (DER 30 00) trips the memchr
 * guard against wolfSSL's XSTRLEN raw-name recovery (the 0x00 length octet),
 * and with no CN present the signer cert gets the literal "SCEP Enrollee".
 * (The CN-fallback branch needs an embedded-NUL or oversized DN that
 * wc_MakeCertReq cannot produce, so only the default branch is exercised.) */
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

    /* Empty subject: raw path skipped, no CN, so the literal is used. */
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

/* All fingerprint assertions run against a caller-owned CA DER so the buffer is
 * freed exactly once by test_ca_fingerprint no matter which REQUIRE fires - the
 * same ownership split as check_no_envelope / test_non_success_has_no_envelope. */
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
    /* SHA-1 absent: an explicit SHA-1 request, and AUTO with a 20-byte
     * (SHA-1-length) fingerprint, both fall to the outer switch default and
     * must report the algorithm unsupported rather than mis-dispatching. The
     * buffer contents are irrelevant - the algorithm check precedes the
     * fingerprint compare. */
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

/* wolfcert_scep_verify_ca_fingerprint: correct digest verifies, a tampered one
 * is rejected, AUTO dispatches on length, and length/argument misuse is caught. */
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

/* Percent-decode `in` into `out` (which must hold at least strlen(in) bytes),
 * reversing url_encode()'s "%XX" escaping. Returns the decoded byte count, or
 * -1 on a malformed escape. */
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

/* wolfcert_scep_build_pki_get_url: builds a well-formed GET URL for small
 * messages and refuses one that would exceed WOLFCERT_SCEP_MAX_GET_URL. */
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
    /* Capture the assertions, then free url before the REQUIREs so a failing
     * check cannot leak the heap-allocated URL. */
    prefix_ok = (strncmp(url, pfx, strlen(pfx)) == 0);
    /* Round-trip the message= value rather than only checking it is non-empty:
     * percent-decode, then base64-decode, and confirm it reproduces the
     * original bytes. A url_encode that dropped the mandatory base64 escaping
     * (+, /, =) would corrupt this and be caught here. */
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
    WOLFCERT_XFREE(url, NULL);   /* url came from the wolfCert heap, not malloc */
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

/* wolfcert_scep_build_getca_url: omits message= when no CA identifier is set,
 * appends it (URL-encoded) when one is. */
static int test_getca_url(void)
{
    /* The URLs come from the wolfCert heap, so they are released with
     * WOLFCERT_XFREE and not free(): under WOLFSSL_NO_MALLOC that heap is a
     * static pool and libc never saw the pointer. */
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

/* The mirror of test_est_rejects_scep_cfg: WolfCertServerCfg.protocol
 * discriminates the proto_opts union, so a SCEP entry point handed an EST
 * config must refuse it rather than read the wrong arm. Reading the SCEP arm
 * here would send the EST username as the CA identifier and derive the txid
 * mode and content cipher from the bytes of the password pointer. The
 * enrollment entry points share the same gate; the ones exercised below are
 * those reachable without a live RSA signer. Nothing here touches the
 * network. */
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

    /* Both session-open paths gate on the discriminator too, before they copy
     * the SCEP options out of the union. */
    REQUIRE(wolfcert_scep_session_open(&srv, &sess) == WOLFCERT_ERR_BAD_ARG);
    REQUIRE(sess == NULL);
    REQUIRE(wolfcert_scep_session_open_async(&srv, &sess) == WOLFCERT_ERR_BAD_ARG);
    REQUIRE(sess == NULL);

    /* An unset discriminator is refused for the same reason: nothing says
     * which arm of the union the caller populated. */
    srv.protocol = (WolfCertProtocol)0;
    REQUIRE(wolfcert_scep_get_ca_caps(&srv, &caps) == WOLFCERT_ERR_BAD_ARG);
    REQUIRE(wolfcert_scep_session_open(&srv, &sess) == WOLFCERT_ERR_BAD_ARG);

    return 0;
}

/* Only meaningful where wolfSSL can actually run an AES-CBC content cipher. */
#if defined(HAVE_AES_CBC) && \
        (defined(WOLFSSL_AES_128) || defined(WOLFSSL_AES_256))
/* The content-cipher choice reaches the wire: enveloping with AES256CBCb /
 * AES128CBCb yields a message carrying the matching AES-CBC OID. */
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

#if defined(WOLFSSL_AES_256) && defined(HAVE_AES_CBC)
    WolfCertBuffer env256 = { 0 };
    REQUIRE(wolfcert_scep_envelop(ca_der, ca_len, payload, sizeof(payload),
                                  AES256CBCb, &env256, NULL) == WOLFCERT_OK);
    REQUIRE(memmem(env256.data, env256.len, OID_AES256, sizeof(OID_AES256)) != NULL);
    REQUIRE(memmem(env256.data, env256.len, OID_AES128, sizeof(OID_AES128)) == NULL);
    wolfcert_buffer_free(&env256);
#endif

#if defined(WOLFSSL_AES_128) && defined(HAVE_AES_CBC)
    WolfCertBuffer env128 = { 0 };
    REQUIRE(wolfcert_scep_envelop(ca_der, ca_len, payload, sizeof(payload),
                                  AES128CBCb, &env128, NULL) == WOLFCERT_OK);
    REQUIRE(memmem(env128.data, env128.len, OID_AES128, sizeof(OID_AES128)) != NULL);
    wolfcert_buffer_free(&env128);
#endif

    free(ca_der);
    free(key_der);
    return 0;
}
#endif /* HAVE_AES_CBC && (WOLFSSL_AES_128 || WOLFSSL_AES_256) */

int main(void)
{
    REQUIRE(test_static_mem_init() == 0);
    REQUIRE(wolfcert_init(NULL) == WOLFCERT_OK);
    if (test_getca_url())
        return 1;
    if (test_scep_rejects_est_cfg())
        return 1;
#if defined(HAVE_AES_CBC) && \
        (defined(WOLFSSL_AES_128) || defined(WOLFSSL_AES_256))
    if (test_envelop_cipher_oid())
        return 1;
#endif
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
#ifdef HAVE_ECC
    if (test_envelop_rejects_ecc_ra())
        return 1;
#endif
    wolfcert_cleanup();
    printf("OK\n");
    return 0;
}
