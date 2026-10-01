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
 * Negative-path tests for the parsers that ingest untrusted bytes:
 * the URL parser, base64 decoder, PKCS#7 certs-only extractor, and CSR
 * PEM->DER path. Each fuzz-style input should produce an error without
 * crashing, reading past the buffer, or allocating unboundedly.
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include <wolfcert/wolfcert.h>
#include "../test_static_mem.h"
#include "internal.h"

#include <stdio.h>
#include <string.h>

#if defined(WOLFCERT_HAVE_EST) || defined(WOLFCERT_HAVE_SCEP)
#include "../integration/tls_test_util.h"
#include <wolfssl/wolfcrypt/pkcs7.h>
#endif

#if defined(WOLFCERT_HAVE_SCEP) && defined(WOLFCERT_HAVE_RSA)
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/random.h>
#endif

#define REQUIRE(cond) \
    do {                                                                    \
        if (!(cond)) {                                                      \
            fprintf(stderr, "FAIL %s:%d %s\n", __FILE__, __LINE__, #cond);  \
            return 1;                                                       \
        }                                                                   \
    } while (0)

static int test_url(void)
{
    WolfCertUrl u;
    /* A missing scheme is not an error - it defaults to TLS (see test_http);
     * but a schemeless URL with a bad port is still rejected. */
    REQUIRE(wolfcert_http_url_parse("no-scheme:0/p", &u, NULL) == WOLFCERT_ERR_PARSE);
    /* Empty bracketed IPv6. */
    REQUIRE(wolfcert_http_url_parse("http://[:/p", &u, NULL) == WOLFCERT_ERR_PARSE);
    /* Unknown scheme. */
    REQUIRE(wolfcert_http_url_parse("ftp://x/", &u, NULL) == WOLFCERT_ERR_UNSUPPORTED);
    /* Port out of range. */
    REQUIRE(wolfcert_http_url_parse("http://x:0/", &u, NULL) == WOLFCERT_ERR_PARSE);
    REQUIRE(wolfcert_http_url_parse("http://x:99999/", &u, NULL) == WOLFCERT_ERR_PARSE);
    /* Hostname longer than the cap. */
    char big[400];
    memset(big, 'a', sizeof(big) - 1);
    big[sizeof(big) - 1] = '\0';
    char url[512];
    snprintf(url, sizeof(url), "http://%s/", big);
    REQUIRE(wolfcert_http_url_parse(url, &u, NULL) == WOLFCERT_ERR_PARSE);
    return 0;
}

static int test_base64(void)
{
    WolfCertBuffer out = { 0 };
    /* Garbage chars. */
    const uint8_t bad[] = "!!!!";
    REQUIRE(wolfcert_base64_decode(bad, sizeof(bad) - 1, &out, NULL) != WOLFCERT_OK);
    return 0;
}

#if defined(WOLFCERT_HAVE_EST) || defined(WOLFCERT_HAVE_SCEP)
static int test_pkcs7(void)
{
    /* Zero-length input. */
    WolfCertBuffer out = { 0 };
    REQUIRE(wolfcert_pkcs7_certs_to_pem(NULL, 0, &out, NULL) == WOLFCERT_ERR_BAD_ARG);

    /* Garbage DER. */
    uint8_t buf[32];
    memset(buf, 0xFF, sizeof(buf));
    REQUIRE(wolfcert_pkcs7_certs_to_pem(buf, sizeof(buf), &out, NULL) != WOLFCERT_OK);

    /* Truncated SEQUENCE. */
    uint8_t trunc[] = { 0x30, 0x10, 0x06 };
    REQUIRE(wolfcert_pkcs7_certs_to_pem(trunc, sizeof(trunc), &out, NULL) != WOLFCERT_OK);

    /* certs_only build rejects non-SEQUENCE cert input. */
    const uint8_t junk[8] = { 0x00 };
    const uint8_t* certs[1] = { junk };
    size_t lens[1] = { sizeof(junk) };
    REQUIRE(wolfcert_pkcs7_build_certs_only(certs, lens, 1, &out, NULL)
            == WOLFCERT_ERR_PARSE);
    return 0;
}

/* Mint a self-signed certificate named `cn` as DER into `out`. */
static int mint_cert_der(const char* cn, uint8_t* out, size_t cap,
                         size_t* out_len)
{
    uint8_t* cert_pem = NULL;
    uint8_t* key_pem = NULL;
    size_t cert_len = 0;
    size_t key_len = 0;
    DerBuffer* der = NULL;
    int rc;

    rc = mint_self_id(cn, 1, &cert_pem, &cert_len, &key_pem, &key_len);
    if (rc == 0)
        rc = wc_PemToDer(cert_pem, (long)cert_len, CERT_TYPE, &der, NULL, NULL,
                         NULL);
    if (rc == 0 && der->length > cap)
        rc = -1;
    if (rc == 0) {
        memcpy(out, der->buffer, der->length);
        *out_len = der->length;
    }

    wc_FreeDer(&der);
    free(cert_pem);
    free(key_pem);
    return rc;
}

/* Header size of the definite-length TLV at p. */
static size_t tlv_hdr_len(const uint8_t* p)
{
    return (p[1] & 0x80) ? 2 + (size_t)(p[1] & 0x7F) : 2;
}

/* BER forms bundle_to_ber() writes. */
enum { BER_WRAPPERS, BER_STREAMED, BER_CERT_LIST };

/* Re-encode a certs-only bundle with indefinite lengths on its outer wrappers
 * and, per `form`, on encapContentInfo (carrying content, as a streaming
 * encoder writes it) or on the certificate list. The caller frees *out. */
static int bundle_to_ber(const uint8_t* der, size_t der_len, int form,
                         uint8_t** out, size_t* out_len)
{
    static const uint8_t wrap[] = { 0xA0, 0x80, 0x30, 0x80 };
    static const uint8_t list_open[] = { 0xA0, 0x80 };
    static const uint8_t signer_infos[] = { 0x31, 0x00 };
    static const uint8_t eoc[6] = { 0 };
    /* encapContentInfo as the encoder writes it, after version and an empty
     * digestAlgorithms, and its streamed form holding the content "A". */
    static const uint8_t encap[] = {
        0x30, 0x0B, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01,
        0x07, 0x01
    };
    static const uint8_t encap_streamed[] = {
        0x30, 0x80, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01,
        0x07, 0x01, 0xA0, 0x80, 0x24, 0x80, 0x04, 0x01, 0x41, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00
    };
    const size_t encap_at = 5;
    const size_t list_at = encap_at + sizeof(encap);
    const uint8_t* oid = der + tlv_hdr_len(der);
    size_t oid_len = 2 + (size_t)oid[1];
    const uint8_t* body = oid + oid_len + tlv_hdr_len(oid + oid_len);
    const uint8_t* piece[5];
    size_t piece_len[5];
    size_t pieces = 0;
    size_t body_len;
    size_t list_hdr;
    size_t i;
    uint8_t* p;

    body += tlv_hdr_len(body);
    body_len = (size_t)(der + der_len - body);
    if (form != BER_WRAPPERS &&
            (body_len < list_at + 4 ||
             memcmp(body + encap_at, encap, sizeof(encap)) != 0 ||
             body[list_at] != 0xA0 ||
             memcmp(body + body_len - sizeof(signer_infos), signer_infos,
                    sizeof(signer_infos)) != 0))
        return -1;

    if (form == BER_WRAPPERS) {
        piece[0] = body;
        piece_len[0] = body_len;
        pieces = 1;
    }
    else if (form == BER_STREAMED) {
        piece[0] = body;
        piece_len[0] = encap_at;
        piece[1] = encap_streamed;
        piece_len[1] = sizeof(encap_streamed);
        piece[2] = body + list_at;
        piece_len[2] = body_len - list_at;
        pieces = 3;
    }
    else {
        list_hdr = tlv_hdr_len(body + list_at);
        piece[0] = body;
        piece_len[0] = list_at;
        piece[1] = list_open;
        piece_len[1] = sizeof(list_open);
        piece[2] = body + list_at + list_hdr;
        piece_len[2] = body_len - list_at - list_hdr - sizeof(signer_infos);
        piece[3] = eoc;
        piece_len[3] = 2;
        piece[4] = signer_infos;
        piece_len[4] = sizeof(signer_infos);
        pieces = 5;
    }

    *out_len = 2 + oid_len + sizeof(wrap) + sizeof(eoc);
    for (i = 0; i < pieces; i++)
        *out_len += piece_len[i];
    *out = (uint8_t*)malloc(*out_len);
    if (*out == NULL)
        return -1;

    p = *out;
    *p++ = 0x30;
    *p++ = 0x80;
    memcpy(p, oid, oid_len);
    p += oid_len;
    memcpy(p, wrap, sizeof(wrap));
    p += sizeof(wrap);
    for (i = 0; i < pieces; i++) {
        memcpy(p, piece[i], piece_len[i]);
        p += piece_len[i];
    }
    memcpy(p, eoc, sizeof(eoc));
    return 0;
}

/* Does extracting `bundle` as DER give certs[0..count) in order? */
static int extracts_in_order(const uint8_t* bundle, size_t bundle_len,
                             const uint8_t* const* certs, const size_t* lens,
                             size_t count)
{
    WolfCertBuffer out = { 0 };
    size_t off = 0;
    size_t i;
    int ok;

    ok = wolfcert_pkcs7_certs_to_der(bundle, bundle_len, &out, NULL)
         == WOLFCERT_OK;
    for (i = 0; ok && i < count; i++) {
        ok = off + lens[i] <= out.len &&
             memcmp(out.data + off, certs[i], lens[i]) == 0;
        off += lens[i];
    }
    ok = ok && off == out.len;

    wolfcert_buffer_free(&out);
    return ok;
}

/* Is `bundle` refused with `want`, with nothing handed back? */
static int refused_with(const uint8_t* bundle, size_t bundle_len, int want)
{
    WolfCertBuffer out = { 0 };
    int rc = wolfcert_pkcs7_certs_to_der(bundle, bundle_len, &out, NULL);
    int ok = (rc == want && out.data == NULL);

    wolfcert_buffer_free(&out);
    return ok;
}

/* Does this wolfSSL build accept the bundle at all? */
static int wolfssl_accepts(const uint8_t* bundle, size_t bundle_len)
{
    PKCS7* p7 = wc_PKCS7_New(NULL, INVALID_DEVID);
    int ok;

    if (p7 == NULL)
        return 0;

    ok = wc_PKCS7_VerifySignedData(p7, (byte*)bundle, (word32)bundle_len) == 0;
    wc_PKCS7_Free(p7);
    return ok;
}

/* Re-encode `p7` as BER and check it as extracts_in_order() does. A BER form
 * this wolfSSL build does not accept counts as a pass. */
static int ber_extracts_in_order(const WolfCertBuffer* p7, int form,
                                 const uint8_t* const* certs,
                                 const size_t* lens, size_t count)
{
    uint8_t* ber = NULL;
    size_t ber_len = 0;
    int ok;

    ok = bundle_to_ber(p7->data, p7->len, form, &ber, &ber_len) == 0;
    if (ok && wolfssl_accepts(ber, ber_len))
        ok = extracts_in_order(ber, ber_len, certs, lens, count);

    free(ber);
    return ok;
}

/* DER and BER bundles come back whole and in order up to the limit; one more,
 * a non-certificate or an unknown entry is refused. Each case frees before
 * asserting so a failed REQUIRE cannot leak. */
static int test_pkcs7_bundle(void)
{
    static const uint8_t not_cert[] = { 0x30, 0x03, 0x02, 0x01, 0x00 };
    static const uint8_t empty_seq[] = { 0x30, 0x00 };
    const uint8_t* certs[WOLFCERT_PKCS7_MAX_CERTS + 1];
    size_t lens[WOLFCERT_PKCS7_MAX_CERTS + 1];
    uint8_t a[2048];
    uint8_t b[2048];
    size_t a_len = 0;
    size_t b_len = 0;
    WolfCertBuffer p7 = { 0 };
    uint8_t* last = NULL;
    int built;
    int der_ok;
    int ber_ok;
    int streamed_ok;
    int accepted;
    int refused;
    size_t i;

    REQUIRE(mint_cert_der("bundle cert A", a, sizeof(a), &a_len) == 0);
    REQUIRE(mint_cert_der("bundle cert B", b, sizeof(b), &b_len) == 0);
    for (i = 0; i < WOLFCERT_PKCS7_MAX_CERTS + 1; i++) {
        certs[i] = (i % 2 == 0) ? a : b;
        lens[i]  = (i % 2 == 0) ? a_len : b_len;
    }

    built = wolfcert_pkcs7_build_certs_only(certs, lens,
                WOLFCERT_PKCS7_MAX_CERTS, &p7, NULL) == WOLFCERT_OK;
    der_ok = built && extracts_in_order(p7.data, p7.len, certs, lens,
                                        WOLFCERT_PKCS7_MAX_CERTS);
    ber_ok = built && ber_extracts_in_order(&p7, BER_WRAPPERS, certs, lens,
                                            WOLFCERT_PKCS7_MAX_CERTS);
    streamed_ok = built && ber_extracts_in_order(&p7, BER_STREAMED, certs,
                                                 lens,
                                                 WOLFCERT_PKCS7_MAX_CERTS);
    wolfcert_buffer_free(&p7);
    REQUIRE(built);
    REQUIRE(der_ok);
    REQUIRE(ber_ok);
    REQUIRE(streamed_ok);

    built = wolfcert_pkcs7_build_certs_only(certs, lens, 1, &p7, NULL)
            == WOLFCERT_OK;
    ber_ok = built && ber_extracts_in_order(&p7, BER_CERT_LIST, certs, lens, 1);
    wolfcert_buffer_free(&p7);
    REQUIRE(built);
    REQUIRE(ber_ok);

    built = wolfcert_pkcs7_build_certs_only(certs, lens,
                WOLFCERT_PKCS7_MAX_CERTS + 1, &p7, NULL) == WOLFCERT_OK;
    der_ok = built && refused_with(p7.data, p7.len, WOLFCERT_ERR_UNSUPPORTED);
    wolfcert_buffer_free(&p7);
    REQUIRE(built);
    REQUIRE(der_ok);

    certs[1] = not_cert;
    lens[1] = sizeof(not_cert);
    built = wolfcert_pkcs7_build_certs_only(certs, lens, 2, &p7, NULL)
            == WOLFCERT_OK;
    accepted = built && wolfssl_accepts(p7.data, p7.len);
    refused = accepted && refused_with(p7.data, p7.len, WOLFCERT_ERR_PARSE);
    wolfcert_buffer_free(&p7);
    REQUIRE(built);
    REQUIRE(accepted);
    REQUIRE(refused);

    /* Turn an empty SEQUENCE after A into an empty OCTET STRING, which no
     * CertificateChoices alternative allows. */
    certs[1] = empty_seq;
    lens[1] = sizeof(empty_seq);
    built = wolfcert_pkcs7_build_certs_only(certs, lens, 2, &p7, NULL)
            == WOLFCERT_OK;
    if (built) {
        last = p7.data + p7.len - 2 - sizeof(empty_seq);
        built = memcmp(last, empty_seq, sizeof(empty_seq)) == 0;
    }
    if (built)
        last[0] = 0x04;
    accepted = built && wolfssl_accepts(p7.data, p7.len);
    refused = accepted && refused_with(p7.data, p7.len, WOLFCERT_ERR_PARSE);
    wolfcert_buffer_free(&p7);
    REQUIRE(built);
    REQUIRE(accepted);
    REQUIRE(refused);

    return 0;
}
#endif

#if defined(WOLFCERT_HAVE_SCEP) && defined(WOLFCERT_HAVE_RSA)
static int oid_present(const uint8_t* hay, size_t hl,
                       const uint8_t* needle, size_t nl)
{
    size_t i;
    if (nl > hl)
        return 0;

    for (i = 0; i + nl <= hl; ++i) {
        if (memcmp(hay + i, needle, nl) == 0)
            return 1;
    }

    return 0;
}

/* The RFC 8894 GetCACaps "AES" keyword advertises AES-128-CBC as the
 * content cipher. wolfcert_scep_envelop must emit exactly the cipher the
 * caller selects, not silently fall back to AES-256-CBC which a
 * minimally-compliant peer cannot decrypt. The non-AES fallback (a peer that
 * does not advertise "AES") selects triple DES-CBC, so verify that DES3b
 * emits the 3DES-CBC OID too. */
static int test_scep_envelop_alg(void)
{
    static const uint8_t OID_AES128_CBC[] =
        { 0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x01,0x02 };
    static const uint8_t OID_AES256_CBC[] =
        { 0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x01,0x2A };
#ifndef NO_DES3
    static const uint8_t OID_DES3_CBC[] =
        { 0x06,0x08,0x2A,0x86,0x48,0x86,0xF7,0x0D,0x03,0x07 };
#endif
    static const uint8_t payload[] = { 0x04, 0x03, 0x61, 0x62, 0x63 };

    RsaKey key;
    WC_RNG rng;
    uint8_t* ra_der = NULL;
    size_t ra_len = 0;
    WolfCertBuffer env = { 0 };
    Cert* req = NULL;
    uint8_t* csr_der = NULL;
    int csr_body = 0;
    int csr_len = 0;

    REQUIRE(wc_InitRng(&rng) == 0);
    REQUIRE(wc_InitRsaKey(&key, NULL) == 0);
    REQUIRE(wc_MakeRsaKey(&key, 2048, 65537L, &rng) == 0);

    /* wolfcert_scep_self_signed_rsa now derives the signer subject from an
     * enclosed PKCS#10 request (RFC 8894 section 2.3), so build a minimal CSR
     * to feed it. The subject is irrelevant to this test's cipher check. */
    req = wc_CertNew(NULL);
    REQUIRE(req != NULL);
    wc_InitCert_ex(req, NULL, INVALID_DEVID);
    strncpy(req->subject.commonName, "scep-test", CTC_NAME_SIZE - 1);
    req->subject.commonName[CTC_NAME_SIZE - 1] = '\0';
    req->sigType = CTC_SHA256wRSA;

    csr_der = (uint8_t*)WOLFCERT_XMALLOC(4096, NULL);
    REQUIRE(csr_der != NULL);
    csr_body = wc_MakeCertReq(req, csr_der, 4096, &key, NULL);
    REQUIRE(csr_body > 0);
    csr_len = wc_SignCert(csr_body, CTC_SHA256wRSA, csr_der, 4096, &key, NULL,
                          &rng);
    REQUIRE(csr_len > 0);

    REQUIRE(wolfcert_scep_self_signed_rsa(&key, csr_der, (size_t)csr_len,
                                          &ra_der, &ra_len, NULL) == WOLFCERT_OK);

    REQUIRE(wolfcert_scep_envelop(ra_der, ra_len, payload, sizeof(payload),
                                  AES128CBCb, &env, NULL) == WOLFCERT_OK);

    REQUIRE(oid_present(env.data, env.len,
                        OID_AES128_CBC, sizeof(OID_AES128_CBC)));
    REQUIRE(!oid_present(env.data, env.len,
                         OID_AES256_CBC, sizeof(OID_AES256_CBC)));

    wolfcert_buffer_free(&env);

#ifndef NO_DES3
    REQUIRE(wolfcert_scep_envelop(ra_der, ra_len, payload, sizeof(payload),
                                  DES3b, &env, NULL) == WOLFCERT_OK);

    REQUIRE(oid_present(env.data, env.len,
                        OID_DES3_CBC, sizeof(OID_DES3_CBC)));

    wolfcert_buffer_free(&env);
#endif

    WOLFCERT_XFREE(ra_der, NULL);
    WOLFCERT_XFREE(csr_der, NULL);
    wc_CertFree(req);
    wc_FreeRsaKey(&key);
    wc_FreeRng(&rng);
    return 0;
}
#endif

static int test_ip_literal(void)
{
    /* The output lands verbatim in a certificate iPAddress SAN, so pin the
     * byte layout the "::" slide produces, not just the accept/reject call. */
    static const struct {
        const char*   text;
        size_t        len;
        const uint8_t bytes[16];
    } good[] = {
        { "192.0.2.10",       4, { 192, 0, 2, 10 } },
        { "::",              16, { 0 } },
        { "::1",             16, { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1 } },
        { "fe80::1",         16, { 0xfe,0x80,0,0,0,0,0,0,0,0,0,0,0,0,0,1 } },
        { "::ffff:192.0.2.1", 16,
          { 0,0,0,0,0,0,0,0,0,0,0xff,0xff,192,0,2,1 } },
        { "1:2:3:4:5:6:7:8", 16, { 0,1,0,2,0,3,0,4,0,5,0,6,0,7,0,8 } }
    };
    static const char* const bad[] = {
        "010.1.1.1", "256.1.1.1", "1.2.3", "1.2.3.4.5",
        "fe80::1%eth0", "2001:db8::/32", "1::2::3", "12345::", "g::1", ""
    };
    uint8_t out[16];
    size_t len;
    size_t i;

    for (i = 0; i < sizeof(good) / sizeof(good[0]); ++i) {
        len = 0;
        REQUIRE(wolfcert_parse_ip(good[i].text, out, &len) == WOLFCERT_OK);
        REQUIRE(len == good[i].len);
        REQUIRE(memcmp(out, good[i].bytes, len) == 0);
    }

    for (i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i) {
        len = 0;
        REQUIRE(wolfcert_parse_ip(bad[i], out, &len) == WOLFCERT_ERR_PARSE);
    }

    REQUIRE(wolfcert_parse_ip(NULL, out, &len) == WOLFCERT_ERR_BAD_ARG);
    return 0;
}

static int test_csr_pem(void)
{
    WolfCertBuffer der = { 0 };
    REQUIRE(wolfcert_csr_pem_to_der((const uint8_t*)"not pem", 7, &der) == WOLFCERT_ERR_PARSE);
    return 0;
}

int main(void)
{
    REQUIRE(test_static_mem_init() == 0);
    REQUIRE(wolfcert_init(NULL) == WOLFCERT_OK);
    if (test_url())
        return 1;
    if (test_base64())
        return 1;
#if defined(WOLFCERT_HAVE_EST) || defined(WOLFCERT_HAVE_SCEP)
    if (test_pkcs7())
        return 1;
    if (test_pkcs7_bundle())
        return 1;
#endif
    if (test_csr_pem())
        return 1;
    if (test_ip_literal())
        return 1;
#if defined(WOLFCERT_HAVE_SCEP) && defined(WOLFCERT_HAVE_RSA)
    if (test_scep_envelop_alg())
        return 1;
#endif
    wolfcert_cleanup();
    printf("OK\n");
    return 0;
}
