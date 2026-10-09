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

/* wolfcert_est_parse_csr_attrs over hand-built CsrAttrs DER blobs. */

#define _POSIX_C_SOURCE 200809L

#include <wolfcert/wolfcert.h>
#include "../test_static_mem.h"
#include <wolfcert/est.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define REQUIRE(cond) \
    do {                                                                    \
        if (!(cond)) {                                                      \
            fprintf(stderr, "FAIL %s:%d %s\n", __FILE__, __LINE__, #cond);  \
            return 1;                                                       \
        }                                                                   \
    } while (0)

/* Short-form DER TLV (body_len < 128); returns bytes written. */
static size_t der_tlv(uint8_t tag, const uint8_t* body, size_t body_len,
                      uint8_t* out)
{
    out[0] = tag;
    out[1] = (uint8_t)body_len;
    memcpy(out + 2, body, body_len);
    return 2 + body_len;
}

static const uint8_t OID_CHALLENGE_PASSWORD[] = {
    0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x07
};
static const uint8_t OID_EXTENSION_REQUEST[]  = {
    0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x0E
};
static const uint8_t OID_ECDSA_SHA384[] = {
    0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03
};
static const uint8_t OID_EC_PUBLIC_KEY[] = {
    0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01
};
static const uint8_t OID_SECP384R1[] = { 0x2B, 0x81, 0x04, 0x00, 0x22 };

int main(void)
{
    REQUIRE(test_static_mem_init() == 0);
    REQUIRE(wolfcert_init(test_heap_hint()) == WOLFCERT_OK);

    /* Empty input gives no items and zero hints. */
    {
        WolfCertCsrAttrs a;
        REQUIRE(wolfcert_est_parse_csr_attrs(NULL, 0, &a) == WOLFCERT_OK);
        REQUIRE(a.count == 0);
        REQUIRE(a.require_challenge_password == 0);
        wolfcert_csr_attrs_free(&a);
    }

    /* Two bare OIDs, a sig-alg bare OID and an id-ecPublicKey Attribute. */
    uint8_t body[256];
    size_t body_len = 0;

    /* (1) bare OID challengePassword */
    body_len += der_tlv(0x06, OID_CHALLENGE_PASSWORD,
                        sizeof(OID_CHALLENGE_PASSWORD), body + body_len);
    /* (2) bare OID extensionRequest */
    body_len += der_tlv(0x06, OID_EXTENSION_REQUEST,
                        sizeof(OID_EXTENSION_REQUEST), body + body_len);
    /* (3) bare OID ecdsa-with-SHA384 (signature algorithm hint) */
    body_len += der_tlv(0x06, OID_ECDSA_SHA384, sizeof(OID_ECDSA_SHA384),
                        body + body_len);

    /* (4) Attribute SEQUENCE { OID id-ecPublicKey, SET { OID secp384r1 } } */
    uint8_t set_body[64];
    size_t set_body_len = 0;
    set_body_len += der_tlv(0x06, OID_SECP384R1, sizeof(OID_SECP384R1),
                            set_body + set_body_len);
    uint8_t attr_body[128];
    size_t attr_body_len = 0;
    attr_body_len += der_tlv(0x06, OID_EC_PUBLIC_KEY,
                             sizeof(OID_EC_PUBLIC_KEY), attr_body + attr_body_len);
    attr_body_len += der_tlv(0x31, set_body, set_body_len,
                             attr_body + attr_body_len);
    body_len += der_tlv(0x30, attr_body, attr_body_len, body + body_len);

    uint8_t outer[320];
    size_t outer_len = der_tlv(0x30, body, body_len, outer);

    WolfCertCsrAttrs a;
    REQUIRE(wolfcert_est_parse_csr_attrs(outer, outer_len, &a) == WOLFCERT_OK);
    REQUIRE(a.count == 4);

    REQUIRE(a.require_challenge_password == 1);
    REQUIRE(a.require_extension_request  == 1);
    REQUIRE(a.preferred_hash             == 384);
    REQUIRE(a.preferred_key_type         == WOLFCERT_KEY_ECC);
    REQUIRE(a.preferred_ecc_curve_bits   == 384);

    const WolfCertCsrAttrItem* cp = wolfcert_csr_attrs_find(
        &a, OID_CHALLENGE_PASSWORD, sizeof(OID_CHALLENGE_PASSWORD));
    REQUIRE(cp != NULL);
    REQUIRE(cp->kind == WOLFCERT_CSRATTR_BARE_OID);

    const WolfCertCsrAttrItem* pk = wolfcert_csr_attrs_find(
        &a, OID_EC_PUBLIC_KEY, sizeof(OID_EC_PUBLIC_KEY));
    REQUIRE(pk != NULL);
    REQUIRE(pk->kind == WOLFCERT_CSRATTR_ATTRIBUTE);
    REQUIRE(pk->values_der != NULL);
    REQUIRE(pk->values_len > 0);

    static const uint8_t BOGUS[] = { 0x2A, 0x03, 0x04, 0x05 };
    REQUIRE(wolfcert_csr_attrs_find(&a, BOGUS, sizeof(BOGUS)) == NULL);

    wolfcert_csr_attrs_free(&a);

    /* Outer tag is not SEQUENCE. */
    {
        uint8_t bad[] = { 0x31, 0x00 };
        WolfCertCsrAttrs b;
        REQUIRE(wolfcert_est_parse_csr_attrs(bad, sizeof(bad), &b)
                == WOLFCERT_ERR_PARSE);
    }

    /* Truncated long-form length. */
    {
        uint8_t bad[] = { 0x30, 0x82, 0x00 };  /* 0x82 needs two length bytes */
        WolfCertCsrAttrs b;
        int rc = wolfcert_est_parse_csr_attrs(bad, sizeof(bad), &b);
        REQUIRE(rc == WOLFCERT_ERR_PARSE);
    }

    /* AttrOrOID tag that is neither OID nor SEQUENCE. */
    {
        uint8_t bad_body[] = { 0x04, 0x01, 0xAA };          /* OCTET STRING */
        uint8_t bad[8];
        size_t n = der_tlv(0x30, bad_body, sizeof(bad_body), bad);
        WolfCertCsrAttrs b;
        REQUIRE(wolfcert_est_parse_csr_attrs(bad, n, &b) == WOLFCERT_ERR_PARSE);
    }

    /* Attribute missing its SET OF values; RFC 2985 requires SIZE(1..MAX). */
    {
        uint8_t attr_only_oid[32];
        size_t al = der_tlv(0x06, OID_EC_PUBLIC_KEY, sizeof(OID_EC_PUBLIC_KEY),
                            attr_only_oid);
        uint8_t attr_seq[48];
        size_t tl = der_tlv(0x30, attr_only_oid, al, attr_seq);
        uint8_t outer_bad[64];
        size_t bl = der_tlv(0x30, attr_seq, tl, outer_bad);
        WolfCertCsrAttrs b;
        REQUIRE(wolfcert_est_parse_csr_attrs(outer_bad, bl, &b)
                == WOLFCERT_ERR_PARSE);
    }

    /* Builder rejects a zero-length bare OID. */
    {
        WolfCertCsrAttrItem bad_item = {
            .kind = WOLFCERT_CSRATTR_BARE_OID, .oid = NULL, .oid_len = 0,
        };
        WolfCertBuffer out = { 0 };
        REQUIRE(wolfcert_csr_attrs_build(&bad_item, 1, &out)
                == WOLFCERT_ERR_BAD_ARG);
        REQUIRE(out.data == NULL);
    }
    /* Builder rejects an Attribute without values. */
    {
        WolfCertCsrAttrItem bad_item = {
            .kind = WOLFCERT_CSRATTR_ATTRIBUTE,
            .oid = OID_EC_PUBLIC_KEY, .oid_len = sizeof(OID_EC_PUBLIC_KEY),
            .values_der = NULL, .values_len = 0,
        };
        WolfCertBuffer out = { 0 };
        REQUIRE(wolfcert_csr_attrs_build(&bad_item, 1, &out)
                == WOLFCERT_ERR_BAD_ARG);
    }
    /* An empty build round-trips through the parser to zero items. */
    {
        WolfCertBuffer out = { 0 };
        REQUIRE(wolfcert_csr_attrs_build(NULL, 0, &out) == WOLFCERT_OK);
        WolfCertCsrAttrs b;
        REQUIRE(wolfcert_est_parse_csr_attrs(out.data, out.len, &b)
                == WOLFCERT_OK);
        REQUIRE(b.count == 0);
        wolfcert_csr_attrs_free(&b);
        wolfcert_buffer_free(&out);
    }

    /* Ed25519, Ed448 and ML-DSA bare OIDs set preferred_key_type. */
    {
        static const uint8_t OID_ED25519[]   = { 0x2B, 0x65, 0x70 };
        static const uint8_t OID_ED448[]     = { 0x2B, 0x65, 0x71 };
        static const uint8_t OID_ML_DSA_44[] = {
            0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11 };
        static const uint8_t OID_ML_DSA_65[] = {
            0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12 };
        static const uint8_t OID_ML_DSA_87[] = {
            0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13 };

        const struct {
            const uint8_t* oid;
            size_t         oid_len;
            int            expect_type;
        } cases[] = {
            {
                OID_ED25519,   sizeof(OID_ED25519),   WOLFCERT_KEY_ED25519
            }
            ,
            {
                OID_ED448,     sizeof(OID_ED448),     WOLFCERT_KEY_ED448
            }
            ,
            {
                OID_ML_DSA_44, sizeof(OID_ML_DSA_44), WOLFCERT_KEY_MLDSA44
            }
            ,
            {
                OID_ML_DSA_65, sizeof(OID_ML_DSA_65), WOLFCERT_KEY_MLDSA65
            }
            ,
            {
                OID_ML_DSA_87, sizeof(OID_ML_DSA_87), WOLFCERT_KEY_MLDSA87
            }
            ,
        };
        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
            uint8_t body2[64];
            size_t  body2_len = der_tlv(0x06, cases[i].oid, cases[i].oid_len, body2);
            uint8_t outer2[80];
            size_t  outer2_len = der_tlv(0x30, body2, body2_len, outer2);
            WolfCertCsrAttrs a2;
            REQUIRE(wolfcert_est_parse_csr_attrs(outer2, outer2_len, &a2)
                    == WOLFCERT_OK);
            REQUIRE(a2.preferred_key_type == cases[i].expect_type);
            /* Ed25519 / Ed448 / ML-DSA use no separate hash. */
            REQUIRE(a2.preferred_hash == 0);
            wolfcert_csr_attrs_free(&a2);
        }
    }

    /* Zeroed key_cfg and meta take ECC P-384 and SHA-384 from outer. */
    {
        WolfCertCsrAttrs a3;
        REQUIRE(wolfcert_est_parse_csr_attrs(outer, outer_len, &a3)
                == WOLFCERT_OK);

        WolfCertKeyCfg   kc = { 0 };
        WolfCertCertMeta mm = { 0 };
        REQUIRE(wolfcert_csr_attrs_apply(&a3, &kc, &mm) == WOLFCERT_OK);
        REQUIRE(kc.type   == WOLFCERT_KEY_ECC);
        REQUIRE(kc.param  == 384);
        REQUIRE(mm.preferred_hash == 384);

        wolfcert_csr_attrs_free(&a3);
    }

    /* A caller's RSA-2048 and SHA-256 survive the ECC P-384 / SHA-384 hints. */
    {
        WolfCertCsrAttrs a4;
        REQUIRE(wolfcert_est_parse_csr_attrs(outer, outer_len, &a4)
                == WOLFCERT_OK);

        WolfCertKeyCfg kc = {
            .type = WOLFCERT_KEY_RSA, .param = 2048,
        };
        WolfCertCertMeta mm = { .preferred_hash = 256 };
        REQUIRE(wolfcert_csr_attrs_apply(&a4, &kc, &mm) == WOLFCERT_OK);
        REQUIRE(kc.type           == WOLFCERT_KEY_RSA);
        REQUIRE(kc.param          == 2048);
        REQUIRE(mm.preferred_hash == 256);

        wolfcert_csr_attrs_free(&a4);
    }

    /* RSA or ECC type hint with no size hint: param becomes 2048 or 256. */
#ifdef WOLFCERT_HAVE_RSA
    {
        WolfCertCsrAttrs stub = { 0 };
        stub.preferred_key_type = WOLFCERT_KEY_RSA;
        WolfCertKeyCfg kc = { 0 };
        REQUIRE(wolfcert_csr_attrs_apply(&stub, &kc, NULL) == WOLFCERT_OK);
        REQUIRE(kc.type  == WOLFCERT_KEY_RSA);
        REQUIRE(kc.param == 2048);
    }
#endif
#ifdef WOLFCERT_HAVE_ECC
    {
        WolfCertCsrAttrs stub = { 0 };
        stub.preferred_key_type     = WOLFCERT_KEY_ECC;
        stub.preferred_ecc_curve_bits = 0;
        WolfCertKeyCfg kc = { 0 };
        REQUIRE(wolfcert_csr_attrs_apply(&stub, &kc, NULL) == WOLFCERT_OK);
        REQUIRE(kc.type  == WOLFCERT_KEY_ECC);
        REQUIRE(kc.param == 256);
    }
#endif

    /* Empty attrs with NULL key_cfg and NULL meta returns OK. */
    {
        WolfCertCsrAttrs a5 = { 0 };
        REQUIRE(wolfcert_csr_attrs_apply(&a5, NULL, NULL) == WOLFCERT_OK);
    }

    /* NULL attrs is BAD_ARG. */
    {
        WolfCertKeyCfg kc = { 0 };
        REQUIRE(wolfcert_csr_attrs_apply(NULL, &kc, NULL)
                == WOLFCERT_ERR_BAD_ARG);
    }

    /* Ed25519, Ed448, ML-DSA hints: OK if compiled in, else UNSUPPORTED. */
    {
        const WolfCertKeyType gated_types[] = {
            WOLFCERT_KEY_ED25519,
            WOLFCERT_KEY_ED448,
            WOLFCERT_KEY_MLDSA44,
            WOLFCERT_KEY_MLDSA65,
            WOLFCERT_KEY_MLDSA87,
        };
        const int expected_ok[] = {
#ifdef WOLFCERT_HAVE_ED25519
            1,
#else
            0,
#endif
#ifdef WOLFCERT_HAVE_ED448
            1,
#else
            0,
#endif
#ifdef WOLFCERT_HAVE_MLDSA
            1, 1, 1,
#else
            0, 0, 0,
#endif
        };
        for (size_t i = 0; i < sizeof(gated_types)/sizeof(gated_types[0]); ++i) {
            WolfCertCsrAttrs stub = { 0 };
            stub.preferred_key_type = (int)gated_types[i];
            WolfCertKeyCfg kc = { 0 };
            int rc = wolfcert_csr_attrs_apply(&stub, &kc, NULL);
            if (expected_ok[i]) {
                REQUIRE(rc == WOLFCERT_OK);
                REQUIRE(kc.type == gated_types[i]);
            } else {
                REQUIRE(rc == WOLFCERT_ERR_UNSUPPORTED);
            }
        }
    }

    wolfcert_cleanup();
    printf("OK\n");
    return 0;
}
