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
 * EST client cases, parameterised by the server config so they run against an
 * in-process server or one across a network. Each returns 0 on success and
 * prints the failing check.
 */

#ifndef WOLFCERT_EST_CLIENT_CASES_H
#define WOLFCERT_EST_CLIENT_CASES_H

#include <wolfcert/wolfcert.h>

#include "tls_test_util.h"

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/asn_public.h>

#include <stdio.h>
#include <string.h>

#ifndef REQUIRE
#define REQUIRE(cond) \
    do {                                                                    \
        if (!(cond)) {                                                      \
            fprintf(stderr, "FAIL %s:%d %s\n", __FILE__, __LINE__, #cond);  \
            return 1;                                                       \
        }                                                                   \
    } while (0)
#endif

/* Enroll one key of the given type and verify the issued cert against ca_pem. */
static inline int enroll_one(const WolfCertServerCfg* client_cfg,
                             WolfCertKeyType kt, int param,
                             const WolfCertBuffer* ca_pem)
{
    WolfCertKeyCfg kcfg = { .type = kt, .param = param,
                            .dev_id = WOLFCERT_DEVID_SOFTWARE };
    WolfCertKey* dk = NULL;
    REQUIRE(wolfcert_key_generate(&kcfg, &dk) == WOLFCERT_OK);

    const char* dns[] = { "device-7.local" };
    WolfCertCertMeta meta = { .subject_dn = "CN=device-7,O=Acme",
                              .san_dns = dns, .san_dns_len = 1 };
    WolfCertBuffer csr = { 0 };
    REQUIRE(wolfcert_csr_build(dk, &meta, &csr) == WOLFCERT_OK);

    WolfCertBuffer issued = { 0 };
    int rc = wolfcert_est_simple_enroll(client_cfg, csr.data, csr.len, &issued);
    if (rc != WOLFCERT_OK) {
        fprintf(stderr, "enroll_one: rc=%d (%s) wolfssl=%d %s\n", rc,
                wolfcert_strerror(rc), wolfcert_last_wolfssl_err(),
                wolfcert_last_error_message());
    }
    REQUIRE(rc == WOLFCERT_OK);

    DerBuffer* issued_der = NULL;
    REQUIRE(wc_PemToDer(issued.data, (long)issued.len, CERT_TYPE,
                        &issued_der, NULL, NULL, NULL) == 0);
    WOLFSSL_CERT_MANAGER* cm = wolfSSL_CertManagerNew();
    REQUIRE(cm != NULL);
    REQUIRE(wolfSSL_CertManagerLoadCABuffer(cm, ca_pem->data, (long)ca_pem->len,
                                            WOLFSSL_FILETYPE_PEM)
            == WOLFSSL_SUCCESS);
    REQUIRE(wolfSSL_CertManagerVerifyBuffer(cm, issued_der->buffer,
                                            (long)issued_der->length,
                                            WOLFSSL_FILETYPE_ASN1)
            == WOLFSSL_SUCCESS);
    wolfSSL_CertManagerFree(cm);
    wc_FreeDer(&issued_der);

    wolfcert_buffer_free(&csr);
    wolfcert_buffer_free(&issued);
    wolfcert_key_free(dk);
    return 0;
}

static inline int has_alt(const DNS_entry* list, int type, const char* val,
                          int len)
{
    for (const DNS_entry* e = list; e != NULL; e = e->next) {
        if (e->type == type && e->len == len &&
            memcmp(e->name, val, (size_t)len) == 0)
            return 1;
    }
    return 0;
}

/* Regression: a CSR carrying DNS + IP + rfc822 (email) SANs must round-trip
 * into the issued certificate. wolfSSL splits parsed alt names by type --
 * rfc822Name lands in DecodedCert.altEmailNames, not altNames -- so the CA
 * must recombine the lists when re-emitting. This previously dropped the
 * email SAN from the issued cert entirely. */
static inline int enroll_check_san(const WolfCertServerCfg* client_cfg)
{
    WolfCertKeyCfg kcfg = { .type = TEST_ENROLL_KEY_TYPE, .param = TEST_ENROLL_KEY_PARAM,
                            .dev_id = WOLFCERT_DEVID_SOFTWARE };
    WolfCertKey* dk = NULL;
    REQUIRE(wolfcert_key_generate(&kcfg, &dk) == WOLFCERT_OK);

    const char* dns[]    = { "device-san.local" };
    const char* ips[]    = { "10.20.30.40" };
    const char* emails[] = { "dev-san@example.com" };
    WolfCertCertMeta meta = { .subject_dn   = "CN=device-san",
                              .san_dns      = dns,    .san_dns_len   = 1,
                              .san_ip       = ips,    .san_ip_len    = 1,
                              .san_email    = emails, .san_email_len = 1 };
    WolfCertBuffer csr = { 0 };
    REQUIRE(wolfcert_csr_build(dk, &meta, &csr) == WOLFCERT_OK);

    WolfCertBuffer issued = { 0 };
    int rc = wolfcert_est_simple_enroll(client_cfg, csr.data, csr.len, &issued);
    if (rc != WOLFCERT_OK) {
        fprintf(stderr, "enroll_check_san: rc=%d (%s) wolfssl=%d %s\n", rc,
                wolfcert_strerror(rc), wolfcert_last_wolfssl_err(),
                wolfcert_last_error_message());
    }
    REQUIRE(rc == WOLFCERT_OK);

    DerBuffer* der = NULL;
    REQUIRE(wc_PemToDer(issued.data, (long)issued.len, CERT_TYPE, &der,
                        NULL, NULL, NULL) == 0);

    DecodedCert dc;
    wc_InitDecodedCert(&dc, der->buffer, der->length, NULL);
    REQUIRE(wc_ParseCert(&dc, CERT_TYPE, NO_VERIFY, NULL) == 0);

    /* DNS + IP travel in altNames. */
    const byte ip[] = { 10, 20, 30, 40 };
    REQUIRE(has_alt(dc.altNames, ASN_DNS_TYPE, "device-san.local",
                    (int)strlen("device-san.local")));
    REQUIRE(has_alt(dc.altNames, ASN_IP_TYPE, (const char*)ip, (int)sizeof(ip)));
    /* The regression guard: email lands in altEmailNames, must still survive. */
    REQUIRE(has_alt(dc.altEmailNames, ASN_RFC822_TYPE, "dev-san@example.com",
                    (int)strlen("dev-san@example.com")));

    wc_FreeDecodedCert(&dc);
    wc_FreeDer(&der);
    wolfcert_buffer_free(&csr);
    wolfcert_buffer_free(&issued);
    wolfcert_key_free(dk);
    return 0;
}

/* HTTP Basic (RFC 7030 section 3.2.3) must authenticate a keep-alive session
 * too, not just the one-shot calls: the credentials have to ride every request
 * on the connection. Enrolls with the good credentials from `client_cfg`, then
 * repeats with a wrong password and requires a rejection - so a session that
 * silently dropped the Authorization header cannot pass both halves. */
static inline int session_basic_auth(const WolfCertServerCfg* client_cfg)
{
    WolfCertKeyCfg kcfg = { .type = TEST_ENROLL_KEY_TYPE, .param = TEST_ENROLL_KEY_PARAM,
                            .dev_id = WOLFCERT_DEVID_SOFTWARE };
    WolfCertKey* dk = NULL;
    REQUIRE(wolfcert_key_generate(&kcfg, &dk) == WOLFCERT_OK);
    WolfCertCertMeta meta = { .subject_dn = "CN=session-basic-auth" };
    WolfCertBuffer csr = { 0 };
    REQUIRE(wolfcert_csr_build(dk, &meta, &csr) == WOLFCERT_OK);

    WolfCertEstSession* s = NULL;
    int orc = wolfcert_est_session_open(client_cfg, &s);
    if (orc != WOLFCERT_OK) {
        fprintf(stderr, "session_open: rc=%d (%s) wolfssl=%d %s\n", orc,
                wolfcert_strerror(orc), wolfcert_last_wolfssl_err(),
                wolfcert_last_error_message());
    }
    REQUIRE(orc == WOLFCERT_OK);

    WolfCertBuffer ca_pem = { 0 }, issued = { 0 };
    REQUIRE(wolfcert_est_session_get_cacerts(s, &ca_pem) == WOLFCERT_OK);
    REQUIRE(ca_pem.len > 0);
    REQUIRE(wolfcert_est_session_simple_enroll(s, csr.data, csr.len, &issued)
            == WOLFCERT_OK);

    DerBuffer* issued_der = NULL;
    REQUIRE(wc_PemToDer(issued.data, (long)issued.len, CERT_TYPE,
                        &issued_der, NULL, NULL, NULL) == 0);
    wc_FreeDer(&issued_der);

    wolfcert_buffer_free(&ca_pem);
    wolfcert_buffer_free(&issued);
    wolfcert_est_session_close(s);

    /* Same session shape, wrong password: the server must reject the enroll. */
    WolfCertServerCfg bad_cfg = *client_cfg;
    bad_cfg.proto_opts.est.password = "wrong";

    WolfCertEstSession* bs = NULL;
    REQUIRE(wolfcert_est_session_open(&bad_cfg, &bs) == WOLFCERT_OK);

    WolfCertBuffer bad_out = { 0 };
    int brc = wolfcert_est_session_simple_enroll(bs, csr.data, csr.len, &bad_out);
    if (brc != WOLFCERT_ERR_AUTH) {
        fprintf(stderr, "bad-password enroll: rc=%d (%s) wolfssl=%d %s\n", brc,
                wolfcert_strerror(brc), wolfcert_last_wolfssl_err(),
                wolfcert_last_error_message());
    }
    REQUIRE(brc == WOLFCERT_ERR_AUTH);
    REQUIRE(bad_out.data == NULL);
    wolfcert_est_session_close(bs);

    wolfcert_buffer_free(&csr);
    wolfcert_key_free(dk);
    return 0;
}

#endif /* WOLFCERT_EST_CLIENT_CASES_H */
