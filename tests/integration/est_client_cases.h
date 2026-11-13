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

/* EST client cases, parameterised by the server config. Each returns 0 on
 * success. */

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

/* Record the first failure and skip later checks without returning, so the
 * case's cleanup still runs; the Zephyr image shares one heap across cases. */
#define EST_CHECK(cond) \
    do {                                                                    \
        if (ret == 0 && !(cond)) {                                          \
            fprintf(stderr, "FAIL %s:%d %s\n", __FILE__, __LINE__, #cond);  \
            ret = 1;                                                        \
        }                                                                   \
    } while (0)

/* Enroll one key and verify the issued cert against ca_pem. */
static inline int enroll_one(const WolfCertServerCfg* client_cfg,
                             WolfCertKeyType kt, int param,
                             const WolfCertBuffer* ca_pem)
{
    WolfCertKeyCfg kcfg = { .type = kt, .param = param,
                            .dev_id = INVALID_DEVID };
    const char* dns[] = { "device-7.local" };
    WolfCertCertMeta meta = { .subject_dn = "CN=device-7,O=Acme",
                              .san_dns = dns, .san_dns_len = 1 };
    WolfCertKey* dk = NULL;
    WolfCertBuffer csr = { 0 };
    WolfCertEstResult issued = { 0 };
    DerBuffer* issued_der = NULL;
    WOLFSSL_CERT_MANAGER* cm = NULL;
    int rc = WOLFCERT_OK;
    int ret = 0;

    EST_CHECK(wolfcert_key_generate(&kcfg, &dk) == WOLFCERT_OK);
    EST_CHECK(wolfcert_csr_build(dk, &meta, &csr) == WOLFCERT_OK);
    if (ret == 0) {
        rc = wolfcert_est_simple_enroll(client_cfg, csr.data, csr.len, &issued);
        if (rc != WOLFCERT_OK) {
            fprintf(stderr, "enroll_one: rc=%d (%s) wolfssl=%d %s\n", rc,
                    wolfcert_strerror(rc), wolfcert_last_wolfssl_err(),
                    wolfcert_last_error_message());
        }
    }
    EST_CHECK(rc == WOLFCERT_OK);
    EST_CHECK(wc_PemToDer(issued.cert_pem.data, (long)issued.cert_pem.len,
                          CERT_TYPE, &issued_der, NULL, NULL, NULL) == 0);
    if (ret == 0)
        cm = wolfSSL_CertManagerNew();
    EST_CHECK(cm != NULL);
    EST_CHECK(wolfSSL_CertManagerLoadCABuffer(cm, ca_pem->data,
                                              (long)ca_pem->len,
                                              WOLFSSL_FILETYPE_PEM)
              == WOLFSSL_SUCCESS);
    EST_CHECK(wolfSSL_CertManagerVerifyBuffer(cm, issued_der->buffer,
                                              (long)issued_der->length,
                                              WOLFSSL_FILETYPE_ASN1)
              == WOLFSSL_SUCCESS);

    wolfSSL_CertManagerFree(cm);
    wc_FreeDer(&issued_der);
    wolfcert_est_result_free(&issued);
    wolfcert_buffer_free(&csr);
    wolfcert_key_free(dk);
    return ret;
}

static inline int has_alt(const DNS_entry* list, int type, const char* val,
                          int len)
{
    const DNS_entry* e;

    for (e = list; e != NULL; e = e->next) {
        if (e->type == type && e->len == len &&
            memcmp(e->name, val, (size_t)len) == 0)
            return 1;
    }
    return 0;
}

/* CSR with a DNS, an IP and an email SAN; all three must appear in the issued
 * cert, the email one in altEmailNames. */
static inline int enroll_check_san(const WolfCertServerCfg* client_cfg)
{
    WolfCertKeyCfg kcfg = { .type = TEST_ENROLL_KEY_TYPE, .param = TEST_ENROLL_KEY_PARAM,
                            .dev_id = INVALID_DEVID };
    const char* dns[]    = { "device-san.local" };
    const char* ips[]    = { "10.20.30.40" };
    const char* emails[] = { "dev-san@example.com" };
    WolfCertCertMeta meta = { .subject_dn   = "CN=device-san",
                              .san_dns      = dns,    .san_dns_len   = 1,
                              .san_ip       = ips,    .san_ip_len    = 1,
                              .san_email    = emails, .san_email_len = 1 };
    const byte ip[] = { 10, 20, 30, 40 };
    WolfCertKey* dk = NULL;
    WolfCertBuffer csr = { 0 };
    WolfCertEstResult issued = { 0 };
    DerBuffer* der = NULL;
    DecodedCert dc;
    int dc_init = 0;
    int rc = WOLFCERT_OK;
    int ret = 0;

    memset(&dc, 0, sizeof(dc));

    EST_CHECK(wolfcert_key_generate(&kcfg, &dk) == WOLFCERT_OK);
    EST_CHECK(wolfcert_csr_build(dk, &meta, &csr) == WOLFCERT_OK);
    if (ret == 0) {
        rc = wolfcert_est_simple_enroll(client_cfg, csr.data, csr.len, &issued);
        if (rc != WOLFCERT_OK) {
            fprintf(stderr, "enroll_check_san: rc=%d (%s) wolfssl=%d %s\n", rc,
                    wolfcert_strerror(rc), wolfcert_last_wolfssl_err(),
                    wolfcert_last_error_message());
        }
    }
    EST_CHECK(rc == WOLFCERT_OK);
    EST_CHECK(wc_PemToDer(issued.cert_pem.data, (long)issued.cert_pem.len,
                          CERT_TYPE, &der, NULL, NULL, NULL) == 0);
    if (ret == 0) {
        wc_InitDecodedCert(&dc, der->buffer, der->length, NULL);
        dc_init = 1;
    }
    EST_CHECK(wc_ParseCert(&dc, CERT_TYPE, NO_VERIFY, NULL) == 0);

    EST_CHECK(has_alt(dc.altNames, ASN_DNS_TYPE, "device-san.local",
                      (int)strlen("device-san.local")));
    EST_CHECK(has_alt(dc.altNames, ASN_IP_TYPE, (const char*)ip,
                      (int)sizeof(ip)));
    EST_CHECK(has_alt(dc.altEmailNames, ASN_RFC822_TYPE, "dev-san@example.com",
                      (int)strlen("dev-san@example.com")));

    if (dc_init)
        wc_FreeDecodedCert(&dc);
    wc_FreeDer(&der);
    wolfcert_est_result_free(&issued);
    wolfcert_buffer_free(&csr);
    wolfcert_key_free(dk);
    return ret;
}

/* HTTP Basic (RFC 7030 section 3.2.3) on a keep-alive session; a wrong
 * password fails the enroll. */
static inline int session_basic_auth(const WolfCertServerCfg* client_cfg)
{
    WolfCertKeyCfg kcfg = { .type = TEST_ENROLL_KEY_TYPE, .param = TEST_ENROLL_KEY_PARAM,
                            .dev_id = INVALID_DEVID };
    WolfCertCertMeta meta = { .subject_dn = "CN=session-basic-auth" };
    WolfCertServerCfg bad_cfg = *client_cfg;
    WolfCertKey* dk = NULL;
    WolfCertBuffer csr = { 0 };
    WolfCertBuffer ca_pem = { 0 };
    WolfCertEstResult issued = { 0 };
    WolfCertEstResult bad_res = { 0 };
    WolfCertEstSession* s = NULL;
    WolfCertEstSession* bs = NULL;
    DerBuffer* issued_der = NULL;
    int orc = WOLFCERT_OK;
    int brc = WOLFCERT_OK;
    int ret = 0;

    bad_cfg.proto_opts.est.password = "wrong";

    EST_CHECK(wolfcert_key_generate(&kcfg, &dk) == WOLFCERT_OK);
    EST_CHECK(wolfcert_csr_build(dk, &meta, &csr) == WOLFCERT_OK);
    if (ret == 0) {
        orc = wolfcert_est_session_open(client_cfg, &s);
        if (orc != WOLFCERT_OK) {
            fprintf(stderr, "session_open: rc=%d (%s) wolfssl=%d %s\n", orc,
                    wolfcert_strerror(orc), wolfcert_last_wolfssl_err(),
                    wolfcert_last_error_message());
        }
    }
    EST_CHECK(orc == WOLFCERT_OK);
    if (ret == 0) {
        orc = wolfcert_est_session_get_cacerts(s, WOLFCERT_ENCODING_PEM,
                                               &ca_pem);
        if (orc != WOLFCERT_OK) {
            fprintf(stderr, "session_get_cacerts: rc=%d (%s) wolfssl=%d %s\n",
                    orc, wolfcert_strerror(orc), wolfcert_last_wolfssl_err(),
                    wolfcert_last_error_message());
        }
    }
    EST_CHECK(orc == WOLFCERT_OK);
    EST_CHECK(ca_pem.len > 0);
    EST_CHECK(wolfcert_est_session_simple_enroll(s, csr.data, csr.len, &issued)
              == WOLFCERT_OK);
    EST_CHECK(wc_PemToDer(issued.cert_pem.data, (long)issued.cert_pem.len,
                          CERT_TYPE, &issued_der, NULL, NULL, NULL) == 0);

    /* The target heap is too small for two open sessions. */
    wc_FreeDer(&issued_der);
    wolfcert_buffer_free(&ca_pem);
    wolfcert_est_result_free(&issued);
    wolfcert_est_session_close(s);
    s = NULL;

    EST_CHECK(wolfcert_est_session_open(&bad_cfg, &bs) == WOLFCERT_OK);
    if (ret == 0) {
        brc = wolfcert_est_session_simple_enroll(bs, csr.data, csr.len,
                                                 &bad_res);
        if (brc != WOLFCERT_ERR_AUTH) {
            fprintf(stderr, "bad-password enroll: rc=%d (%s) wolfssl=%d %s\n",
                    brc, wolfcert_strerror(brc), wolfcert_last_wolfssl_err(),
                    wolfcert_last_error_message());
        }
    }
    EST_CHECK(brc == WOLFCERT_ERR_AUTH);
    EST_CHECK(bad_res.status == WOLFCERT_EST_STATUS_FAILURE);
    EST_CHECK(bad_res.cert_pem.data == NULL);

    wolfcert_est_session_close(bs);
    wolfcert_est_result_free(&bad_res);
    wolfcert_buffer_free(&csr);
    wolfcert_key_free(dk);
    return ret;
}

#endif /* WOLFCERT_EST_CLIENT_CASES_H */
