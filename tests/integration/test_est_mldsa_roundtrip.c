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

/* EST enrollment for ML-DSA-44/65/87 (FIPS 204); a wolfSSL without ML-DSA
 * PKCS#7 support fails each enroll with ASN_PARSE_E. */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#define _GNU_SOURCE

#include <wolfcert/wolfcert.h>
#include <wolfcert/server.h>

#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/asn_public.h>

#include "tls_test_util.h"

#include <pthread.h>
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

#ifndef WOLFCERT_HAVE_MLDSA
int main(void)
{
    printf("SKIP (wolfSSL built without ML-DSA)\n");
    return 0;
}
#else

static void* server_thread(void* arg)
{
    wolfcert_server_run((WolfCertServer*)arg);
    return NULL;
}

static int enroll_mldsa(const WolfCertServerCfg* client_cfg, WolfCertKeyType kt,
                        const char* label, const WolfCertBuffer* ca_pem)
{
    WolfCertKeyCfg kcfg = { .type = kt, .dev_id = WOLFCERT_DEVID_SOFTWARE };
    WolfCertKey* dk = NULL;
    REQUIRE(wolfcert_key_generate(&kcfg, &dk) == WOLFCERT_OK);

    char dn[64];
    snprintf(dn, sizeof(dn), "CN=%s,O=Acme", label);
    WolfCertCertMeta meta = { .subject_dn = dn };
    WolfCertBuffer csr = { 0 };
    REQUIRE(wolfcert_csr_build(dk, &meta, &csr) == WOLFCERT_OK);

    WolfCertBuffer issued = { 0 };
    REQUIRE(wolfcert_est_simple_enroll(client_cfg, csr.data, csr.len, &issued)
            == WOLFCERT_OK);
    REQUIRE(issued.len > 0);
    size_t pem_len = issued.len;

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
    printf("  %s: enrolled + verified (%zu byte PEM)\n", label, pem_len);
    return 0;
}

int main(void)
{
    REQUIRE(wolfcert_init(NULL) == WOLFCERT_OK);

    uint8_t *tls_cert = NULL, *tls_key = NULL;
    size_t tls_cert_len = 0, tls_key_len = 0;
    REQUIRE(gen_server_identity(&tls_cert, &tls_cert_len,
                                &tls_key, &tls_key_len) == 0);

    WolfCertServerCfgSrv cfg = {
        .protocol        = WOLFCERT_PROTO_EST,
        .bind_host       = "127.0.0.1",
        .bind_port       = 0,
        .ca_store        = test_ca_store(),
        .http_basic_user = "alice",
        .http_basic_pass = "hunter2",
        .tls_cert_pem    = tls_cert, .tls_cert_pem_len = tls_cert_len,
        .tls_key_pem     = tls_key,  .tls_key_pem_len  = tls_key_len,
    };
    WolfCertServer* s = NULL;
    REQUIRE(wolfcert_server_start(&cfg, &s) == WOLFCERT_OK);

    pthread_t tid;
    REQUIRE(pthread_create(&tid, NULL, server_thread, s) == 0);

    char url[128];
    snprintf(url, sizeof(url), "https://127.0.0.1:%u/.well-known/est",
             wolfcert_server_port(s));
    WolfCertServerCfg client_cfg = { .protocol = WOLFCERT_PROTO_EST,
                                     .server_url = url,
                                     .proto_opts.est = { .username = "alice",
                                                         .password = "hunter2" },
                                     .trust_anchors = tls_cert,
                                     .trust_anchors_len = tls_cert_len,
                                     .verify_server = 1 };

    WolfCertBuffer ca_pem = { 0 };
    REQUIRE(wolfcert_est_get_cacerts(&client_cfg, &ca_pem) == WOLFCERT_OK);

    int rc = 0;
#ifndef WOLFSSL_NO_ML_DSA_44
    rc |= enroll_mldsa(&client_cfg, WOLFCERT_KEY_MLDSA44, "mldsa44", &ca_pem);
#endif
#ifndef WOLFSSL_NO_ML_DSA_65
    rc |= enroll_mldsa(&client_cfg, WOLFCERT_KEY_MLDSA65, "mldsa65", &ca_pem);
#endif
#ifndef WOLFSSL_NO_ML_DSA_87
    rc |= enroll_mldsa(&client_cfg, WOLFCERT_KEY_MLDSA87, "mldsa87", &ca_pem);
#endif

    wolfcert_server_stop(s);
    pthread_join(tid, NULL);
    wolfcert_server_free(s);
    wolfcert_buffer_free(&ca_pem);
    free(tls_cert);
    free(tls_key);
    test_ca_store_close();
    wolfcert_cleanup();

    if (rc == 0)
        printf("OK\n");
    return rc;
}
#endif /* WOLFCERT_HAVE_MLDSA */
