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
 * End-to-end coverage for RFC 8894 section 3.3.3 GetCert (messageType 21):
 * enroll, then fetch the issued certificate back by its serial number, and
 * check that an unknown serial answers FAILURE with failInfo badCertId.
 *
 * GetCert is off by default, so a second server instance without
 * scep_enable_get_cert must answer as though it did not implement it.
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#define _DARWIN_C_SOURCE   /* expose memmem/strcasestr/INADDR_LOOPBACK on macOS */
#define _GNU_SOURCE

#include <wolfcert/wolfcert.h>
#include <wolfcert/scep.h>
#include <wolfcert/server.h>
#include "internal.h"

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/asn_public.h>

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

static void* server_thread(void* arg)
{
    wolfcert_server_run((WolfCertServer*)arg);
    return NULL;
}

static int get_cert_path(WolfCertServer* s)
{
    char url[128];
    snprintf(url, sizeof(url), "http://127.0.0.1:%u/scep", wolfcert_server_port(s));
    WolfCertServerCfg cli = { .protocol = WOLFCERT_PROTO_SCEP, .server_url = url };

    WolfCertScepCaps caps = { 0 };
    REQUIRE(wolfcert_scep_get_ca_caps(&cli, &caps) == WOLFCERT_OK);

    WolfCertBuffer ca_pem = { 0 };
    REQUIRE(wolfcert_scep_get_ca_cert(&cli, &ca_pem) == WOLFCERT_OK);
    DerBuffer* ca_der = NULL;
    REQUIRE(wc_PemToDer(ca_pem.data, (long)ca_pem.len, CERT_TYPE,
                        &ca_der, NULL, NULL, NULL) == 0);

    WolfCertKeyCfg kcfg = { .type = WOLFCERT_KEY_RSA, .param = 2048,
                            .dev_id = WOLFCERT_DEVID_SOFTWARE };
    WolfCertKey* dk = NULL;
    REQUIRE(wolfcert_key_generate(&kcfg, &dk) == WOLFCERT_OK);
    WolfCertCertMeta meta = { .subject_dn = "CN=device-getcert-1" };
    WolfCertBuffer csr = { 0 };
    REQUIRE(wolfcert_csr_build(dk, &meta, &csr) == WOLFCERT_OK);

    /* Step 1: enroll, so the CA has a certificate to hand back. */
    WolfCertScepResult r1 = { 0 };
    REQUIRE(wolfcert_scep_pkcs_req_ex(&cli, &caps,
                                      ca_der->buffer, ca_der->length,
                                      ca_der->buffer, ca_der->length,
                                      dk, csr.data, csr.len, &r1) == WOLFCERT_OK);
    REQUIRE(r1.status == WOLFCERT_SCEP_STATUS_SUCCESS);
    REQUIRE(r1.cert_pem.data != NULL);

    DerBuffer* issued_der = NULL;
    REQUIRE(wc_PemToDer(r1.cert_pem.data, (long)r1.cert_pem.len, CERT_TYPE,
                        &issued_der, NULL, NULL, NULL) == 0);

    DecodedCert ic;
    wc_InitDecodedCert(&ic, issued_der->buffer, issued_der->length, NULL);
    REQUIRE(wc_ParseCert(&ic, CERT_TYPE, NO_VERIFY, NULL) == 0);
    REQUIRE(ic.serialSz > 0);

    /* Step 2: GetCert for that serial, signed with the cert just issued,
     * returns the very same DER. */
    WolfCertScepResult r2 = { 0 };
    int rc = wolfcert_scep_get_cert(&cli, &caps,
                                    ca_der->buffer, ca_der->length,
                                    ca_der->buffer, ca_der->length,
                                    issued_der->buffer, issued_der->length,
                                    dk, ic.serial, (size_t)ic.serialSz, &r2);
    REQUIRE(rc == WOLFCERT_OK);
    REQUIRE(r2.status == WOLFCERT_SCEP_STATUS_SUCCESS);
    REQUIRE(r2.cert_pem.data != NULL);

    DerBuffer* fetched_der = NULL;
    REQUIRE(wc_PemToDer(r2.cert_pem.data, (long)r2.cert_pem.len, CERT_TYPE,
                        &fetched_der, NULL, NULL, NULL) == 0);
    REQUIRE(fetched_der->length == issued_der->length);
    REQUIRE(memcmp(fetched_der->buffer, issued_der->buffer,
                   issued_der->length) == 0);

    /* Step 3: a serial the CA never issued -> FAILURE / badCertId. */
    uint8_t bogus[8];
    memset(bogus, 0x7E, sizeof(bogus));
    WolfCertScepResult r3 = { 0 };
    rc = wolfcert_scep_get_cert(&cli, &caps,
                                ca_der->buffer, ca_der->length,
                                ca_der->buffer, ca_der->length,
                                issued_der->buffer, issued_der->length,
                                dk, bogus, sizeof(bogus), &r3);
    REQUIRE(rc == WOLFCERT_OK);
    REQUIRE(r3.status == WOLFCERT_SCEP_STATUS_FAILURE);
    REQUIRE(r3.fail_info == 4);

    /* Step 4: argument checks. */
    WolfCertScepResult r4 = { 0 };
    REQUIRE(wolfcert_scep_get_cert(&cli, &caps,
                                   ca_der->buffer, ca_der->length,
                                   ca_der->buffer, ca_der->length,
                                   NULL, 0, dk, ic.serial, (size_t)ic.serialSz,
                                   &r4) == WOLFCERT_ERR_BAD_ARG);
    REQUIRE(wolfcert_scep_get_cert(&cli, &caps,
                                   ca_der->buffer, ca_der->length,
                                   ca_der->buffer, ca_der->length,
                                   issued_der->buffer, issued_der->length,
                                   dk, ic.serial, 0, &r4) == WOLFCERT_ERR_BAD_ARG);

    /* Step 5: the operation GetCert exists for - one holder fetching a
     * certificate issued to someone else. The reply is enveloped to the
     * requester's own cert, so the signer and the fetched cert differ. */
    WolfCertKey* other = NULL;
    REQUIRE(wolfcert_key_generate(&kcfg, &other) == WOLFCERT_OK);
    WolfCertCertMeta other_meta = { .subject_dn = "CN=device-getcert-2" };
    WolfCertBuffer other_csr = { 0 };
    REQUIRE(wolfcert_csr_build(other, &other_meta, &other_csr) == WOLFCERT_OK);

    WolfCertScepResult ro = { 0 };
    REQUIRE(wolfcert_scep_pkcs_req_ex(&cli, &caps,
                                      ca_der->buffer, ca_der->length,
                                      ca_der->buffer, ca_der->length,
                                      other, other_csr.data, other_csr.len,
                                      &ro) == WOLFCERT_OK);
    REQUIRE(ro.status == WOLFCERT_SCEP_STATUS_SUCCESS);

    DerBuffer* other_der = NULL;
    REQUIRE(wc_PemToDer(ro.cert_pem.data, (long)ro.cert_pem.len, CERT_TYPE,
                        &other_der, NULL, NULL, NULL) == 0);
    DecodedCert oc;
    wc_InitDecodedCert(&oc, other_der->buffer, other_der->length, NULL);
    REQUIRE(wc_ParseCert(&oc, CERT_TYPE, NO_VERIFY, NULL) == 0);

    /* dk/issued_der sign; oc's serial is what we ask for. */
    WolfCertScepResult rx = { 0 };
    REQUIRE(wolfcert_scep_get_cert(&cli, &caps,
                                   ca_der->buffer, ca_der->length,
                                   ca_der->buffer, ca_der->length,
                                   issued_der->buffer, issued_der->length,
                                   dk, oc.serial, (size_t)oc.serialSz,
                                   &rx) == WOLFCERT_OK);
    REQUIRE(rx.status == WOLFCERT_SCEP_STATUS_SUCCESS);
    DerBuffer* rx_der = NULL;
    REQUIRE(wc_PemToDer(rx.cert_pem.data, (long)rx.cert_pem.len, CERT_TYPE,
                        &rx_der, NULL, NULL, NULL) == 0);
    REQUIRE(rx_der->length == other_der->length);
    REQUIRE(memcmp(rx_der->buffer, other_der->buffer, rx_der->length) == 0);

    wc_FreeDer(&rx_der);
    wolfcert_scep_result_free(&rx);
    wc_FreeDecodedCert(&oc);
    wc_FreeDer(&other_der);
    wolfcert_scep_result_free(&ro);
    wolfcert_buffer_free(&other_csr);
    wolfcert_key_free(other);

    /* Step 6: the registry holds the last SCEP_ISSUED_MAX certificates, so
     * enrolling past that evicts the oldest. Re-using one key and CSR keeps
     * this to one keygen; every enrollment still gets its own serial. */
    uint8_t first_serial[32];
    size_t  first_serial_len = 0;
    uint8_t last_serial[32];
    size_t  last_serial_len = 0;
    for (int i = 0; i < 17; i++) {
        WolfCertScepResult rn = { 0 };
        REQUIRE(wolfcert_scep_pkcs_req_ex(&cli, &caps,
                                          ca_der->buffer, ca_der->length,
                                          ca_der->buffer, ca_der->length,
                                          dk, csr.data, csr.len, &rn) == WOLFCERT_OK);
        REQUIRE(rn.status == WOLFCERT_SCEP_STATUS_SUCCESS);

        DerBuffer* nd = NULL;
        REQUIRE(wc_PemToDer(rn.cert_pem.data, (long)rn.cert_pem.len, CERT_TYPE,
                            &nd, NULL, NULL, NULL) == 0);
        DecodedCert nc;
        wc_InitDecodedCert(&nc, nd->buffer, nd->length, NULL);
        REQUIRE(wc_ParseCert(&nc, CERT_TYPE, NO_VERIFY, NULL) == 0);

        if (i == 0) {
            REQUIRE((size_t)nc.serialSz <= sizeof(first_serial));
            memcpy(first_serial, nc.serial, (size_t)nc.serialSz);
            first_serial_len = (size_t)nc.serialSz;
        }

        REQUIRE((size_t)nc.serialSz <= sizeof(last_serial));
        memcpy(last_serial, nc.serial, (size_t)nc.serialSz);
        last_serial_len = (size_t)nc.serialSz;

        wc_FreeDecodedCert(&nc);
        wc_FreeDer(&nd);
        wolfcert_scep_result_free(&rn);
    }

    /* The cert from step 1 and the first of the loop have both aged out. */
    WolfCertScepResult r5 = { 0 };
    REQUIRE(wolfcert_scep_get_cert(&cli, &caps,
                                   ca_der->buffer, ca_der->length,
                                   ca_der->buffer, ca_der->length,
                                   issued_der->buffer, issued_der->length,
                                   dk, first_serial, first_serial_len,
                                   &r5) == WOLFCERT_OK);
    REQUIRE(r5.status == WOLFCERT_SCEP_STATUS_FAILURE);
    REQUIRE(r5.fail_info == 4);
    wolfcert_scep_result_free(&r5);

    /* ...while the newest is still there, so the miss above is eviction and
     * not a registry that stopped recording. */
    WolfCertScepResult r6 = { 0 };
    REQUIRE(wolfcert_scep_get_cert(&cli, &caps,
                                   ca_der->buffer, ca_der->length,
                                   ca_der->buffer, ca_der->length,
                                   issued_der->buffer, issued_der->length,
                                   dk, last_serial, last_serial_len,
                                   &r6) == WOLFCERT_OK);
    REQUIRE(r6.status == WOLFCERT_SCEP_STATUS_SUCCESS);
    REQUIRE(r6.cert_pem.data != NULL);
    wolfcert_scep_result_free(&r6);

    /* Step 7: a CA that answers with some other certificate is refused, rather
     * than handing the caller a cert it never asked for. */
    wolfcert_scep_server_set_getcert_fault(s, 1);
    WolfCertScepResult r7 = { 0 };
    rc = wolfcert_scep_get_cert(&cli, &caps,
                                ca_der->buffer, ca_der->length,
                                ca_der->buffer, ca_der->length,
                                issued_der->buffer, issued_der->length,
                                dk, last_serial, last_serial_len, &r7);
    REQUIRE(rc == WOLFCERT_ERR_PROTOCOL);
    REQUIRE(r7.cert_pem.data == NULL);
    REQUIRE(r7.status != WOLFCERT_SCEP_STATUS_SUCCESS);
    wolfcert_scep_result_free(&r7);
    wolfcert_scep_server_set_getcert_fault(s, 0);

    wolfcert_scep_result_free(&r1);
    wolfcert_scep_result_free(&r2);
    wolfcert_scep_result_free(&r3);
    wc_FreeDecodedCert(&ic);
    wc_FreeDer(&issued_der);
    wc_FreeDer(&fetched_der);
    wc_FreeDer(&ca_der);
    wolfcert_buffer_free(&ca_pem);
    wolfcert_buffer_free(&csr);
    wolfcert_key_free(dk);
    return 0;
}

/* Default-off: the server refuses a GetCert the same way it refuses a
 * messageType it does not implement, so a client cannot tell the two apart. */
static int disabled_path(WolfCertServer* s)
{
    char url[128];
    snprintf(url, sizeof(url), "http://127.0.0.1:%u/scep", wolfcert_server_port(s));
    WolfCertServerCfg cli = { .protocol = WOLFCERT_PROTO_SCEP, .server_url = url };

    WolfCertScepCaps caps = { 0 };
    REQUIRE(wolfcert_scep_get_ca_caps(&cli, &caps) == WOLFCERT_OK);

    WolfCertBuffer ca_pem = { 0 };
    REQUIRE(wolfcert_scep_get_ca_cert(&cli, &ca_pem) == WOLFCERT_OK);
    DerBuffer* ca_der = NULL;
    REQUIRE(wc_PemToDer(ca_pem.data, (long)ca_pem.len, CERT_TYPE,
                        &ca_der, NULL, NULL, NULL) == 0);

    WolfCertKeyCfg kcfg = { .type = WOLFCERT_KEY_RSA, .param = 2048,
                            .dev_id = WOLFCERT_DEVID_SOFTWARE };
    WolfCertKey* dk = NULL;
    REQUIRE(wolfcert_key_generate(&kcfg, &dk) == WOLFCERT_OK);
    WolfCertCertMeta meta = { .subject_dn = "CN=device-getcert-off" };
    WolfCertBuffer csr = { 0 };
    REQUIRE(wolfcert_csr_build(dk, &meta, &csr) == WOLFCERT_OK);

    WolfCertScepResult r1 = { 0 };
    REQUIRE(wolfcert_scep_pkcs_req_ex(&cli, &caps,
                                      ca_der->buffer, ca_der->length,
                                      ca_der->buffer, ca_der->length,
                                      dk, csr.data, csr.len, &r1) == WOLFCERT_OK);
    REQUIRE(r1.status == WOLFCERT_SCEP_STATUS_SUCCESS);

    DerBuffer* issued_der = NULL;
    REQUIRE(wc_PemToDer(r1.cert_pem.data, (long)r1.cert_pem.len, CERT_TYPE,
                        &issued_der, NULL, NULL, NULL) == 0);
    DecodedCert ic;
    wc_InitDecodedCert(&ic, issued_der->buffer, issued_der->length, NULL);
    REQUIRE(wc_ParseCert(&ic, CERT_TYPE, NO_VERIFY, NULL) == 0);

    /* The certificate exists and the serial is right; only the gate is shut,
     * so this is badRequest rather than the badCertId of a genuine miss. */
    WolfCertScepResult r2 = { 0 };
    REQUIRE(wolfcert_scep_get_cert(&cli, &caps,
                                   ca_der->buffer, ca_der->length,
                                   ca_der->buffer, ca_der->length,
                                   issued_der->buffer, issued_der->length,
                                   dk, ic.serial, (size_t)ic.serialSz,
                                   &r2) == WOLFCERT_OK);
    REQUIRE(r2.status == WOLFCERT_SCEP_STATUS_FAILURE);
    REQUIRE(r2.fail_info == 2);

    wolfcert_scep_result_free(&r1);
    wolfcert_scep_result_free(&r2);
    wc_FreeDecodedCert(&ic);
    wc_FreeDer(&issued_der);
    wc_FreeDer(&ca_der);
    wolfcert_buffer_free(&ca_pem);
    wolfcert_buffer_free(&csr);
    wolfcert_key_free(dk);
    return 0;
}

int main(void)
{
    REQUIRE(wolfcert_init(NULL) == WOLFCERT_OK);

    WolfCertServerCfgSrv cfg = {
        .protocol = WOLFCERT_PROTO_SCEP,
        .bind_host = "127.0.0.1", .bind_port = 0,
        .scep_enable_get_cert = 1,
    };
    WolfCertServer* s = NULL;
    REQUIRE(wolfcert_server_start(&cfg, &s) == WOLFCERT_OK);
    pthread_t t;
    REQUIRE(pthread_create(&t, NULL, server_thread, s) == 0);

    int rc = get_cert_path(s);

    wolfcert_server_stop(s);
    pthread_join(t, NULL);
    wolfcert_server_free(s);
    if (rc != 0)
        return rc;

    /* ---- the same server with GetCert left at its default */
    WolfCertServerCfgSrv cfg_off = {
        .protocol = WOLFCERT_PROTO_SCEP,
        .bind_host = "127.0.0.1", .bind_port = 0,
    };
    WolfCertServer* s_off = NULL;
    REQUIRE(wolfcert_server_start(&cfg_off, &s_off) == WOLFCERT_OK);
    pthread_t t_off;
    REQUIRE(pthread_create(&t_off, NULL, server_thread, s_off) == 0);

    rc = disabled_path(s_off);

    wolfcert_server_stop(s_off);
    pthread_join(t_off, NULL);
    wolfcert_server_free(s_off);
    if (rc != 0)
        return rc;

    wolfcert_cleanup();
    printf("OK\n");
    return 0;
}
