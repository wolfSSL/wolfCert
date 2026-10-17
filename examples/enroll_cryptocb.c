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
 * CryptoCb offloading example.
 *
 * The application registers a wolfSSL CryptoCb for its key backend
 * (wolfPKCS11, wolfTPM, an HSM, ...) and passes its devId in WolfCertKeyCfg.
 * The pass-through callback here returns CRYPTOCB_UNAVAILABLE, so wolfSSL
 * does every operation in software until a real backend replaces it.
 */

#include <wolfcert/wolfcert.h>
#ifndef WOLFCERT_HAVE_EST
#  error "examples/enroll_cryptocb.c needs wolfCert built with EST enabled"
#endif

#include <wolfssl/wolfcrypt/cryptocb.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#ifndef WOLF_CRYPTO_CB
#  error "examples/enroll_cryptocb.c needs wolfSSL built with --enable-cryptocb"
#endif

#include <stdio.h>
#include <string.h>

#define MY_DEV_ID 42

static int passthrough_cb(int devIdIn, wc_CryptoInfo* info, void* ctx)
{
    (void)devIdIn;
    (void)ctx;
    fprintf(stderr, "[cryptocb] algo=%d falling back to software\n", info->algo_type);
    return CRYPTOCB_UNAVAILABLE;
}

int main(int argc, char** argv)
{
    if (argc < 3) {
        fprintf(stderr, "usage: %s URL SUBJECT\n", argv[0]);
        return 1;
    }

    if (wolfcert_init(NULL) != WOLFCERT_OK)
        return 1;

    /* Register the CryptoCb once, application-side. */
    if (wc_CryptoCb_RegisterDevice(MY_DEV_ID, passthrough_cb, NULL) != 0) {
        fprintf(stderr, "wc_CryptoCb_RegisterDevice failed\n");
        return 1;
    }

    /* Pass the device id; the rest matches the software path. */
    WolfCertKeyCfg kcfg = { .type = WOLFCERT_KEY_ECC, .param = 256,
                            .dev_id = MY_DEV_ID,
                            .key_label = "demo/device-key" };
    WolfCertKey* key = NULL;
    if (wolfcert_key_generate(&kcfg, &key) != WOLFCERT_OK) {
        fprintf(stderr, "keygen failed\n");
        return 2;
    }

    WolfCertCertMeta meta = { .subject_dn = argv[2] };
    WolfCertBuffer csr = { 0 };
    if (wolfcert_csr_build(key, &meta, &csr) != WOLFCERT_OK)
        return 2;

    WolfCertServerCfg srv = { .protocol = WOLFCERT_PROTO_EST, .server_url = argv[1] };
    WolfCertEstResult res = { 0 };
    int rc = wolfcert_est_simple_enroll(&srv, csr.data, csr.len, &res);
    if (rc != WOLFCERT_OK) {
        fprintf(stderr, "enroll failed: %s\n", wolfcert_strerror(rc));
        return 2;
    }
    if (res.status == WOLFCERT_EST_STATUS_PENDING) {
        fprintf(stderr, "enroll pending; retry after %d s\n",
                res.retry_after_sec);
        return 2;
    }
    fwrite(res.cert_pem.data, 1, res.cert_pem.len, stdout);

    wolfcert_buffer_free(&csr);
    wolfcert_est_result_free(&res);
    wolfcert_key_free(key);
    wc_CryptoCb_UnRegisterDevice(MY_DEV_ID);
    wolfcert_cleanup();
    return 0;
}
