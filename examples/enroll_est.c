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
 * Minimal EST enrollment example.
 *
 * Usage:
 *   enroll_est <server_url> <subject_dn> [trust.pem]
 * e.g.
 *   ./enroll_est https://ra.example/.well-known/est "CN=device-42,O=Acme" ca.pem
 */

#include <wolfcert/wolfcert.h>
#ifndef WOLFCERT_HAVE_EST
#  error "examples/enroll_est.c needs wolfCert built with EST enabled"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint8_t* read_whole(const char* path, size_t* out_len)
{
    FILE* f = fopen(path, "rb");
    if (!f)
        return NULL;

    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t* b = (uint8_t*)malloc((size_t)len);
    if (!b || fread(b, 1, (size_t)len, f) != (size_t)len) {
        free(b);
        fclose(f);
        return NULL;
    }

    fclose(f);
    *out_len = (size_t)len;
    return b;
}

int main(int argc, char** argv)
{
    if (argc < 3) {
        fprintf(stderr, "usage: %s URL SUBJECT [TRUST_PEM]\n", argv[0]);
        return 1;
    }

    const char* url = argv[1];
    const char* dn  = argv[2];

    size_t trust_len = 0;
    uint8_t* trust = argc > 3 ? read_whole(argv[3], &trust_len) : NULL;

    if (wolfcert_init(NULL) != WOLFCERT_OK)
        return 1;

    /* 1) Generate an Ed25519 key, or P-256 when wolfSSL lacks Ed25519. */
#ifdef WOLFCERT_HAVE_ED25519
    WolfCertKeyCfg kcfg = { .type = WOLFCERT_KEY_ED25519, .param = 0,
                            .dev_id = INVALID_DEVID };
#else
    WolfCertKeyCfg kcfg = { .type = WOLFCERT_KEY_ECC, .param = 256,
                            .dev_id = INVALID_DEVID };
#endif
    WolfCertKey* key = NULL;
    if (wolfcert_key_generate(&kcfg, &key) != WOLFCERT_OK)
        return 2;

    /* 2) Build a CSR. */
    WolfCertCertMeta meta = { .subject_dn = dn };
    WolfCertBuffer csr = { 0 };
    if (wolfcert_csr_build(key, &meta, &csr) != WOLFCERT_OK)
        return 2;

    /* 3) POST /simpleenroll. */
    WolfCertServerCfg srv = {
        .protocol          = WOLFCERT_PROTO_EST,
        .server_url        = url,
        .trust_anchors     = trust,
        .trust_anchors_len = trust_len,
        .verify_server     = trust != NULL,
    };
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
    free(trust);
    wolfcert_cleanup();

    return 0;
}
