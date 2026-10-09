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
 * Minimal SCEP enrollment example.
 *
 * Usage:
 *   enroll_scep <server_url> <subject_dn> <ca_sha256_hex>
 *
 * Fetches the CA cert via GetCACert, checks it against the SHA-256
 * fingerprint, then PKCSReq-enrolls a fresh 2048-bit RSA key. Writes the
 * issued cert in PEM to stdout.
 */

#include <wolfcert/wolfcert.h>
#ifndef WOLFCERT_HAVE_SCEP
#  error "examples/enroll_scep.c needs wolfCert built with SCEP enabled"
#endif
#include <wolfcert/scep.h>

#include <wolfssl/wolfcrypt/asn_public.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* SCEP is RSA-only (RFC 8894); other key types enroll over EST. */

static int hex_decode(const char* hex, uint8_t* out, size_t out_len)
{
    size_t i;

    if (strlen(hex) != 2 * out_len)
        return -1;

    for (i = 0; i < 2 * out_len; i++) {
        char c = hex[i];
        int v = (c >= '0' && c <= '9') ? c - '0'
              : (c >= 'a' && c <= 'f') ? c - 'a' + 10
              : (c >= 'A' && c <= 'F') ? c - 'A' + 10 : -1;
        if (v < 0)
            return -1;
        if (i % 2 == 0)
            out[i / 2] = (uint8_t)(v << 4);
        else
            out[i / 2] |= (uint8_t)v;
    }
    return 0;
}

int main(int argc, char** argv)
{
    uint8_t fp[32];

    if (argc < 4) {
        fprintf(stderr, "usage: %s URL SUBJECT CA_SHA256_HEX\n", argv[0]);
        return 1;
    }
    if (hex_decode(argv[3], fp, sizeof(fp)) != 0) {
        fprintf(stderr, "CA fingerprint must be 64 hex digits\n");
        return 1;
    }

    if (wolfcert_init(NULL) != WOLFCERT_OK)
        return 1;

    WolfCertServerCfg srv = { .protocol = WOLFCERT_PROTO_SCEP, .server_url = argv[1] };

    /* 1) GetCACert, converted to DER for the SCEP envelope. */
    WolfCertBuffer ca_pem = { 0 };
    if (wolfcert_scep_get_ca_cert(&srv, &ca_pem) != WOLFCERT_OK) {
        fprintf(stderr, "GetCACert failed\n");
        return 2;
    }
    DerBuffer* ca_der = NULL;
    if (wc_PemToDer(ca_pem.data, (long)ca_pem.len, CERT_TYPE,
                    &ca_der, NULL, NULL, NULL) != 0) return 2;

    /* GetCACert is unauthenticated over plain HTTP, so pin the CA. */
    int rc = wolfcert_scep_verify_ca_fingerprint(ca_der->buffer,
            ca_der->length, fp, sizeof(fp), WOLFCERT_SCEP_FP_SHA256);
    if (rc != WOLFCERT_OK) {
        fprintf(stderr, "CA fingerprint check failed: %s\n",
                wolfcert_strerror(rc));
        return 2;
    }

    /* 2) Optionally query capabilities. */
    WolfCertScepCaps caps = { 0 };
    wolfcert_scep_get_ca_caps(&srv, &caps);

    /* 3) Generate RSA key + CSR. */
    WolfCertKeyCfg kcfg = { .type = WOLFCERT_KEY_RSA, .param = 2048,
                            .dev_id = WOLFCERT_DEVID_SOFTWARE };
    WolfCertKey* key = NULL;
    if (wolfcert_key_generate(&kcfg, &key) != WOLFCERT_OK)
        return 2;

    WolfCertCertMeta meta = { .subject_dn = argv[2] };
    WolfCertBuffer csr = { 0 };
    if (wolfcert_csr_build(key, &meta, &csr) != WOLFCERT_OK)
        return 2;

    /* 4) PKCSReq. */
    WolfCertBuffer cert = { 0 };
    rc = wolfcert_scep_pkcs_req(&srv, &caps, ca_der->buffer, ca_der->length,
                                key, csr.data, csr.len, &cert);
    if (rc != WOLFCERT_OK) {
        fprintf(stderr, "PKCSReq failed: %s\n", wolfcert_strerror(rc));
        return 2;
    }
    fwrite(cert.data, 1, cert.len, stdout);

    wc_FreeDer(&ca_der);
    wolfcert_buffer_free(&ca_pem);
    wolfcert_buffer_free(&csr);
    wolfcert_buffer_free(&cert);
    wolfcert_key_free(key);
    wolfcert_cleanup();
    return 0;
}
