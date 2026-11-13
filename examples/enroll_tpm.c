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
 * EST enrollment and re-enrollment with a private key that stays in a TPM.
 * The key_id is the key's 4-byte TPM handle, persistent (0x81xxxxxx) or
 * transient (0x80xxxxxx). A new key goes to a free persistent handle, or for
 * 0x80000000 to a transient handle the TPM picks. A TPM resource manager such
 * as /dev/tpmrm0 flushes a transient key when the process exits.
 *
 * Usage:
 *   enroll_tpm enroll   URL TRUST_PEM SUBJECT KEY_TYPE HANDLE OUT_CERT
 *   enroll_tpm reenroll URL TRUST_PEM KEY_TYPE HANDLE CERT OUT_CERT
 *       [NEW_HANDLE]
 * KEY_TYPE is ecc:256, ecc:384, rsa:2048 or, with a wolfTPM built for
 * TPM 2.0 v1.85, mldsa:44, mldsa:65 or mldsa:87. e.g.
 *   ./enroll_tpm enroll https://127.0.0.1:8443/.well-known/est ca.pem \
 *       "CN=device-42" ecc:256 0x81000100 dev.crt
 *   ./enroll_tpm reenroll https://127.0.0.1:8443/.well-known/est ca.pem \
 *       ecc:256 0x81000100 dev.crt dev2.crt 0x81000101
 */

#define _POSIX_C_SOURCE 200809L

#include <wolfcert/wolfcert.h>
#ifndef WOLFCERT_HAVE_EST
#  error "examples/enroll_tpm.c needs wolfCert built with EST enabled"
#endif

#include <wolftpm/tpm2_wrap.h>
#if !defined(WOLFTPM_CRYPTOCB) || !defined(WOLF_PRIVATE_KEY_ID)
#  error "examples/enroll_tpm.c needs wolfTPM's CryptoCb and wolfSSL key ids"
#endif
/* An older wolfTPM lacks it, and keygen then fails at run time */
#ifndef WOLFTPM2_KEYID_TRANSIENT
#  define WOLFTPM2_KEYID_TRANSIENT TRANSIENT_FIRST
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct {
    WOLFTPM2_DEV    dev;
    WOLFTPM2_KEY    srk;
    TpmCryptoDevCtx ctx;
    int             dev_id;
} Tpm;

static uint8_t* read_whole(const char* path, size_t* out_len)
{
    FILE* f = fopen(path, "rb");
    if (!f)
        return NULL;

    long len = -1;
    if (fseek(f, 0, SEEK_END) == 0)
        len = ftell(f);
    if (len <= 0 || fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return NULL;
    }
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

/* Writes through a synced temporary file, so a failure keeps the old file. */
static int write_whole(const char* path, const WolfCertBuffer* b)
{
    char tmp[4096];

    if (snprintf(tmp, sizeof(tmp), "%s.tmp", path) >= (int)sizeof(tmp))
        return -1;
    remove(tmp);
    FILE* f = fopen(tmp, "wbx");
    if (!f)
        return -1;

    int ok = fwrite(b->data, 1, b->len, f) == b->len;
    ok = ok && fflush(f) == 0 && fsync(fileno(f)) == 0;
    ok = fclose(f) == 0 && ok;
    if (ok && rename(tmp, path) == 0)
        return 0;
    remove(tmp);
    return -1;
}

static const struct {
    const char*     name;
    WolfCertKeyType type;
    int             param;
} key_types[] = {
    { "ecc:256",  WOLFCERT_KEY_ECC,     256  },
    { "ecc:384",  WOLFCERT_KEY_ECC,     384  },
    { "rsa:2048", WOLFCERT_KEY_RSA,     2048 },
#ifdef WOLFTPM_MLDSA_SIGN
    { "mldsa:44", WOLFCERT_KEY_MLDSA44, 0    },
    { "mldsa:65", WOLFCERT_KEY_MLDSA65, 0    },
    { "mldsa:87", WOLFCERT_KEY_MLDSA87, 0    },
#endif
};

static int parse_key_type(const char* s, WolfCertKeyCfg* cfg)
{
    for (size_t i = 0; i < sizeof(key_types) / sizeof(key_types[0]); i++) {
        if (strcmp(s, key_types[i].name) == 0) {
            cfg->type  = key_types[i].type;
            cfg->param = key_types[i].param;
            return 0;
        }
    }
    fprintf(stderr, "unknown KEY_TYPE %s\n", s);
    return -1;
}

static int parse_handle(const char* s, TPM_HANDLE* h, uint8_t id[4])
{
    char* end = NULL;
    unsigned long v = strtoul(s, &end, 0);

    if (end == s || *end != '\0' ||
            ((v >> HR_SHIFT) != TPM_HT_PERSISTENT &&
             (v >> HR_SHIFT) != TPM_HT_TRANSIENT)) {
        fprintf(stderr, "HANDLE %s is not a persistent (0x81xxxxxx) or "
                "transient (0x80xxxxxx) handle\n", s);
        return -1;
    }
    *h = (TPM_HANDLE)v;
    id[0] = (uint8_t)(v >> 24);
    id[1] = (uint8_t)(v >> 16);
    id[2] = (uint8_t)(v >> 8);
    id[3] = (uint8_t)v;
    return 0;
}

static void tpm_close(Tpm* t)
{
    if (t->dev_id != INVALID_DEVID)
        wolfTPM2_ClearCryptoDevCb(&t->dev, t->dev_id);
    if (t->srk.handle.hndl != 0)
        wolfTPM2_UnloadHandle(&t->dev, &t->srk.handle);
    wolfTPM2_Cleanup(&t->dev);
}

static int tpm_open(Tpm* t)
{
    memset(t, 0, sizeof(*t));
    t->dev_id = INVALID_DEVID;

    /* /dev/tpmrm0 and socket TPMs such as the fwTPM take no I/O callback. */
    int rc = wolfTPM2_Init(&t->dev, NULL, NULL);
    if (rc != 0) {
        fprintf(stderr, "TPM: %s\n", wolfTPM2_GetRCString(rc));
        return rc;
    }
    rc = wolfTPM2_CreateSRK(&t->dev, &t->srk, TPM_ALG_ECC, NULL, 0);
    if (rc == 0) {
        t->ctx.storageKey = &t->srk;
        rc = wolfTPM2_SetCryptoDevCb(&t->dev, wolfTPM2_CryptoDevCb, &t->ctx,
                                     &t->dev_id);
    }
    if (rc != 0) {
        fprintf(stderr, "TPM: %s\n", wolfTPM2_GetRCString(rc));
        tpm_close(t);
    }
    return rc;
}

static int new_handle_ok(Tpm* t, TPM_HANDLE handle)
{
    WOLFTPM2_KEY k;
    int ok;

    memset(&k, 0, sizeof(k));
    if ((handle >> HR_SHIFT) == TPM_HT_TRANSIENT)
        ok = handle == WOLFTPM2_KEYID_TRANSIENT;
    else {
        int rc = wolfTPM2_ReadPublicKey(&t->dev, &k, handle);

        ok = rc > 0 && (rc & RC_MAX_FMT1) == TPM_RC_HANDLE;
        if (rc != 0 && !ok) {
            fprintf(stderr, "cannot check TPM handle 0x%08x (%s)\n",
                    (unsigned)handle, wolfTPM2_GetRCString(rc));
            return 0;
        }
    }
    if (!ok)
        fprintf(stderr, "a new key needs a free persistent handle or 0x%08x, "
                "not 0x%08x\n", (unsigned)WOLFTPM2_KEYID_TRANSIENT,
                (unsigned)handle);
    return ok;
}

/* The handle the TPM holds a key under, 0 if it has no key_id */
static TPM_HANDLE key_handle(const WolfCertKey* key)
{
    const uint8_t* id = NULL;
    size_t len = 0;

    if (key == NULL || wolfcert_key_id(key, &id, &len) != WOLFCERT_OK ||
            len != 4)
        return 0;
    return ((TPM_HANDLE)id[0] << 24) | ((TPM_HANDLE)id[1] << 16) |
           ((TPM_HANDLE)id[2] << 8) | (TPM_HANDLE)id[3];
}

static int evict(Tpm* t, TPM_HANDLE handle)
{
    WOLFTPM2_KEY k;

    memset(&k, 0, sizeof(k));
    int rc = wolfTPM2_ReadPublicKey(&t->dev, &k, handle);
    if (rc == 0 && (handle >> HR_SHIFT) == TPM_HT_PERSISTENT)
        rc = wolfTPM2_NVDeleteKey(&t->dev, TPM_RH_OWNER, &k);
    else if (rc == 0)
        rc = wolfTPM2_UnloadHandle(&t->dev, &k.handle);
    if (rc != 0)
        fprintf(stderr, "cannot evict TPM handle 0x%08x (%s); clear it by "
                "hand\n", (unsigned)handle, wolfTPM2_GetRCString(rc));
    return rc;
}

static void report(const char* what, int rc)
{
    const char* m = wolfcert_last_error_message();
    fprintf(stderr, "%s failed: %s%s%s\n", what, wolfcert_strerror(rc),
            m != NULL && *m != '\0' ? ": " : "", m != NULL ? m : "");
}

/* Shows a certificate that was issued but could not be kept. */
static void show_cert(const char* why, const WolfCertBuffer* cert)
{
    fprintf(stderr, "%s:\n", why);
    fwrite(cert->data, 1, cert->len, stderr);
}

/* URL TRUST_PEM SUBJECT KEY_TYPE HANDLE OUT_CERT */
static int cmd_enroll(Tpm* t, const WolfCertServerCfg* srv, char** argv)
{
    WolfCertKeyCfg kcfg = { .dev_id = t->dev_id };
    WolfCertCertMeta meta = { .subject_dn = argv[2] };
    WolfCertClient* client = NULL;
    WolfCertKey* key = NULL;
    WolfCertBuffer cert = { 0 };
    TPM_HANDLE handle;
    uint8_t id[4];

    if (parse_key_type(argv[3], &kcfg) != 0 ||
            parse_handle(argv[4], &handle, id) != 0)
        return 1;
    kcfg.key_id     = id;
    kcfg.key_id_len = sizeof(id);
    if (!new_handle_ok(t, handle))
        return 1;

    int rc = wolfcert_client_new(&client);
    if (rc == WOLFCERT_OK)
        rc = wolfcert_client_enroll(client, srv, &kcfg, &meta, &key, &cert);
    if (rc != WOLFCERT_OK) {
        report("enroll", rc);
    }
    else if (write_whole(argv[5], &cert) != 0) {
        fprintf(stderr, "cannot write %s\n", argv[5]);
        rc = WOLFCERT_ERR_IO;
    }
    else {
        printf("enrolled: key in TPM handle 0x%08x, certificate in %s\n",
               (unsigned)key_handle(key), argv[5]);
    }
    /* A key under a key_id comes back on failure too. */
    if (rc != WOLFCERT_OK && key_handle(key) != 0 &&
            evict(t, key_handle(key)) == 0 && cert.data != NULL)
        show_cert("revoke this certificate, its key is evicted", &cert);

    wolfcert_buffer_free(&cert);
    wolfcert_key_free(key);
    wolfcert_client_free(client);
    return rc == WOLFCERT_OK ? 0 : 2;
}

/* URL TRUST_PEM KEY_TYPE HANDLE CERT OUT_CERT [NEW_HANDLE] */
static int cmd_reenroll(Tpm* t, const WolfCertServerCfg* srv, int argc,
                        char** argv)
{
    WolfCertKeyCfg cur_cfg = { .dev_id = t->dev_id };
    WolfCertKeyCfg new_cfg;
    WolfCertCertMeta meta = { 0 };
    WolfCertClient* client = NULL;
    WolfCertKey* cur_key = NULL;
    WolfCertKey* new_key = NULL;
    WolfCertBuffer renewed = { 0 };
    TPM_HANDLE handle;
    TPM_HANDLE new_handle = 0;
    uint8_t id[4];
    uint8_t new_id[4];
    size_t cert_len = 0;
    uint8_t* cert = NULL;
    int rekey = argc > 6;

    if (parse_key_type(argv[2], &cur_cfg) != 0 ||
            parse_handle(argv[3], &handle, id) != 0 ||
            (rekey && parse_handle(argv[6], &new_handle, new_id) != 0))
        return 1;
    if (rekey && !new_handle_ok(t, new_handle))
        return 1;
    if (rekey && (handle >> HR_SHIFT) == TPM_HT_PERSISTENT &&
            (new_handle >> HR_SHIFT) == TPM_HT_TRANSIENT) {
        fprintf(stderr, "NEW_HANDLE must be persistent when HANDLE is; a "
                "transient key does not survive a TPM reset\n");
        return 1;
    }
    cur_cfg.key_id     = id;
    cur_cfg.key_id_len = sizeof(id);
    new_cfg            = cur_cfg;
    new_cfg.key_id     = new_id;

    cert = read_whole(argv[4], &cert_len);
    if (cert == NULL) {
        fprintf(stderr, "cannot read %s\n", argv[4]);
        return 1;
    }

    /* The certificate supplies the public half of the TPM key. */
    int rc = wolfcert_key_from_id(&cur_cfg, cert, cert_len, &cur_key);
    if (rc == WOLFCERT_OK)
        rc = wolfcert_client_new(&client);
    if (rc == WOLFCERT_OK)
        rc = wolfcert_client_reenroll(client, srv, cert, cert_len, cur_key,
                                      rekey ? &new_cfg : NULL, &meta,
                                      &new_key, &renewed);
    if (rc != WOLFCERT_OK) {
        report("reenroll", rc);
    }
    else if (write_whole(argv[5], &renewed) != 0) {
        fprintf(stderr, "cannot write %s\n", argv[5]);
        if (!rekey)
            show_cert("the renewed certificate", &renewed);
        rc = WOLFCERT_ERR_IO;
    }
    else if (rekey) {
        printf("re-enrolled: new key in TPM handle 0x%08x, certificate in %s\n",
               (unsigned)key_handle(new_key), argv[5]);
        if (evict(t, handle) == 0)
            printf("old key at TPM handle 0x%08x evicted\n", (unsigned)handle);
    }
    else {
        printf("re-enrolled: key in TPM handle 0x%08x, certificate in %s\n",
               (unsigned)handle, argv[5]);
    }
    if (rc != WOLFCERT_OK && key_handle(new_key) != 0 &&
            evict(t, key_handle(new_key)) == 0 && renewed.data != NULL)
        show_cert("revoke this certificate, its key is evicted", &renewed);

    wolfcert_buffer_free(&renewed);
    wolfcert_key_free(new_key);
    wolfcert_key_free(cur_key);
    wolfcert_client_free(client);
    free(cert);
    return rc == WOLFCERT_OK ? 0 : 2;
}

int main(int argc, char** argv)
{
    int enroll   = argc == 8 && strcmp(argv[1], "enroll") == 0;
    int reenroll = (argc == 8 || argc == 9) && strcmp(argv[1], "reenroll") == 0;

    if (!enroll && !reenroll) {
        fprintf(stderr,
            "usage: %s enroll   URL TRUST_PEM SUBJECT KEY_TYPE HANDLE "
            "OUT_CERT\n"
            "       %s reenroll URL TRUST_PEM KEY_TYPE HANDLE CERT OUT_CERT "
            "[NEW_HANDLE]\n"
            "KEY_TYPE: ecc:256, ecc:384, rsa:2048"
#ifdef WOLFTPM_MLDSA_SIGN
            ", mldsa:44, mldsa:65, mldsa:87"
#endif
            "\n", argv[0], argv[0]);
        return 1;
    }

    size_t trust_len = 0;
    uint8_t* trust = read_whole(argv[3], &trust_len);
    if (trust == NULL) {
        fprintf(stderr, "cannot read %s\n", argv[3]);
        return 1;
    }

    WolfCertServerCfg srv = {
        .protocol          = WOLFCERT_PROTO_EST,
        .server_url        = argv[2],
        .trust_anchors     = trust,
        .trust_anchors_len = trust_len,
        .verify_server     = 1,
    };
    Tpm tpm;
    int ret = 1;

    if (wolfcert_init(NULL) == WOLFCERT_OK && tpm_open(&tpm) == 0) {
        ret = enroll ? cmd_enroll(&tpm, &srv, argv + 2)
                     : cmd_reenroll(&tpm, &srv, argc - 2, argv + 2);
        tpm_close(&tpm);
    }

    wolfcert_cleanup();
    free(trust);
    return ret;
}
