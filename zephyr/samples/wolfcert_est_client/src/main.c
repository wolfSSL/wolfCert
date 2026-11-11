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

#include <wolfcert/wolfcert.h>

#include <string.h>
#include <time.h>

#include <zephyr/kernel.h>

/* An empty Kconfig string becomes NULL. */
#define OPT_OR_NULL(s) (sizeof(s) > 1 ? (s) : NULL)

/* EST requires server authentication (RFC 7030 section 3.3). */
static const uint8_t ca_cert_pem[] = {
#include "est_ca_cert.inc"
};

static void log_sink(WolfCertLogLevel level, const char* module,
                     const char* msg, void* ctx)
{
    ARG_UNUSED(level);
    ARG_UNUSED(ctx);
    printk("wolfcert[%s]: %s\n", module, msg);
}

/* WolfCertBuffer is length-delimited; print it in NUL-terminated chunks. */
static void print_pem(const WolfCertBuffer* pem)
{
    char chunk[65];
    size_t off = 0;
    size_t n;

    while (off < pem->len) {
        n = pem->len - off;
        if (n > sizeof(chunk) - 1)
            n = sizeof(chunk) - 1;
        memcpy(chunk, pem->data + off, n);
        chunk[n] = '\0';
        printk("%s", chunk);
        off += n;
    }
    printk("\n");
}

static int enroll(void)
{
    WolfCertServerCfg srv = {
        .protocol          = WOLFCERT_PROTO_EST,
        .server_url        = CONFIG_WOLFCERT_SAMPLE_EST_URL,
        .proto_opts.est    = {
            .username = OPT_OR_NULL(CONFIG_WOLFCERT_SAMPLE_EST_USER),
            .password = OPT_OR_NULL(CONFIG_WOLFCERT_SAMPLE_EST_PASS) },
        .trust_anchors     = ca_cert_pem,
        .trust_anchors_len = sizeof(ca_cert_pem),
        .verify_server     = 1,
    };
    WolfCertKeyCfg key_cfg = { .type = WOLFCERT_KEY_ECC, .param = 256,
                               .dev_id = INVALID_DEVID };
    WolfCertCertMeta meta = { .subject_dn = CONFIG_WOLFCERT_SAMPLE_SUBJECT };
    WolfCertClient* client = NULL;
    WolfCertKey* key = NULL;
    WolfCertBuffer cert = { 0 };
    int rc;

    rc = wolfcert_client_new(&client);
    if (rc == WOLFCERT_OK)
        rc = wolfcert_client_enroll(client, &srv, &key_cfg, &meta, &key, &cert);

    if (rc == WOLFCERT_OK) {
        printk("enrolled: %u bytes\n", (unsigned)cert.len);
        print_pem(&cert);
    }
    else {
        printk("enroll failed: %s (%s)\n", wolfcert_strerror(rc),
               wolfcert_last_error_message());
    }

    wolfcert_buffer_free(&cert);
    wolfcert_key_free(key);
    wolfcert_client_free(client);
    return rc;
}

int main(void)
{
    struct timespec ts = { 0 };
    int rc;

    /* Set the clock from the build time. */
    ts.tv_sec = (time_t)WOLFCERT_SAMPLE_EPOCH;
    if (clock_settime(CLOCK_REALTIME, &ts) != 0) {
        printk("clock_settime failed\n");
        k_panic();
    }

    wolfcert_set_log_cb(log_sink, NULL);
    wolfcert_set_log_level(WOLFCERT_LOG_WARN);

    rc = wolfcert_init(NULL);
    if (rc != WOLFCERT_OK) {
        printk("wolfcert_init failed: %s\n", wolfcert_strerror(rc));
        k_panic();
    }

    rc = enroll();
    wolfcert_cleanup();
    if (rc != WOLFCERT_OK)
        k_panic();
    return 0;
}
