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
 * EST enrollment against a wolfcert-server on the host, reached through the
 * QEMU SLIRP gateway. The cases come from tests/integration/est_client_cases.h,
 * so this file only supplies the server config and the trust anchor.
 */

#include <wolfcert/wolfcert.h>

#include "est_client_cases.h"

#include <wolfssl/ssl.h>

#include <time.h>

#include <zephyr/kernel.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/net_ip.h>
#include <zephyr/ztest.h>

/* Start the host side with:
 *   wolfcert-server --proto est --listen 0.0.0.0:8443 --basic alice:hunter2 \
 *       --tls-cert examples/certs/ecc/server-cert.pem \
 *       --tls-key  examples/certs/ecc/server-key.pem */
#define EST_URL  "https://10.0.2.2:8443/.well-known/est"
#define EST_USER "alice"
#define EST_PASS "hunter2"

static const uint8_t ca_cert_pem[] = {
#include "est_ca_cert.inc"
};

static WolfCertServerCfg g_cfg;
static WolfCertBuffer    g_ca_pem;

/* Safe guard for waiting until the interface has an IPv4 address */
static int wait_for_ipv4(struct net_if* iface, int timeout_ms)
{
    int waited = 0;

    if (iface == NULL)
        return -1;

    while (waited < timeout_ms) {
        if (iface->config.ip.ipv4 != NULL &&
            iface->config.ip.ipv4->unicast[0].ipv4.is_used)
            return 0;
        k_sleep(K_MSEC(100));
        waited += 100;
    }
    return -1;
}

static void log_sink(WolfCertLogLevel level, const char* module,
                     const char* msg, void* ctx)
{
    ARG_UNUSED(level);
    ARG_UNUSED(ctx);
    printk("wolfcert[%s]: %s\n", module, msg);
}

/* Zephyr resets the realtime clock after every ztest (a ZTEST_RULE in
 * lib/os/clock.c under CONFIG_ZTEST). Set it before each test, not once. */
static void est_set_clock(void* fixture)
{
    struct timespec ts = { 0 };

    ARG_UNUSED(fixture);
    ts.tv_sec = (time_t)WOLFCERT_TEST_EPOCH;
    zassert_ok(clock_settime(CLOCK_REALTIME, &ts), "clock_settime");
}

static void* est_setup(void)
{
    struct net_if* iface = net_if_get_default();
    char addr[NET_IPV4_ADDR_LEN] = "none";
    int rc;

    g_cfg = (WolfCertServerCfg){
        .protocol          = WOLFCERT_PROTO_EST,
        .server_url        = EST_URL,
        .proto_opts.est    = { .username = EST_USER, .password = EST_PASS },
        .trust_anchors     = ca_cert_pem,
        .trust_anchors_len = sizeof(ca_cert_pem),
        .verify_server     = 1,
    };

    zassert_ok(wait_for_ipv4(iface, 30000), "no IPv4 address");
    net_addr_ntop(NET_AF_INET,
                  &iface->config.ip.ipv4->unicast[0].ipv4.address.in_addr,
                  addr, sizeof(addr));
    printk("wolfcert_est: local address %s, server %s\n", addr, EST_URL);

    wolfcert_set_log_cb(log_sink, NULL);
    wolfcert_set_log_level(WOLFCERT_LOG_DEBUG);

    est_set_clock(NULL);
    zassert_ok(wolfcert_init(NULL), "wolfcert_init");
    rc = wolfcert_est_get_cacerts(&g_cfg, &g_ca_pem);
    if (rc != WOLFCERT_OK) {
        printk("wolfcert_est: get_cacerts rc=%d (%s) wolfssl=%d: %s\n", rc,
               wolfcert_strerror(rc), wolfcert_last_wolfssl_err(),
               wolfcert_last_error_message());
    }
    zassert_ok(rc, "get_cacerts");
    zassert_true(g_ca_pem.len > 0, "empty CA bundle");

    return NULL;
}

static void est_teardown(void* fixture)
{
    ARG_UNUSED(fixture);
    wolfcert_buffer_free(&g_ca_pem);
    wolfcert_cleanup();
}

ZTEST_SUITE(wolfcert_est, NULL, est_setup, est_set_clock, NULL, est_teardown);

ZTEST(wolfcert_est, test_enroll)
{
    zassert_ok(enroll_one(&g_cfg, TEST_ENROLL_KEY_TYPE, TEST_ENROLL_KEY_PARAM,
                          &g_ca_pem), "enroll_one");
}

ZTEST(wolfcert_est, test_san_roundtrip)
{
    zassert_ok(enroll_check_san(&g_cfg), "enroll_check_san");
}

ZTEST(wolfcert_est, test_session_basic_auth)
{
    zassert_ok(session_basic_auth(&g_cfg), "session_basic_auth");
}
