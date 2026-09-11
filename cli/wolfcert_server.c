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
 * wolfcert-server - minimal EST/SCEP test server. Issues certificates
 * against a local CA generated on startup. EST needs --tls-cert/--tls-key
 * (RFC 7030); SCEP may be served over plaintext HTTP.
 */

#define _POSIX_C_SOURCE 200809L

#include <wolfcert/wolfcert.h>
#include <wolfcert/server.h>
#ifdef WOLFCERT_HAVE_EST
#  include <wolfcert/est.h>
#endif

#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static WolfCertServer* g_server = NULL;

static void stderr_log_cb(WolfCertLogLevel lvl, const char* mod,
                          const char* msg, void* ctx)
{
    (void)ctx;
    fprintf(stderr, "[wolfcert %d %s] %s\n", (int)lvl, mod ? mod : "?", msg);
}

static void on_signal(int sig)
{
    (void)sig;
    if (g_server)
        wolfcert_server_stop(g_server);
}

static void print_usage(FILE* out)
{
    fprintf(out,
        "wolfcert-server %s\n"
        "Usage: wolfcert-server --proto est|scep [--listen HOST:PORT]\n"
        "                       [--basic USER:PASS] [--challenge PASS]\n"
        "                       [--tls-cert PEM --tls-key PEM [--tls-client-ca PEM]]\n"
        "                       [--scep-require-approval] [--scep-enable-next-ca]\n"
        "\n"
        "Options:\n"
        "  --proto est|scep         Protocol to serve (required)\n"
        "  --listen HOST:PORT       Bind address (default 0.0.0.0:8080)\n"
        "  --basic USER:PASS        Require HTTP Basic auth (EST enroll)\n"
        "  --challenge PASS         Require this SCEP challengePassword in the CSR\n"
        "  --tls-cert PEMFILE       Terminate TLS with this server certificate (PEM);\n"
        "                           required for --proto est (RFC 7030)\n"
        "  --tls-key  PEMFILE       Private key for --tls-cert (PEM)\n"
        "  --tls-client-ca PEMFILE  Require mutual TLS; verify clients against this CA\n"
        "  --scep-require-approval  Defer SCEP PKCSReq/RenewalReq (pkiStatus=PENDING); issue\n"
        "                           on first GetCertInitial with the same transactionID\n"
        "  --scep-enable-next-ca    Advertise + answer GetNextCACert (RFC 8894 section 4.6.1),\n"
        "                           generating a roll-over CA on first request\n"
        "  --est-require-approval   Defer EST /simpleenroll + /simplereenroll: first POST for\n"
        "                           a CSR returns 202 Accepted + Retry-After; next POST of\n"
        "                           the same CSR body issues the cert (RFC 7030 section 4.2.3)\n"
        "  --est-retry-after SECS   Retry-After delta-seconds to emit with the 202 (default 1)\n"
        "  --tls-post-handshake-auth\n"
        "                           TLS 1.3 post-handshake auth (RFC 8446 section 4.6.2): initial\n"
        "                           handshake is anonymous, client cert is requested when\n"
        "                           EST /simpleenroll is hit on the kept-alive connection.\n"
        "                           Requires --tls-cert/-key and --tls-client-ca.\n"
        "  --csrattrs-file PATH     Serve this DER-encoded CsrAttrs blob (RFC 7030 section 4.5.2)\n"
        "                           from GET /.well-known/est/csrattrs; without this the\n"
        "                           server answers 204 No Content.\n"
        "  --est-require-csrattrs   Reject EST /simpleenroll + /simplereenroll requests\n"
        "                           whose CSR omits a bare-OID attribute advertised in\n"
        "                           --csrattrs-file (presence-only enforcement).\n"
        "\n"
        "Environment:\n"
        "  WOLFCERT_LOG=1           Enable debug logging to stderr\n",
        wolfcert_version_string());
}

static int parse_listen(const char* arg, char** host, uint16_t* port)
{
    const char* colon = strrchr(arg, ':');
    if (colon == NULL) {
        *host = strdup(arg);
        *port = 8080;
        return 0;
    }

    long p = strtol(colon + 1, NULL, 10);
    if (p <= 0 || p > 65535)
        return -1;

    *host = strndup(arg, (size_t)(colon - arg));
    *port = (uint16_t)p;

    return 0;
}

static int parse_basic(const char* arg, char** user, char** pass)
{
    const char* colon = strchr(arg, ':');
    if (colon == NULL)
        return -1;

    *user = strndup(arg, (size_t)(colon - arg));
    *pass = strdup(colon + 1);

    return 0;
}

static uint8_t* slurp(const char* path, size_t* len)
{
    FILE* f = fopen(path, "rb");
    if (f == NULL)
        return NULL;

    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (n <= 0) {
        fclose(f);
        return NULL;
    }

    uint8_t* b = malloc((size_t)n);
    if (b == NULL || fread(b, 1, (size_t)n, f) != (size_t)n) {
        free(b);
        fclose(f);
        return NULL;
    }

    fclose(f);
    *len = (size_t)n;

    return b;
}

int main(int argc, char** argv)
{
    static const struct option opts[] = {
        { "proto",                   required_argument, NULL, 'p' },
        { "listen",                  required_argument, NULL, 'l' },
        { "basic",                   required_argument, NULL, 'b' },
        { "challenge",               required_argument, NULL, 'X' },
        { "tls-cert",                required_argument, NULL, 'C' },
        { "tls-key",                 required_argument, NULL, 'K' },
        { "tls-client-ca",           required_argument, NULL, 'A' },
        { "scep-require-approval",   no_argument,       NULL, 'R' },
        { "scep-enable-next-ca",     no_argument,       NULL, 'N' },
        { "est-require-approval",    no_argument,       NULL, 'E' },
        { "est-retry-after",         required_argument, NULL, 'T' },
        { "tls-post-handshake-auth", no_argument,       NULL, 'H' },
        { "csrattrs-file",            required_argument, NULL, 'F' },
        { "est-require-csrattrs",    no_argument,       NULL, 'Q' },
        { "help",                    no_argument,       NULL, 'h' },
        { "version",                 no_argument,       NULL, 'V' },
        { 0 }
    };

    char*    proto = NULL;
    char*    host  = NULL;
    uint16_t port  = 8080;
    char*    user  = NULL;
    char*    pass  = NULL;
    char*    challenge = NULL;
    uint8_t* tls_cert = NULL;
    size_t tls_cert_len = 0;
    uint8_t* tls_key  = NULL;
    size_t tls_key_len  = 0;
    uint8_t* tls_ca   = NULL;
    size_t tls_ca_len   = 0;
    int scep_require_approval = 0;
    int scep_enable_next_ca   = 0;
    int est_require_approval  = 0;
    int est_retry_after_sec   = 0;
    int tls_post_handshake_auth = 0;
    uint8_t* csr_attrs_blob   = NULL;
    size_t csr_attrs_blob_len = 0;
    int est_require_csr_attrs = 0;
    int c;

    while ((c = getopt_long(argc, argv, "", opts, NULL)) != -1) {
        switch (c) {
            case 'p':
                proto = optarg;
                break;
            case 'l':
                if (parse_listen(optarg, &host, &port) != 0) {
                    fprintf(stderr, "invalid --listen\n");
                    return 1;
                }
                break;
            case 'b':
                if (parse_basic(optarg, &user, &pass) != 0) {
                    fprintf(stderr, "invalid --basic (expected USER:PASS)\n");
                    return 1;
                }
                break;
            case 'X':
                challenge = optarg;
                break;
            case 'C':
                tls_cert = slurp(optarg, &tls_cert_len);
                if (tls_cert == NULL) {
                    fprintf(stderr, "cannot read --tls-cert %s\n", optarg);
                    return 1;
                }
                break;
            case 'K':
                tls_key = slurp(optarg, &tls_key_len);
                if (tls_key == NULL) {
                    fprintf(stderr, "cannot read --tls-key %s\n", optarg);
                    return 1;
                }
                break;
            case 'A':
                tls_ca = slurp(optarg, &tls_ca_len);
                if (tls_ca == NULL) {
                    fprintf(stderr, "cannot read --tls-client-ca %s\n", optarg);
                    return 1;
                }
                break;
            case 'R':
                scep_require_approval = 1;
                break;
            case 'N':
                scep_enable_next_ca   = 1;
                break;
            case 'E':
                est_require_approval  = 1;
                break;
            case 'T':
                est_retry_after_sec   = atoi(optarg);
                break;
            case 'H':
                tls_post_handshake_auth = 1;
                break;
            case 'F':
                csr_attrs_blob = slurp(optarg, &csr_attrs_blob_len);
                if (csr_attrs_blob == NULL) {
                    fprintf(stderr, "cannot read --csrattrs-file %s\n", optarg);
                    return 1;
                }
                break;
            case 'Q':
                est_require_csr_attrs = 1;
                break;
            case 'V':
                printf("wolfcert-server %s\n", wolfcert_version_string());
                return 0;
            case 'h':
                print_usage(stdout);
                return 0;
            default:
                print_usage(stderr);
                return 1;
        }
    }

    if ((tls_cert == NULL) != (tls_key == NULL)) {
        fprintf(stderr, "--tls-cert and --tls-key must be supplied together\n");
        return 1;
    }

    WolfCertProtocol sel;
    if (proto != NULL && strcmp(proto, "est") == 0) {
        sel = WOLFCERT_PROTO_EST;
    }
    else if (proto != NULL && strcmp(proto, "scep") == 0) {
        sel = WOLFCERT_PROTO_SCEP;
    }
    else {
        fprintf(stderr, "wolfcert-server: --proto est|scep required\n");
        print_usage(stderr);
        return 1;
    }

    if (sel == WOLFCERT_PROTO_EST && tls_cert == NULL) {
        fprintf(stderr, "wolfcert-server: --proto est requires --tls-cert and "
                "--tls-key (RFC 7030 has no plaintext mode)\n");
        return 1;
    }

    if (host == NULL)
        host = strdup("0.0.0.0");

    if (wolfcert_init(NULL) != WOLFCERT_OK) {
        fprintf(stderr, "wolfcert_init failed\n");
        return 1;
    }

    if (getenv("WOLFCERT_LOG") != NULL) {
        wolfcert_set_log_cb(stderr_log_cb, NULL);
        wolfcert_set_log_level(WOLFCERT_LOG_DEBUG);
    }

    /* Parse --csrattrs-file at startup so a bad blob fails fast with a
     * clear operator-facing message instead of an obscure error from
     * the first /csrattrs hit. CsrAttrs is an EST-only concept (RFC 7030
     * section 4.5.2), so the validation is compiled only when EST is built;
     * a SCEP-only server ignores the blob. */
#ifdef WOLFCERT_HAVE_EST
    if (csr_attrs_blob != NULL && csr_attrs_blob_len > 0) {
        WolfCertCsrAttrs check;
        int prc = wolfcert_est_parse_csr_attrs(csr_attrs_blob,
                                               csr_attrs_blob_len, &check);
        if (prc != WOLFCERT_OK) {
            fprintf(stderr, "wolfcert-server: --csrattrs-file: "
                    "invalid CsrAttrs DER (%s)\n", wolfcert_strerror(prc));
            free(csr_attrs_blob);
            free(host);
            free(user);
            free(pass);
            free(tls_cert);
            free(tls_key);
            free(tls_ca);
            wolfcert_cleanup();
            return 1;
        }
        wolfcert_csr_attrs_free(&check);
    }
#endif

    WolfCertServerCfgSrv cfg = {
        .protocol                   = sel,
        .bind_host                  = host,
        .bind_port                  = port,
        .http_basic_user            = user,
        .http_basic_pass            = pass,
        .challenge_password         = challenge,
        .tls_cert_pem               = tls_cert,
        .tls_cert_pem_len           = tls_cert_len,
        .tls_key_pem                = tls_key,
        .tls_key_pem_len            = tls_key_len,
        .tls_client_ca_pem          = tls_ca,
        .tls_client_ca_pem_len      = tls_ca_len,
        .scep_require_approval      = scep_require_approval,
        .scep_enable_next_ca        = scep_enable_next_ca,
        .est_require_approval       = est_require_approval,
        .est_retry_after_sec        = est_retry_after_sec,
        .tls_post_handshake_auth    = tls_post_handshake_auth,
        .csr_attributes_der         = csr_attrs_blob,
        .csr_attributes_len         = csr_attrs_blob_len,
        .est_require_csr_attributes = est_require_csr_attrs,
    };

    int rc = wolfcert_server_start(&cfg, &g_server);
    if (rc != WOLFCERT_OK) {
        fprintf(stderr, "wolfcert-server: start failed (%s)\n", wolfcert_strerror(rc));
        goto out;
    }

    fprintf(stderr, "wolfcert-server: %s listening on %s:%u\n",
            sel == WOLFCERT_PROTO_EST ? "EST" : "SCEP",
            host, wolfcert_server_port(g_server));

    signal(SIGINT,  on_signal);
    signal(SIGTERM, on_signal);

    rc = wolfcert_server_run(g_server);
    if (rc != WOLFCERT_OK)
        fprintf(stderr, "wolfcert-server: exited with %s\n", wolfcert_strerror(rc));

out:
    wolfcert_server_free(g_server);
    g_server = NULL;
    free(host);
    free(user);
    free(pass);
    free(tls_cert);
    free(tls_key);
    free(tls_ca);
    free(csr_attrs_blob);
    wolfcert_cleanup();

    return rc == WOLFCERT_OK ? 0 : 2;
}
