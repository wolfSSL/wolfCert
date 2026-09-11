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
 * Server lifecycle + protocol dispatch. Per-protocol handlers live under
 * src/est/ and src/scep/ and register themselves via a WolfCertServerOps
 * vtable, so adding a new protocol doesn't require another ifdef branch
 * here.
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#define _DARWIN_C_SOURCE

#include <wolfcert/server.h>
#include <wolfcert/errors.h>
#include "internal.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <wolfssl/ssl.h>

/* WOLFCERT_SEND_FLAGS suppresses SIGPIPE per send(), leaving the process
 * signal disposition to the embedding application. */
#ifdef MSG_NOSIGNAL
#define WOLFCERT_SEND_FLAGS MSG_NOSIGNAL
#else
#define WOLFCERT_SEND_FLAGS 0
#endif

/* accept() poll cadence: how often wolfcert_server_run() wakes to re-check the
 * stopping flag while idle. Bounds shutdown latency; not performance-critical.
 */
#ifndef WOLFCERT_SERVER_POLL_MS
#define WOLFCERT_SERVER_POLL_MS 200
#endif

ssize_t wolfcert_io_recv(WolfCertServer* srv, int fd, void* buf, size_t len)
{
    if (srv != NULL && srv->tls_current != NULL) {
        int r = wolfSSL_read(srv->tls_current, buf, (int)len);
        return r <= 0 ? -1 : (ssize_t)r;
    }

    return recv(fd, buf, len, 0);
}

ssize_t wolfcert_io_send(WolfCertServer* srv, int fd, const void* buf, size_t len)
{
    if (srv != NULL && srv->tls_current != NULL) {
        int r = wolfSSL_write(srv->tls_current, buf, (int)len);
        return r <= 0 ? -1 : (ssize_t)r;
    }

    return send(fd, buf, len, WOLFCERT_SEND_FLAGS);
}

static int tls_setup(WolfCertServer* s, const WolfCertServerCfgSrv* cfg)
{
    int rc = WOLFCERT_OK;

    if (cfg->tls_cert_pem == NULL || cfg->tls_key_pem == NULL) {
        /* plaintext: nothing to do */
        return WOLFCERT_OK;
    }

    if (cfg->tls_cert_pem_len == 0 || cfg->tls_key_pem_len == 0) {
        return WOLFCERT_ERR_BAD_ARG;
    }

    /* Flex method: negotiates the highest mutually-supported TLS version
     * (prefers TLS 1.3). The floor is TLS 1.2, or TLS 1.3 when wolfSSL is
     * built without TLS 1.2 (WOLFSSL_NO_TLS12). */
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(wolfTLS_server_method());
    if (ctx == NULL)
        return WOLFCERT_ERR_CRYPTO;

#ifdef WOLFSSL_NO_TLS12
    (void)wolfSSL_CTX_SetMinVersion(ctx, WOLFSSL_TLSV1_3);
#else
    (void)wolfSSL_CTX_SetMinVersion(ctx, WOLFSSL_TLSV1_2);
#endif

    rc = wolfSSL_CTX_use_certificate_buffer(ctx, cfg->tls_cert_pem,
            (long)cfg->tls_cert_pem_len, WOLFSSL_FILETYPE_PEM);
    if (rc != WOLFSSL_SUCCESS) {
        wolfSSL_CTX_free(ctx);
        return WOLFCERT_ERR(WOLFCERT_ERR_CRYPTO, "server",
                            "TLS: use_certificate_buffer failed");
    }

    rc = wolfSSL_CTX_use_PrivateKey_buffer(ctx, cfg->tls_key_pem,
            (long)cfg->tls_key_pem_len, WOLFSSL_FILETYPE_PEM);
    if (rc != WOLFSSL_SUCCESS) {
        wolfSSL_CTX_free(ctx);
        return WOLFCERT_ERR(WOLFCERT_ERR_CRYPTO, "server",
                            "TLS: use_PrivateKey_buffer failed");
    }

    if (cfg->tls_client_ca_pem != NULL && cfg->tls_client_ca_pem_len > 0) {
        rc = wolfSSL_CTX_load_verify_buffer(ctx, cfg->tls_client_ca_pem,
                (long)cfg->tls_client_ca_pem_len, WOLFSSL_FILETYPE_PEM);
        if (rc != WOLFSSL_SUCCESS) {
            wolfSSL_CTX_free(ctx);
            return WOLFCERT_ERR(WOLFCERT_ERR_CRYPTO, "server",
                                "TLS: load_verify_buffer (client CA) failed");
        }

        /* With PHA the initial handshake is anonymous; the CTX verifies
         * any peer cert the client sends later (post-handshake) against
         * the same trust anchor bundle. Without PHA we keep the
         * original "must present a cert up front" behaviour. */
        int verify = WOLFSSL_VERIFY_PEER;
        if (!cfg->tls_post_handshake_auth)
            verify |= WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT;

        wolfSSL_CTX_set_verify(ctx, verify, NULL);
    }
#ifdef WOLFSSL_POST_HANDSHAKE_AUTH
    if (cfg->tls_post_handshake_auth) {
        /* On a server CTX this returns 0 (SIDE_ERROR): "allowing" PHA is a
         * client-side opt-in, while the server drives it per-session via the
         * mid-handshake certificate request. The call is a harmless no-op
         * here, so its return value is intentionally ignored - do NOT treat
         * the 0 as a failure. */
        (void)wolfSSL_CTX_set_post_handshake_auth(ctx, 1);
    }
#else
    if (cfg->tls_post_handshake_auth) {
        wolfSSL_CTX_free(ctx);
        return WOLFCERT_ERR(WOLFCERT_ERR_UNSUPPORTED, "server",
            "wolfSSL was built without WOLFSSL_POST_HANDSHAKE_AUTH; "
            "rebuild with --enable-postauth");
    }
#endif

    s->tls_ctx = ctx;
    return WOLFCERT_OK;
}

static const WolfCertServerOps* lookup_ops(WolfCertProtocol p)
{
    switch (p) {
#ifdef WOLFCERT_HAVE_EST
        case WOLFCERT_PROTO_EST:
            return wolfcert_est_server_ops();
#endif
#ifdef WOLFCERT_HAVE_SCEP
        case WOLFCERT_PROTO_SCEP:
            return wolfcert_scep_server_ops();
#endif
        default:
            return NULL;
    }
}

int wolfcert_server_start(const WolfCertServerCfgSrv* cfg, WolfCertServer** out)
{
    if (cfg == NULL || out == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    const WolfCertServerOps* ops = lookup_ops(cfg->protocol);
    if (ops == NULL)
        return WOLFCERT_ERR_UNSUPPORTED;

    void* heap = cfg->heap ? cfg->heap : wolfcert_default_heap();
    WolfCertServer* s = (WolfCertServer*)WOLFCERT_XMALLOC(sizeof(*s), heap);
    if (s == NULL)
        return WOLFCERT_ERR_MEMORY;

    /* Zero-init covers every field, including the wolfSSL_Atomic_Int `stopping`
     * flag: it is a lock-free integer atomic, so an all-zero representation is
     * a valid initialized value of 0. Nothing else touches `s` until the caller
     * publishes it to the serving thread (pthread_create is the happens-before
     * edge), so no atomic_init()/barrier is needed here. */
    memset(s, 0, sizeof(*s));
    s->cfg       = *cfg;
    s->listen_fd = -1;
    s->ops       = ops;
    s->heap      = heap;

    s->cfg_bind_host = wolfcert_strdup(cfg->bind_host ? cfg->bind_host : "0.0.0.0", heap);

    if (cfg->challenge_password)
        s->cfg_challenge = wolfcert_strdup(cfg->challenge_password, heap);

    if (cfg->http_basic_user)
        s->cfg_basic_user = wolfcert_strdup(cfg->http_basic_user, heap);

    if (cfg->http_basic_pass)
        s->cfg_basic_pass = wolfcert_strdup(cfg->http_basic_pass, heap);

    if (cfg->csr_attributes_der != NULL && cfg->csr_attributes_len > 0) {
        s->cfg_csr_attrs = (uint8_t*)WOLFCERT_XMALLOC(cfg->csr_attributes_len, heap);
        if (s->cfg_csr_attrs == NULL) {
            wolfcert_server_free(s);
            return WOLFCERT_ERR_MEMORY;
        }

        memcpy(s->cfg_csr_attrs, cfg->csr_attributes_der, cfg->csr_attributes_len);
        s->cfg_csr_attrs_len = cfg->csr_attributes_len;
    }

    int rc;
    if (cfg->ca_store != NULL &&
        wolfcert_ca_load(&s->ca, cfg->ca_store, heap) == WOLFCERT_OK) {
        /* loaded existing CA */
    }
    else {
        WolfCertKeyType kt = cfg->ca_key_type ? cfg->ca_key_type
                                              : WOLFCERT_DEFAULT_KEY_TYPE;
        int kp = cfg->ca_key_param;

        rc = wolfcert_ca_generate(&s->ca, kt, kp, heap);
        if (rc != WOLFCERT_OK)
            goto fail;

        if (cfg->ca_store != NULL)
            wolfcert_ca_save(&s->ca, cfg->ca_store);
    }

    rc = ops->start(cfg, s);
    if (rc != WOLFCERT_OK)
        goto fail;

    rc = tls_setup(s, cfg);
    if (rc != WOLFCERT_OK)
        goto fail;

    s->listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (s->listen_fd < 0) {
        rc = WOLFCERT_ERR_IO;
        goto fail;
    }

    int yes = 1;
    setsockopt(s->listen_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    struct sockaddr_in sa = { .sin_family = AF_INET, .sin_port = htons(cfg->bind_port) };
    if (inet_pton(AF_INET, s->cfg_bind_host, &sa.sin_addr) != 1)
        sa.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(s->listen_fd, (struct sockaddr*)&sa, sizeof(sa)) < 0 ||
            listen(s->listen_fd, 8) < 0) {
        rc = WOLFCERT_ERR_IO; goto fail;
    }

    socklen_t slen = sizeof(sa);
    if (getsockname(s->listen_fd, (struct sockaddr*)&sa, &slen) == 0)
        s->cfg.bind_port = ntohs(sa.sin_port);

    *out = s;
    return WOLFCERT_OK;

fail:
    wolfcert_server_free(s);
    return rc;
}

int wolfcert_server_run(WolfCertServer* srv)
{
    struct pollfd pfd;
    int ret;
    int pr;
    int cs;

    if (srv == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    /* Poll the listener with a short timeout rather than blocking in accept(),
     * so the loop re-checks the stopping flag on its own. This keeps shutdown
     * portable -- neither shutdown() nor close() from another thread reliably
     * wakes a blocked accept() on BSD/macOS -- and race-free: listen_fd is
     * touched only by start() (before the serving thread exists) and free()
     * (after it has been joined), never concurrently with this loop. */
    while (!WOLFSSL_ATOMIC_LOAD(srv->stopping)) {
        pfd.fd     = srv->listen_fd;
        pfd.events = POLLIN;

        pr = poll(&pfd, 1, WOLFCERT_SERVER_POLL_MS);
        if (pr < 0) {
            if (errno == EINTR)
                continue;

            return WOLFCERT_ERR_IO;
        }
        if (pr == 0)
            continue;   /* timed out -- re-check stopping */

        /* poll() reports the listener ready for either a pending connection
         * (POLLIN) or an error/hangup condition (POLLERR/POLLHUP/POLLNVAL).
         * Accept only on POLLIN: an error condition on the listener is fatal,
         * and accepting on it could block or spin the loop. */
        if ((pfd.revents & POLLIN) == 0)
            return WOLFCERT_ERR_IO;

        /* stopping may have been set between poll() returning and here; honour
         * it now rather than serving one more connection. */
        if (WOLFSSL_ATOMIC_LOAD(srv->stopping))
            break;

        cs = accept(srv->listen_fd, NULL, NULL);
        if (cs < 0) {
            /* A single misbehaving peer must not take the listener down. A
             * reset between poll() reporting POLLIN and accept() running
             * surfaces as ECONNABORTED (ECONNRESET on some systems); EINTR is
             * a delivered signal. Retry those -- only a genuine listener
             * failure is fatal. */
            if (errno == EINTR || errno == ECONNABORTED || errno == ECONNRESET)
                continue;

            return WOLFCERT_ERR_IO;
        }

        wolfcert_sock_nosigpipe(cs);

        if (srv->tls_ctx != NULL) {
            /* Terminate TLS on this accepted fd. The protocol handler sees
             * plaintext HTTP through wolfcert_io_{recv,send}. */
            WOLFSSL* ssl = wolfSSL_new(srv->tls_ctx);
            if (ssl != NULL) {
                wolfSSL_set_fd(ssl, cs);
                wolfSSL_SetIOWriteFlags(ssl, WOLFCERT_SEND_FLAGS);

                if ((ret = wolfSSL_accept(ssl)) == WOLFSSL_SUCCESS) {
                    srv->tls_current = ssl;

                    /* Keep-alive loop: protocol handlers read one
                     * request at a time and return. We keep calling
                     * them until the handler reports the peer closed
                     * the connection (an I/O error while reading the
                     * next request line). This lets an EST client
                     * hit /cacerts anonymously and /simpleenroll with
                     * PHA-provided auth on the same TLS connection. */
                    do {
                        srv->keep_alive = 1;
                        if (srv->ops->serve_fd(srv, cs) != WOLFCERT_OK)
                            break;
                    }
                    while (srv->keep_alive && !WOLFSSL_ATOMIC_LOAD(srv->stopping));

                    srv->tls_current = NULL;
                    wolfSSL_shutdown(ssl);
                }
                else {
                    int error = wolfSSL_get_error(ssl, ret);
                    WOLFCERT_LOG_DBG("server", "wolfSSL_accept failed: %d", error);
                }
                wolfSSL_free(ssl);
            }
        }
        else {
            /* Plaintext: no TLS. */
            do {
                srv->keep_alive = 1;
                if (srv->ops->serve_fd(srv, cs) != WOLFCERT_OK)
                    break;
            }
            while (srv->keep_alive && !WOLFSSL_ATOMIC_LOAD(srv->stopping));
        }

        close(cs);
    }

    return WOLFCERT_OK;
}

int wolfcert_server_serve_fd(WolfCertServer* srv, int fd)
{
    if (srv == NULL || fd < 0)
        return WOLFCERT_ERR_BAD_ARG;

    wolfcert_sock_nosigpipe(fd);

    return srv->ops->serve_fd(srv, fd);
}

int wolfcert_server_stop(WolfCertServer* srv)
{
    if (srv == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    /* Signal the accept loop to exit. It polls the listener on a short timeout
     * (WOLFCERT_SERVER_POLL_MS) and re-checks this flag, so no fd surgery is
     * needed here -- wolfcert_server_free() closes listen_fd after the serving
     * thread is joined. Setting the flag from another thread (test harness) or
     * a signal handler (wolfcert-server CLI) is safe: the store is atomic. */
    WOLFSSL_ATOMIC_STORE(srv->stopping, 1);

    return WOLFCERT_OK;
}

void wolfcert_server_free(WolfCertServer* srv)
{
    if (srv == NULL)
        return;

    if (srv->ops && srv->ops->free_priv)
        srv->ops->free_priv(srv);

    if (srv->tls_ctx != NULL) {
        wolfSSL_CTX_free(srv->tls_ctx);
        srv->tls_ctx = NULL;
    }

    if (srv->listen_fd >= 0)
        close(srv->listen_fd);

    wolfcert_ca_free(&srv->ca);
    WOLFCERT_XFREE(srv->cfg_bind_host,  srv->heap);
    WOLFCERT_XFREE(srv->cfg_challenge,  srv->heap);
    WOLFCERT_XFREE(srv->cfg_basic_user, srv->heap);
    WOLFCERT_XFREE(srv->cfg_basic_pass, srv->heap);
    WOLFCERT_XFREE(srv->cfg_csr_attrs,  srv->heap);
    WOLFCERT_XFREE(srv, srv->heap);
}

uint16_t wolfcert_server_port(const WolfCertServer* srv)
{
    return srv ? srv->cfg.bind_port : 0;
}
