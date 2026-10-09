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

/* Server lifecycle and protocol dispatch through WolfCertServerOps. */

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
#include <sys/time.h>
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

/* Listener poll interval, which bounds shutdown latency. */
#ifndef WOLFCERT_SERVER_POLL_MS
#define WOLFCERT_SERVER_POLL_MS 200
#endif

/* Send/receive timeout on an accepted connection; each expiry is a retry
 * that re-checks io_should_stop(). */
#ifndef WOLFCERT_SERVER_IO_TIMEOUT_MS
#define WOLFCERT_SERVER_IO_TIMEOUT_MS WOLFCERT_SERVER_POLL_MS
#endif

/* Time limit for the TLS handshake and each request; 0 or less disables it. */
#ifndef WOLFCERT_SERVER_REQUEST_TIMEOUT_MS
#define WOLFCERT_SERVER_REQUEST_TIMEOUT_MS 10000
#endif

/* A timeout armed on the accepted connection surfaces as WANT_READ or
 * WANT_WRITE depending on which direction stalled, and either is resumable. */
static int tls_want_io(WOLFSSL* ssl, int ret)
{
    int err = wolfSSL_get_error(ssl, ret);

    return err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_WANT_WRITE;
}

/* Start the connection's deadline for its next phase. */
static void arm_deadline(WolfCertServer* srv)
{
#if WOLFCERT_SERVER_REQUEST_TIMEOUT_MS > 0
    srv->deadline_ms = wolfcert_mono_ms() + WOLFCERT_SERVER_REQUEST_TIMEOUT_MS;
#else
    (void)srv;
#endif
}

/* True once shutdown is requested or the connection's deadline has passed. */
static int io_should_stop(WolfCertServer* srv)
{
    return WOLFSSL_ATOMIC_LOAD(srv->stopping) ||
           (srv->deadline_ms != 0 && wolfcert_mono_ms() >= srv->deadline_ms);
}

ssize_t wolfcert_io_recv(WolfCertServer* srv, int fd, void* buf, size_t len)
{
    ssize_t r;

    /* A trickling peer never times out, so the loops below never see this. */
    if (srv != NULL && io_should_stop(srv))
        return -1;

    /* An armed receive timeout expires as a want in wolfSSL and as EAGAIN on
     * a raw socket; both are retried. */
    if (srv != NULL && srv->tls_current != NULL) {
        int tr;

        /* wolfSSL_read() wants a write whenever the record layer must send
         * first, as post-handshake auth and a key update both do. */
        do {
            tr = wolfSSL_read(srv->tls_current, buf, (int)len);
        }
        while (tr <= 0 && tls_want_io(srv->tls_current, tr) &&
               !io_should_stop(srv));

        return tr <= 0 ? -1 : (ssize_t)tr;
    }

    do {
        r = recv(fd, buf, len, 0);
    }
    while (r < 0 && srv != NULL &&
           (errno == EINTR ||
            (srv->poll_timeouts_armed &&
             (errno == EAGAIN || errno == EWOULDBLOCK))) &&
           !io_should_stop(srv));

    return r;
}

ssize_t wolfcert_io_send(WolfCertServer* srv, int fd, const void* buf, size_t len)
{
    ssize_t r;

    if (srv != NULL && io_should_stop(srv))
        return -1;

    if (srv != NULL && srv->tls_current != NULL) {
        int tr;

        do {
            tr = wolfSSL_write(srv->tls_current, buf, (int)len);
        }
        while (tr <= 0 && tls_want_io(srv->tls_current, tr) &&
               !io_should_stop(srv));

        return tr <= 0 ? -1 : (ssize_t)tr;
    }

    do {
        r = send(fd, buf, len, WOLFCERT_SEND_FLAGS);
    }
    while (r < 0 && srv != NULL &&
           (errno == EINTR ||
            (srv->poll_timeouts_armed &&
             (errno == EAGAIN || errno == EWOULDBLOCK))) &&
           !io_should_stop(srv));

    return r;
}

int wolfcert_server_te_chunked(const char* v, size_t vlen)
{
    while (vlen > 0 && (*v == ' ' || *v == '\t')) {
        v++;
        vlen--;
    }
    while (vlen > 0 && (v[vlen - 1] == ' ' || v[vlen - 1] == '\t'))
        vlen--;

    return vlen == 7 && wolfcert_ascii_ncasecmp(v, "chunked", 7) == 0;
}

WOLFCERT_TEST_VIS int wolfcert_server_read_chunked(WolfCertServer* srv, int fd,
                                 const void* have, size_t have_len,
                                 size_t max_bytes, uint8_t** body,
                                 size_t* body_len, void* heap)
{
    size_t raw_max = max_bytes + 64 * 1024; /* room for the framing */
    uint8_t* raw = NULL;
    size_t raw_len = 0;
    size_t raw_cap = 0;
    WolfCertChunkScan scan = { 0 };
    int framed;
    int rc;

    if (have_len > raw_max)
        return WOLFCERT_ERR_PROTOCOL;

    if (have_len > 0) {
        raw = (uint8_t*)WOLFCERT_XMALLOC(have_len, heap);
        if (raw == NULL)
            return WOLFCERT_ERR_MEMORY;

        memcpy(raw, have, have_len);
        raw_len = have_len;
        raw_cap = have_len;
    }

    while ((framed = wolfcert_http_chunked_complete(raw, raw_len,
                                                    &scan)) == 0) {
        ssize_t r;

        if (raw_len == raw_cap) {
            size_t grow = raw_cap < 2048 ? 2048 : raw_cap;
            uint8_t* nb;

            if (grow > raw_max - raw_cap)
                grow = raw_max - raw_cap;
            if (grow == 0) {
                WOLFCERT_XFREE(raw, heap);
                return WOLFCERT_ERR_PROTOCOL;
            }

            nb = (uint8_t*)WOLFCERT_XREALLOC(raw, raw_cap + grow, heap);
            if (nb == NULL) {
                WOLFCERT_XFREE(raw, heap);
                return WOLFCERT_ERR_MEMORY;
            }

            raw = nb;
            raw_cap += grow;
        }

        r = wolfcert_io_recv(srv, fd, raw + raw_len, raw_cap - raw_len);
        if (r <= 0) {
            WOLFCERT_XFREE(raw, heap);
            return WOLFCERT_ERR_IO;
        }

        raw_len += (size_t)r;
    }

    if (framed < 0)
        rc = WOLFCERT_ERR_PROTOCOL;
    else
        rc = wolfcert_http_chunked_decode(raw, raw_len, body, body_len,
                                          max_bytes, heap);

    WOLFCERT_XFREE(raw, heap);

    return rc;
}

static int tls_setup(WolfCertServer* s, const WolfCertServerCfgSrv* cfg)
{
    int rc = WOLFCERT_OK;

    if (cfg->tls_post_handshake_auth &&
        (cfg->tls_client_ca_pem == NULL || cfg->tls_client_ca_pem_len == 0)) {
        return WOLFCERT_ERR(WOLFCERT_ERR_BAD_ARG, "server",
            "post-handshake auth needs tls_client_ca_pem");
    }

    if (cfg->tls_cert_pem == NULL || cfg->tls_key_pem == NULL)
        return WOLFCERT_OK;

    if (cfg->tls_cert_pem_len == 0 || cfg->tls_key_pem_len == 0) {
        return WOLFCERT_ERR_BAD_ARG;
    }

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

        /* PHA mode must still accept an anonymous TLS 1.2 handshake. */
        int verify = WOLFSSL_VERIFY_PEER;
        if (cfg->tls_post_handshake_auth)
            verify |= WOLFSSL_VERIFY_POST_HANDSHAKE;
        else
            verify |= WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT;

        wolfSSL_CTX_set_verify(ctx, verify, NULL);
    }
    /* Grouped messages would hold back the PHA CertificateRequest. */
    if (cfg->tls_post_handshake_auth)
        (void)wolfSSL_CTX_clear_group_messages(ctx);
#ifndef WOLFSSL_POST_HANDSHAKE_AUTH
    if (cfg->tls_post_handshake_auth) {
        wolfSSL_CTX_free(ctx);
        return WOLFCERT_ERR(WOLFCERT_ERR_UNSUPPORTED, "server",
            "wolfSSL was built without WOLFSSL_POST_HANDSHAKE_AUTH; "
            "rebuild with --enable-postauth");
    }
#elif !defined(WOLFSSL_HAVE_TLS_UNIQUE) || !defined(KEEP_PEER_CERT)
    if (cfg->tls_post_handshake_auth) {
        wolfSSL_CTX_free(ctx);
        return WOLFCERT_ERR(WOLFCERT_ERR_UNSUPPORTED, "server",
            "post-handshake auth needs wolfSSL built with "
            "WOLFSSL_HAVE_TLS_UNIQUE and KEEP_PEER_CERT; rebuild with "
            "CPPFLAGS=\"-DWOLFSSL_HAVE_TLS_UNIQUE -DKEEP_PEER_CERT\"");
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

    if (cfg->protocol == WOLFCERT_PROTO_EST &&
            (cfg->tls_cert_pem == NULL || cfg->tls_key_pem == NULL))
        return WOLFCERT_ERR(WOLFCERT_ERR_TLS, "server",
            "EST requires TLS: set tls_cert_pem and tls_key_pem (RFC 7030)");

    if (cfg->http_basic_user != NULL &&
            (cfg->http_basic_user[0] == '\0' ||
             cfg->http_basic_pass == NULL || cfg->http_basic_pass[0] == '\0'))
        return WOLFCERT_ERR(WOLFCERT_ERR_BAD_ARG, "server",
            "http_basic_user and http_basic_pass must both be non-empty");

    if (cfg->protocol == WOLFCERT_PROTO_EST && cfg->http_basic_user == NULL &&
            (cfg->tls_client_ca_pem == NULL ||
             cfg->tls_client_ca_pem_len == 0) &&
            !cfg->est_allow_anonymous_enroll)
        return WOLFCERT_ERR(WOLFCERT_ERR_BAD_ARG, "server",
            "EST enrollment needs http_basic_user or tls_client_ca_pem, "
            "or est_allow_anonymous_enroll");

    /* Only EST requests the certificate that PHA defers past the handshake. */
    if (cfg->protocol != WOLFCERT_PROTO_EST && cfg->tls_post_handshake_auth)
        return WOLFCERT_ERR(WOLFCERT_ERR_BAD_ARG, "server",
            "post-handshake auth is supported only for EST");

    struct in_addr bind_addr = { .s_addr = htonl(INADDR_ANY) };
    if (cfg->bind_host != NULL &&
            inet_pton(AF_INET, cfg->bind_host, &bind_addr) != 1)
        return WOLFCERT_ERR(WOLFCERT_ERR_BAD_ARG, "server",
            "bind_host \"%s\" is not a numeric IPv4 address", cfg->bind_host);

    void* heap = cfg->heap ? cfg->heap : wolfcert_default_heap();
    WolfCertServer* s = (WolfCertServer*)WOLFCERT_XMALLOC(sizeof(*s), heap);
    if (s == NULL)
        return WOLFCERT_ERR_MEMORY;

    memset(s, 0, sizeof(*s));
    s->cfg       = *cfg;
    s->listen_fd = -1;
    s->ops       = ops;
    s->heap      = heap;

    if (cfg->challenge_password)
        s->cfg_challenge = wolfcert_strdup(cfg->challenge_password, heap);

    if (cfg->http_basic_user)
        s->cfg_basic_user = wolfcert_strdup(cfg->http_basic_user, heap);

    if (cfg->http_basic_pass)
        s->cfg_basic_pass = wolfcert_strdup(cfg->http_basic_pass, heap);

    if ((cfg->challenge_password && s->cfg_challenge == NULL) ||
            (cfg->http_basic_user && s->cfg_basic_user == NULL) ||
            (cfg->http_basic_pass && s->cfg_basic_pass == NULL)) {
        wolfcert_server_free(s);
        return WOLFCERT_ERR_MEMORY;
    }

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
    int have_ca = 0;

    if (cfg->ca_store != NULL) {
        rc = wolfcert_ca_load(&s->ca, cfg->ca_store, heap);
        if (rc == WOLFCERT_OK)
            have_ca = 1;
        /* Only an empty store means no CA yet; any other failure must not
         * replace the stored CA. */
        else if (rc != WOLFCERT_ERR_NOT_FOUND)
            goto fail;
    }

    if (!have_ca) {
        WolfCertKeyType kt = cfg->ca_key_type ? cfg->ca_key_type
                                              : WOLFCERT_DEFAULT_KEY_TYPE;
        int kp = cfg->ca_key_param;

        rc = wolfcert_ca_generate(&s->ca, kt, kp, heap);
        if (rc != WOLFCERT_OK)
            goto fail;

        if (cfg->ca_store != NULL) {
            /* Not re-wrapped: it would lose ca_save's rollback diagnostic. */
            rc = wolfcert_ca_save(&s->ca, cfg->ca_store);
            if (rc != WOLFCERT_OK)
                goto fail;
        }
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

    struct sockaddr_in sa = { .sin_family = AF_INET, .sin_port = htons(cfg->bind_port),
                              .sin_addr = bind_addr };

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
    struct timeval poll_to;
    int ret;
    int pr;
    int cs;

    if (srv == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    /* Neither shutdown() nor close() from another thread reliably wakes a
     * blocked accept() on BSD/macOS, so the listener is polled. */
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
            continue;

        if ((pfd.revents & POLLIN) == 0)
            return WOLFCERT_ERR_IO;

        if (WOLFSSL_ATOMIC_LOAD(srv->stopping))
            break;

        cs = accept(srv->listen_fd, NULL, NULL);
        if (cs < 0) {
            /* A peer reset between poll() and accept() is not fatal. */
            if (errno == EINTR || errno == ECONNABORTED || errno == ECONNRESET)
                continue;

            return WOLFCERT_ERR_IO;
        }

        /* A silent peer must not outlast wolfcert_server_stop(). */
        poll_to.tv_sec  = WOLFCERT_SERVER_IO_TIMEOUT_MS / 1000;
        poll_to.tv_usec = (WOLFCERT_SERVER_IO_TIMEOUT_MS % 1000) * 1000;
        if (setsockopt(cs, SOL_SOCKET, SO_RCVTIMEO, &poll_to,
                       sizeof(poll_to)) != 0 ||
                setsockopt(cs, SOL_SOCKET, SO_SNDTIMEO, &poll_to,
                           sizeof(poll_to)) != 0) {
            close(cs);
            continue;
        }

        srv->poll_timeouts_armed = 1;
        wolfcert_sock_nosigpipe(cs);

        arm_deadline(srv);

        if (srv->tls_ctx != NULL) {
            WOLFSSL* ssl = wolfSSL_new(srv->tls_ctx);
            if (ssl != NULL) {
                wolfSSL_set_fd(ssl, cs);
                wolfSSL_SetIOWriteFlags(ssl, WOLFCERT_SEND_FLAGS);

                /* A stalled flight is resumable either way round: a large
                 * chain blocks on the send timeout, not the receive one. */
                do {
                    ret = wolfSSL_accept(ssl);
                }
                while (ret != WOLFSSL_SUCCESS && tls_want_io(ssl, ret) &&
                       !io_should_stop(srv));

                if (ret == WOLFSSL_SUCCESS) {
                    srv->tls_current = ssl;

                    /* Keep-alive lets an EST client fetch /cacerts
                     * anonymously and enroll with PHA on one connection. */
                    do {
                        srv->keep_alive = 1;
                        arm_deadline(srv);
                        if (srv->ops->serve_fd(srv, cs) != WOLFCERT_OK)
                            break;
                    }
                    while (srv->keep_alive && !io_should_stop(srv));

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
            do {
                srv->keep_alive = 1;
                arm_deadline(srv);
                if (srv->ops->serve_fd(srv, cs) != WOLFCERT_OK)
                    break;
            }
            while (srv->keep_alive && !io_should_stop(srv));
        }

        srv->poll_timeouts_armed = 0;
        srv->deadline_ms = 0;
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
    if (srv->cfg_challenge != NULL)
        wc_ForceZero(srv->cfg_challenge, (word32)strlen(srv->cfg_challenge));
    if (srv->cfg_basic_pass != NULL)
        wc_ForceZero(srv->cfg_basic_pass, (word32)strlen(srv->cfg_basic_pass));
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
