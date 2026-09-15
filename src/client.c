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

#include <wolfcert/client.h>
#include <wolfcert/errors.h>
#include <wolfcert/csr.h>
#ifdef WOLFCERT_HAVE_EST
#  include <wolfcert/est.h>
#endif
#ifdef WOLFCERT_HAVE_SCEP
#  include <wolfcert/scep.h>
#endif
#include "internal.h"

#include <stdlib.h>

struct WolfCertClient { void* heap; };

int wolfcert_client_new(WolfCertClient** out)
{
    if (out == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    void* heap = wolfcert_default_heap();
    WolfCertClient* c = (WolfCertClient*)WOLFCERT_XMALLOC(sizeof(*c), heap);
    if (c == NULL)
        return WOLFCERT_ERR_MEMORY;

    c->heap = heap;
    *out = c;

    return WOLFCERT_OK;
}

void wolfcert_client_free(WolfCertClient* c)
{
    if (c == NULL)
        return;
    WOLFCERT_XFREE(c, c->heap);
}

/* The orchestration API currently just forwards to the protocol-specific
 * primitives. Keeping it thin so both code paths share auth/trust/TLS
 * configuration. */

int wolfcert_client_get_ca(WolfCertClient* client, const WolfCertServerCfg* srv,
                           WolfCertEncoding encoding, WolfCertBuffer* out_ca)
{
    (void)client;
    if (srv == NULL || out_ca == NULL)
        return WOLFCERT_ERR_BAD_ARG;

#ifdef WOLFCERT_HAVE_EST
    if (srv->protocol == WOLFCERT_PROTO_EST)
        return wolfcert_est_get_cacerts_enc(srv, encoding, out_ca);
#endif

#ifdef WOLFCERT_HAVE_SCEP
    if (srv->protocol == WOLFCERT_PROTO_SCEP)
        return wolfcert_scep_get_ca_cert_enc(srv, encoding, out_ca);
#endif

    return WOLFCERT_ERR_UNSUPPORTED;
}

int wolfcert_client_fetch_meta(WolfCertClient* client, const WolfCertServerCfg* srv,
                               WolfCertCertMeta* meta)
{
    (void)client;
    if (srv == NULL)
        return WOLFCERT_ERR_BAD_ARG;

#ifdef WOLFCERT_HAVE_EST
    if (srv->protocol == WOLFCERT_PROTO_EST) {
        WolfCertBuffer raw = { 0 };
        int rc = wolfcert_est_get_csr_attrs(srv, &raw);
        if (rc != WOLFCERT_OK)
            return rc;

        /* 204 No Content - server has no policy; nothing to apply. */
        if (raw.data == NULL || raw.len == 0)
            return WOLFCERT_OK;

        WolfCertCsrAttrs attrs;
        rc = wolfcert_est_parse_csr_attrs(raw.data, raw.len, &attrs);
        wolfcert_buffer_free(&raw);
        if (rc != WOLFCERT_OK)
            return rc;

        /* fetch_meta is the meta-only entry point; only overlays the
         * hash hint. The full two-sided overlay (key_cfg + meta) is
         * done inline by wolfcert_client_enroll when auto_csrattrs is
         * set, since that path owns both structs. */
        if (meta != NULL)
            rc = wolfcert_csr_attrs_apply(&attrs, NULL, meta);

        wolfcert_csr_attrs_free(&attrs);
        return rc;
    }
#endif

    /* SCEP has no /csrattrs equivalent. */
    (void)meta;
    return WOLFCERT_ERR_UNSUPPORTED;
}

#ifdef WOLFCERT_HAVE_EST
/* Apply the server's /csrattrs hints to the given key_cfg + meta
 * in-place. Silent no-op when the server returns 204. Internal helper
 * used by wolfcert_client_enroll's auto-discovery path - kept separate
 * so the failure mode of a broken /csrattrs response is one place. */
static int wolfcert_client_auto_csrattrs(const WolfCertServerCfg* srv,
                                         WolfCertKeyCfg* key_cfg,
                                         WolfCertCertMeta* meta)
{
    WolfCertBuffer raw = { 0 };
    int rc = wolfcert_est_get_csr_attrs(srv, &raw);
    if (rc != WOLFCERT_OK)
        return rc;

    if (raw.data == NULL || raw.len == 0)
        return WOLFCERT_OK;

    WolfCertCsrAttrs attrs;
    rc = wolfcert_est_parse_csr_attrs(raw.data, raw.len, &attrs);

    wolfcert_buffer_free(&raw);
    if (rc != WOLFCERT_OK)
        return rc;

    rc = wolfcert_csr_attrs_apply(&attrs, key_cfg, meta);

    wolfcert_csr_attrs_free(&attrs);
    return rc;
}
#endif

int wolfcert_client_enroll(WolfCertClient* client, const WolfCertServerCfg* srv,
                           const WolfCertKeyCfg* key_cfg,
                           const WolfCertCertMeta* meta,
                           WolfCertKey** out_key, WolfCertBuffer* out_cert_pem)
{
    (void)client;
    if (srv == NULL || key_cfg == NULL || meta == NULL ||
            out_key == NULL || out_cert_pem == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    /* Copy caller's key_cfg + meta onto the stack so auto-discovery
     * can overlay server hints without mutating caller memory. The
     * copies are shallow (pointers shared with caller) but that's
     * fine - the apply helper only writes scalar fields. */
    WolfCertKeyCfg   eff_key  = *key_cfg;
    WolfCertCertMeta eff_meta = *meta;

#ifdef WOLFCERT_HAVE_EST
    /* auto_csrattrs lives in the EST arm of proto_opts, so the protocol test
     * has to come first: on a SCEP config that arm is not the active union
     * member and its contents mean nothing. There is no SCEP equivalent of
     * /csrattrs, and no way to ask for one - the flag simply does not exist
     * on WolfCertScepServerOpts. */
    if (srv->protocol == WOLFCERT_PROTO_EST && srv->proto_opts.est.auto_csrattrs) {
        int rc = wolfcert_client_auto_csrattrs(srv, &eff_key, &eff_meta);
        if (rc != WOLFCERT_OK)
            return rc;
    }
#endif

    WolfCertKey* key = NULL;
    int rc = wolfcert_key_generate(&eff_key, &key);
    if (rc != WOLFCERT_OK)
        return rc;

    WolfCertBuffer csr = { 0 };
    rc = wolfcert_csr_build(key, &eff_meta, &csr);
    if (rc != WOLFCERT_OK) {
        wolfcert_key_free(key);
        return rc;
    }

#ifdef WOLFCERT_HAVE_EST
    if (srv->protocol == WOLFCERT_PROTO_EST) {
        rc = wolfcert_est_simple_enroll(srv, csr.data, csr.len, out_cert_pem);
    }
    else
#endif
#ifdef WOLFCERT_HAVE_SCEP
    if (srv->protocol == WOLFCERT_PROTO_SCEP) {
        rc = WOLFCERT_ERR_UNSUPPORTED;
        /* SCEP enrollment needs the RA cert; caller must call
         * wolfcert_scep_get_ca_cert + wolfcert_scep_pkcs_req directly
         * until client grows a config for the RA trust anchor. */
    }
    else
#endif
    {
        rc = WOLFCERT_ERR_UNSUPPORTED;
    }

    wolfcert_buffer_free(&csr);
    if (rc != WOLFCERT_OK) {
        wolfcert_key_free(key);
        return rc;
    }
    *out_key = key;
    return WOLFCERT_OK;
}

int wolfcert_client_reenroll(WolfCertClient* client, const WolfCertServerCfg* srv,
                             const uint8_t* current_cert, size_t current_cert_len,
                             const WolfCertKey* current_key,
                             const WolfCertKeyCfg* new_key_cfg,
                             const WolfCertCertMeta* meta,
                             WolfCertKey** out_key, WolfCertBuffer* out_cert_pem)
{
    (void)client;
#ifndef WOLFCERT_HAVE_EST
    (void)current_cert_len;   /* only the EST reenroll path reads it */
#endif
    if (srv == NULL || current_cert == NULL || current_key == NULL ||
        meta == NULL || out_key == NULL || out_cert_pem == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    WolfCertKey* nk = NULL;
    int rc;
    if (new_key_cfg != NULL) {
        rc = wolfcert_key_generate(new_key_cfg, &nk);
        if (rc != WOLFCERT_OK)
            return rc;
    }
    const WolfCertKey* signing_key = nk ? nk : current_key;

    WolfCertBuffer csr = { 0 };
    rc = wolfcert_csr_build(signing_key, meta, &csr);
    if (rc != WOLFCERT_OK) {
        if (nk)
            wolfcert_key_free(nk);
        return rc;
    }

#ifdef WOLFCERT_HAVE_EST
    if (srv->protocol == WOLFCERT_PROTO_EST) {
        rc = wolfcert_est_simple_reenroll(srv, current_cert, current_cert_len,
                                          current_key, csr.data, csr.len,
                                          out_cert_pem);
    }
    else
#endif
    {
        rc = WOLFCERT_ERR_UNSUPPORTED;
    }

    wolfcert_buffer_free(&csr);
    if (rc != WOLFCERT_OK) {
        if (nk)
            wolfcert_key_free(nk);
        return rc;
    }
    *out_key = nk ? nk : NULL;
    return WOLFCERT_OK;
}
