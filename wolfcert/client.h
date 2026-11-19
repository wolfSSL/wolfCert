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

#ifndef WOLFCERT_CLIENT_H
#define WOLFCERT_CLIENT_H

#include <wolfcert/types.h>
#include <wolfcert/keygen.h>
#ifdef WOLFCERT_HAVE_EST
#  include <wolfcert/est.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* High-level orchestration over the est_* / scep_* primitives. Only
 * wolfcert_client_get_ca supports SCEP; the rest are EST-only. */

typedef struct WolfCertClient WolfCertClient;

WOLFCERT_API int  wolfcert_client_new(WolfCertClient** out);
WOLFCERT_API void wolfcert_client_free(WolfCertClient* client);

/* Fetch the CA chain unwrapped from its PKCS#7 envelope. PEM gives the
 * certificates as concatenated CERTIFICATE blocks; DER gives their DER
 * back-to-back, so a single ASN.1 load reads only the first one. */
WOLFCERT_API int  wolfcert_client_get_ca(WolfCertClient* client,
                                         const WolfCertServerCfg* srv,
                                         WolfCertEncoding encoding,
                                         WolfCertBuffer* out_ca);

/* Query the EST server's CSR attributes. Fields already set in meta are
 * preserved; unset ones may be filled from the server. */
WOLFCERT_API int  wolfcert_client_fetch_meta(WolfCertClient* client,
                                             const WolfCertServerCfg* srv,
                                             WolfCertCertMeta* meta);

#ifdef WOLFCERT_HAVE_EST
/* Generate a key from key_cfg (dev_id selects a CryptoCb device), build a CSR
 * from meta and POST it to /simpleenroll. out is filled as
 * wolfcert_est_simple_enroll fills it and is freed with
 * wolfcert_est_result_free after any return.
 * - WOLFCERT_OK, status SUCCESS: out->cert_pem holds the issued cert first
 *   and *out_key owns the key.
 * - WOLFCERT_ERR_PENDING, status PENDING, with retry_after_sec: when out_csr
 *   is not NULL, *out_key and *out_csr hold the key and the DER CSR to re-POST
 *   through wolfcert_est_simple_enroll. With out_csr NULL the CSR is dropped,
 *   a software key is freed and a key generated under a key_id is still
 *   handed out so the caller can delete it from the backend. out_csr may
 *   hold the challengePassword; free it with wolfcert_buffer_free_secure.
 * - Any other error: a key generated under a key_id is still handed out so
 *   the caller can delete it from the backend; a software key is freed. */
WOLFCERT_API int  wolfcert_client_enroll(WolfCertClient* client,
                                         const WolfCertServerCfg* srv,
                                         const WolfCertKeyCfg* key_cfg,
                                         const WolfCertCertMeta* meta,
                                         WolfCertKey** out_key,
                                         WolfCertEstResult* out,
                                         WolfCertBuffer* out_csr);

/* POST a renewal of current_cert to /simplereenroll over TLS client
 * authentication with current_cert and current_key. A NULL new_key_cfg reuses
 * current_key and leaves *out_key NULL; otherwise a new key is generated as
 * for wolfcert_client_enroll. The CSR copies current_cert's Subject and SAN:
 * WOLFCERT_ERR_BAD_ARG if meta sets them, WOLFCERT_ERR_PARSE for a bad
 * current_cert, WOLFCERT_ERR_UNSUPPORTED if one cannot be carried. Results,
 * out, out_csr and key ownership are as for wolfcert_client_enroll; a parked
 * renewal is re-POSTed through wolfcert_est_simple_reenroll with the same
 * current_cert and current_key. */
WOLFCERT_API int  wolfcert_client_reenroll(WolfCertClient* client,
                                           const WolfCertServerCfg* srv,
                                           const uint8_t* current_cert, size_t current_cert_len,
                                           const WolfCertKey* current_key,
                                           const WolfCertKeyCfg* new_key_cfg,
                                           const WolfCertCertMeta* meta,
                                           WolfCertKey** out_key,
                                           WolfCertEstResult* out,
                                           WolfCertBuffer* out_csr);
#endif /* WOLFCERT_HAVE_EST */

#ifdef __cplusplus
}
#endif

#endif /* WOLFCERT_CLIENT_H */
