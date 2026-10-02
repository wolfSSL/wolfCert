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

#ifdef __cplusplus
extern "C" {
#endif

/* Protocol-agnostic orchestration. srv->protocol selects EST vs SCEP.
 * These are the functions an application will usually call; they internally
 * invoke the lower-level est_* / scep_* primitives. */

typedef struct WolfCertClient WolfCertClient;

WOLFCERT_API int  wolfcert_client_new(WolfCertClient** out);
WOLFCERT_API void wolfcert_client_free(WolfCertClient* client);

/* Retrieve the CA chain as the member certificates themselves (the PKCS#7
 * transport envelope used by EST/SCEP on the wire is unwrapped internally),
 * encoded per `encoding`:
 *   - PEM: the certificates concatenated as -----BEGIN/END CERTIFICATE-----
 *     blocks - a bundle that loads in full via the usual PEM trust-store calls.
 *   - DER: the certificates' raw DER concatenated back-to-back. For the common
 *     single-CA-cert case this is exactly that cert's DER, ready to load as
 *     WOLFSSL_FILETYPE_ASN1. With more than one cert it is a concatenation, so
 *     a single ASN.1 load consumes only the first; walk it (each cert is a
 *     complete DER SEQUENCE) or use PEM for multi-cert chains.
 * Returns WOLFCERT_ERR_UNSUPPORTED when the chain holds more than
 * WOLFCERT_PKCS7_MAX_CERTS certificates (see docs/EMBEDDED.md). */
WOLFCERT_API int  wolfcert_client_get_ca(WolfCertClient* client,
                                         const WolfCertServerCfg* srv,
                                         WolfCertEncoding encoding,
                                         WolfCertBuffer* out_ca);

/* Query server for CSR attributes / SCEP capabilities. Fields already set
 * in meta are preserved; unset ones may be filled from the server. */
WOLFCERT_API int  wolfcert_client_fetch_meta(WolfCertClient* client,
                                             const WolfCertServerCfg* srv,
                                             WolfCertCertMeta* meta);

/* Generate a new key (honoring cfg->dev_id for CryptoCb offloading), build
 * a CSR from meta, and enroll. On success out_key owns the key and
 * out_cert_pem owns the issued certificate. */
WOLFCERT_API int  wolfcert_client_enroll(WolfCertClient* client,
                                         const WolfCertServerCfg* srv,
                                         const WolfCertKeyCfg* key_cfg,
                                         const WolfCertCertMeta* meta,
                                         WolfCertKey** out_key,
                                         WolfCertBuffer* out_cert_pem);

/* Re-enroll using an existing cert/key; a NULL new_key_cfg reuses the key.
 * The CSR copies current_cert's Subject and SAN: WOLFCERT_ERR_BAD_ARG if meta
 * sets them, _PARSE for a bad cert, _UNSUPPORTED if one cannot be carried. */
WOLFCERT_API int  wolfcert_client_reenroll(WolfCertClient* client,
                                           const WolfCertServerCfg* srv,
                                           const uint8_t* current_cert, size_t current_cert_len,
                                           const WolfCertKey* current_key,
                                           const WolfCertKeyCfg* new_key_cfg,
                                           const WolfCertCertMeta* meta,
                                           WolfCertKey** out_key,
                                           WolfCertBuffer* out_cert_pem);

#ifdef __cplusplus
}
#endif

#endif /* WOLFCERT_CLIENT_H */
