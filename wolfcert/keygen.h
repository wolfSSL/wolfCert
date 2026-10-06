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

#ifndef WOLFCERT_KEYGEN_H
#define WOLFCERT_KEYGEN_H

#include <wolfcert/types.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct WolfCertKey WolfCertKey;

/* Generate a key per cfg. cfg->dev_id != -1 routes its operations through
 * that CryptoCb device; with cfg->key_id the key also stays in the device and
 * the handle only references it. Allocated from cfg->heap or the default. */
WOLFCERT_API int wolfcert_key_generate(const WolfCertKeyCfg* cfg, WolfCertKey** out_key);

/* Reference a key a CryptoCb device holds under cfg->key_id, its public half
 * from `cert`, PEM or DER: a curve or RSA size keygen makes, matching a
 * non-zero cfg->param. Nothing checks that `cert` belongs to that key.
 * *out_key is NULL after a failure. */
WOLFCERT_API int wolfcert_key_from_id(const WolfCertKeyCfg* cfg,
                                      const uint8_t* cert, size_t cert_len,
                                      WolfCertKey** out_key);

/* Load a software key from PEM or DER; the encoding is auto-detected. */
WOLFCERT_API int wolfcert_key_from_pem(const uint8_t* data, size_t data_len,
                                       void* heap, WolfCertKey** out_key);

/* Export a software key as PEM. Fails with WOLFCERT_ERR_UNSUPPORTED for a
 * key with a key_id. */
WOLFCERT_API int wolfcert_key_to_pem(const WolfCertKey* key, WolfCertBuffer* out_pem);

/* Export a software key as raw DER (same export constraints as
 * wolfcert_key_to_pem). */
WOLFCERT_API int wolfcert_key_to_der(const WolfCertKey* key, WolfCertBuffer* out_der);

/* Frees the handle; for a key_id key, the device's free callback decides what
 * happens to the key it holds. */
WOLFCERT_API void wolfcert_key_free(WolfCertKey* key);

/* Accessors. wolfcert_key_type returns 0 on NULL. */
WOLFCERT_API WolfCertKeyType wolfcert_key_type(const WolfCertKey* key);
WOLFCERT_API int wolfcert_key_dev_id(const WolfCertKey* key);
/* Points *id at the key's backend id, or NULL with *id_len 0 if it has
 * none. The bytes stay owned by the key. */
WOLFCERT_API int wolfcert_key_id(const WolfCertKey* key, const uint8_t** id,
                                 size_t* id_len);

#ifdef __cplusplus
}
#endif

#endif /* WOLFCERT_KEYGEN_H */
