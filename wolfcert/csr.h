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

#ifndef WOLFCERT_CSR_H
#define WOLFCERT_CSR_H

#include <wolfcert/types.h>
#include <wolfcert/keygen.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Build and self-sign a PKCS#10 CSR from the given key and metadata.
 * Output is DER-encoded. */
WOLFCERT_API int wolfcert_csr_build(const WolfCertKey*      key,
                                    const WolfCertCertMeta* meta,
                                    WolfCertBuffer*         out_der);

/* wolfcert_csr_build() for a renewal: with renew_cert (a PEM or DER
 * certificate, or a chain led by it) set, the CSR carries that certificate's
 * Subject and SAN. Returns WOLFCERT_ERR_BAD_ARG
 * when meta also sets a subject or SAN, WOLFCERT_ERR_PARSE when renew_cert is
 * not a certificate and WOLFCERT_ERR_UNSUPPORTED when its Subject or SAN does
 * not fit a CSR; otherwise as wolfcert_csr_build(). */
WOLFCERT_API int wolfcert_csr_build_ex(const WolfCertKey*      key,
                                       const WolfCertCertMeta* meta,
                                       const uint8_t*          renew_cert,
                                       size_t                  renew_cert_len,
                                       WolfCertBuffer*         out_der);

/* Convert between DER and PEM forms of a CSR. */
WOLFCERT_API int wolfcert_csr_der_to_pem(const uint8_t* der, size_t der_len,
                                         WolfCertBuffer* out_pem);
WOLFCERT_API int wolfcert_csr_pem_to_der(const uint8_t* pem, size_t pem_len,
                                         WolfCertBuffer* out_der);

#ifdef __cplusplus
}
#endif

#endif /* WOLFCERT_CSR_H */
