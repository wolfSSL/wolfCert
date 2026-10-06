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

/* Per-key-type dispatch table. */

#ifndef WOLFCERT_KEY_ALGS_H
#define WOLFCERT_KEY_ALGS_H

#include <wolfcert/types.h>

#include <wolfssl/wolfcrypt/types.h>

struct WolfCertKey;
struct WC_RNG;

typedef struct WolfCertKeyAlg {
    WolfCertKeyType type;
    int    wc_keytype_enum;    /* RSA_TYPE / ECC_TYPE / ED25519_TYPE / ... */
    int    ctc_sig_default;    /* CTC_SHA256wRSA / CTC_ED25519 / ...       */
    int    key_oid;            /* RSAk / ED25519k / ...                    */
    int    pem_type;           /* PRIVATEKEY_TYPE / ED25519_TYPE / ...     */
    size_t der_cap_hint;       /* upper bound for priv-key DER             */

    /* Allocate + wc_*_init_ex the backing wolfSSL struct into key->impl. */
    int  (*alloc_init)(struct WolfCertKey* key);
    int  (*make)      (struct WolfCertKey* key, const WolfCertKeyCfg* cfg,
                       WC_RNG* rng);
    int  (*priv_decode)(struct WolfCertKey* key,
                        const uint8_t* der, word32 len);
    /* Returns the DER length written, or negative on error. */
    int  (*priv_to_der)(const struct WolfCertKey* key,
                        uint8_t* buf, word32 cap);
    /* Confirm the private key matches `pub`. May mutate `key`, which is not
     * usable after a failure. */
    int  (*pub_check) (struct WolfCertKey* key,
                       const uint8_t* pub, word32 pub_len);
    /* Decode a SubjectPublicKeyInfo, for a key behind a key_id. NULL if the
     * type cannot take one. */
    int  (*pub_decode)(struct WolfCertKey* key,
                       const uint8_t* der, word32 len);
    /* Non-zero if the private half sits in host memory. NULL if the type
     * cannot take a key_id. */
    int  (*host_priv) (const struct WolfCertKey* key);
    void (*free_)     (struct WolfCertKey* key);
} WolfCertKeyAlg;

/* NULL if `t` is not a known or compiled-in algorithm. */
const WolfCertKeyAlg* wolfcert_key_alg(WolfCertKeyType t);

/* NULL-terminated list of compiled-in algorithms. */
const WolfCertKeyAlg* const* wolfcert_key_algs_all(void);

/* Non-zero for an RSA modulus size wolfCert generates and accepts. */
int wolfcert_rsa_bits_ok(int bits);

#endif /* WOLFCERT_KEY_ALGS_H */
