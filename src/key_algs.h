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
 * Algorithm dispatch table. Centralizes every per-key-type branch -
 * wolfSSL key struct allocation + free, keygen, PEM/DER round-trip, and the
 * constants (keyType / sigType / keyOID / PEM type) needed elsewhere -
 * instead of scattering them across keygen.c / csr.c / ca_issue.c.
 *
 * Adding a new algorithm = adding one struct literal at the bottom of
 * src/key_algs.c plus (if applicable) a WOLFCERT_HAVE_<ALG> compile
 * guard.
 */

#ifndef WOLFCERT_KEY_ALGS_H
#define WOLFCERT_KEY_ALGS_H

#include <wolfcert/types.h>

#include <wolfssl/options.h>
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
    /* Generate. Called after alloc_init. */
    int  (*make)      (struct WolfCertKey* key, const WolfCertKeyCfg* cfg,
                       WC_RNG* rng);
    /* Decode a DER-encoded private key into the backing struct. */
    int  (*priv_decode)(struct WolfCertKey* key,
                        const uint8_t* der, word32 len);
    /* Serialize the private key as DER into caller-provided buffer.
     * Returns written length (>0) on success, negative on error. */
    int  (*priv_to_der)(const struct WolfCertKey* key,
                        uint8_t* buf, word32 cap);
    /* Confirm the private key belongs to the given public key. Most
     * implementations mutate `key` to do it - importing the verified public
     * half (Ed25519/Ed448, ML-DSA) or deriving it (ECC) - so a key that fails
     * carries an unverified public half and must be freed. */
    int  (*pub_check) (struct WolfCertKey* key,
                       const uint8_t* pub, word32 pub_len);
    /* wc_*_free + free(key->impl). */
    void (*free_)     (struct WolfCertKey* key);
} WolfCertKeyAlg;

/* NULL if `t` is not a known or compiled-in algorithm. */
const WolfCertKeyAlg* wolfcert_key_alg(WolfCertKeyType t);

/* Iterate all registered algorithms (NULL-terminated). */
const WolfCertKeyAlg* const* wolfcert_key_algs_all(void);

#endif /* WOLFCERT_KEY_ALGS_H */
