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
 * wolfSSL configuration for a Zephyr build of wolfCert. The wolfSSL module
 * includes this in place of its own default block, so it must be
 * self-contained. Key algorithms follow the CONFIG_WOLFCERT_* symbols.
 */

#ifndef WOLFCERT_ZEPHYR_WOLFSSL_USER_SETTINGS_H
#define WOLFCERT_ZEPHYR_WOLFSSL_USER_SETTINGS_H

#ifdef __cplusplus
extern "C" {
#endif

/* ---- platform ----------------------------------------------------------- */
#define WOLFSSL_GENERAL_ALIGNMENT 4
#define SIZEOF_LONG_LONG 8
#define WOLFSSL_IGNORE_FILE_WARN
#define NO_FILESYSTEM
#define NO_WRITEV
#define NO_MAIN_DRIVER

#define WOLFSSL_USER_IO

/* ---- TLS ---------------------------------------------------------------- */
#define WOLFSSL_TLS13
#define NO_OLD_TLS
#define HAVE_TLS_EXTENSIONS
#define HAVE_SUPPORTED_CURVES
#define HAVE_EXTENDED_MASTER
#define HAVE_ENCRYPT_THEN_MAC
#define HAVE_SERVER_RENEGOTIATION_INFO
#define HAVE_HKDF
#define HAVE_SESSION_TICKET
#define SMALL_SESSION_CACHE

#define HAVE_SNI

#define WOLFSSL_POST_HANDSHAKE_AUTH

/* ---- certificate handling ----------------------------------------------- */
#define OPENSSL_EXTRA
#define WOLFSSL_ASN_TEMPLATE
#define WOLFSSL_CERT_GEN
#define WOLFSSL_CERT_REQ
#define WOLFSSL_CERT_EXT
#define WOLFSSL_CERT_NAME_ALL
#define WOLFSSL_ALT_NAMES
#define WOLFSSL_IP_ALT_NAME
#define WOLFSSL_KEY_GEN
#define WOLFSSL_DER_TO_PEM
#define WOLFSSL_BASE64_ENCODE
#define KEEP_PEER_CERT

/* ---- PKCS#7 (SCEP pkiMessage, EST /cacerts) ----------------------------- */
#define HAVE_PKCS7
#define HAVE_AES_KEYWRAP
#define WOLFSSL_AES_DIRECT
#define HAVE_X963_KDF

/* ---- CryptoCb ------------------------------------------------------------ */
#define WOLF_CRYPTO_CB

/* ---- RNG ----------------------------------------------------------------- */
#define HAVE_HASHDRBG

/* ---- symmetric ----------------------------------------------------------- */
#define HAVE_AES_CBC
#define HAVE_AES_ECB
#define HAVE_AESGCM
#define GCM_SMALL
#define WOLFSSL_SHA224
#define WOLFSSL_SHA384
#define WOLFSSL_SHA512
#define WOLFSSL_SHA3
#define WOLFSSL_CMAC
#define HAVE_CHACHA
#define HAVE_POLY1305
#define HAVE_ONE_TIME_AUTH

/* ---- key algorithms, following Kconfig ----------------------------------- */
#ifdef CONFIG_WOLFCERT_RSA
    #undef  NO_RSA
    #define WC_RSA_BLINDING
    #define WC_RSA_PSS
#else
    #define NO_RSA
#endif

#ifdef CONFIG_WOLFCERT_ECC
    #define HAVE_ECC
    #define ECC_TIMING_RESISTANT
    #define HAVE_ECC_KEY_EXPORT
#endif

#ifdef CONFIG_WOLFCERT_ED25519
    #define HAVE_ED25519
    #define HAVE_CURVE25519
    #define HAVE_ED25519_KEY_EXPORT
#endif

#ifdef CONFIG_WOLFCERT_ED448
    #define HAVE_ED448
    #define HAVE_CURVE448
    #define WOLFSSL_SHAKE256
#endif

#ifdef CONFIG_WOLFCERT_MLDSA
    #define WOLFSSL_HAVE_MLDSA
    #define WOLFSSL_SHAKE128
    #define WOLFSSL_SHAKE256
#endif

#if !defined(WOLFSSL_SHAKE128) && !defined(CONFIG_WOLFCERT_MLDSA)
    #define WOLFSSL_NO_SHAKE128
#endif
#if !defined(WOLFSSL_SHAKE256)
    #define WOLFSSL_NO_SHAKE256
#endif

/* ---- disabled algorithms -------------------------------------------------- */
#define NO_DSA
#define NO_DH
#define NO_RC4
#define NO_MD4
#define NO_MD5
#define NO_PSK

/* No 3DES: the SCEP fallback for a peer that does not advertise AES. */
#define NO_DES3

/* ---- math ---------------------------------------------------------------- */
/* SP_MATH_ALL, not SP_MATH: the restricted variant cannot generate keys. */
#define WOLFSSL_SP_MATH_ALL
#define WOLFSSL_OLD_PRIME_CHECK

#ifdef CONFIG_WOLFCERT_SMALL_MATH
    #define WOLFSSL_SP_SMALL
#endif

#ifdef __cplusplus
}
#endif

#endif /* WOLFCERT_ZEPHYR_WOLFSSL_USER_SETTINGS_H */
