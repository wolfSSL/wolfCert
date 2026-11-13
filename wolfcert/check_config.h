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

/* Compile-time validation of the resolved wolfCert and wolfSSL feature set.
 * WOLFCERT_NO_WOLFSSL_FEATURE_CHECK skips the wolfSSL feature checks. */

#ifndef WOLFCERT_CHECK_CONFIG_H
#define WOLFCERT_CHECK_CONFIG_H

#if !defined(WOLFSSL_USER_SETTINGS) && !defined(WOLFSSL_USE_OPTIONS_H) && \
    !defined(WOLFSSL_NO_OPTIONS_H) && !defined(WOLFSSL_CUSTOM_CONFIG) && \
    !defined(ARDUINO) && !defined(PLATFORMIO) && \
    !defined(USE_HAL_DRIVER) && !defined(NUCLEUS_PLUS_2_3) && \
    !defined(WOLFSSL_MX2_CONF_INCLUDE)
    #define WOLFSSL_USE_OPTIONS_H
#endif
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/version.h>

#if defined(WOLFSSL_USE_OPTIONS_H) && !defined(WOLFSSL_OPTIONS_H) && \
    !defined(WOLFSSL_NO_OPTIONS_H)
#define WOLFCERT_WOLFSSL_CONFIG_UNRESOLVED
#error "A wolfSSL header was included before wolfCert's, so <wolfssl/options.h> was never read and wolfSSL's feature set is at its defaults. Include <wolfcert/wolfcert.h> first; or, if wolfSSL takes its configuration another way, define WOLFSSL_USE_OPTIONS_H, WOLFSSL_CUSTOM_CONFIG or WOLFSSL_NO_OPTIONS_H before the wolfSSL header."
#endif

/* wolfCert feature constraints */
#if !defined(WOLFCERT_HAVE_RSA) && !defined(WOLFCERT_HAVE_ECC) && \
    !defined(WOLFCERT_HAVE_ED25519) && !defined(WOLFCERT_HAVE_ED448) && \
    !defined(WOLFCERT_HAVE_MLDSA)
#error "wolfCert needs at least one key algorithm: define one of WOLFCERT_HAVE_RSA / " \
       "WOLFCERT_HAVE_ECC / WOLFCERT_HAVE_ED25519 / WOLFCERT_HAVE_ED448 / WOLFCERT_HAVE_MLDSA."
#endif

#if defined(WOLFCERT_HAVE_SCEP) && !defined(WOLFCERT_HAVE_RSA)
#error "wolfCert SCEP is RSA-only (RFC 8894): define WOLFCERT_HAVE_RSA, or drop " \
       "WOLFCERT_HAVE_SCEP for an EST-only build."
#endif

#if !defined(WOLFCERT_HAVE_BUILTIN_TRANSPORT) && \
    !defined(WOLFCERT_NO_BUILTIN_TRANSPORT)
#error "Define WOLFCERT_HAVE_BUILTIN_TRANSPORT for the built-in POSIX socket transport, or WOLFCERT_NO_BUILTIN_TRANSPORT to confirm every config supplies its own WolfCertTransport."
#endif

/* Required wolfSSL feature set */

#if !defined(WOLFCERT_NO_WOLFSSL_FEATURE_CHECK) && \
    !defined(WOLFCERT_WOLFSSL_CONFIG_UNRESOLVED)

#if LIBWOLFSSL_VERSION_HEX < 0x05009004
#error "wolfCert requires wolfSSL 5.9.4 or newer."
#endif

#ifndef HAVE_PKCS7
#error "wolfSSL is missing HAVE_PKCS7; rebuild wolfSSL with --enable-pkcs7."
#endif
#ifndef WOLFSSL_CERT_GEN
#error "wolfSSL is missing WOLFSSL_CERT_GEN; rebuild wolfSSL with --enable-certgen."
#endif
#ifndef WOLFSSL_CERT_REQ
#error "wolfSSL is missing WOLFSSL_CERT_REQ; rebuild wolfSSL with --enable-certreq."
#endif
#ifndef WOLFSSL_CERT_EXT
#error "wolfSSL is missing WOLFSSL_CERT_EXT; rebuild wolfSSL with --enable-certext."
#endif
#ifndef WOLFSSL_KEY_GEN
#error "wolfSSL is missing WOLFSSL_KEY_GEN; rebuild wolfSSL with --enable-keygen."
#endif
#ifndef WOLF_CRYPTO_CB
#error "wolfSSL is missing WOLF_CRYPTO_CB; rebuild wolfSSL with --enable-cryptocb."
#endif
#ifndef WOLFSSL_BASE64_ENCODE
#error "wolfSSL is missing WOLFSSL_BASE64_ENCODE; rebuild wolfSSL with --enable-base64encode."
#endif
#ifndef WOLFSSL_ALT_NAMES
#error "wolfSSL is missing WOLFSSL_ALT_NAMES; rebuild wolfSSL with CPPFLAGS=\"-DWOLFSSL_ALT_NAMES\"."
#endif
#ifndef WOLFSSL_CERT_NAME_ALL
#error "wolfSSL is missing WOLFSSL_CERT_NAME_ALL; rebuild wolfSSL with CPPFLAGS=\"-DWOLFSSL_CERT_NAME_ALL\"."
#endif

#ifdef NO_AES
#error "wolfSSL was built with NO_AES; wolfCert requires AES. Rebuild wolfSSL with --enable-aes."
#endif
#ifdef NO_SHA256
#error "wolfSSL was built with NO_SHA256; wolfCert requires SHA-256. Rebuild wolfSSL with --enable-sha256."
#endif
#if defined(WOLFCERT_HAVE_SCEP) && (!defined(WOLFSSL_AES_128) || \
    !defined(HAVE_AES_CBC) || !defined(HAVE_AES_DECRYPT))
#error "wolfCert SCEP requires AES-128-CBC (RFC 8894). Rebuild wolfSSL without NO_AES_128, NO_AES_CBC or NO_AES_DECRYPT, or drop WOLFCERT_HAVE_SCEP."
#endif
#ifdef WOLFSSL_NO_CONST_CMP
#error "wolfSSL was built with WOLFSSL_NO_CONST_CMP; wolfCert requires wc_ConstantCompare. Rebuild wolfSSL without WOLFSSL_NO_CONST_CMP."
#endif
#ifdef WOLFSSL_NO_FORCE_ZERO
#error "wolfSSL was built with WOLFSSL_NO_FORCE_ZERO; wolfCert requires wc_ForceZero to scrub key material. Rebuild wolfSSL without WOLFSSL_NO_FORCE_ZERO."
#endif

#if !defined(HAVE_SNI) && !defined(WOLFCERT_NO_SNI)
#error "wolfSSL is missing HAVE_SNI; rebuild wolfSSL with --enable-sni. Define WOLFCERT_NO_SNI to build without it (only safe when every endpoint serves one certificate, or is addressed by IP)."
#endif

#if defined(WOLFSSL_NO_TLS12) && !defined(WOLFSSL_TLS13)
#error "wolfSSL provides neither TLS 1.2 nor TLS 1.3; wolfCert needs at least one for its HTTPS transport."
#endif

/* Zephyr takes these algorithms from Kconfig, separately from the wolfSSL
 * settings file, so the two can disagree. */
#ifdef __ZEPHYR__
#if defined(WOLFCERT_HAVE_RSA) && defined(NO_RSA)
#error "CONFIG_WOLFCERT_RSA is set but the wolfSSL settings file defines NO_RSA; remove NO_RSA or disable CONFIG_WOLFCERT_RSA."
#endif
#if defined(WOLFCERT_HAVE_ECC) && !defined(HAVE_ECC)
#error "CONFIG_WOLFCERT_ECC is set but the wolfSSL settings file lacks HAVE_ECC; define it or disable CONFIG_WOLFCERT_ECC."
#endif
#if defined(WOLFCERT_HAVE_ED25519) && !defined(HAVE_ED25519)
#error "CONFIG_WOLFCERT_ED25519 is set but the wolfSSL settings file lacks HAVE_ED25519; define it or disable CONFIG_WOLFCERT_ED25519."
#endif
#if defined(WOLFCERT_HAVE_ED448) && !defined(HAVE_ED448)
#error "CONFIG_WOLFCERT_ED448 is set but the wolfSSL settings file lacks HAVE_ED448; define it or disable CONFIG_WOLFCERT_ED448."
#endif
#if defined(WOLFCERT_HAVE_MLDSA) && !defined(WOLFSSL_HAVE_MLDSA)
#error "CONFIG_WOLFCERT_MLDSA is set but the wolfSSL settings file lacks WOLFSSL_HAVE_MLDSA; define it or disable CONFIG_WOLFCERT_MLDSA."
#endif
#endif /* __ZEPHYR__ */

#endif /* tier 2 */

#endif /* WOLFCERT_CHECK_CONFIG_H */
