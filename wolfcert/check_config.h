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
 * wolfcert/check_config.h - compile-time validation of the resolved feature
 * configuration.
 *
 * Included by wolfcert/types.h right after the WOLFCERT_HAVE_* set is loaded
 * (from the generated wolfcert/options.h, or from a user-supplied
 * user_settings.h when WOLFCERT_USER_SETTINGS is defined). It re-checks, as
 * #error directives, the same constraints the CMake/autoconf configure step
 * enforces - so a header-only build with a contradictory or incomplete config
 * fails loudly here instead of much later with a confusing compile or link
 * error. The checks run in BOTH config modes as defense-in-depth: a configured
 * build has already satisfied them, so they are a no-op there.
 *
 * Two tiers:
 *   1. wolfCert's own constraints, from the WOLFCERT_HAVE_* macros.
 *   2. The wolfSSL feature set wolfCert depends on, read through
 *      <wolfssl/wolfcrypt/settings.h> so it also sees a wolfSSL configured by
 *      its own user_settings.h. Define WOLFCERT_NO_WOLFSSL_FEATURE_CHECK to
 *      skip the tier-2 checks.
 */

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

#if defined(WOLFSSL_USE_OPTIONS_H) && !defined(WOLFSSL_OPTIONS_H) && \
    !defined(WOLFSSL_NO_OPTIONS_H)
#define WOLFCERT_WOLFSSL_CONFIG_UNRESOLVED
#error "A wolfSSL header was included before wolfCert's, so <wolfssl/options.h> was never read and wolfSSL's feature set is at its defaults. Include <wolfcert/wolfcert.h> first; or, if wolfSSL takes its configuration another way, define WOLFSSL_USE_OPTIONS_H, WOLFSSL_CUSTOM_CONFIG or WOLFSSL_NO_OPTIONS_H before the wolfSSL header."
#endif

/* ---- Tier 1: wolfCert feature constraints ---- */

/* At least one key algorithm must be present. */
#if !defined(WOLFCERT_HAVE_RSA) && !defined(WOLFCERT_HAVE_ECC) && \
    !defined(WOLFCERT_HAVE_ED25519) && !defined(WOLFCERT_HAVE_ED448) && \
    !defined(WOLFCERT_HAVE_MLDSA)
#error "wolfCert needs at least one key algorithm: define one of WOLFCERT_HAVE_RSA / " \
       "WOLFCERT_HAVE_ECC / WOLFCERT_HAVE_ED25519 / WOLFCERT_HAVE_ED448 / WOLFCERT_HAVE_MLDSA."
#endif

/* SCEP is RSA-only (RFC 8894). */
#if defined(WOLFCERT_HAVE_SCEP) && !defined(WOLFCERT_HAVE_RSA)
#error "wolfCert SCEP is RSA-only (RFC 8894): define WOLFCERT_HAVE_RSA, or drop " \
       "WOLFCERT_HAVE_SCEP for an EST-only build."
#endif

#if !defined(WOLFCERT_HAVE_BUILTIN_TRANSPORT) && \
    !defined(WOLFCERT_NO_BUILTIN_TRANSPORT)
#error "Define WOLFCERT_HAVE_BUILTIN_TRANSPORT for the built-in POSIX socket transport, or WOLFCERT_NO_BUILTIN_TRANSPORT to confirm every config supplies its own WolfCertTransport."
#endif
#if !defined(WOLFCERT_HAVE_POSIX_STORE) && !defined(WOLFCERT_NO_POSIX_STORE)
#error "Define WOLFCERT_HAVE_POSIX_STORE for the POSIX file store, or WOLFCERT_NO_POSIX_STORE to confirm you supply your own WolfCertStoreOps."
#endif

/* ---- Tier 2: required wolfSSL feature set ---- */

#if !defined(WOLFCERT_NO_WOLFSSL_FEATURE_CHECK) && \
    !defined(WOLFCERT_WOLFSSL_CONFIG_UNRESOLVED)

/* Mandatory wolfSSL features. Rebuild wolfSSL with:
 *   ./configure --enable-pkcs7 --enable-certgen --enable-certreq \
 *       --enable-certext --enable-keygen --enable-cryptocb \
 *       --enable-base64encode --enable-sni \
 *       CPPFLAGS="-DWOLFSSL_ALT_NAMES -DWOLFSSL_CERT_NAME_ALL \
 *                 -DWOLFSSL_PUBLIC_ASN" */
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

/* Default-on wolfSSL features wolfCert requires unconditionally. */
#ifdef NO_AES
#error "wolfSSL was built with NO_AES; wolfCert requires AES. Rebuild wolfSSL with --enable-aes."
#endif
#ifdef NO_SHA256
#error "wolfSSL was built with NO_SHA256; wolfCert requires SHA-256. Rebuild wolfSSL with --enable-sha256."
#endif
/* wc_ConstantCompare backs every constant-time comparison of secret material
 * (SCEP CA fingerprint / challenge password, EST Basic-auth credential). A
 * wolfSSL built WOLFSSL_NO_CONST_CMP drops the symbol, so catch it here with a
 * clear message instead of a later missing-symbol link error. */
#ifdef WOLFSSL_NO_CONST_CMP
#error "wolfSSL was built with WOLFSSL_NO_CONST_CMP; wolfCert requires wc_ConstantCompare. Rebuild wolfSSL without WOLFSSL_NO_CONST_CMP."
#endif
/* wc_ForceZero scrubs private-key DER/PEM and other secret buffers on every
 * exit path (keygen, store, CA issuance, SCEP/EST clients). A wolfSSL built
 * WOLFSSL_NO_FORCE_ZERO drops the symbol, so catch it here too rather than as a
 * later missing-symbol link error. */
#ifdef WOLFSSL_NO_FORCE_ZERO
#error "wolfSSL was built with WOLFSSL_NO_FORCE_ZERO; wolfCert requires wc_ForceZero to scrub key material. Rebuild wolfSSL without WOLFSSL_NO_FORCE_ZERO."
#endif

/* SNI. wolfSSL leaves HAVE_SNI off by default on most cross builds; without it
 * a hosted EST endpoint serves its default certificate and verification then
 * fails. WOLFCERT_NO_SNI accepts that trade for a smaller build. */
#if !defined(HAVE_SNI) && !defined(WOLFCERT_NO_SNI)
#error "wolfSSL is missing HAVE_SNI; rebuild wolfSSL with --enable-sni. Define WOLFCERT_NO_SNI to build without it (only safe when every endpoint serves one certificate, or is addressed by IP)."
#endif

/* The HTTPS transport needs at least TLS 1.2 or TLS 1.3. */
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
