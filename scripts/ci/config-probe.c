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
 * scripts/ci/config-probe.c - one translation unit, one wolfCert entry header.
 *
 * Driven by check-config-resolution.sh. WOLFCERT_PROBE_HEADER selects the
 * header under test. Each macro below becomes a declaration naming itself, so
 * `cc -E` alone reports the resolved wolfSSL feature set, and the report
 * survives a tier-2 #error earlier in the file.
 *
 * WC_PROBE takes each macro name as a literal token: ## suppresses expansion,
 * which matters because wolfSSL's feature macros are defined empty.
 */

#include WOLFCERT_PROBE_HEADER

#define WC_PROBE(name, v) extern int wcprobe_##name##_is_##v;


/* Provenance: which file supplied the feature set. */
#ifdef WOLFCERT_CI_DECOY_OPTIONS_H
WC_PROBE(WOLFCERT_CI_DECOY_OPTIONS_H, 1)
#else
WC_PROBE(WOLFCERT_CI_DECOY_OPTIONS_H, 0)
#endif
#ifdef WOLFSSL_OPTIONS_H
WC_PROBE(WOLFSSL_OPTIONS_H, 1)
#else
WC_PROBE(WOLFSSL_OPTIONS_H, 0)
#endif
#ifdef WOLFSSL_USER_SETTINGS_H
WC_PROBE(WOLFSSL_USER_SETTINGS_H, 1)
#else
WC_PROBE(WOLFSSL_USER_SETTINGS_H, 0)
#endif
#ifdef WOLF_CRYPT_SETTINGS_H
WC_PROBE(WOLF_CRYPT_SETTINGS_H, 1)
#else
WC_PROBE(WOLF_CRYPT_SETTINGS_H, 0)
#endif

/* The tier-2 set wolfcert/check_config.h validates. */
#ifdef HAVE_PKCS7
WC_PROBE(HAVE_PKCS7, 1)
#else
WC_PROBE(HAVE_PKCS7, 0)
#endif
#ifdef WOLFSSL_CERT_GEN
WC_PROBE(WOLFSSL_CERT_GEN, 1)
#else
WC_PROBE(WOLFSSL_CERT_GEN, 0)
#endif
#ifdef WOLFSSL_CERT_REQ
WC_PROBE(WOLFSSL_CERT_REQ, 1)
#else
WC_PROBE(WOLFSSL_CERT_REQ, 0)
#endif
#ifdef WOLFSSL_CERT_EXT
WC_PROBE(WOLFSSL_CERT_EXT, 1)
#else
WC_PROBE(WOLFSSL_CERT_EXT, 0)
#endif
#ifdef WOLFSSL_KEY_GEN
WC_PROBE(WOLFSSL_KEY_GEN, 1)
#else
WC_PROBE(WOLFSSL_KEY_GEN, 0)
#endif
#ifdef WOLF_CRYPTO_CB
WC_PROBE(WOLF_CRYPTO_CB, 1)
#else
WC_PROBE(WOLF_CRYPTO_CB, 0)
#endif
#ifdef WOLFSSL_BASE64_ENCODE
WC_PROBE(WOLFSSL_BASE64_ENCODE, 1)
#else
WC_PROBE(WOLFSSL_BASE64_ENCODE, 0)
#endif
#ifdef WOLFSSL_ALT_NAMES
WC_PROBE(WOLFSSL_ALT_NAMES, 1)
#else
WC_PROBE(WOLFSSL_ALT_NAMES, 0)
#endif
#ifdef WOLFSSL_CERT_NAME_ALL
WC_PROBE(WOLFSSL_CERT_NAME_ALL, 1)
#else
WC_PROBE(WOLFSSL_CERT_NAME_ALL, 0)
#endif
#ifdef NO_AES
WC_PROBE(NO_AES, 1)
#else
WC_PROBE(NO_AES, 0)
#endif
#ifdef NO_SHA256
WC_PROBE(NO_SHA256, 1)
#else
WC_PROBE(NO_SHA256, 0)
#endif
#ifdef WOLFSSL_NO_CONST_CMP
WC_PROBE(WOLFSSL_NO_CONST_CMP, 1)
#else
WC_PROBE(WOLFSSL_NO_CONST_CMP, 0)
#endif
#ifdef WOLFSSL_NO_FORCE_ZERO
WC_PROBE(WOLFSSL_NO_FORCE_ZERO, 1)
#else
WC_PROBE(WOLFSSL_NO_FORCE_ZERO, 0)
#endif
#ifdef HAVE_SNI
WC_PROBE(HAVE_SNI, 1)
#else
WC_PROBE(HAVE_SNI, 0)
#endif
#ifdef WOLFSSL_NO_TLS12
WC_PROBE(WOLFSSL_NO_TLS12, 1)
#else
WC_PROBE(WOLFSSL_NO_TLS12, 0)
#endif
#ifdef WOLFSSL_TLS13
WC_PROBE(WOLFSSL_TLS13, 1)
#else
WC_PROBE(WOLFSSL_TLS13, 0)
#endif

/* Allocator shape, the reason wolfcert/memory.h resolves the config at all. */
#ifdef WOLFSSL_STATIC_MEMORY
WC_PROBE(WOLFSSL_STATIC_MEMORY, 1)
#else
WC_PROBE(WOLFSSL_STATIC_MEMORY, 0)
#endif
#ifdef WOLFSSL_NO_MALLOC
WC_PROBE(WOLFSSL_NO_MALLOC, 1)
#else
WC_PROBE(WOLFSSL_NO_MALLOC, 0)
#endif
#ifdef WOLFCERT_CUSTOM_ALLOC
WC_PROBE(WOLFCERT_CUSTOM_ALLOC, 1)
#else
WC_PROBE(WOLFCERT_CUSTOM_ALLOC, 0)
#endif
