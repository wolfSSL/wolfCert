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

/* Combined wolfSSL + wolfCert config for the freestanding ARM gate
 * (scripts/ci/compile-freestanding.sh), read via -DWOLFSSL_USER_SETTINGS
 * -DWOLFCERT_USER_SETTINGS. One file for both, as docs/EMBEDDED.md advises.
 * Deliberately absent: the built-in transport, POSIX store, server and
 * HAVE_SNI, so this no-sockets target keeps those paths compiled out. */

#ifndef WOLFSSL_USER_SETTINGS_H
#define WOLFSSL_USER_SETTINGS_H

/* --- target shape: no OS, no filesystem, app-supplied I/O --- */
#define SINGLE_THREADED
#define NO_FILESYSTEM
#define NO_WRITEV
#define WOLFSSL_USER_IO
#define NO_MAIN_DRIVER
#define WOLFSSL_IGNORE_FILE_WARN
#define NO_WOLFSSL_DIR
#define WOLFSSL_NO_SOCK

/* --- the ten wolfCert requires --- */
#define HAVE_PKCS7
#define WOLFSSL_CERT_GEN
#define WOLFSSL_CERT_REQ
#define WOLFSSL_CERT_EXT
#define WOLFSSL_KEY_GEN
#define WOLF_CRYPTO_CB
#define WOLFSSL_BASE64_ENCODE
#define OPENSSL_EXTRA
#define WOLFSSL_ALT_NAMES
#define WOLFSSL_CERT_NAME_ALL

/* --- algorithms PKCS#7 + TLS need --- */
#define HAVE_AES_CBC
#define HAVE_AESGCM
#define WOLFSSL_AES_DIRECT
#define HAVE_ECC
#define HAVE_HKDF
#define WOLFSSL_SHA384
#define WOLFSSL_SHA512
#define HAVE_TLS_EXTENSIONS
#define HAVE_ED25519
#define HAVE_ED448
#define WOLFSSL_SHAKE256
#define WOLFSSL_SHA3
#define HAVE_DILITHIUM
#define WOLFSSL_WC_DILITHIUM
#define HAVE_SUPPORTED_CURVES
#define WOLFSSL_TLS13
#define HAVE_ENCRYPT_THEN_MAC


/* ---- wolfCert: no sockets, no filesystem ---- */
#define WOLFCERT_NO_SNI
#define WOLFCERT_HAVE_EST    1   /* EST  (RFC 7030) */
#define WOLFCERT_HAVE_SCEP   1   /* SCEP (RFC 8894) - requires WOLFCERT_HAVE_RSA */
#define WOLFCERT_HAVE_RSA     1
#define WOLFCERT_HAVE_ECC     1
#define WOLFCERT_HAVE_ED25519 1
#define WOLFCERT_HAVE_ED448   1
#define WOLFCERT_HAVE_MLDSA   1

#endif
