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
 * Fixture for the optionsh-decoy case of check-config-resolution.sh. It holds
 * no wolfSSL macros, so the tier-2 checks pass only if the staged
 * <wolfssl/options.h> was consulted; a wolfSSL feature macro here defeats it.
 */

#ifndef WOLFSSL_USER_SETTINGS_H
#define WOLFSSL_USER_SETTINGS_H

#define WOLFCERT_HAVE_EST    1
#define WOLFCERT_HAVE_SCEP   1
#define WOLFCERT_HAVE_SERVER 1

#define WOLFCERT_HAVE_BUILTIN_TRANSPORT 1

#define WOLFCERT_HAVE_RSA     1
#define WOLFCERT_HAVE_ECC     1
#define WOLFCERT_HAVE_ED25519 1
#define WOLFCERT_HAVE_ED448   1
#define WOLFCERT_HAVE_MLDSA   1

#endif /* WOLFSSL_USER_SETTINGS_H */
