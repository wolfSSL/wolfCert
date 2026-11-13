#                                               -*- Autoconf -*-
# SPDX-License-Identifier: GPL-3.0-or-later

AC_PREREQ([2.69])
AC_INIT([wolfCert], [0.1.0], [https://github.com/wolfSSL/wolfCert/issues])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIRS([m4])
AC_CONFIG_SRCDIR([src/wolfcert.c])
# No AC_CONFIG_HEADERS: configuration lives in the generated wolfcert/options.h.

AM_INIT_AUTOMAKE([1.14 foreign subdir-objects -Wall -Werror])
AM_SILENT_RULES([yes])

# Keep AC_PROG_CC's default "-g -O2" out of CFLAGS, which follows AM_CFLAGS.
: ${CFLAGS=""}

AC_PROG_CC
AC_PROG_CPP
AM_PROG_CC_C_O
AM_PROG_AR
LT_INIT

AC_PROG_INSTALL
AC_PROG_MAKE_SET

AC_CANONICAL_HOST
case "$host_os" in
    linux*|darwin*) ;;
    *) AC_MSG_WARN([wolfCert is only tested on Linux and macOS; host is $host_os]) ;;
esac

# Build options
# The non-debug default matches CMake's RelWithDebInfo.
OPTIMIZE_CFLAGS="-O2 -g -DNDEBUG"
DEBUG_CFLAGS="-O0 -g3"
AC_ARG_ENABLE([debug],
    [AS_HELP_STRING([--enable-debug],
      [build without optimizations and with full debug info (-O0 -g3)])],
    [enable_debug=$enableval], [enable_debug=no])
AS_IF([test "x$enable_debug" = "xyes"],
      [WOLFCERT_OPT_CFLAGS="$DEBUG_CFLAGS"],
      [WOLFCERT_OPT_CFLAGS="$OPTIMIZE_CFLAGS"])
AC_SUBST([WOLFCERT_OPT_CFLAGS])

# Feature flags
AC_ARG_ENABLE([est],
    [AS_HELP_STRING([--disable-est], [disable EST (RFC 7030) support])],
    [enable_est=$enableval], [enable_est=yes])
AM_CONDITIONAL([WOLFCERT_HAVE_EST],  [test "x$enable_est"  = "xyes"])

AC_ARG_ENABLE([scep],
    [AS_HELP_STRING([--disable-scep], [disable SCEP (RFC 8894) support])],
    [enable_scep=$enableval], [enable_scep=yes])
AM_CONDITIONAL([WOLFCERT_HAVE_SCEP], [test "x$enable_scep" = "xyes"])

AC_ARG_ENABLE([server],
    [AS_HELP_STRING([--disable-server], [do not build the minimal test server])],
    [enable_server=$enableval], [enable_server=yes])
AM_CONDITIONAL([WOLFCERT_HAVE_SERVER], [test "x$enable_server" = "xyes"])

AC_ARG_ENABLE([cli],
    [AS_HELP_STRING([--disable-cli], [do not build the CLI tools])],
    [enable_cli=$enableval], [enable_cli=yes])
AM_CONDITIONAL([WOLFCERT_BUILD_CLI], [test "x$enable_cli" = "xyes"])

AC_ARG_ENABLE([builtin-transport],
    [AS_HELP_STRING([--disable-builtin-transport],
        [do not build the built-in POSIX socket transport])],
    [enable_builtin_transport=$enableval], [enable_builtin_transport=yes])
AM_CONDITIONAL([WOLFCERT_HAVE_BUILTIN_TRANSPORT],
    [test "x$enable_builtin_transport" = "xyes"])

AS_IF([test "x$enable_builtin_transport" != "xyes"], [
  AS_IF([test "x$enable_cli" = "xyes"],
    [AC_MSG_ERROR([--enable-cli needs the built-in transport: the CLI
cannot supply a custom one])])
  AS_IF([test "x$enable_server" = "xyes"],
    [AC_MSG_ERROR([--enable-server needs the built-in transport: its
round-trip tests drive the client over real sockets])])
])

AC_ARG_ENABLE([tests],
    [AS_HELP_STRING([--enable-tests], [build unit and integration tests])],
    [enable_tests=$enableval], [enable_tests=no])
AM_CONDITIONAL([WOLFCERT_BUILD_TESTS], [test "x$enable_tests" = "xyes"])

AC_ARG_ENABLE([examples],
    [AS_HELP_STRING([--enable-examples], [build example programs])],
    [enable_examples=$enableval], [enable_examples=no])
AM_CONDITIONAL([WOLFCERT_BUILD_EXAMPLES], [test "x$enable_examples" = "xyes"])

# The est/scep/server flags still pick the sources under user settings, so
# they must match the macros in user_settings.h.
AC_ARG_ENABLE([user-settings],
    [AS_HELP_STRING([--enable-user-settings],
      [take feature config from a user-supplied user_settings.h instead of the generated options.h])],
    [enable_user_settings=$enableval], [enable_user_settings=no])
AC_ARG_WITH([user-settings],
    [AS_HELP_STRING([--with-user-settings=DIR],
      [directory containing user_settings.h (implies --enable-user-settings)])],
    [user_settings_dir=$withval; enable_user_settings=yes], [user_settings_dir=])
AM_CONDITIONAL([WOLFCERT_USER_SETTINGS], [test "x$enable_user_settings" = "xyes"])
AS_IF([test "x$enable_user_settings" = "xyes"],
  [WOLFCERT_USER_SETTINGS_CPPFLAGS="-DWOLFCERT_USER_SETTINGS"
   AS_IF([test -n "$user_settings_dir"],
     [WOLFCERT_USER_SETTINGS_CPPFLAGS="$WOLFCERT_USER_SETTINGS_CPPFLAGS -I$user_settings_dir"])],
  [WOLFCERT_USER_SETTINGS_CPPFLAGS=""])
AC_SUBST([WOLFCERT_USER_SETTINGS_CPPFLAGS])

AC_ARG_ENABLE([cmake-install],
    [AS_HELP_STRING([--disable-cmake-install],
      [do not install CMake package-config files])],
    [enable_cmake_install=$enableval], [enable_cmake_install=yes])
AM_CONDITIONAL([CMAKE_INSTALL], [test "x$enable_cmake_install" = "xyes"])

# wolfSSL
AC_ARG_WITH([wolfssl],
    [AS_HELP_STRING([--with-wolfssl=PATH],
      [wolfSSL install prefix (PATH/lib/pkgconfig/wolfssl.pc must exist)])],
    [], [with_wolfssl=no])
wolfssl_origin=""
AS_IF([test "x$with_wolfssl" != "xno" && test "x$with_wolfssl" != "xyes" && test -n "$with_wolfssl"],
    [AS_IF([test ! -f "$with_wolfssl/lib/pkgconfig/wolfssl.pc"],
       [AC_MSG_ERROR([--with-wolfssl=$with_wolfssl: $with_wolfssl/lib/pkgconfig/wolfssl.pc not found])])
     PKG_CONFIG_PATH="$with_wolfssl/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
     export PKG_CONFIG_PATH
     wolfssl_origin=" (from $with_wolfssl)"
     AC_MSG_NOTICE([using wolfSSL from $with_wolfssl])])

PKG_CHECK_MODULES([WOLFSSL], [wolfssl >= 5.9.4],
    [have_wolfssl=yes],
    [AC_MSG_ERROR([wolfssl >= 5.9.4 not found via pkg-config. wolfCert
      requires a wolfSSL build with HAVE_PKCS7, WOLFSSL_CERT_GEN,
      WOLFSSL_CERT_REQ, WOLFSSL_CERT_EXT, WOLFSSL_KEY_GEN, HAVE_ECC,
      WOLFSSL_BASE64_ENCODE, WOLFSSL_ALT_NAMES, WOLFSSL_CERT_NAME_ALL;
      a shared wolfSSL also needs WOLFSSL_PUBLIC_ASN.])])
AM_CONDITIONAL([HAVE_WOLFSSL], [test "x$have_wolfssl" = "xyes"])

# Probe wolfSSL's feature set the way wolfcert/check_config.h resolves it, so
# configure and the headers agree.
m4_define([WOLFCERT_WOLFSSL_PROLOGUE], [[
#if !defined(WOLFSSL_USER_SETTINGS) && !defined(WOLFSSL_USE_OPTIONS_H) && !defined(WOLFSSL_NO_OPTIONS_H) && !defined(WOLFSSL_CUSTOM_CONFIG) && !defined(ARDUINO) && !defined(PLATFORMIO) && !defined(USE_HAL_DRIVER) && !defined(NUCLEUS_PLUS_2_3) && !defined(WOLFSSL_MX2_CONF_INCLUDE)
#define WOLFSSL_USE_OPTIONS_H
#endif
#include <wolfssl/wolfcrypt/settings.h>
]])

AC_DEFUN([WOLFCERT_REJECT_NEG],
[AC_MSG_CHECKING([that wolfSSL does not define $1])
 AC_COMPILE_IFELSE(
   [AC_LANG_PROGRAM(WOLFCERT_WOLFSSL_PROLOGUE,
    [[#ifdef $1
      #error disabled
      #endif]])],
   [AC_MSG_RESULT([ok])],
   [AC_MSG_RESULT([defined])
    AC_MSG_ERROR([wolfSSL was built with $1 defined; wolfCert needs $2.
      Rebuild wolfSSL without --disable-$(echo $2 | tr 'A-Z' 'a-z').])])])

# WOLFCERT_OPT(SUBST_VAR, $cond_value, MACRO): an options.h line for MACRO.
AC_DEFUN([WOLFCERT_OPT],
[AS_IF([test "x$2" = "xyes"],
   [$1="@%:@define $3 1"],
   [$1="/* $3 not enabled */"])
 AC_SUBST([$1])])

# WOLFCERT_PLAT(SUBST_VAR, $cond_value, HAVE_MACRO, NO_MACRO): defines
# HAVE_MACRO when $cond_value is yes, else NO_MACRO.
AC_DEFUN([WOLFCERT_PLAT],
[AS_IF([test "x$2" = "xyes"],
   [$1="@%:@define $3 1"],
   [$1="@%:@define $4 1"])
 AC_SUBST([$1])])

save_CPPFLAGS="$CPPFLAGS"
CPPFLAGS="$CPPFLAGS $WOLFSSL_CFLAGS"
AC_CHECK_DECLS([HAVE_PKCS7, WOLFSSL_CERT_GEN, WOLFSSL_CERT_REQ, WOLFSSL_CERT_EXT,
                WOLFSSL_KEY_GEN, WOLFSSL_BASE64_ENCODE,
                WOLFSSL_ALT_NAMES, WOLFSSL_CERT_NAME_ALL],
    [], [AC_MSG_ERROR([wolfSSL is missing a required feature (see above).
      Rebuild wolfSSL with --enable-pkcs7 --enable-ecc
      --enable-certgen --enable-certreq --enable-certext --enable-keygen
      --enable-base64encode CPPFLAGS="-DWOLFSSL_ALT_NAMES
      -DWOLFSSL_CERT_NAME_ALL".])],
    WOLFCERT_WOLFSSL_PROLOGUE)

# Link the WOLFSSL_ASN_API helpers wolfCert calls, without wolfSSL's headers.
AC_MSG_CHECKING([whether wolfSSL exports its ASN helpers])
save_LIBS="$LIBS"
LIBS="$WOLFSSL_LIBS $LIBS"
AC_LINK_IFELSE(
  [AC_LANG_PROGRAM(
[[extern char FreeAltNames(void);
extern char wc_SetDNSEntry(void);
extern char wc_SetAltNamesFromList(void);
extern char SetLength(void);
extern char GetASNTag(void);
extern char GetLength(void);]],
   [[return FreeAltNames() + wc_SetDNSEntry() + wc_SetAltNamesFromList() +
       SetLength() + GetASNTag() + GetLength();]])],
  [AC_MSG_RESULT([yes])],
  [AC_MSG_RESULT([no])
   AC_MSG_ERROR([wolfSSL does not export its ASN helpers (wc_SetDNSEntry,
     wc_SetAltNamesFromList, FreeAltNames, SetLength, GetASNTag, GetLength).
     Rebuild wolfSSL with CPPFLAGS="-DWOLFSSL_PUBLIC_ASN".])])
LIBS="$save_LIBS"

# Default-on wolfSSL features wolfCert requires.
WOLFCERT_REJECT_NEG([NO_AES],          [AES])
WOLFCERT_REJECT_NEG([NO_SHA256],       [SHA-256])

# RSA is required by SCEP (RFC 8894) and optional for an EST-only build.
AC_MSG_CHECKING([whether wolfSSL provides RSA])
AC_COMPILE_IFELSE(
  [AC_LANG_PROGRAM(WOLFCERT_WOLFSSL_PROLOGUE,
   [[#ifdef NO_RSA
     #error disabled
     #endif]])],
  [AC_MSG_RESULT([yes]); have_rsa=yes],
  [AC_MSG_RESULT([no]);  have_rsa=no])
AS_IF([test "x$have_rsa" = "xno"],
  [AS_IF([test "x$enable_scep" = "xyes"],
     [AC_MSG_ERROR([wolfSSL was built with NO_RSA, but wolfCert SCEP is RSA-only
       (RFC 8894). Rebuild wolfSSL with RSA, or configure with --disable-scep.])],
     [AC_MSG_WARN([wolfSSL was built with NO_RSA; wolfCert will compile without
       RSA and the rsa:* key type will return WOLFCERT_ERR_UNSUPPORTED.])])])
AM_CONDITIONAL([WOLFCERT_HAVE_RSA], [test "x$have_rsa" = "xyes"])

# AES-128-CBC: mandatory-to-implement for SCEP (RFC 8894 section 2.9).
AS_IF([test "x$enable_scep" = "xyes"],
  [AC_MSG_CHECKING([whether wolfSSL provides AES-128-CBC])
   AC_COMPILE_IFELSE(
     [AC_LANG_PROGRAM(WOLFCERT_WOLFSSL_PROLOGUE,
      [[#if !defined(WOLFSSL_AES_128) || !defined(HAVE_AES_CBC) || !defined(HAVE_AES_DECRYPT)
        #error noaes128cbc
        #endif]])],
     [AC_MSG_RESULT([yes])],
     [AC_MSG_RESULT([no])
      AC_MSG_ERROR([wolfCert SCEP requires AES-128-CBC (RFC 8894). Rebuild
        wolfSSL without NO_AES_128, NO_AES_CBC or NO_AES_DECRYPT, or configure
        with --disable-scep.])])])

# The HTTPS transport needs TLS 1.2 or TLS 1.3.
AC_MSG_CHECKING([whether wolfSSL provides TLS 1.2])
AC_COMPILE_IFELSE(
  [AC_LANG_PROGRAM(WOLFCERT_WOLFSSL_PROLOGUE,
   [[#ifdef WOLFSSL_NO_TLS12
     #error notls12
     #endif]])],
  [AC_MSG_RESULT([yes]); have_tls12=yes], [AC_MSG_RESULT([no]); have_tls12=no])
AC_MSG_CHECKING([whether wolfSSL provides TLS 1.3])
AC_COMPILE_IFELSE(
  [AC_LANG_PROGRAM(WOLFCERT_WOLFSSL_PROLOGUE,
   [[#ifndef WOLFSSL_TLS13
     #error notls13
     #endif]])],
  [AC_MSG_RESULT([yes]); have_tls13=yes], [AC_MSG_RESULT([no]); have_tls13=no])
AS_IF([test "x$have_tls12" = "xno" && test "x$have_tls13" = "xno"],
  [AC_MSG_ERROR([wolfSSL provides neither TLS 1.2 nor TLS 1.3; wolfCert needs
    at least one for its HTTPS transport.])])

# Optional key algorithms.
AC_CHECK_DECL([HAVE_ECC], [have_ecc=yes],
    [have_ecc=no; AC_MSG_WARN([wolfSSL was built without HAVE_ECC; ECC key
      types will return WOLFCERT_ERR_UNSUPPORTED. Rebuild with --enable-ecc.])],
    WOLFCERT_WOLFSSL_PROLOGUE)
AC_CHECK_DECL([HAVE_ED25519], [have_ed25519=yes],
    [have_ed25519=no; AC_MSG_WARN([wolfSSL was built without HAVE_ED25519;
      Ed25519 key types will return WOLFCERT_ERR_UNSUPPORTED. Rebuild with
      --enable-ed25519.])],
    WOLFCERT_WOLFSSL_PROLOGUE)
AC_CHECK_DECL([HAVE_ED448], [have_ed448=yes],
    [have_ed448=no; AC_MSG_WARN([wolfSSL was built without HAVE_ED448; Ed448
      key types will return WOLFCERT_ERR_UNSUPPORTED. Rebuild with
      --enable-ed448.])],
    WOLFCERT_WOLFSSL_PROLOGUE)
AC_CHECK_DECL([WOLFSSL_HAVE_MLDSA], [have_mldsa=yes],
    [have_mldsa=no; AC_MSG_WARN([wolfSSL was built without WOLFSSL_HAVE_MLDSA;
      mldsa:44/65/87 will return WOLFCERT_ERR_UNSUPPORTED. Rebuild with
      --enable-mldsa.])],
    WOLFCERT_WOLFSSL_PROLOGUE)

# The SBOM records the wolfSSL version of the headers compiled against.
AC_MSG_CHECKING([wolfSSL version])
AC_LANG_CONFTEST([AC_LANG_SOURCE([[#include <wolfssl/version.h>
wolfcert_wolfssl_version LIBWOLFSSL_VERSION_STRING]])])
WOLFCERT_WOLFSSL_VERSION=`$CPP $CFLAGS $CPPFLAGS conftest.$ac_ext \
    2>/dev/null | sed -n 's/^wolfcert_wolfssl_version "\(.*\)" *$/\1/p'`
rm -f conftest.$ac_ext
AC_MSG_RESULT([${WOLFCERT_WOLFSSL_VERSION:-unknown}])
AC_SUBST([WOLFCERT_WOLFSSL_VERSION])
CPPFLAGS="$save_CPPFLAGS"

AS_IF([test "x$have_rsa" = "xno" && test "x$have_ecc" = "xno" \
    && test "x$have_ed25519" = "xno" && test "x$have_ed448" = "xno" \
    && test "x$have_mldsa" = "xno"],
  [AC_MSG_ERROR([wolfSSL provides none of RSA/ECC/Ed25519/Ed448/ML-DSA;
    wolfCert needs at least one key algorithm.])])

WOLFCERT_OPT([WOLFCERT_OPT_EST],     [$enable_est],    [WOLFCERT_HAVE_EST])
WOLFCERT_OPT([WOLFCERT_OPT_SCEP],    [$enable_scep],   [WOLFCERT_HAVE_SCEP])
WOLFCERT_OPT([WOLFCERT_OPT_SERVER],  [$enable_server], [WOLFCERT_HAVE_SERVER])
WOLFCERT_PLAT([WOLFCERT_OPT_BUILTIN_TRANSPORT], [$enable_builtin_transport],
              [WOLFCERT_HAVE_BUILTIN_TRANSPORT], [WOLFCERT_NO_BUILTIN_TRANSPORT])
WOLFCERT_OPT([WOLFCERT_OPT_RSA],     [$have_rsa],      [WOLFCERT_HAVE_RSA])
WOLFCERT_OPT([WOLFCERT_OPT_ECC],     [$have_ecc],      [WOLFCERT_HAVE_ECC])
WOLFCERT_OPT([WOLFCERT_OPT_ED25519], [$have_ed25519],  [WOLFCERT_HAVE_ED25519])
WOLFCERT_OPT([WOLFCERT_OPT_ED448],   [$have_ed448],    [WOLFCERT_HAVE_ED448])
WOLFCERT_OPT([WOLFCERT_OPT_MLDSA],   [$have_mldsa],    [WOLFCERT_HAVE_MLDSA])

# make sbom
AC_PATH_PROG([PYTHON3], [python3])
AC_PATH_PROG([PYSPDXTOOLS], [pyspdxtools])
AC_PATH_PROG([GIT], [git])

# The CMake targets file needs absolute paths; $prefix is NONE until evaluated.
WOLFCERT_PREFIX_ABS=$prefix
test "x$WOLFCERT_PREFIX_ABS" = "xNONE" && WOLFCERT_PREFIX_ABS=$ac_default_prefix
WOLFCERT_EXEC_PREFIX_ABS=$exec_prefix
test "x$WOLFCERT_EXEC_PREFIX_ABS" = "xNONE" && WOLFCERT_EXEC_PREFIX_ABS=$WOLFCERT_PREFIX_ABS
saved_prefix=$prefix
saved_exec_prefix=$exec_prefix
prefix=$WOLFCERT_PREFIX_ABS
exec_prefix=$WOLFCERT_EXEC_PREFIX_ABS
eval WOLFCERT_LIBDIR_ABS=\"$libdir\"
eval WOLFCERT_INCLUDEDIR_ABS=\"$includedir\"
prefix=$saved_prefix
exec_prefix=$saved_exec_prefix
AC_SUBST([WOLFCERT_PREFIX_ABS])
AC_SUBST([WOLFCERT_LIBDIR_ABS])
AC_SUBST([WOLFCERT_INCLUDEDIR_ABS])

AC_CONFIG_FILES([
    Makefile
    wolfcert.pc
])
AS_IF([test "x$enable_user_settings" != "xyes"],
  [AC_CONFIG_FILES([wolfcert/options.h])])
AS_IF([test "x$enable_cmake_install" = "xyes"], [
AC_CONFIG_FILES([cmake/wolfCertConfig.cmake:cmake/Config.cmake.in
        cmake/wolfCertConfigVersion.cmake:cmake/wolfCertConfigVersion.cmake.in
        cmake/wolfCertTargets.cmake:cmake/wolfCertTargets.cmake.in
        ])
])
AC_OUTPUT

AC_MSG_NOTICE([
  ----------------------------------------
  wolfCert $PACKAGE_VERSION configuration:

    EST support   : $enable_est
    SCEP support  : $enable_scep
    Key algs      : RSA=$have_rsa ECC=$have_ecc Ed25519=$have_ed25519
                    Ed448=$have_ed448 ML-DSA=$have_mldsa
    TLS 1.2/1.3   : $have_tls12 / $have_tls13
    Test server   : $enable_server
    Builtin transp: $enable_builtin_transport
    User settings : $enable_user_settings
    CLI tools     : $enable_cli
    Tests         : $enable_tests
    Examples      : $enable_examples
    CMake config   : $enable_cmake_install
    Debug build   : $enable_debug
    wolfSSL       : $have_wolfssl$wolfssl_origin
  ----------------------------------------
])
