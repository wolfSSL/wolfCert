#                                               -*- Autoconf -*-
# SPDX-License-Identifier: GPL-3.0-or-later

AC_PREREQ([2.69])
AC_INIT([wolfCert], [0.1.0], [https://github.com/wolfSSL/wolfCert/issues])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIRS([m4])
AC_CONFIG_SRCDIR([src/wolfcert.c])
# No AC_CONFIG_HEADERS: wolfCert's compile-time configuration lives in the
# generated wolfcert/options.h (see AC_CONFIG_FILES below), not a config.h that
# no source includes.

AM_INIT_AUTOMAKE([1.14 foreign subdir-objects -Wall -Werror])
AM_SILENT_RULES([yes])

# Suppress AC_PROG_CC's habit of defaulting CFLAGS to "-g -O2" when the caller
# sets none. Like wolfSSL, wolfCert manages optimization/debug itself via
# AM_CFLAGS (see the build-options section); leaving the autoconf default in
# CFLAGS would override those because automake emits "$(AM_CFLAGS) $(CFLAGS)".
# A user-supplied CFLAGS is still respected and still wins.
: ${CFLAGS=""}

AC_PROG_CC
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

# ---- build options ----------------------------------------------------------
# Optimization / debug flags, handled the wolfSSL way: split OPTIMIZE_CFLAGS vs
# DEBUG_CFLAGS and inject the chosen set through AM_CFLAGS (precedes $(CFLAGS)
# on the compile line; the default CFLAGS was emptied above so these win).
#
# --enable-debug drops optimizations and emits full debug info. The non-debug
# default mirrors CMake's RelWithDebInfo (-O2 -g -DNDEBUG), so both build
# systems agree. This is a compiler-flag change only; the runtime logging
# infrastructure (wolfcert/log.h) is untouched - verbosity stays a runtime
# decision via wolfcert_set_log_level(). The CMake analogue is
# -DCMAKE_BUILD_TYPE=Debug.
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

# ---- feature flags ----------------------------------------------------------
AC_ARG_ENABLE([est],
    [AS_HELP_STRING([--disable-est], [disable EST (RFC 7030) support])],
    [enable_est=$enableval], [enable_est=yes])
# EST/SCEP/SERVER feature macros are emitted into wolfcert/options.h (see the
# WOLFCERT_OPT calls below); the AM_CONDITIONALs gate which sources are built.
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

# store.c is always compiled; only its POSIX file backend is gated, so this
# needs no AM_CONDITIONAL.
AC_ARG_ENABLE([posix-store],
    [AS_HELP_STRING([--disable-posix-store],
        [do not build the POSIX file storage backend])],
    [enable_posix_store=$enableval], [enable_posix_store=yes])

AC_ARG_ENABLE([tests],
    [AS_HELP_STRING([--enable-tests], [build unit and integration tests])],
    [enable_tests=$enableval], [enable_tests=no])
# WOLFCERT_BUILD_TESTING reaches the compiler via Makefile.am (-D, conditional
# on this); it is a per-build-variant flag, not a library feature, so it stays
# out of wolfcert/options.h.
AM_CONDITIONAL([WOLFCERT_BUILD_TESTS], [test "x$enable_tests" = "xyes"])

AC_ARG_ENABLE([examples],
    [AS_HELP_STRING([--enable-examples], [build example programs])],
    [enable_examples=$enableval], [enable_examples=no])
AM_CONDITIONAL([WOLFCERT_BUILD_EXAMPLES], [test "x$enable_examples" = "xyes"])

# Header-based configuration: the user_settings.h analogue of wolfSSL's
# WOLFSSL_USER_SETTINGS. When enabled, wolfcert/options.h is neither generated
# nor installed; instead the build defines WOLFCERT_USER_SETTINGS and the
# integrator supplies user_settings.h on the include path (see
# --with-user-settings and examples/user_settings.h.example). The
# --enable/--disable-est/scep/server flags still select which sources build, so
# keep them in sync with the macros in your user_settings.h.
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

# Install CMake package-config files ($(libdir)/cmake/wolfCert) so an autoconf
# `make install` is consumable via find_package(wolfCert), like a native CMake
# install. See AC_CONFIG_FILES + Makefile.am (CMAKE_INSTALL).
AC_ARG_ENABLE([cmake-install],
    [AS_HELP_STRING([--disable-cmake-install],
      [do not install CMake package-config files])],
    [enable_cmake_install=$enableval], [enable_cmake_install=yes])
AM_CONDITIONAL([CMAKE_INSTALL], [test "x$enable_cmake_install" = "xyes"])

# ---- wolfSSL ----------------------------------------------------------------
# Optional convenience: --with-wolfssl=PATH points at a wolfSSL install
# prefix whose lib/pkgconfig/wolfssl.pc the PKG_CHECK_MODULES below should
# pick up. Equivalent to prepending PATH/lib/pkgconfig to PKG_CONFIG_PATH.
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

PKG_CHECK_MODULES([WOLFSSL], [wolfssl >= 5.9.2],
    [have_wolfssl=yes],
    [AC_MSG_ERROR([wolfssl >= 5.9.2 not found via pkg-config. wolfCert
      requires a wolfSSL build with HAVE_PKCS7, WOLFSSL_CERT_GEN,
      WOLFSSL_CERT_REQ, WOLFSSL_CERT_EXT, WOLFSSL_KEY_GEN, HAVE_ECC,
      WOLF_CRYPTO_CB, WOLFSSL_BASE64_ENCODE, OPENSSL_EXTRA,
      WOLFSSL_ALT_NAMES, WOLFSSL_CERT_NAME_ALL.])])
AM_CONDITIONAL([HAVE_WOLFSSL], [test "x$have_wolfssl" = "xyes"])

AC_DEFUN([WOLFCERT_REJECT_NEG],
[AC_MSG_CHECKING([that wolfSSL does not define $1])
 AC_COMPILE_IFELSE(
   [AC_LANG_PROGRAM([[#include <wolfssl/options.h>]],
    [[#ifdef $1
      #error disabled
      #endif]])],
   [AC_MSG_RESULT([ok])],
   [AC_MSG_RESULT([defined])
    AC_MSG_ERROR([wolfSSL was built with $1 defined; wolfCert needs $2.
      Rebuild wolfSSL without --disable-$(echo $2 | tr 'A-Z' 'a-z').])])])

# WOLFCERT_OPT(SUBST_VAR, $cond_value, MACRO): emit a "#define MACRO 1" line for
# wolfcert/options.h when $cond_value is "yes", otherwise a disabled comment,
# then AC_SUBST it. (@%:@ is the m4 quadrigraph for '#'.)
AC_DEFUN([WOLFCERT_OPT],
[AS_IF([test "x$2" = "xyes"],
   [$1="@%:@define $3 1"],
   [$1="/* $3 not enabled */"])
 AC_SUBST([$1])])

save_CPPFLAGS="$CPPFLAGS"
CPPFLAGS="$CPPFLAGS $WOLFSSL_CFLAGS"
AC_CHECK_DECLS([HAVE_PKCS7, WOLFSSL_CERT_GEN, WOLFSSL_CERT_REQ, WOLFSSL_CERT_EXT,
                WOLFSSL_KEY_GEN, WOLF_CRYPTO_CB, WOLFSSL_BASE64_ENCODE,
                OPENSSL_EXTRA, WOLFSSL_ALT_NAMES, WOLFSSL_CERT_NAME_ALL],
    [], [AC_MSG_ERROR([wolfSSL is missing a required feature (see above).
      Rebuild wolfSSL with --enable-pkcs7 --enable-ecc --enable-cryptocb
      --enable-certgen --enable-certreq --enable-certext --enable-keygen
      --enable-base64encode --enable-opensslextra
      CPPFLAGS="-DWOLFSSL_ALT_NAMES -DWOLFSSL_CERT_NAME_ALL".])],
    [[#include <wolfssl/options.h>]])

# wolfSSL default-on features that wolfCert requires unconditionally: AES,
# SHA-256. Each must NOT be marked disabled by a NO_* macro.
WOLFCERT_REJECT_NEG([NO_AES],          [AES])
WOLFCERT_REJECT_NEG([NO_SHA256],       [SHA-256])

# RSA: default-on in wolfSSL. Required by SCEP (RSA-only per RFC 8894), but
# optional for an EST-only build (ECC / Ed25519 / Ed448 / ML-DSA).
# WOLFCERT_HAVE_RSA gates the RSA key algorithm.
AC_MSG_CHECKING([whether wolfSSL provides RSA])
AC_COMPILE_IFELSE(
  [AC_LANG_PROGRAM([[#include <wolfssl/options.h>]],
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

# TLS: the HTTPS transport needs at least TLS 1.2 or TLS 1.3; the endpoints pin
# their floor to whichever lower version is available.
AC_MSG_CHECKING([whether wolfSSL provides TLS 1.2])
AC_COMPILE_IFELSE(
  [AC_LANG_PROGRAM([[#include <wolfssl/options.h>]],
   [[#ifdef WOLFSSL_NO_TLS12
     #error notls12
     #endif]])],
  [AC_MSG_RESULT([yes]); have_tls12=yes], [AC_MSG_RESULT([no]); have_tls12=no])
AC_MSG_CHECKING([whether wolfSSL provides TLS 1.3])
AC_COMPILE_IFELSE(
  [AC_LANG_PROGRAM([[#include <wolfssl/options.h>]],
   [[#ifndef WOLFSSL_TLS13
     #error notls13
     #endif]])],
  [AC_MSG_RESULT([yes]); have_tls13=yes], [AC_MSG_RESULT([no]); have_tls13=no])
AS_IF([test "x$have_tls12" = "xno" && test "x$have_tls13" = "xno"],
  [AC_MSG_ERROR([wolfSSL provides neither TLS 1.2 nor TLS 1.3; wolfCert needs
    at least one for its HTTPS transport.])])

# Optional key algorithms: ECC / Ed25519 / Ed448 / ML-DSA. Absent => warn.
# (RSA is handled above.) Recorded as shell vars for wolfcert/options.h.
AC_CHECK_DECL([HAVE_ECC], [have_ecc=yes],
    [have_ecc=no; AC_MSG_WARN([wolfSSL was built without HAVE_ECC; ECC key
      types will return WOLFCERT_ERR_UNSUPPORTED. Rebuild with --enable-ecc.])],
    [[#include <wolfssl/options.h>]])
AC_CHECK_DECL([HAVE_ED25519], [have_ed25519=yes],
    [have_ed25519=no; AC_MSG_WARN([wolfSSL was built without HAVE_ED25519;
      Ed25519 key types will return WOLFCERT_ERR_UNSUPPORTED. Rebuild with
      --enable-ed25519.])],
    [[#include <wolfssl/options.h>]])
AC_CHECK_DECL([HAVE_ED448], [have_ed448=yes],
    [have_ed448=no; AC_MSG_WARN([wolfSSL was built without HAVE_ED448; Ed448
      key types will return WOLFCERT_ERR_UNSUPPORTED. Rebuild with
      --enable-ed448.])],
    [[#include <wolfssl/options.h>]])
AC_CHECK_DECL([WOLFSSL_HAVE_MLDSA], [have_mldsa=yes],
    [have_mldsa=no; AC_MSG_WARN([wolfSSL was built without WOLFSSL_HAVE_MLDSA;
      mldsa:44/65/87 will return WOLFCERT_ERR_UNSUPPORTED. Rebuild with
      --enable-mldsa.])],
    [[#include <wolfssl/options.h>]])
CPPFLAGS="$save_CPPFLAGS"

# Require at least one key algorithm.
AS_IF([test "x$have_rsa" = "xno" && test "x$have_ecc" = "xno" \
    && test "x$have_ed25519" = "xno" && test "x$have_ed448" = "xno" \
    && test "x$have_mldsa" = "xno"],
  [AC_MSG_ERROR([wolfSSL provides none of RSA/ECC/Ed25519/Ed448/ML-DSA;
    wolfCert needs at least one key algorithm.])])

# Render the wolfcert/options.h lines from the resolved feature set.
WOLFCERT_OPT([WOLFCERT_OPT_EST],     [$enable_est],    [WOLFCERT_HAVE_EST])
WOLFCERT_OPT([WOLFCERT_OPT_SCEP],    [$enable_scep],   [WOLFCERT_HAVE_SCEP])
WOLFCERT_OPT([WOLFCERT_OPT_SERVER],  [$enable_server], [WOLFCERT_HAVE_SERVER])
WOLFCERT_OPT([WOLFCERT_OPT_POSIX_STORE], [$enable_posix_store],
             [WOLFCERT_HAVE_POSIX_STORE])
WOLFCERT_OPT([WOLFCERT_OPT_RSA],     [$have_rsa],      [WOLFCERT_HAVE_RSA])
WOLFCERT_OPT([WOLFCERT_OPT_ECC],     [$have_ecc],      [WOLFCERT_HAVE_ECC])
WOLFCERT_OPT([WOLFCERT_OPT_ED25519], [$have_ed25519],  [WOLFCERT_HAVE_ED25519])
WOLFCERT_OPT([WOLFCERT_OPT_ED448],   [$have_ed448],    [WOLFCERT_HAVE_ED448])
WOLFCERT_OPT([WOLFCERT_OPT_MLDSA],   [$have_mldsa],    [WOLFCERT_HAVE_MLDSA])

# Resolve the install paths to absolutes so the generated CMake targets file
# can point find_library / include dirs at the real install tree (autoconf
# leaves $prefix as NONE and $libdir as ${exec_prefix}/lib until evaluated).
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
# Under --enable-user-settings the integrator supplies user_settings.h, so we
# neither generate nor ship wolfcert/options.h.
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
    POSIX store   : $enable_posix_store
    User settings : $enable_user_settings
    CLI tools     : $enable_cli
    Tests         : $enable_tests
    Examples      : $enable_examples
    CMake config   : $enable_cmake_install
    Debug build   : $enable_debug
    wolfSSL       : $have_wolfssl$wolfssl_origin
  ----------------------------------------
])
