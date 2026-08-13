# SPDX-License-Identifier: GPL-3.0-or-later
cmake_minimum_required(VERSION 3.16)

project(wolfCert
    VERSION 0.1.0
    DESCRIPTION "Certificate lifecycle management library built on wolfSSL"
    LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# Default to RelWithDebInfo (-O2 -g) when the caller gives no build type, so a
# bare `cmake -S . -B build` produces an optimized-with-symbols library instead
# of the compiler default (-O0, no symbols). This matches the autoconf path,
# whose non-debug default is likewise -O2 -g -DNDEBUG. Skipped for multi-config
# generators (Xcode, Visual Studio, Ninja Multi-Config), which pick the config
# at build time rather than configure time. For an unoptimized debug build use
# -DCMAKE_BUILD_TYPE=Debug (the analogue of autoconf's --enable-debug).
get_property(_wolfcert_multi_config GLOBAL PROPERTY GENERATOR_IS_MULTI_CONFIG)
if(NOT _wolfcert_multi_config AND NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING
        "Build type (Debug, Release, RelWithDebInfo, MinSizeRel)" FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS
        Debug Release RelWithDebInfo MinSizeRel)
    message(STATUS "No CMAKE_BUILD_TYPE set; defaulting to RelWithDebInfo")
endif()

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

option(WOLFCERT_BUILD_SHARED   "Build wolfCert as a shared library"     ON)
option(WOLFCERT_ENABLE_EST     "Enable EST (RFC 7030) support"          ON)
option(WOLFCERT_ENABLE_SCEP    "Enable SCEP (RFC 8894) support"         ON)
option(WOLFCERT_ENABLE_SERVER  "Build the minimal EST/SCEP test server" ON)
option(WOLFCERT_ENABLE_CLI     "Build wolfcert-client / wolfcert-server" ON)
option(WOLFCERT_ENABLE_TESTS   "Build unit and integration tests"       OFF)
option(WOLFCERT_ENABLE_EXAMPLES "Build example programs"                OFF)
option(WOLFCERT_ENABLE_POSIX_STORE "Build the POSIX file storage backend" ON)
option(WOLFCERT_WERROR         "Treat warnings as errors"               OFF)
# Header-based configuration (the user_settings.h analogue of wolfSSL's
# WOLFSSL_USER_SETTINGS). When ON, wolfCert does not generate or install
# wolfcert/options.h; instead it compiles with -DWOLFCERT_USER_SETTINGS and the
# integrator supplies a user_settings.h on the include path (see
# WOLFCERT_USER_SETTINGS_DIR and examples/user_settings.h.example). The
# WOLFCERT_ENABLE_EST/SCEP/SERVER options still select which source files
# compile, so keep them in sync with the macros in your user_settings.h.
option(WOLFCERT_USER_SETTINGS  "Take feature config from a user-supplied user_settings.h instead of the generated options.h" OFF)
set(WOLFCERT_USER_SETTINGS_DIR "" CACHE PATH
    "Directory containing user_settings.h (used when WOLFCERT_USER_SETTINGS=ON)")
# ----- wolfSSL ---------------------------------------------------------------
# Optional convenience: -DWITH_WOLFSSL=PATH points at a wolfSSL install
# prefix. Adds it to CMAKE_PREFIX_PATH (for find_package CONFIG mode) and
# prepends PATH/lib/pkgconfig to PKG_CONFIG_PATH (for the pkg-config fallback).
set(WITH_WOLFSSL "" CACHE PATH "Path to a wolfSSL install prefix")
if(WITH_WOLFSSL)
    if(NOT IS_DIRECTORY "${WITH_WOLFSSL}")
        message(FATAL_ERROR "WITH_WOLFSSL=${WITH_WOLFSSL} is not a directory")
    endif()
    list(PREPEND CMAKE_PREFIX_PATH "${WITH_WOLFSSL}")
    if(EXISTS "${WITH_WOLFSSL}/lib/pkgconfig/wolfssl.pc")
        if(DEFINED ENV{PKG_CONFIG_PATH} AND NOT "$ENV{PKG_CONFIG_PATH}" STREQUAL "")
            set(ENV{PKG_CONFIG_PATH} "${WITH_WOLFSSL}/lib/pkgconfig:$ENV{PKG_CONFIG_PATH}")
        else()
            set(ENV{PKG_CONFIG_PATH} "${WITH_WOLFSSL}/lib/pkgconfig")
        endif()
    endif()
    message(STATUS "wolfCert: using wolfSSL from ${WITH_WOLFSSL}")
endif()

# Prefer a CMake package config (newer wolfSSL), fall back to pkg-config.
find_package(wolfssl CONFIG QUIET)
if(NOT wolfssl_FOUND)
    find_package(PkgConfig QUIET)
    if(PkgConfig_FOUND)
        pkg_check_modules(WOLFSSL IMPORTED_TARGET wolfssl)
    endif()
    if(NOT WOLFSSL_FOUND)
        message(FATAL_ERROR
            "wolfSSL not found via CMake config or pkg-config. wolfCert "
            "requires wolfSSL 5.9.2 or newer, built with: HAVE_PKCS7, "
            "WOLFSSL_CERT_GEN, WOLFSSL_CERT_REQ, WOLFSSL_CERT_EXT, "
            "WOLFSSL_KEY_GEN, HAVE_ECC, WOLF_CRYPTO_CB, WOLFSSL_BASE64_ENCODE, "
            "OPENSSL_EXTRA, WOLFSSL_ALT_NAMES, WOLFSSL_CERT_NAME_ALL.")
    endif()
endif()

# Verify the wolfSSL build enables every feature wolfCert relies on.
include(CheckCSourceCompiles)
if(TARGET PkgConfig::WOLFSSL)
    get_target_property(_wolfssl_cflags PkgConfig::WOLFSSL INTERFACE_INCLUDE_DIRECTORIES)
elseif(TARGET wolfssl::wolfssl)
    get_target_property(_wolfssl_cflags wolfssl::wolfssl INTERFACE_INCLUDE_DIRECTORIES)
endif()
set(CMAKE_REQUIRED_INCLUDES ${_wolfssl_cflags})
foreach(sym IN ITEMS HAVE_PKCS7 WOLFSSL_CERT_GEN WOLFSSL_CERT_REQ WOLFSSL_CERT_EXT
                     WOLFSSL_KEY_GEN WOLF_CRYPTO_CB WOLFSSL_BASE64_ENCODE
                     OPENSSL_EXTRA WOLFSSL_ALT_NAMES WOLFSSL_CERT_NAME_ALL)
    unset(_have_${sym} CACHE)
    check_c_source_compiles("
        #include <wolfssl/options.h>
        #ifndef ${sym}
        #error missing
        #endif
        int main(void) { return 0; }
    " _have_${sym})
    if(NOT _have_${sym})
        message(FATAL_ERROR
            "wolfSSL was built without ${sym}. Rebuild with the appropriate "
            "wolfSSL configure flag. For all the symbols wolfCert requires: "
            "./configure --enable-pkcs7 --enable-certgen --enable-certreq "
            "--enable-certext --enable-keygen --enable-ecc --enable-cryptocb "
            "--enable-base64encode --enable-opensslextra "
            "CPPFLAGS=\"-DWOLFSSL_ALT_NAMES -DWOLFSSL_CERT_NAME_ALL\"")
    endif()
endforeach()

# Features that default-on in wolfSSL and that wolfCert depends on
# unconditionally. Detect explicit disable markers and reject.
foreach(entry IN ITEMS "NO_AES;AES;--enable-aes"
                       "NO_SHA256;SHA-256;--enable-sha256")
    list(GET entry 0 _neg)
    list(GET entry 1 _name)
    list(GET entry 2 _flag)
    unset(_off_${_neg} CACHE)
    check_c_source_compiles("
        #include <wolfssl/options.h>
        #ifdef ${_neg}
        #error disabled
        #endif
        int main(void) { return 0; }
    " _off_${_neg})
    if(NOT _off_${_neg})
        message(FATAL_ERROR
            "wolfSSL was built with ${_neg} defined; wolfCert requires "
            "${_name}. Rebuild wolfSSL with ${_flag} (i.e. do not pass "
            "--disable-<feature>).")
    endif()
endforeach()

# RSA: default-on in wolfSSL. Required by SCEP (RSA-only per RFC 8894), but
# optional for an EST-only build (ECC / Ed25519 / Ed448 / ML-DSA). The
# WOLFCERT_HAVE_RSA definition gates the RSA key algorithm.
unset(_off_NO_RSA CACHE)
check_c_source_compiles("
    #include <wolfssl/options.h>
    #ifdef NO_RSA
    #error disabled
    #endif
    int main(void) { return 0; }
" _off_NO_RSA)
if(_off_NO_RSA)
    set(WOLFCERT_HAVE_RSA ON)
elseif(WOLFCERT_ENABLE_SCEP)
    message(FATAL_ERROR
        "wolfSSL was built with NO_RSA, but wolfCert SCEP is RSA-only "
        "(RFC 8894). Rebuild wolfSSL with RSA, or set "
        "-DWOLFCERT_ENABLE_SCEP=OFF for an EST-only build.")
else()
    set(WOLFCERT_HAVE_RSA OFF)
    message(WARNING
        "wolfSSL was built with NO_RSA; wolfCert will compile without RSA and "
        "the rsa:* key type will return WOLFCERT_ERR_UNSUPPORTED.")
endif()

# TLS: the HTTPS transport needs at least TLS 1.2 or TLS 1.3; the endpoints pin
# their floor to whichever lower version is available.
unset(_have_tls12 CACHE)
check_c_source_compiles("
    #include <wolfssl/options.h>
    #ifdef WOLFSSL_NO_TLS12
    #error notls12
    #endif
    int main(void) { return 0; }
" _have_tls12)
unset(_have_tls13 CACHE)
check_c_source_compiles("
    #include <wolfssl/options.h>
    #ifndef WOLFSSL_TLS13
    #error notls13
    #endif
    int main(void) { return 0; }
" _have_tls13)
if(NOT _have_tls12 AND NOT _have_tls13)
    message(FATAL_ERROR
        "wolfSSL provides neither TLS 1.2 nor TLS 1.3; wolfCert needs at least "
        "one for its HTTPS transport.")
endif()

# Optional wolfSSL features: probed here, gating definitions applied after
# the wolfcert target is created (see below).
foreach(entry IN ITEMS "HAVE_ECC;ECC;--enable-ecc"
                       "HAVE_ED25519;ED25519;--enable-ed25519"
                       "HAVE_ED448;ED448;--enable-ed448"
                       "WOLFSSL_HAVE_MLDSA;MLDSA;--enable-mldsa")
    list(GET entry 0 _sym)
    list(GET entry 1 _short)
    list(GET entry 2 _flag)
    unset(_have_${_sym} CACHE)
    check_c_source_compiles("
        #include <wolfssl/options.h>
        #ifndef ${_sym}
        #error missing
        #endif
        int main(void) { return 0; }
    " _have_${_sym})
    if(NOT _have_${_sym})
        message(WARNING
            "wolfSSL was built without ${_sym}; wolfCert will compile without "
            "${_short} and that key type will return WOLFCERT_ERR_UNSUPPORTED. "
            "To enable, rebuild wolfSSL with ${_flag}.")
    endif()
endforeach()

# Resolve the final feature set and require at least one key algorithm.
# Normalize the raw check_c_source_compiles results to ON/OFF so every
# WOLFCERT_HAVE_* carries the same truthiness convention as WOLFCERT_HAVE_RSA.
foreach(pair IN ITEMS "WOLFCERT_HAVE_ECC;_have_HAVE_ECC"
                      "WOLFCERT_HAVE_ED25519;_have_HAVE_ED25519"
                      "WOLFCERT_HAVE_ED448;_have_HAVE_ED448"
                      "WOLFCERT_HAVE_MLDSA;_have_WOLFSSL_HAVE_MLDSA")
    list(GET pair 0 _out)
    list(GET pair 1 _src)
    if(${_src})
        set(${_out} ON)
    else()
        set(${_out} OFF)
    endif()
endforeach()
if(NOT WOLFCERT_HAVE_RSA AND NOT WOLFCERT_HAVE_ECC AND NOT WOLFCERT_HAVE_ED25519
   AND NOT WOLFCERT_HAVE_ED448 AND NOT WOLFCERT_HAVE_MLDSA)
    message(FATAL_ERROR
        "wolfSSL provides none of RSA/ECC/Ed25519/Ed448/ML-DSA; wolfCert needs "
        "at least one key algorithm.")
endif()

# ---- Generate wolfcert/options.h (replaces -D feature flags) ----------------
# Skipped under WOLFCERT_USER_SETTINGS: the integrator supplies user_settings.h
# instead, so there is no generated options.h to produce, ship, or shadow.
if(NOT WOLFCERT_USER_SETTINGS)
    macro(_wc_opt out flag sym)
        if(${flag})
            set(${out} "#define ${sym} 1")
        else()
            set(${out} "/* ${sym} not enabled */")
        endif()
    endmacro()
    _wc_opt(WOLFCERT_OPT_EST     "${WOLFCERT_ENABLE_EST}"    WOLFCERT_HAVE_EST)
    _wc_opt(WOLFCERT_OPT_SCEP    "${WOLFCERT_ENABLE_SCEP}"   WOLFCERT_HAVE_SCEP)
    _wc_opt(WOLFCERT_OPT_SERVER  "${WOLFCERT_ENABLE_SERVER}" WOLFCERT_HAVE_SERVER)
    _wc_opt(WOLFCERT_OPT_POSIX_STORE "${WOLFCERT_ENABLE_POSIX_STORE}"
            WOLFCERT_HAVE_POSIX_STORE)
    _wc_opt(WOLFCERT_OPT_RSA     "${WOLFCERT_HAVE_RSA}"      WOLFCERT_HAVE_RSA)
    _wc_opt(WOLFCERT_OPT_ECC     "${WOLFCERT_HAVE_ECC}"      WOLFCERT_HAVE_ECC)
    _wc_opt(WOLFCERT_OPT_ED25519 "${WOLFCERT_HAVE_ED25519}"  WOLFCERT_HAVE_ED25519)
    _wc_opt(WOLFCERT_OPT_ED448   "${WOLFCERT_HAVE_ED448}"    WOLFCERT_HAVE_ED448)
    _wc_opt(WOLFCERT_OPT_MLDSA   "${WOLFCERT_HAVE_MLDSA}"    WOLFCERT_HAVE_MLDSA)
    configure_file("${CMAKE_CURRENT_SOURCE_DIR}/wolfcert/options.h.in"
                   "${CMAKE_CURRENT_BINARY_DIR}/wolfcert/options.h" @ONLY)
endif()

# ----- library sources -------------------------------------------------------
set(WOLFCERT_SOURCES
    src/wolfcert.c
    src/version.c
    src/errors.c
    src/internal.c
    src/key_algs.c
    src/keygen.c
    src/csr.c
    src/store.c
    src/http.c
    src/net_posix.c
    src/client.c)

if(WOLFCERT_ENABLE_EST OR WOLFCERT_ENABLE_SCEP)
    list(APPEND WOLFCERT_SOURCES src/pkcs7_util.c)
endif()
if(WOLFCERT_ENABLE_EST)
    list(APPEND WOLFCERT_SOURCES src/est/est_client.c src/est/csr_attrs.c)
endif()
if(WOLFCERT_ENABLE_SCEP)
    list(APPEND WOLFCERT_SOURCES src/scep/scep_client.c src/scep/scep_msg.c)
endif()
if(WOLFCERT_ENABLE_SERVER)
    list(APPEND WOLFCERT_SOURCES src/server.c src/ca_issue.c)
    if(WOLFCERT_ENABLE_EST)
        list(APPEND WOLFCERT_SOURCES src/est/est_server.c)
    endif()
    if(WOLFCERT_ENABLE_SCEP)
        list(APPEND WOLFCERT_SOURCES src/scep/scep_server.c)
    endif()
endif()

if(WOLFCERT_BUILD_SHARED)
    add_library(wolfcert SHARED ${WOLFCERT_SOURCES})
else()
    add_library(wolfcert STATIC ${WOLFCERT_SOURCES})
endif()
add_library(wolfCert::wolfcert ALIAS wolfcert)

set_target_properties(wolfcert PROPERTIES
    VERSION   ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
    C_VISIBILITY_PRESET hidden)

target_include_directories(wolfcert
    PUBLIC
        # Build dir first so the freshly generated wolfcert/options.h always
        # wins over any stale in-tree copy left by an autoconf build.
        $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)

target_compile_options(wolfcert PRIVATE
    -Wall -Wextra -Wshadow -Wpedantic $<$<BOOL:${WOLFCERT_WERROR}>:-Werror>)

target_compile_definitions(wolfcert
    PRIVATE $<$<BOOL:${WOLFCERT_BUILD_SHARED}>:WOLFCERT_BUILD_DLL>
            $<$<BOOL:${WOLFCERT_ENABLE_TESTS}>:WOLFCERT_BUILD_TESTING>
    INTERFACE $<$<BOOL:${WOLFCERT_BUILD_SHARED}>:WOLFCERT_USE_DLL>
              $<$<BOOL:${WOLFCERT_ENABLE_TESTS}>:WOLFCERT_BUILD_TESTING>)

# Feature flags (WOLFCERT_HAVE_*) are not passed via -D; they live
# in the generated wolfcert/options.h, included by wolfcert/types.h - unless
# WOLFCERT_USER_SETTINGS is on, in which case types.h pulls a user-supplied
# user_settings.h and we only define the switch + add its directory.
if(WOLFCERT_USER_SETTINGS)
    target_compile_definitions(wolfcert PUBLIC WOLFCERT_USER_SETTINGS)
    if(WOLFCERT_USER_SETTINGS_DIR)
        target_include_directories(wolfcert PUBLIC
            $<BUILD_INTERFACE:${WOLFCERT_USER_SETTINGS_DIR}>)
    endif()
endif()

if(TARGET wolfssl::wolfssl)
    target_link_libraries(wolfcert PUBLIC wolfssl::wolfssl)
elseif(TARGET PkgConfig::WOLFSSL)
    target_link_libraries(wolfcert PUBLIC PkgConfig::WOLFSSL)
endif()

# ----- CLIs ------------------------------------------------------------------
if(WOLFCERT_ENABLE_CLI)
    add_executable(wolfcert-client cli/wolfcert_client.c)
    target_link_libraries(wolfcert-client PRIVATE wolfcert)

    if(WOLFCERT_ENABLE_SERVER)
        add_executable(wolfcert-server cli/wolfcert_server.c)
        target_link_libraries(wolfcert-server PRIVATE wolfcert)
    endif()
endif()

# ----- tests / examples ------------------------------------------------------
if(WOLFCERT_ENABLE_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
if(WOLFCERT_ENABLE_EXAMPLES)
    add_subdirectory(examples)
endif()

# ----- install ---------------------------------------------------------------
install(TARGETS wolfcert
    EXPORT  wolfCertTargets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
# Install only the public headers (skips options.h.in and any non-header file).
install(DIRECTORY wolfcert DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
        FILES_MATCHING PATTERN "*.h")
# The generated options.h lives in the build tree; install it alongside.
# Under WOLFCERT_USER_SETTINGS none is generated, and the integrator owns
# user_settings.h, so there is nothing to install here.
if(NOT WOLFCERT_USER_SETTINGS)
    install(FILES "${CMAKE_CURRENT_BINARY_DIR}/wolfcert/options.h"
            DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/wolfcert)
endif()

if(WOLFCERT_ENABLE_CLI)
    install(TARGETS wolfcert-client RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
    if(WOLFCERT_ENABLE_SERVER)
        install(TARGETS wolfcert-server RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
    endif()
endif()

install(EXPORT wolfCertTargets
    FILE        wolfCertTargets.cmake
    NAMESPACE   wolfCert::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/wolfCert)

write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/wolfCertConfigVersion.cmake"
    VERSION       ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion)

configure_package_config_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/wolfCertConfig.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/wolfCertConfig.cmake"
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/wolfCert)

install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/wolfCertConfig.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/wolfCertConfigVersion.cmake"
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/wolfCert)

configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/wolfcert.pc.in"
    "${CMAKE_CURRENT_BINARY_DIR}/wolfcert.pc" @ONLY)
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/wolfcert.pc"
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)

message(STATUS "wolfCert ${PROJECT_VERSION}: EST=${WOLFCERT_ENABLE_EST}, "
    "SCEP=${WOLFCERT_ENABLE_SCEP}, server=${WOLFCERT_ENABLE_SERVER}, "
    "cli=${WOLFCERT_ENABLE_CLI}, posix_store=${WOLFCERT_ENABLE_POSIX_STORE}, "
    "user_settings=${WOLFCERT_USER_SETTINGS}")
