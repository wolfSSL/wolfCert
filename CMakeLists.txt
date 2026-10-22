# SPDX-License-Identifier: GPL-3.0-or-later
cmake_minimum_required(VERSION 3.16)

project(wolfCert
    VERSION 0.1.0
    DESCRIPTION "Certificate lifecycle management library built on wolfSSL"
    LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# Default to RelWithDebInfo, matching autoconf's -O2 -g.
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
option(WOLFCERT_ENABLE_BUILTIN_TRANSPORT
    "Build the built-in POSIX socket transport" ON)
option(WOLFCERT_WERROR         "Treat warnings as errors"               OFF)
# The EST/SCEP/SERVER options still pick the sources under user settings, so
# they must match the macros in user_settings.h.
option(WOLFCERT_USER_SETTINGS  "Take feature config from a user-supplied user_settings.h instead of the generated options.h" OFF)
set(WOLFCERT_USER_SETTINGS_DIR "" CACHE PATH
    "Directory containing user_settings.h (used when WOLFCERT_USER_SETTINGS=ON)")

if(NOT WOLFCERT_ENABLE_BUILTIN_TRANSPORT)
    if(WOLFCERT_ENABLE_CLI)
        message(FATAL_ERROR "WOLFCERT_ENABLE_CLI needs "
            "WOLFCERT_ENABLE_BUILTIN_TRANSPORT: the CLI cannot supply a "
            "custom transport")
    endif()
    if(WOLFCERT_ENABLE_SERVER)
        message(FATAL_ERROR "WOLFCERT_ENABLE_SERVER needs "
            "WOLFCERT_ENABLE_BUILTIN_TRANSPORT: its round-trip tests drive "
            "the client over real sockets")
    endif()
endif()
# wolfSSL
# -DWITH_WOLFSSL=PATH: wolfSSL install prefix for find_package and pkg-config.
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
# The package config records only MAJOR.MINOR, so the floor is probed below.
find_package(wolfssl CONFIG QUIET)
if(NOT wolfssl_FOUND)
    find_package(PkgConfig QUIET)
    if(PkgConfig_FOUND)
        pkg_check_modules(WOLFSSL IMPORTED_TARGET "wolfssl>=5.9.4")
    endif()
    if(NOT WOLFSSL_FOUND)
        message(FATAL_ERROR
            "wolfSSL >= 5.9.4 not found via CMake config or pkg-config. "
            "wolfCert requires wolfSSL 5.9.4 or newer, built with: HAVE_PKCS7, "
            "WOLFSSL_CERT_GEN, WOLFSSL_CERT_REQ, WOLFSSL_CERT_EXT, "
            "WOLFSSL_KEY_GEN, HAVE_ECC, WOLF_CRYPTO_CB, WOLFSSL_BASE64_ENCODE, "
            "WOLFSSL_ALT_NAMES, WOLFSSL_CERT_NAME_ALL; a shared wolfSSL also "
            "needs WOLFSSL_PUBLIC_ASN.")
    endif()
endif()

# Verify the wolfSSL build enables every feature wolfCert relies on.
include(CheckCSourceCompiles)
if(TARGET PkgConfig::WOLFSSL)
    get_target_property(_wolfssl_cflags PkgConfig::WOLFSSL INTERFACE_INCLUDE_DIRECTORIES)
elseif(TARGET wolfssl::wolfssl)
    get_target_property(_wolfssl_cflags wolfssl::wolfssl INTERFACE_INCLUDE_DIRECTORIES)
endif()
# Probe wolfSSL's feature set the way wolfcert/check_config.h resolves it, so
# configure and the headers agree.
set(_wc_wolfssl_prologue "
#if !defined(WOLFSSL_USER_SETTINGS) && !defined(WOLFSSL_USE_OPTIONS_H) && !defined(WOLFSSL_NO_OPTIONS_H) && !defined(WOLFSSL_CUSTOM_CONFIG) && !defined(ARDUINO) && !defined(PLATFORMIO) && !defined(USE_HAL_DRIVER) && !defined(NUCLEUS_PLUS_2_3) && !defined(WOLFSSL_MX2_CONF_INCLUDE)
#define WOLFSSL_USE_OPTIONS_H
#endif
#include <wolfssl/wolfcrypt/settings.h>
")

set(CMAKE_REQUIRED_INCLUDES ${_wolfssl_cflags})
unset(_have_wolfssl_floor CACHE)
check_c_source_compiles("${_wc_wolfssl_prologue}
    #include <wolfssl/version.h>
    #if LIBWOLFSSL_VERSION_HEX < 0x05009004
    #error too old
    #endif
    int main(void) { return 0; }
" _have_wolfssl_floor)
if(NOT _have_wolfssl_floor)
    message(FATAL_ERROR "wolfCert requires wolfSSL 5.9.4 or newer.")
endif()
foreach(sym IN ITEMS HAVE_PKCS7 WOLFSSL_CERT_GEN WOLFSSL_CERT_REQ WOLFSSL_CERT_EXT
                     WOLFSSL_KEY_GEN WOLF_CRYPTO_CB WOLFSSL_BASE64_ENCODE
                     WOLFSSL_ALT_NAMES WOLFSSL_CERT_NAME_ALL)
    unset(_have_${sym} CACHE)
    check_c_source_compiles("${_wc_wolfssl_prologue}
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
            "--enable-base64encode "
            "CPPFLAGS=\"-DWOLFSSL_ALT_NAMES -DWOLFSSL_CERT_NAME_ALL\"")
    endif()
endforeach()

# Link the WOLFSSL_ASN_API helpers wolfCert calls, without wolfSSL's headers.
if(TARGET PkgConfig::WOLFSSL)
    set(CMAKE_REQUIRED_LIBRARIES PkgConfig::WOLFSSL)
else()
    set(CMAKE_REQUIRED_LIBRARIES wolfssl::wolfssl)
endif()
unset(_have_asn_helpers CACHE)
check_c_source_compiles("
    extern char FreeAltNames(void);
    extern char wc_SetDNSEntry(void);
    extern char wc_SetAltNamesFromList(void);
    extern char SetLength(void);
    extern char GetASNTag(void);
    extern char GetLength(void);
    int main(void)
    {
        return FreeAltNames() + wc_SetDNSEntry() + wc_SetAltNamesFromList() +
            SetLength() + GetASNTag() + GetLength();
    }
" _have_asn_helpers)
unset(CMAKE_REQUIRED_LIBRARIES)
if(NOT _have_asn_helpers)
    message(FATAL_ERROR
        "wolfSSL does not export its ASN helpers (wc_SetDNSEntry, "
        "wc_SetAltNamesFromList, FreeAltNames, SetLength, GetASNTag, "
        "GetLength). Rebuild wolfSSL with CPPFLAGS=\"-DWOLFSSL_PUBLIC_ASN\".")
endif()

# Default-on wolfSSL features wolfCert requires.
foreach(entry IN ITEMS "NO_AES;AES;--enable-aes"
                       "NO_SHA256;SHA-256;--enable-sha256")
    list(GET entry 0 _neg)
    list(GET entry 1 _name)
    list(GET entry 2 _flag)
    unset(_off_${_neg} CACHE)
    check_c_source_compiles("${_wc_wolfssl_prologue}
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

# RSA is required by SCEP (RFC 8894) and optional for an EST-only build.
unset(_off_NO_RSA CACHE)
check_c_source_compiles("${_wc_wolfssl_prologue}
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

# AES-128-CBC: mandatory-to-implement for SCEP (RFC 8894 section 2.9).
if(WOLFCERT_ENABLE_SCEP)
    unset(_have_aes128cbc CACHE)
    check_c_source_compiles("${_wc_wolfssl_prologue}
        #if !defined(WOLFSSL_AES_128) || !defined(HAVE_AES_CBC) || !defined(HAVE_AES_DECRYPT)
        #error noaes128cbc
        #endif
        int main(void) { return 0; }
    " _have_aes128cbc)
    if(NOT _have_aes128cbc)
        message(FATAL_ERROR
            "wolfCert SCEP requires AES-128-CBC (RFC 8894). Rebuild wolfSSL "
            "without NO_AES_128, NO_AES_CBC or NO_AES_DECRYPT, or set "
            "-DWOLFCERT_ENABLE_SCEP=OFF for an EST-only build.")
    endif()
endif()

# The HTTPS transport needs TLS 1.2 or TLS 1.3.
unset(_have_tls12 CACHE)
check_c_source_compiles("${_wc_wolfssl_prologue}
    #ifdef WOLFSSL_NO_TLS12
    #error notls12
    #endif
    int main(void) { return 0; }
" _have_tls12)
unset(_have_tls13 CACHE)
check_c_source_compiles("${_wc_wolfssl_prologue}
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

# Optional key algorithms.
foreach(entry IN ITEMS "HAVE_ECC;ECC;--enable-ecc"
                       "HAVE_ED25519;ED25519;--enable-ed25519"
                       "HAVE_ED448;ED448;--enable-ed448"
                       "WOLFSSL_HAVE_MLDSA;MLDSA;--enable-mldsa")
    list(GET entry 0 _sym)
    list(GET entry 1 _short)
    list(GET entry 2 _flag)
    unset(_have_${_sym} CACHE)
    check_c_source_compiles("${_wc_wolfssl_prologue}
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

# Normalize the probe results to ON/OFF and require one key algorithm.
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

# Generate wolfcert/options.h
if(NOT WOLFCERT_USER_SETTINGS)
    macro(_wc_opt out flag sym)
        if(${flag})
            set(${out} "#define ${sym} 1")
        else()
            set(${out} "/* ${sym} not enabled */")
        endif()
    endmacro()
    # Platform gates always define a macro: have_sym enabled, no_sym disabled.
    macro(_wc_plat out flag have_sym no_sym)
        if(${flag})
            set(${out} "#define ${have_sym} 1")
        else()
            set(${out} "#define ${no_sym} 1")
        endif()
    endmacro()
    _wc_opt(WOLFCERT_OPT_EST     "${WOLFCERT_ENABLE_EST}"    WOLFCERT_HAVE_EST)
    _wc_opt(WOLFCERT_OPT_SCEP    "${WOLFCERT_ENABLE_SCEP}"   WOLFCERT_HAVE_SCEP)
    _wc_opt(WOLFCERT_OPT_SERVER  "${WOLFCERT_ENABLE_SERVER}" WOLFCERT_HAVE_SERVER)
    _wc_plat(WOLFCERT_OPT_POSIX_STORE "${WOLFCERT_ENABLE_POSIX_STORE}"
             WOLFCERT_HAVE_POSIX_STORE WOLFCERT_NO_POSIX_STORE)
    _wc_plat(WOLFCERT_OPT_BUILTIN_TRANSPORT
             "${WOLFCERT_ENABLE_BUILTIN_TRANSPORT}"
             WOLFCERT_HAVE_BUILTIN_TRANSPORT WOLFCERT_NO_BUILTIN_TRANSPORT)
    _wc_opt(WOLFCERT_OPT_RSA     "${WOLFCERT_HAVE_RSA}"      WOLFCERT_HAVE_RSA)
    _wc_opt(WOLFCERT_OPT_ECC     "${WOLFCERT_HAVE_ECC}"      WOLFCERT_HAVE_ECC)
    _wc_opt(WOLFCERT_OPT_ED25519 "${WOLFCERT_HAVE_ED25519}"  WOLFCERT_HAVE_ED25519)
    _wc_opt(WOLFCERT_OPT_ED448   "${WOLFCERT_HAVE_ED448}"    WOLFCERT_HAVE_ED448)
    _wc_opt(WOLFCERT_OPT_MLDSA   "${WOLFCERT_HAVE_MLDSA}"    WOLFCERT_HAVE_MLDSA)
    configure_file("${CMAKE_CURRENT_SOURCE_DIR}/wolfcert/options.h.in"
                   "${CMAKE_CURRENT_BINARY_DIR}/wolfcert/options.h" @ONLY)
endif()

# Library sources
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
    src/client.c)

if(WOLFCERT_ENABLE_BUILTIN_TRANSPORT)
    list(APPEND WOLFCERT_SOURCES src/net_posix.c)
endif()

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

# WOLFCERT_HAVE_* come from options.h or user_settings.h, never from -D.
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

# CLIs
if(WOLFCERT_ENABLE_CLI)
    add_executable(wolfcert-client cli/wolfcert_client.c)
    target_link_libraries(wolfcert-client PRIVATE wolfcert)

    if(WOLFCERT_ENABLE_SERVER)
        add_executable(wolfcert-server cli/wolfcert_server.c)
        target_link_libraries(wolfcert-server PRIVATE wolfcert)
    endif()
endif()

# Tests / examples
if(WOLFCERT_ENABLE_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
if(WOLFCERT_ENABLE_EXAMPLES)
    add_subdirectory(examples)
endif()

# Install
install(TARGETS wolfcert
    EXPORT  wolfCertTargets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
# Install only the public headers (skips options.h.in and any non-header file).
install(DIRECTORY wolfcert DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
        FILES_MATCHING PATTERN "*.h")
# The generated options.h lives in the build tree.
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

# SBOM: the wolfcert-sbom target, also named sbom when wolfCert is top level.
set(WOLFCERT_SBOM_LICENSE "" CACHE STRING
    "SPDX license expression recorded in the SBOM (default: from LICENSING)")
set(WOLFCERT_SBOM_LICENSE_TEXT "" CACHE FILEPATH
    "License text for a LicenseRef-* in WOLFCERT_SBOM_LICENSE")
set(WOLFCERT_SBOM_WOLFSSL_VERSION "" CACHE STRING
    "wolfSSL version recorded in the SBOM (default: from wolfssl/version.h)")
find_program(WOLFCERT_PYTHON3 python3)
find_program(WOLFCERT_PYSPDXTOOLS pyspdxtools)

# The wolfSSL version of the headers this build compiles against.
set(_wc_wolfssl_version "${WOLFCERT_SBOM_WOLFSSL_VERSION}")
if(NOT _wc_wolfssl_version)
    if(TARGET wolfssl::wolfssl)
        set(_wc_wolfssl_target wolfssl::wolfssl)
    else()
        set(_wc_wolfssl_target PkgConfig::WOLFSSL)
    endif()
    set(_wc_vdir "${CMAKE_CURRENT_BINARY_DIR}/CMakeFiles/wolfssl-version")
    file(WRITE "${_wc_vdir}/version.c" "#include <wolfssl/version.h>\n"
        "const char wc_ver[] = \"WCVER:\" LIBWOLFSSL_VERSION_STRING;\n")
    set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)
    try_compile(_wc_ok "${_wc_vdir}" SOURCES "${_wc_vdir}/version.c"
        LINK_LIBRARIES ${_wc_wolfssl_target}
        COPY_FILE "${_wc_vdir}/version.a")
    unset(CMAKE_TRY_COMPILE_TARGET_TYPE)
    if(_wc_ok)
        file(STRINGS "${_wc_vdir}/version.a" _line REGEX "WCVER:")
        if(_line MATCHES "WCVER:([0-9A-Za-z.+-]+)")
            set(_wc_wolfssl_version "${CMAKE_MATCH_1}")
        endif()
    endif()
endif()

if(WIN32 AND NOT (MINGW OR MSYS))
    set(_wc_sbom_error "needs a POSIX shell, use MSYS2, Cygwin or WSL")
elseif(NOT WOLFCERT_PYTHON3)
    set(_wc_sbom_error "python3 not found")
elseif(NOT WOLFCERT_PYSPDXTOOLS)
    set(_wc_sbom_error "pyspdxtools not found (pip install spdx-tools)")
elseif(WOLFCERT_USER_SETTINGS AND
       (MSVC OR NOT CMAKE_C_COMPILER_ID MATCHES "GNU|Clang"))
    set(_wc_sbom_error "reading user_settings.h needs GCC or Clang")
elseif(NOT _wc_wolfssl_version)
    string(CONCAT _wc_sbom_error "cannot read the wolfSSL version from "
           "wolfssl/version.h, set WOLFCERT_SBOM_WOLFSSL_VERSION")
else()
    set(_wc_sbom_error "")
endif()

if(NOT _wc_sbom_error STREQUAL "")
    add_custom_target(wolfcert-sbom
        COMMAND ${CMAKE_COMMAND} -E echo "sbom: ${_wc_sbom_error}"
        COMMAND ${CMAKE_COMMAND} -E false
        VERBATIM)
else()
    include(${CMAKE_CURRENT_SOURCE_DIR}/tools/sbom/build/sbom.cmake)

    if(WOLFCERT_USER_SETTINGS)
        set(_wc_sbom_opts "${CMAKE_CURRENT_BINARY_DIR}/sbom-options.h")
        separate_arguments(_wc_sbom_cflags UNIX_COMMAND
            "${CMAKE_C_COMPILER_ARG1} ${CMAKE_C_FLAGS}")
        if(CMAKE_C_EXTENSIONS OR NOT DEFINED CMAKE_C_EXTENSIONS)
            set(_wc_std "CMAKE_C${CMAKE_C_STANDARD}_EXTENSION_COMPILE_OPTION")
        else()
            set(_wc_std "CMAKE_C${CMAKE_C_STANDARD}_STANDARD_COMPILE_OPTION")
        endif()
        list(APPEND _wc_sbom_cflags ${${_wc_std}})
        foreach(_cfg IN LISTS CMAKE_CONFIGURATION_TYPES CMAKE_BUILD_TYPE)
            string(TOUPPER "${_cfg}" _ucfg)
            separate_arguments(_f UNIX_COMMAND "${CMAKE_C_FLAGS_${_ucfg}}")
            if(_f)
                string(REPLACE ";" "$<SEMICOLON>" _f "${_f}")
                list(APPEND _wc_sbom_cflags "$<$<CONFIG:${_cfg}>:${_f}>")
            endif()
        endforeach()
        if(CMAKE_C_COMPILER_TARGET AND CMAKE_C_COMPILE_OPTIONS_TARGET)
            list(APPEND _wc_sbom_cflags
                "${CMAKE_C_COMPILE_OPTIONS_TARGET}${CMAKE_C_COMPILER_TARGET}")
        endif()
        if(CMAKE_SYSROOT AND CMAKE_C_COMPILE_OPTIONS_SYSROOT)
            list(APPEND _wc_sbom_cflags
                "${CMAKE_C_COMPILE_OPTIONS_SYSROOT}${CMAKE_SYSROOT}")
        endif()
        set(_wc_defs "$<TARGET_PROPERTY:wolfcert,COMPILE_DEFINITIONS>")
        set(_wc_incs "$<TARGET_PROPERTY:wolfcert,INCLUDE_DIRECTORIES>")
        add_custom_target(wolfcert-sbom-options
            COMMAND ${WOLFCERT_PYTHON3}
                "${CMAKE_CURRENT_SOURCE_DIR}/scripts/sbom-user-settings.py"
                "${_wc_sbom_opts}" ${CMAKE_C_COMPILER} ${_wc_sbom_cflags}
                "$<TARGET_PROPERTY:wolfcert,COMPILE_OPTIONS>"
                "$<$<BOOL:${_wc_defs}>:-D$<JOIN:${_wc_defs},;-D>>"
                "$<$<BOOL:${_wc_incs}>:-I$<JOIN:${_wc_incs},;-I>>"
            COMMAND_EXPAND_LISTS VERBATIM)
    else()
        set(_wc_sbom_opts "${CMAKE_CURRENT_BINARY_DIR}/wolfcert/options.h")
    endif()

    set(_wc_sbom_out "${CMAKE_CURRENT_BINARY_DIR}/wolfcert-${PROJECT_VERSION}")
    set(_wc_sbom_stage "${CMAKE_CURRENT_BINARY_DIR}/_sbom_staging")
    if((WIN32 OR CYGWIN) AND WOLFCERT_BUILD_SHARED)
        set(_wc_dir BINDIR)
    else()
        set(_wc_dir LIBDIR)
    endif()
    set(_wc_rel "${CMAKE_INSTALL_${_wc_dir}}")
    if(CMAKE_STAGING_PREFIX AND NOT IS_ABSOLUTE "${_wc_rel}")
        set(_wc_sbom_libdir "${CMAKE_STAGING_PREFIX}/${_wc_rel}")
    else()
        set(_wc_sbom_libdir "${CMAKE_INSTALL_FULL_${_wc_dir}}")
    endif()
    # DESTDIR drops the drive letter of a Windows install path.
    string(REGEX REPLACE "^[A-Za-z]:" "" _wc_sbom_libdir "${_wc_sbom_libdir}")
    set(_wc_sbom_lib
        "${_wc_sbom_stage}${_wc_sbom_libdir}/$<TARGET_FILE_NAME:wolfcert>")
    if(CMAKE_INSTALL_DEFAULT_COMPONENT_NAME)
        set(_wc_sbom_component "${CMAKE_INSTALL_DEFAULT_COMPONENT_NAME}")
    else()
        set(_wc_sbom_component Unspecified)
    endif()
    set(_wc_sbom_args
        NAME wolfcert
        VERSION ${PROJECT_VERSION}
        LIB "${_wc_sbom_lib}"
        OPTIONS_H "${_wc_sbom_opts}"
        LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSING"
        DEP_WOLFSSL yes
        DEP_VERSION "wolfssl=${_wc_wolfssl_version}"
        CDX_OUT "${_wc_sbom_out}.cdx.json"
        SPDX_OUT "${_wc_sbom_out}.spdx.json"
        TARGET_NAME wolfcert-sbom-gen)
    if(WOLFCERT_SBOM_LICENSE)
        list(APPEND _wc_sbom_args LICENSE_OVERRIDE "${WOLFCERT_SBOM_LICENSE}")
    endif()
    if(WOLFCERT_SBOM_LICENSE_TEXT)
        list(APPEND _wc_sbom_args LICENSE_TEXT "${WOLFCERT_SBOM_LICENSE_TEXT}")
    endif()
    wolfssl_compliance_tooling_add_sbom(${_wc_sbom_args})

    # Hash the library as installed; installing rewrites its RPATH.
    add_custom_target(wolfcert-sbom-stage
        COMMAND ${CMAKE_COMMAND} -E remove_directory "${_wc_sbom_stage}"
        COMMAND ${CMAKE_COMMAND} -E env "DESTDIR=${_wc_sbom_stage}"
                ${CMAKE_COMMAND} --install "${CMAKE_CURRENT_BINARY_DIR}"
                --config $<CONFIG> --component ${_wc_sbom_component}
        VERBATIM)
    foreach(_t IN ITEMS wolfcert wolfcert-client wolfcert-server)
        if(TARGET ${_t})
            add_dependencies(wolfcert-sbom-stage ${_t})
        endif()
    endforeach()
    add_dependencies(wolfcert-sbom-gen wolfcert-sbom-stage)
    if(WOLFCERT_USER_SETTINGS)
        add_dependencies(wolfcert-sbom-gen wolfcert-sbom-options)
    endif()

    add_custom_target(wolfcert-sbom
        COMMAND ${WOLFCERT_PYSPDXTOOLS} --infile "${_wc_sbom_out}.spdx.json"
                --outfile "${_wc_sbom_out}.spdx"
        COMMAND ${CMAKE_COMMAND} -E remove_directory "${_wc_sbom_stage}"
        VERBATIM)
    add_dependencies(wolfcert-sbom wolfcert-sbom-gen)
endif()
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    add_custom_target(sbom)
    add_dependencies(sbom wolfcert-sbom)
endif()

message(STATUS "wolfCert ${PROJECT_VERSION}: EST=${WOLFCERT_ENABLE_EST}, "
    "SCEP=${WOLFCERT_ENABLE_SCEP}, server=${WOLFCERT_ENABLE_SERVER}, "
    "cli=${WOLFCERT_ENABLE_CLI}, posix_store=${WOLFCERT_ENABLE_POSIX_STORE}, "
    "builtin_transport=${WOLFCERT_ENABLE_BUILTIN_TRANSPORT}, "
    "user_settings=${WOLFCERT_USER_SETTINGS}")
