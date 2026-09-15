# SPDX-License-Identifier: GPL-3.0-or-later

if(CONFIG_WOLFCERT)
  zephyr_interface_library_named(wolfCert)

  set(WOLFCERT_DIR ${ZEPHYR_CURRENT_MODULE_DIR})

  # ---- generated wolfcert/options.h ----------------------------------------
  # Render options.h.in from Kconfig, so wolfcert/types.h reads its config the
  # same way it does under CMake and autoconf.
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

  _wc_opt(WOLFCERT_OPT_EST     "${CONFIG_WOLFCERT_EST}"      WOLFCERT_HAVE_EST)
  _wc_opt(WOLFCERT_OPT_SCEP    "${CONFIG_WOLFCERT_SCEP}"     WOLFCERT_HAVE_SCEP)
  # Host-only; zephyr/README.md says why.
  _wc_opt(WOLFCERT_OPT_SERVER  "OFF"                         WOLFCERT_HAVE_SERVER)
  _wc_plat(WOLFCERT_OPT_POSIX_STORE "${CONFIG_WOLFCERT_POSIX_STORE}"
           WOLFCERT_HAVE_POSIX_STORE WOLFCERT_NO_POSIX_STORE)
  _wc_plat(WOLFCERT_OPT_BUILTIN_TRANSPORT "${CONFIG_WOLFCERT_BUILTIN_TRANSPORT}"
           WOLFCERT_HAVE_BUILTIN_TRANSPORT WOLFCERT_NO_BUILTIN_TRANSPORT)
  _wc_opt(WOLFCERT_OPT_RSA     "${CONFIG_WOLFCERT_RSA}"      WOLFCERT_HAVE_RSA)
  _wc_opt(WOLFCERT_OPT_ECC     "${CONFIG_WOLFCERT_ECC}"      WOLFCERT_HAVE_ECC)
  _wc_opt(WOLFCERT_OPT_ED25519 "${CONFIG_WOLFCERT_ED25519}"  WOLFCERT_HAVE_ED25519)
  _wc_opt(WOLFCERT_OPT_ED448   "${CONFIG_WOLFCERT_ED448}"    WOLFCERT_HAVE_ED448)
  _wc_opt(WOLFCERT_OPT_MLDSA   "${CONFIG_WOLFCERT_MLDSA}"    WOLFCERT_HAVE_MLDSA)

  set(WOLFCERT_GEN_DIR ${PROJECT_BINARY_DIR}/include/generated/wolfcert_gen)
  configure_file(${WOLFCERT_DIR}/wolfcert/options.h.in
                 ${WOLFCERT_GEN_DIR}/wolfcert/options.h @ONLY)

  # Generated directory first, so an in-source wolfcert/options.h left behind
  # by a host ./configure cannot shadow the one Kconfig just produced. Apps
  # inherit this order; they must not add the module root themselves.
  zephyr_include_directories(${WOLFCERT_GEN_DIR})
  zephyr_include_directories(${WOLFCERT_DIR})

  # ---- library sources ------------------------------------------------------
  zephyr_library()
  zephyr_library_sources(
    ${WOLFCERT_DIR}/src/wolfcert.c
    ${WOLFCERT_DIR}/src/version.c
    ${WOLFCERT_DIR}/src/errors.c
    ${WOLFCERT_DIR}/src/internal.c
    ${WOLFCERT_DIR}/src/key_algs.c
    ${WOLFCERT_DIR}/src/keygen.c
    ${WOLFCERT_DIR}/src/csr.c
    ${WOLFCERT_DIR}/src/store.c
    ${WOLFCERT_DIR}/src/http.c
    ${WOLFCERT_DIR}/src/client.c)

  if(CONFIG_WOLFCERT_BUILTIN_TRANSPORT)
    zephyr_library_sources(${WOLFCERT_DIR}/src/net_posix.c)
  endif()

  if(CONFIG_WOLFCERT_EST OR CONFIG_WOLFCERT_SCEP)
    zephyr_library_sources(${WOLFCERT_DIR}/src/pkcs7_util.c)
  endif()
  if(CONFIG_WOLFCERT_EST)
    zephyr_library_sources(
      ${WOLFCERT_DIR}/src/est/est_client.c
      ${WOLFCERT_DIR}/src/est/csr_attrs.c)
  endif()
  if(CONFIG_WOLFCERT_SCEP)
    zephyr_library_sources(
      ${WOLFCERT_DIR}/src/scep/scep_client.c
      ${WOLFCERT_DIR}/src/scep/scep_msg.c)
  endif()

  zephyr_library_link_libraries(wolfCert wolfSSL)

  target_compile_definitions(wolfCert INTERFACE WOLFCERT_ZEPHYR)

  # Use the shipped wolfSSL settings unless the app named its own. This has to
  # be global: wolfSSL's own sources need it and they do not link wolfCert.
  if(NOT CONFIG_WOLFSSL_SETTINGS_FILE)
    zephyr_compile_definitions(
      WOLFSSL_SETTINGS_FILE="${WOLFCERT_DIR}/zephyr/wolfssl_user_settings.h")
  endif()

  # <wolfssl/options.h> is empty in the Zephyr module, so check_config.h's
  # wolfSSL checks would report every feature missing.
  target_compile_definitions(wolfCert INTERFACE WOLFCERT_NO_WOLFSSL_FEATURE_CHECK)

  if(CONFIG_WOLFCERT_BUILD_TESTING)
    target_compile_definitions(wolfCert INTERFACE WOLFCERT_BUILD_TESTING)
    zephyr_library_compile_definitions(WOLFCERT_BUILD_TESTING)
  endif()

  if(CONFIG_WOLFCERT_DEBUG)
    zephyr_library_compile_options(-g3 -O0)
  endif()

  target_link_libraries(wolfCert INTERFACE zephyr_interface)
endif()
