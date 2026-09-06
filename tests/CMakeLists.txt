# SPDX-License-Identifier: GPL-3.0-or-later

add_executable(test_smoke unit/test_smoke.c)
target_link_libraries(test_smoke PRIVATE wolfcert)
add_test(NAME smoke COMMAND test_smoke)

add_executable(test_keygen unit/test_keygen.c)
target_link_libraries(test_keygen PRIVATE wolfcert)
add_test(NAME keygen COMMAND test_keygen)

add_executable(test_csr unit/test_csr.c)
target_link_libraries(test_csr PRIVATE wolfcert)
add_test(NAME csr COMMAND test_csr)

add_executable(test_store unit/test_store.c)
target_link_libraries(test_store PRIVATE wolfcert)
add_test(NAME store COMMAND test_store)

if(WOLFCERT_ENABLE_BUILTIN_TRANSPORT)
    add_executable(test_net unit/test_net.c)
    target_link_libraries(test_net PRIVATE wolfcert)
    add_test(NAME net COMMAND test_net)
endif()

find_package(Threads REQUIRED)
add_executable(test_transport unit/test_transport.c)
target_link_libraries(test_transport PRIVATE wolfcert)
add_test(NAME transport COMMAND test_transport)
# A lost never-0 guard spins the read-until-close loop, so bound the run.
set_tests_properties(transport PROPERTIES TIMEOUT 30)

add_executable(test_http unit/test_http.c)
target_include_directories(test_http PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(test_http PRIVATE wolfcert Threads::Threads)
add_test(NAME http COMMAND test_http)
set_tests_properties(http PROPERTIES SKIP_RETURN_CODE 77)

add_executable(test_parse_negative unit/test_parse_negative.c)
target_include_directories(test_parse_negative PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(test_parse_negative PRIVATE wolfcert)
add_test(NAME parse_negative COMMAND test_parse_negative)

add_executable(test_tls_http integration/test_tls_http.c)
target_link_libraries(test_tls_http PRIVATE wolfcert Threads::Threads)
add_test(NAME tls_http COMMAND test_tls_http)
set_tests_properties(tls_http PROPERTIES SKIP_RETURN_CODE 77)

if(WOLFCERT_ENABLE_EST)
    add_executable(test_est unit/test_est.c)
    target_include_directories(test_est PRIVATE ${CMAKE_SOURCE_DIR}/src)
    target_link_libraries(test_est PRIVATE wolfcert Threads::Threads)
    add_test(NAME est COMMAND test_est)
    set_tests_properties(est PROPERTIES SKIP_RETURN_CODE 77)

    add_executable(test_csr_attrs unit/test_csr_attrs.c)
    target_link_libraries(test_csr_attrs PRIVATE wolfcert)
    add_test(NAME csr_attrs COMMAND test_csr_attrs)

    if(WOLFCERT_ENABLE_SERVER)
        add_executable(test_est_roundtrip integration/test_est_roundtrip.c)
        target_link_libraries(test_est_roundtrip PRIVATE wolfcert Threads::Threads)
        add_test(NAME est_roundtrip COMMAND test_est_roundtrip)

        add_executable(test_est_tls_roundtrip integration/test_est_tls_roundtrip.c)
        target_link_libraries(test_est_tls_roundtrip PRIVATE wolfcert Threads::Threads)
        add_test(NAME est_tls_roundtrip COMMAND test_est_tls_roundtrip)

        add_executable(test_est_mtls_roundtrip integration/test_est_mtls_roundtrip.c)
        target_link_libraries(test_est_mtls_roundtrip PRIVATE wolfcert Threads::Threads)
        add_test(NAME est_mtls_roundtrip COMMAND test_est_mtls_roundtrip)

        add_executable(test_est_pha_roundtrip integration/test_est_pha_roundtrip.c)
        target_link_libraries(test_est_pha_roundtrip PRIVATE wolfcert Threads::Threads)
        add_test(NAME est_pha_roundtrip COMMAND test_est_pha_roundtrip)

        add_executable(test_est_async_roundtrip integration/test_est_async_roundtrip.c)
        target_link_libraries(test_est_async_roundtrip PRIVATE wolfcert Threads::Threads)
        add_test(NAME est_async_roundtrip COMMAND test_est_async_roundtrip)

        add_executable(test_est_csr_attrs_roundtrip integration/test_est_csr_attrs_roundtrip.c)
        target_link_libraries(test_est_csr_attrs_roundtrip PRIVATE wolfcert Threads::Threads)
        add_test(NAME est_csr_attrs_roundtrip COMMAND test_est_csr_attrs_roundtrip)

        add_executable(test_est_csr_attrs_apply_roundtrip integration/test_est_csr_attrs_apply_roundtrip.c)
        target_link_libraries(test_est_csr_attrs_apply_roundtrip PRIVATE wolfcert Threads::Threads)
        add_test(NAME est_csr_attrs_apply_roundtrip COMMAND test_est_csr_attrs_apply_roundtrip)

        add_executable(test_est_csr_attrs_enforce integration/test_est_csr_attrs_enforce.c)
        target_link_libraries(test_est_csr_attrs_enforce PRIVATE wolfcert Threads::Threads)
        add_test(NAME est_csr_attrs_enforce COMMAND test_est_csr_attrs_enforce)

        add_executable(test_est_chunked_robustness integration/test_est_chunked_robustness.c)
        target_link_libraries(test_est_chunked_robustness PRIVATE wolfcert Threads::Threads)
        add_test(NAME est_chunked_robustness COMMAND test_est_chunked_robustness)

        add_executable(test_est_pending_roundtrip integration/test_est_pending_roundtrip.c)
        target_link_libraries(test_est_pending_roundtrip PRIVATE wolfcert Threads::Threads)
        add_test(NAME est_pending_roundtrip COMMAND test_est_pending_roundtrip)

        add_executable(test_est_mldsa_roundtrip integration/test_est_mldsa_roundtrip.c)
        target_link_libraries(test_est_mldsa_roundtrip PRIVATE wolfcert Threads::Threads)
        add_test(NAME est_mldsa_roundtrip COMMAND test_est_mldsa_roundtrip)
    endif()
endif()

if(WOLFCERT_ENABLE_SCEP)
    add_executable(test_scep_msg unit/test_scep_msg.c)
    target_include_directories(test_scep_msg PRIVATE ${CMAKE_SOURCE_DIR}/src)
    target_link_libraries(test_scep_msg PRIVATE wolfcert)
    add_test(NAME scep_msg COMMAND test_scep_msg)
endif()

if(WOLFCERT_ENABLE_SCEP AND WOLFCERT_ENABLE_SERVER)
    add_executable(test_scep_roundtrip integration/test_scep_roundtrip.c)
    target_include_directories(test_scep_roundtrip PRIVATE ${CMAKE_SOURCE_DIR}/src)
    target_link_libraries(test_scep_roundtrip PRIVATE wolfcert Threads::Threads)
    add_test(NAME scep_roundtrip COMMAND test_scep_roundtrip)

    add_executable(test_scep_poll_roundtrip integration/test_scep_poll_roundtrip.c)
    target_link_libraries(test_scep_poll_roundtrip PRIVATE wolfcert Threads::Threads)
    add_test(NAME scep_poll_roundtrip COMMAND test_scep_poll_roundtrip)

    add_executable(test_scep_async_roundtrip integration/test_scep_async_roundtrip.c)
    target_link_libraries(test_scep_async_roundtrip PRIVATE wolfcert Threads::Threads)
    add_test(NAME scep_async_roundtrip COMMAND test_scep_async_roundtrip)
endif()

# The CLI's protocol scoping and keyword validation, driven against the built
# binary. Every case fails before any network access, so no server is involved.
if(WOLFCERT_ENABLE_CLI AND WOLFCERT_ENABLE_EST AND WOLFCERT_ENABLE_SCEP AND UNIX)
    add_test(NAME cli_proto_scoping
             COMMAND ${CMAKE_COMMAND} -E env bash
                     ${CMAKE_CURRENT_SOURCE_DIR}/integration/cli_proto_scoping.sh
                     $<TARGET_FILE:wolfcert-client>)
    # The script exits 77 when the CLI cannot initialise, which is the case on a
    # wolfSSL built WOLFSSL_NO_MALLOC: no pool is installed for it.
    set_tests_properties(cli_proto_scoping PROPERTIES SKIP_RETURN_CODE 77)
endif()
