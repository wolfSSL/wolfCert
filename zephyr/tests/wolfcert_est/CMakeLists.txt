# SPDX-License-Identifier: GPL-3.0-or-later
cmake_minimum_required(VERSION 3.20.0)

set(CONF_FILE
    ${CMAKE_CURRENT_LIST_DIR}/../common/wolfcert.conf
    ${CMAKE_CURRENT_LIST_DIR}/prj.conf)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(wolfcert_est)

target_sources(app PRIVATE src/main.c)

# qemu_x86 has no RTC; the test sets the clock to build time.
string(TIMESTAMP wolfcert_build_epoch "%s" UTC)
target_compile_definitions(app PRIVATE
  WOLFCERT_TEST_EPOCH=${wolfcert_build_epoch})

target_include_directories(app PRIVATE
  ${ZEPHYR_WOLFCERT_MODULE_DIR}/tests/integration)

# Embed the trust anchor rather than copying its bytes into a source file.
generate_inc_file_for_target(app
  ${ZEPHYR_WOLFCERT_MODULE_DIR}/examples/certs/ecc/ca-cert.pem
  ${ZEPHYR_BINARY_DIR}/include/generated/est_ca_cert.inc)
