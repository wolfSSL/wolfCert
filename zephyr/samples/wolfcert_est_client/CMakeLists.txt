# SPDX-License-Identifier: GPL-3.0-or-later
cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(wolfcert_est_client)

target_sources(app PRIVATE src/main.c)

generate_inc_file_for_target(app
  ${ZEPHYR_WOLFCERT_MODULE_DIR}/examples/certs/ecc/ca-cert.pem
  ${ZEPHYR_BINARY_DIR}/include/generated/est_ca_cert.inc)

# qemu_x86 has no RTC; the sample sets the clock to build time.
string(TIMESTAMP wolfcert_build_epoch "%s" UTC)
target_compile_definitions(app PRIVATE
  WOLFCERT_SAMPLE_EPOCH=${wolfcert_build_epoch})
