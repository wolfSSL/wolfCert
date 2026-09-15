# SPDX-License-Identifier: GPL-3.0-or-later
#
# Build one existing tests/unit/<name>.c as a Zephyr image. Call after
# find_package(Zephyr) and project().

macro(wolfcert_zephyr_unit_test name)
  set(_wc_src ${ZEPHYR_WOLFCERT_MODULE_DIR}/tests/unit/${name}.c)

  if(NOT EXISTS ${_wc_src})
    message(FATAL_ERROR "wolfcert_zephyr_unit_test: no such test source ${_wc_src}")
  endif()

  target_sources(app PRIVATE
    ${_wc_src}
    ${ZEPHYR_WOLFCERT_MODULE_DIR}/zephyr/tests/common/test_shim.c)

  # Only this source, so the shim keeps the real main().
  set_source_files_properties(${_wc_src} PROPERTIES
    COMPILE_DEFINITIONS "main=wolfcert_test_main")

  # For the tests that include "internal.h".
  target_include_directories(app PRIVATE
    ${ZEPHYR_WOLFCERT_MODULE_DIR}/src)
endmacro()
