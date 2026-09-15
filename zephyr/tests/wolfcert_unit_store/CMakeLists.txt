# SPDX-License-Identifier: GPL-3.0-or-later
cmake_minimum_required(VERSION 3.20.0)

set(CONF_FILE
    ${CMAKE_CURRENT_LIST_DIR}/../common/wolfcert.conf
    ${CMAKE_CURRENT_LIST_DIR}/prj.conf)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(wolfcert_unit_store)

include(${ZEPHYR_WOLFCERT_MODULE_DIR}/zephyr/tests/common/unit_test.cmake)
wolfcert_zephyr_unit_test(test_store)
