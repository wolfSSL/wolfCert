# SPDX-License-Identifier: GPL-3.0-or-later

if(WOLFCERT_ENABLE_EST)
    add_executable(example_enroll_est  enroll_est.c)
    target_link_libraries(example_enroll_est  PRIVATE wolfcert)

    if(_have_WOLF_CRYPTO_CB)
        add_executable(example_enroll_cryptocb enroll_cryptocb.c)
        target_link_libraries(example_enroll_cryptocb PRIVATE wolfcert)
    endif()
endif()

if(WOLFCERT_ENABLE_SCEP)
    add_executable(example_enroll_scep enroll_scep.c)
    target_link_libraries(example_enroll_scep PRIVATE wolfcert)
endif()
