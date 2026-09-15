/*
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of wolfCert.
 *
 * wolfCert is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfCert is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with wolfCert.  If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * Runs one tests/unit program as a Zephyr image. The build renames that
 * program's main() to wolfcert_test_main, so its source needs no edit.
 */

#include <wolfcert/wolfcert.h>

#include <stdio.h>

int wolfcert_test_main(void);

int main(void)
{
    int rc = wolfcert_test_main();

    if (rc != 0) {
        printf("WOLFCERT LAST ERROR: %s (wolfssl %d)\n",
               wolfcert_last_error_message(), wolfcert_last_wolfssl_err());
    }
    printf("WOLFCERT TEST RESULT: %d\n", rc);

    if (rc != 0) {
        /* twister only looks for the success line, so a failed test would
         * wait out the timeout and be called a hang. This line stops it. */
        printf("test failed - ending the run\n");
        printf("ZEPHYR FATAL ERROR\n");
    }
    return rc;
}
