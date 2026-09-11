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

#include <wolfcert/wolfcert.h>
#include "internal.h"

#include <wolfssl/ssl.h>

#include <string.h>

/* wolfcert_init()/wolfcert_cleanup() are thin wrappers over
 * wolfSSL_Init()/wolfSSL_Cleanup(). Those are themselves reference-counted
 * and thread-safe internally, so paired wolfcert_init()/wolfcert_cleanup()
 * calls bring wolfSSL up on the first and tear it down on the last with no
 * bookkeeping of our own. That leaves no shared mutable state for wolfCert to
 * guard, hence no library-level lock. */
int wolfcert_init(void* heap)
{
    int rc = wolfSSL_Init();
    if (rc != WOLFSSL_SUCCESS)
        return WOLFCERT_ERR(WOLFCERT_ERR_CRYPTO, "init",
            "wolfSSL_Init failed (%d)", rc);

    wolfcert_set_default_heap(heap);
    wolfcert_clear_error();

    return WOLFCERT_OK;
}

void wolfcert_cleanup(void)
{
    wolfSSL_Cleanup();
}

void wolfcert_buffer_free(WolfCertBuffer* buf)
{
    if (buf == NULL || buf->data == NULL)
        return;

    WOLFCERT_XFREE(buf->data, buf->heap);

    buf->data = NULL;
    buf->len  = 0;
    buf->heap = NULL;
}

#define WOLFCERT_FORCEZERO_CHUNK 0x10000000U

void wolfcert_buffer_free_secure(WolfCertBuffer* buf)
{
    if (buf != NULL && buf->data != NULL && buf->len > 0) {
        uint8_t* p    = buf->data;
        size_t   left = buf->len;

        while (left > 0) {
            word32 chunk = (left > WOLFCERT_FORCEZERO_CHUNK)
                         ? WOLFCERT_FORCEZERO_CHUNK : (word32)left;

            wc_ForceZero(p, chunk);
            p    += chunk;
            left -= chunk;
        }
    }

    wolfcert_buffer_free(buf);
}
