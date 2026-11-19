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

/* One HTTP request on a session opened and closed around it. */

#ifndef WOLFCERT_TEST_HTTP_UTIL_H
#define WOLFCERT_TEST_HTTP_UTIL_H

#include <wolfcert/http.h>
#include "internal.h"

#include <string.h>

/* cfg may be NULL; a NULL base_url takes the request URL. */
static inline int test_http_request(const WolfCertHttpSessionCfg* cfg,
                                    const WolfCertHttpRequest* req,
                                    WolfCertHttpResponse* resp)
{
    WolfCertHttpSessionCfg c;
    WolfCertHttpSession*   s = NULL;
    int rc;

    if (req == NULL || resp == NULL || req->url == NULL || req->method == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    memset(resp, 0, sizeof(*resp));
    if (cfg != NULL)
        c = *cfg;
    else
        memset(&c, 0, sizeof(c));
    if (c.base_url == NULL)
        c.base_url = req->url;

    rc = wolfcert_http_session_open(&c, &s);
    if (rc == WOLFCERT_OK) {
        wolfcert_http_session_set_close(s);
        rc = wolfcert_http_session_request(s, req, resp);
    }
    wolfcert_http_session_close(s);

    return rc;
}

#endif /* WOLFCERT_TEST_HTTP_UTIL_H */
