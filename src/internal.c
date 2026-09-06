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

#include "internal.h"
#include <wolfcert/errors.h>

#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/coding.h>

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

/* ---- default heap, logging, last-error --------------------------------- */

static void*            g_default_heap = NULL;
static WolfCertLogCb    g_log_cb       = NULL;
static void*            g_log_ctx      = NULL;
static WolfCertLogLevel g_log_level    = WOLFCERT_LOG_WARN;

#if defined(__STDC_NO_THREADS__) || defined(WOLFCERT_NO_THREAD_LOCAL)
# define WOLFCERT_TLS /* empty */
#elif defined(__GNUC__) || defined(__clang__)
# define WOLFCERT_TLS __thread
#else
# define WOLFCERT_TLS /* empty */
#endif

typedef struct {
    int  wolfcert_rc;
    int  wolfssl_rc;
    char module[32];
    char message[256];
} WolfCertErrState;

static WOLFCERT_TLS WolfCertErrState g_err;

/* ---- public memory / log / status APIs --------------------------------- */

void  wolfcert_set_default_heap(void* heap)
{
    g_default_heap = heap;
}

void* wolfcert_default_heap(void)
{
    return g_default_heap;
}

void wolfcert_set_log_cb(WolfCertLogCb cb, void* ctx)
{
    g_log_cb = cb;
    g_log_ctx = ctx;
}

void wolfcert_set_log_level(WolfCertLogLevel lvl)
{
    g_log_level = lvl;
}

WolfCertLogLevel wolfcert_log_level(void)
{
    return g_log_level;
}

char* wolfcert_strdup(const char* s, void* heap)
{
    if (s == NULL)
        return NULL;

    size_t n = strlen(s);
    char* r = (char*)WOLFCERT_XMALLOC(n + 1, heap);
    if (r == NULL)
        return NULL;

    memcpy(r, s, n + 1);

    return r;
}

const char* wolfcert_last_error_message(void)
{
    return g_err.message;
}

int wolfcert_last_wolfssl_err(void)
{
    return g_err.wolfssl_rc;
}

void wolfcert_clear_error(void)
{
    memset(&g_err, 0, sizeof(g_err));
}


/* ---- IP literal parsing ------------------------------------------------- */

/* One decimal octet, refusing an octal-ambiguous leading zero. Returns the
 * value or -1, advancing *p. */
static int parse_octet(const char** p)
{
    const char* s = *p;
    int v = 0;
    int n = 0;

    while (n < 3 && s[n] >= '0' && s[n] <= '9') {
        v = v * 10 + (s[n] - '0');
        n++;
    }

    if (n == 0 || v > 255 || (n > 1 && s[0] == '0'))
        return -1;

    *p = s + n;
    return v;
}

static int parse_ipv4(const char* s, uint8_t out[4])
{
    int i;
    int v;

    for (i = 0; i < 4; i++) {
        if (i > 0) {
            if (*s != '.')
                return WOLFCERT_ERR_PARSE;
            s++;
        }

        v = parse_octet(&s);
        if (v < 0)
            return WOLFCERT_ERR_PARSE;
        out[i] = (uint8_t)v;
    }

    return (*s == '\0') ? WOLFCERT_OK : WOLFCERT_ERR_PARSE;
}

static int hex_digit(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;

    return -1;
}

/* Is the group starting at s a dotted-quad tail rather than a hex group? */
static int group_is_ipv4(const char* s)
{
    int i;

    for (i = 0; s[i] != '\0' && s[i] != ':'; i++) {
        if (s[i] == '.')
            return 1;
    }

    return 0;
}

static int parse_ipv6(const char* s, uint8_t out[16])
{
    uint8_t buf[16];
    int filled = 0;
    int gap = -1;     /* byte offset the "::" run expands at */
    int tail;
    int val;
    int n;
    int d;

    XMEMSET(buf, 0, sizeof(buf));

    if (s[0] == ':') {
        if (s[1] != ':')
            return WOLFCERT_ERR_PARSE;
        s += 2;
        gap = 0;
    }

    while (*s != '\0') {
        if (group_is_ipv4(s)) {
            if (filled > 12 || parse_ipv4(s, buf + filled) != WOLFCERT_OK)
                return WOLFCERT_ERR_PARSE;
            filled += 4;
            s += strlen(s);
            break;
        }

        val = 0;
        n = 0;
        while (n < 4 && (d = hex_digit(*s)) >= 0) {
            val = val * 16 + d;
            s++;
            n++;
        }

        if (n == 0 || filled > 14)
            return WOLFCERT_ERR_PARSE;
        buf[filled++] = (uint8_t)(val >> 8);
        buf[filled++] = (uint8_t)(val & 0xFF);

        if (*s == '\0')
            break;
        if (*s != ':')
            return WOLFCERT_ERR_PARSE;
        s++;

        if (*s == ':') {
            if (gap >= 0)
                return WOLFCERT_ERR_PARSE;
            gap = filled;
            s++;
        }
        else if (*s == '\0') {
            /* a trailing single colon is not a valid address */
            return WOLFCERT_ERR_PARSE;
        }
    }

    if (gap < 0) {
        if (filled != 16)
            return WOLFCERT_ERR_PARSE;
    }
    else {
        if (filled >= 16)
            return WOLFCERT_ERR_PARSE;

        /* Slide the groups after "::" down to the end, zeroing the middle.
         * Destinations run ahead of sources, so a descending walk is safe. */
        tail = filled - gap;
        for (d = 0; d < tail; d++)
            buf[15 - d] = buf[filled - 1 - d];
        for (d = gap; d < 16 - tail; d++)
            buf[d] = 0;
    }

    XMEMCPY(out, buf, 16);
    return WOLFCERT_OK;
}

WOLFCERT_TEST_VIS int wolfcert_parse_ip(const char* s, uint8_t out[16],
                                        size_t* out_len)
{
    if (s == NULL || out == NULL || out_len == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    if (parse_ipv4(s, out) == WOLFCERT_OK) {
        *out_len = 4;
        return WOLFCERT_OK;
    }

    if (parse_ipv6(s, out) == WOLFCERT_OK) {
        *out_len = 16;
        return WOLFCERT_OK;
    }

    return WOLFCERT_ERR_PARSE;
}

/* ---- internal log + error helpers -------------------------------------- */

void wolfcert_logv(WolfCertLogLevel lvl, const char* module,
                    const char* fmt, ...)
{
    if (g_log_cb == NULL || lvl > g_log_level)
        return;

    char buf[256];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    g_log_cb(lvl, module, buf, g_log_ctx);
}

int wolfcert_set_error(int wolfcert_rc, int wolfssl_rc,
                        const char* module, const char* fmt, ...)
{
    g_err.wolfcert_rc = wolfcert_rc;
    g_err.wolfssl_rc  = wolfssl_rc;

    if (module) {
        strncpy(g_err.module, module, sizeof(g_err.module) - 1);
        g_err.module[sizeof(g_err.module) - 1] = '\0';
    }
    else {
        g_err.module[0] = '\0';
    }

    va_list ap;
    va_start(ap, fmt);
    vsnprintf(g_err.message, sizeof(g_err.message), fmt, ap);
    va_end(ap);

    /* Also emit at WARN via the log callback so applications see it. */
    wolfcert_logv(WOLFCERT_LOG_WARN, module ? module : "wolfcert",
                   "%s (rc=%d wc=%d)", g_err.message, wolfcert_rc, wolfssl_rc);

    return wolfcert_rc;
}

int wolfcert_rng_new(WC_RNG* rng)
{
    int rc = wc_InitRng(rng);
    return rc == 0 ? WOLFCERT_OK : wolfcert_map_wc_err(rc);
}

int wolfcert_cfg_require_proto(const WolfCertServerCfg* srv,
                               WolfCertProtocol want, const char* module)
{
    if (srv->protocol == want)
        return WOLFCERT_OK;

    return WOLFCERT_ERR(WOLFCERT_ERR_BAD_ARG, module,
        "WolfCertServerCfg.protocol is %d, not %d: it selects the proto_opts "
        "arm, so a %s entry point cannot read a config built for another "
        "protocol", (int)srv->protocol, (int)want, module);
}

int wolfcert_map_wc_err(int wc_rc)
{
    if (wc_rc == 0)
        return WOLFCERT_OK;

    switch (wc_rc) {
        case MEMORY_E:
            return WOLFCERT_ERR_MEMORY;
        case BAD_FUNC_ARG:
            return WOLFCERT_ERR_BAD_ARG;
        case BUFFER_E:
            return WOLFCERT_ERR_MEMORY;
        case ASN_PARSE_E:
            return WOLFCERT_ERR_PARSE;
        case NOT_COMPILED_IN:
        case ALGO_ID_E:
            return WOLFCERT_ERR_UNSUPPORTED;
        default:
            return WOLFCERT_ERR_CRYPTO;
    }
}

#ifdef WOLFCERT_HAVE_ECC
int wolfcert_ecc_curve_from_param(int param, int* out_curve_id, int* out_key_size)
{
    switch (param) {
        case 256:
            *out_curve_id = ECC_SECP256R1;
            *out_key_size = 32;
            return WOLFCERT_OK;
        case 384:
            *out_curve_id = ECC_SECP384R1;
            *out_key_size = 48;
            return WOLFCERT_OK;
        case 521:
            *out_curve_id = ECC_SECP521R1;
            *out_key_size = 66;
            return WOLFCERT_OK;
        default:
            return WOLFCERT_ERR_UNSUPPORTED;
    }
}
#endif /* WOLFCERT_HAVE_ECC */

WOLFCERT_TEST_VIS int wolfcert_base64_encode(const uint8_t* in, size_t in_len,
                                             WolfCertBuffer* out, void* heap)
{
    if (in == NULL || out == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    word32 cap = (word32)(((in_len + 2) / 3) * 4 + 4);
    uint8_t* buf = (uint8_t*)WOLFCERT_XMALLOC(cap, heap);
    if (buf == NULL)
        return WOLFCERT_ERR_MEMORY;

    word32 len = cap;
    int rc = Base64_Encode_NoNl(in, (word32)in_len, buf, &len);
    if (rc != 0) {
        WOLFCERT_XFREE(buf, heap);
        return wolfcert_map_wc_err(rc);
    }

    out->data = buf;
    out->len = len;
    out->heap = heap;

    return WOLFCERT_OK;
}

/* MIME-wrapped (RFC 4648 section 3.1, 64 chars per line) base64 encoder. Used
 * only for HTTP-body payloads where a strict downstream parser - notably
 * OpenSSL's `BIO_f_base64` in libest's estserver - rejects unwrapped
 * input. Most wolfCert call sites should keep using
 * `wolfcert_base64_encode` (no wrapping): HTTP Basic Auth header values
 * and wolfCert's own server-side decode path are single-line by
 * contract. */
WOLFCERT_TEST_VIS int wolfcert_base64_encode_mime(const uint8_t* in, size_t in_len,
                                                  WolfCertBuffer* out, void* heap)
{
    if (in == NULL || out == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    /* Capacity includes one `\n` per 64 output chars plus a small pad. */
    word32 cap = (word32)(((in_len + 2) / 3) * 4 + (in_len / 48 + 2) + 4);
    uint8_t* buf = (uint8_t*)WOLFCERT_XMALLOC(cap, heap);
    if (buf == NULL)
        return WOLFCERT_ERR_MEMORY;

    word32 len = cap;
    int rc = Base64_Encode(in, (word32)in_len, buf, &len);
    if (rc != 0) {
        WOLFCERT_XFREE(buf, heap);
        return wolfcert_map_wc_err(rc);
    }

    out->data = buf;
    out->len = len;
    out->heap = heap;

    return WOLFCERT_OK;
}

WOLFCERT_TEST_VIS int wolfcert_base64_decode(const uint8_t* in, size_t in_len,
                                             WolfCertBuffer* out, void* heap)
{
    if (in == NULL || out == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    word32 cap = (word32)in_len;
    if (cap < 4)
        cap = 4;
    uint8_t* buf = (uint8_t*)WOLFCERT_XMALLOC(cap, heap);
    if (buf == NULL)
        return WOLFCERT_ERR_MEMORY;

    word32 len = cap;
    int rc = Base64_Decode(in, (word32)in_len, buf, &len);
    if (rc != 0) {
        WOLFCERT_XFREE(buf, heap);
        return wolfcert_map_wc_err(rc);
    }

    out->data = buf;
    out->len = len;
    out->heap = heap;

    return WOLFCERT_OK;
}

WOLFCERT_TEST_VIS void wolfcert_hex_encode(const uint8_t* in, size_t in_len,
                                           int upper, char* out)
{
    static const char HEX_LOWER[] = "0123456789abcdef";
    static const char HEX_UPPER[] = "0123456789ABCDEF";
    const char* hex = upper ? HEX_UPPER : HEX_LOWER;
    size_t i;

    if (in == NULL || out == NULL)
        return;

    for (i = 0; i < in_len; ++i) {
        out[i*2]   = hex[in[i] >> 4];
        out[i*2+1] = hex[in[i] & 0x0F];
    }
}

WOLFCERT_TEST_VIS int wolfcert_buffer_is_der(const uint8_t* buf, size_t len)
{
    size_t i = 0;
    if (buf == NULL)
        return 0;

    while (i < len && (buf[i] == ' ' || buf[i] == '\t' ||
                       buf[i] == '\r' || buf[i] == '\n')) {
        ++i;
    }

    return (i < len && buf[i] == 0x30) ? 1 : 0;
}

int wolfcert_pem_cert_to_der(const uint8_t* pem, size_t pem_len,
                              WolfCertBuffer* out_der, void* heap)
{
    if (pem == NULL || pem_len == 0 || out_der == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    DerBuffer* der = NULL;
    int rc = wc_PemToDer(pem, (long)pem_len, CERT_TYPE, &der, NULL, NULL, NULL);
    if (rc != 0 || der == NULL) {
        if (der != NULL)
            wc_FreeDer(&der);
        return WOLFCERT_ERR_PARSE;
    }

    uint8_t* buf = (uint8_t*)WOLFCERT_XMALLOC(der->length, heap);
    if (buf == NULL) {
        wc_FreeDer(&der);
        return WOLFCERT_ERR_MEMORY;
    }

    memcpy(buf, der->buffer, der->length);
    out_der->data = buf;
    out_der->len = der->length;
    out_der->heap = heap;

    wc_FreeDer(&der);
    return WOLFCERT_OK;
}
