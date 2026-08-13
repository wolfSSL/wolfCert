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

/* For the POSIX file backend below. Must precede any system header, so it
 * cannot be gated on WOLFCERT_HAVE_POSIX_STORE; inert when that is off. */
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include <wolfcert/store.h>
#include <wolfcert/errors.h>
#include "internal.h"

#include <wolfssl/wolfcrypt/memory.h>

#include <string.h>

#ifdef WOLFCERT_HAVE_POSIX_STORE
#include <errno.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

/* ================================================================== POSIX */
#ifdef WOLFCERT_HAVE_POSIX_STORE

typedef struct {
    char* root;
} PosixCtx;

static int posix_join(const char* root, const char* key, char** out, void* heap)
{
    size_t rl = strlen(root);
    size_t kl = strlen(key);

    char* p = (char*)WOLFCERT_XMALLOC(rl + 1 + kl + 1, heap);
    if (p == NULL)
        return WOLFCERT_ERR_MEMORY;

    memcpy(p, root, rl);
    p[rl] = '/';
    memcpy(p + rl + 1, key, kl + 1);
    *out = p;

    return WOLFCERT_OK;
}

static int posix_read(void* ctx_, const char* key, WolfCertBuffer* out)
{
    PosixCtx* ctx = (PosixCtx*)ctx_;
    char* path = NULL;
    FILE* f = NULL;
    uint8_t* buf = NULL;
    long len = 0;
    size_t n = 0;
    int rc = posix_join(ctx->root, key, &path, out->heap);
    if (rc != WOLFCERT_OK)
        return rc;

    f = fopen(path, "rb");
    if (f == NULL)
        rc = (errno == ENOENT) ? WOLFCERT_ERR_NOT_FOUND : WOLFCERT_ERR_IO;

    if (rc == WOLFCERT_OK && fseek(f, 0, SEEK_END) != 0)
        rc = WOLFCERT_ERR_IO;

    if (rc == WOLFCERT_OK) {
        len = ftell(f);
        rewind(f);
        if (len < 0)
            rc = WOLFCERT_ERR_IO;
    }

    if (rc == WOLFCERT_OK) {
        buf = (uint8_t*)WOLFCERT_XMALLOC((size_t)len, out->heap);
        if (buf == NULL)
            rc = WOLFCERT_ERR_MEMORY;
    }

    if (rc == WOLFCERT_OK) {
        n = fread(buf, 1, (size_t)len, f);
        if (n != (size_t)len)
            rc = WOLFCERT_ERR_IO;
    }

    if (rc == WOLFCERT_OK) {
        out->data = buf;
        out->len = (size_t)len;
        buf = NULL;   /* ownership moves to out */
    }

    if (f != NULL)
        fclose(f);
    WOLFCERT_XFREE(path, out->heap);
    WOLFCERT_XFREE(buf, out->heap);
    return rc;
}

static int posix_write(void* ctx_, const char* key,
                       const uint8_t* data, size_t len, int sensitive)
{
    PosixCtx* ctx = (PosixCtx*)ctx_;
    char* path = NULL;
    int rc = posix_join(ctx->root, key, &path, NULL);
    if (rc != WOLFCERT_OK)
        return rc;

    size_t plen = strlen(path);
    char* tmp = (char*)WOLFCERT_XMALLOC(plen + 8, NULL);
    if (tmp == NULL) {
        WOLFCERT_XFREE(path, NULL);
        return WOLFCERT_ERR_MEMORY;
    }

    memcpy(tmp, path, plen);
    memcpy(tmp + plen, ".XXXXXX", 8);

    int fd = mkstemp(tmp);
    if (fd < 0) {
        WOLFCERT_XFREE(tmp, NULL);
        WOLFCERT_XFREE(path, NULL);
        return WOLFCERT_ERR_IO;
    }

    if (fchmod(fd, sensitive ? 0600 : 0644) != 0)
        goto fail;

    size_t off = 0;
    while (off < len) {
        ssize_t w = write(fd, data + off, len - off);
        if (w < 0) {
            if (errno == EINTR)
                continue;
            goto fail;
        }
        off += (size_t)w;
    }

    if (fsync(fd) != 0)
        goto fail;

    if (close(fd) != 0) {
        unlink(tmp);
        goto fail_free;
    }

    if (rename(tmp, path) != 0) {
        unlink(tmp);
        goto fail_free;
    }

    WOLFCERT_XFREE(tmp, NULL);
    WOLFCERT_XFREE(path, NULL);

    return WOLFCERT_OK;

fail:
    close(fd);
    unlink(tmp);

fail_free:
    WOLFCERT_XFREE(tmp, NULL);
    WOLFCERT_XFREE(path, NULL);

    return WOLFCERT_ERR_IO;
}

static int posix_remove(void* ctx_, const char* key)
{
    PosixCtx* ctx = (PosixCtx*)ctx_;
    char* path = NULL;

    int rc = posix_join(ctx->root, key, &path, NULL);
    if (rc != WOLFCERT_OK)
        return rc;

    if (unlink(path) != 0 && errno != ENOENT)
        rc = WOLFCERT_ERR_IO;

    WOLFCERT_XFREE(path, NULL);
    return rc;
}

WolfCertStoreOps* wolfcert_store_posix_open(const char* root_dir, void* heap)
{
    if (root_dir == NULL)
        return NULL;

    if (heap == NULL)
        heap = wolfcert_default_heap();

    WolfCertStoreOps* ops = (WolfCertStoreOps*)WOLFCERT_XMALLOC(sizeof(*ops), heap);
    if (ops == NULL)
        return NULL;

    PosixCtx* ctx = (PosixCtx*)WOLFCERT_XMALLOC(sizeof(*ctx), heap);
    if (ctx == NULL) {
        WOLFCERT_XFREE(ops, heap);
        return NULL;
    }

    ctx->root = wolfcert_strdup(root_dir, heap);
    if (ctx->root == NULL) {
        WOLFCERT_XFREE(ctx, heap);
        WOLFCERT_XFREE(ops, heap);
        return NULL;
    }

    ops->read   = posix_read;
    ops->write  = posix_write;
    ops->remove = posix_remove;
    ops->heap   = heap;
    ops->ctx    = ctx;

    return ops;
}

void wolfcert_store_posix_close(WolfCertStoreOps* ops)
{
    if (ops == NULL)
        return;

    PosixCtx* ctx = (PosixCtx*)ops->ctx;
    if (ctx) {
        WOLFCERT_XFREE(ctx->root, ops->heap);
        WOLFCERT_XFREE(ctx, ops->heap);
    }

    WOLFCERT_XFREE(ops, ops->heap);
}

#else /* !WOLFCERT_HAVE_POSIX_STORE */

WolfCertStoreOps* wolfcert_store_posix_open(const char* root_dir, void* heap)
{
    (void)root_dir;
    (void)heap;

    WOLFCERT_ERR(WOLFCERT_ERR_UNSUPPORTED, "store",
        "wolfCert was built without the POSIX file backend");
    return NULL;
}

void wolfcert_store_posix_close(WolfCertStoreOps* ops)
{
    (void)ops;
}

#endif /* WOLFCERT_HAVE_POSIX_STORE */

/* ================================================================ memory */

typedef struct MemEntry {
    char*             key;
    uint8_t*          data;
    size_t            len;
    struct MemEntry*  next;
} MemEntry;

typedef struct {
    MemEntry* head;
} MemCtx;

static MemEntry** find_slot(MemCtx* ctx, const char* key)
{
    MemEntry** p = &ctx->head;
    while (*p) {
        if (strcmp((*p)->key, key) == 0)
            return p;
        p = &(*p)->next;
    }
    return p;
}

static int mem_read(void* ctx_, const char* key, WolfCertBuffer* out)
{
    MemCtx* ctx = (MemCtx*)ctx_;
    MemEntry** slot = find_slot(ctx, key);
    if (*slot == NULL)
        return WOLFCERT_ERR_NOT_FOUND;

    uint8_t* buf = (uint8_t*)WOLFCERT_XMALLOC((*slot)->len, out->heap);
    if (buf == NULL)
        return WOLFCERT_ERR_MEMORY;

    memcpy(buf, (*slot)->data, (*slot)->len);
    out->data = buf;
    out->len = (*slot)->len;

    return WOLFCERT_OK;
}

static int mem_write(void* ctx_, const char* key,
                     const uint8_t* data, size_t len, int sensitive)
{
    (void)sensitive;
    MemCtx* ctx = (MemCtx*)ctx_;
    MemEntry** slot = find_slot(ctx, key);
    void* heap = NULL;   /* memory backend uses default heap */

    if (*slot != NULL) {
        WOLFCERT_XFREE((*slot)->data, heap);
        (*slot)->data = (uint8_t*)WOLFCERT_XMALLOC(len, heap);
        if ((*slot)->data == NULL) {
            (*slot)->len = 0;
            return WOLFCERT_ERR_MEMORY;
        }

        memcpy((*slot)->data, data, len);
        (*slot)->len = len;

        return WOLFCERT_OK;
    }

    MemEntry* e = (MemEntry*)WOLFCERT_XMALLOC(sizeof(*e), heap);
    if (e == NULL)
        return WOLFCERT_ERR_MEMORY;

    memset(e, 0, sizeof(*e));
    e->key  = wolfcert_strdup(key, heap);
    e->data = (uint8_t*)WOLFCERT_XMALLOC(len, heap);
    if (e->key == NULL || e->data == NULL) {
        WOLFCERT_XFREE(e->key,  heap);
        WOLFCERT_XFREE(e->data, heap);
        WOLFCERT_XFREE(e,       heap);
        return WOLFCERT_ERR_MEMORY;
    }

    memcpy(e->data, data, len);
    e->len = len;
    e->next = ctx->head;
    ctx->head = e;

    return WOLFCERT_OK;
}

static int mem_remove(void* ctx_, const char* key)
{
    MemCtx* ctx = (MemCtx*)ctx_;
    MemEntry** slot = find_slot(ctx, key);
    if (*slot == NULL)
        return WOLFCERT_OK;

    MemEntry* e = *slot;
    *slot = e->next;
    WOLFCERT_XFREE(e->key,  NULL);
    WOLFCERT_XFREE(e->data, NULL);
    WOLFCERT_XFREE(e,       NULL);

    return WOLFCERT_OK;
}

WolfCertStoreOps* wolfcert_store_memory_open(void* heap)
{
    if (heap == NULL)
        heap = wolfcert_default_heap();

    WolfCertStoreOps* ops = (WolfCertStoreOps*)WOLFCERT_XMALLOC(sizeof(*ops), heap);
    if (ops == NULL)
        return NULL;

    MemCtx* ctx = (MemCtx*)WOLFCERT_XMALLOC(sizeof(*ctx), heap);
    if (ctx == NULL) {
        WOLFCERT_XFREE(ops, heap);
        return NULL;
    }

    memset(ctx, 0, sizeof(*ctx));
    ops->read   = mem_read;
    ops->write  = mem_write;
    ops->remove = mem_remove;
    ops->heap   = heap;
    ops->ctx    = ctx;

    return ops;
}

void wolfcert_store_memory_close(WolfCertStoreOps* ops)
{
    if (ops == NULL)
        return;

    MemCtx* ctx = (MemCtx*)ops->ctx;
    while (ctx->head) {
        MemEntry* e = ctx->head;
        ctx->head = e->next;
        WOLFCERT_XFREE(e->key,  NULL);
        WOLFCERT_XFREE(e->data, NULL);
        WOLFCERT_XFREE(e,       NULL);
    }

    WOLFCERT_XFREE(ctx, ops->heap);
    WOLFCERT_XFREE(ops, ops->heap);
}

/* ================================================= high-level cert/key */

int wolfcert_store_write_cert(WolfCertStoreOps* store, const char* key,
                              const uint8_t* cert, size_t len)
{
    if (store == NULL || key == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    return store->write(store->ctx, key, cert, len, 0);
}

int wolfcert_store_read_cert(WolfCertStoreOps* store, const char* key,
                             WolfCertBuffer* out)
{
    if (store == NULL || key == NULL || out == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    memset(out, 0, sizeof(*out));
    out->heap = store->heap;

    return store->read(store->ctx, key, out);
}

int wolfcert_store_write_key(WolfCertStoreOps* store, const char* key_name,
                             const WolfCertKey* key)
{
    if (store == NULL || key_name == NULL || key == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    WolfCertBuffer pem = { 0 };
    int rc = wolfcert_key_to_pem(key, &pem);
    if (rc != WOLFCERT_OK)
        return rc;

    rc = store->write(store->ctx, key_name, pem.data, pem.len, 1);
    wc_ForceZero(pem.data, (word32)pem.len);
    wolfcert_buffer_free(&pem);

    return rc;
}

int wolfcert_store_read_key(WolfCertStoreOps* store, const char* key_name,
                            WolfCertKey** out_key)
{
    if (store == NULL || key_name == NULL || out_key == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    WolfCertBuffer pem = { 0 };
    pem.heap = store->heap;

    int rc = store->read(store->ctx, key_name, &pem);
    if (rc != WOLFCERT_OK)
        return rc;

    rc = wolfcert_key_from_pem(pem.data, pem.len, store->heap, out_key);
    wc_ForceZero(pem.data, (word32)pem.len);
    wolfcert_buffer_free(&pem);

    return rc;
}
