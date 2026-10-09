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

#ifndef WOLFCERT_TYPES_H
#define WOLFCERT_TYPES_H

/* Feature set from the generated <wolfcert/options.h>, or from the
 * integrator's user_settings.h when WOLFCERT_USER_SETTINGS is defined. */
#ifdef WOLFCERT_USER_SETTINGS
    #include "user_settings.h"
#else
    #include <wolfcert/options.h>
#endif
#include <wolfcert/check_config.h>

#include <stddef.h>
#include <stdint.h>

#include <wolfcert/api.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    WOLFCERT_PROTO_EST  = 1,
    WOLFCERT_PROTO_SCEP = 2
} WolfCertProtocol;

/* Serialization format for certificate/key buffers. */
typedef enum {
    WOLFCERT_ENCODING_PEM = 0,
    WOLFCERT_ENCODING_DER = 1
} WolfCertEncoding;

/* Pluggable transport, carrying TLS records and plain HTTP alike.
 * Contract: docs/ARCHITECTURE.md 4.6. */
typedef struct WolfCertTransport {
    /* Return WOLFCERT_OK with the handle stored in *conn, else a negative
     * WOLFCERT_ERR_*. *conn is opaque and never NULL-tested, so 0 is valid. */
    int  (*connect)(void* ctx, const char* host, int port,
                    int timeout_ms, void** conn);
    /* Bytes moved, or a negative WOLFCERT_ERR_*; never 0 (orderly close is
     * CONN_CLOSED). */
    int  (*read)(void* ctx, void* conn, uint8_t* buf, size_t len,
                 int timeout_ms);
    int  (*write)(void* ctx, void* conn, const uint8_t* buf, size_t len,
                  int timeout_ms);
    /* Runs exactly once per successful connect, error paths included. */
    int  (*disconnect)(void* ctx, void* conn);
    void* ctx;   /* transport-wide, e.g. the stack instance */
} WolfCertTransport;

typedef enum {
    WOLFCERT_KEY_RSA     = 1,
    WOLFCERT_KEY_ECC     = 2,
    WOLFCERT_KEY_ED25519 = 3,
    WOLFCERT_KEY_ED448   = 4,
    WOLFCERT_KEY_MLDSA44 = 5,
    WOLFCERT_KEY_MLDSA65 = 6,
    WOLFCERT_KEY_MLDSA87 = 7
} WolfCertKeyType;

/* Keys are offloaded through a wolfSSL CryptoCb devId that the application
 * registers; WOLFCERT_DEVID_SOFTWARE selects software. */
#define WOLFCERT_DEVID_SOFTWARE (-1)

typedef struct {
    WolfCertKeyType type;
    int             param;       /* RSA bits (2048/3072/4096) or ECC curve id */
    int             dev_id;      /* wolfSSL CryptoCb devId; -1 for software */
    const char*     key_label;   /* optional backend identifier for persistent keys */
    void*           heap;        /* optional heap hint; NULL = default */
} WolfCertKeyCfg;

/* Called by wolfcert_csr_build() once the standard fields are set, with the
 * wolfSSL Cert* to add what wolfCert does not expose; any error aborts.
 * A renewal then overwrites Cert's subject and altNames from current_cert. */
typedef int (*WolfCertCsrCustomizeCb)(void* wolfssl_cert, void* ctx);

typedef struct {
    /* All pointers are caller-owned. NULL lists => none. */
    const char*        subject_dn;         /* e.g. "CN=device-123,O=Acme".
                                            * Values cannot hold ',';
                                            * customize can set one. A
                                            * CTC_NAME_SIZE-byte or longer
                                            * value is WOLFCERT_ERR_BAD_ARG. */
    const char* const* san_dns;            /* array of length san_dns_len */
    size_t             san_dns_len;
    const char* const* san_ip;             /* textual IPv4/IPv6 */
    size_t             san_ip_len;
    const char* const* san_uri;
    size_t             san_uri_len;
    const char* const* san_email;          /* rfc822Name (e.g. "dev@example.com") */
    size_t             san_email_len;
    const char*        key_usage;          /* comma-separated */
    const char*        extended_key_usage; /* comma-separated EKU names or OIDs */

    /* Raw CSR attribute DER. wolfcert_csr_build does not add it to the CSR
     * yet; customize can set other attributes on the wolfSSL Cert, and
     * wolfcert_csr_attrs_apply maps the typed /csrattrs hints. */
    const uint8_t*     csr_attributes_der;
    size_t             csr_attributes_der_len;

    /* Optional PKCS#9 challengePassword CSR attribute, used by SCEP (RFC 8894
     * section 2.4); NULL emits none. At most CTC_NAME_SIZE - 1 chars. */
    const char*        challenge_password;

    /* Optional signature hash size in bits (256 / 384 / 512); 0, or a hash
     * the wolfSSL build lacks, uses the key type's default. Ed25519, Ed448
     * and ML-DSA ignore it. */
    int                preferred_hash;

    /* Optional: invoked after standard fields are set, before signing. */
    WolfCertCsrCustomizeCb customize;
    void*                  customize_ctx;
} WolfCertCertMeta;

/* SCEP transactionID derivation (WolfCertScepServerOpts.txid_mode). */
typedef enum {
    WOLFCERT_SCEP_TXID_RANDOM      = 0, /* random 16-byte value, hex-encoded (default) */
    WOLFCERT_SCEP_TXID_PUBKEY_HASH = 1  /* SHA-256 of the signer public key */
} WolfCertScepTxidMode;

/* SCEP request content cipher (WolfCertScepServerOpts.content_cipher). */
typedef enum {
    WOLFCERT_SCEP_CIPHER_AUTO   = 0, /* AES-128-CBC when the CA advertises AES, else 3DES */
    WOLFCERT_SCEP_CIPHER_AES128 = 1,
    WOLFCERT_SCEP_CIPHER_AES256 = 2,
    WOLFCERT_SCEP_CIPHER_DES3   = 3
} WolfCertScepContentCipher;

/* messageType of a SCEP renewal (WolfCertScepServerOpts.renewal_msg_type).
 * Both are signed by the certificate being replaced; PKCS_REQ suits CAs that
 * predate RenewalReq. */
typedef enum {
    WOLFCERT_SCEP_RENEWAL_MSG_RENEWAL_REQ = 0, /* messageType 17 (default) */
    WOLFCERT_SCEP_RENEWAL_MSG_PKCS_REQ    = 1  /* messageType 19 */
} WolfCertScepRenewalMsgType;

/* EST-only knobs, reached through WolfCertServerCfg.proto_opts.est. */
typedef struct {
    /* Optional HTTP Basic credentials (RFC 7030 section 3.2.3), sent on every
     * request, session requests included. */
    const char* username;
    const char* password;

    /* TLS 1.3 post-handshake auth opt-in (RFC 8446 section 4.6.2), read only
     * by the keep-alive EST session API. */
    int allow_post_handshake_auth;

    /* When set, wolfcert_client_enroll fetches /csrattrs and applies its
     * hints to copies of key_cfg and meta, filling only zero-valued fields.
     * An empty reply (204, 404 or no body) changes nothing. */
    int auto_csrattrs;
} WolfCertEstServerOpts;

/* SCEP-only knobs, reached through WolfCertServerCfg.proto_opts.scep. Zero
 * keeps the default for every field. */
typedef struct {
    /* CA identifier sent as the message query parameter on GetCACaps,
     * GetCACert and GetNextCACert; NULL omits it. */
    const char*               ca_id;

    /* How the enrollment pkiMessage transactionID is derived. RANDOM (default)
     * uses fresh RNG bytes; PUBKEY_HASH derives it from the signer public key
     * (RFC 8894 section 3.2.1) so retries of the same key reuse one ID. */
    WolfCertScepTxidMode      txid_mode;

    /* Content-encryption cipher for the request EnvelopedData. AUTO (default)
     * keeps the RFC 8894 caps-driven choice (AES-128-CBC, else 3DES); an
     * explicit value forces that cipher for a peer that requires it. */
    WolfCertScepContentCipher content_cipher;

    /* Read only by the renewal entry points. WolfCertScepCaps.renewal says
     * whether the CA advertises RenewalReq. */
    WolfCertScepRenewalMsgType renewal_msg_type;
} WolfCertScepServerOpts;

typedef struct {
    WolfCertProtocol protocol;
    const char*      server_url;     /* e.g. https://ca.example/.well-known/est */
    const uint8_t*   trust_anchors; /* bootstrap trust for TLS; PEM or DER; optional */
    size_t           trust_anchors_len;
    int              verify_server;  /* must be 1 for EST and https:// SCEP */
    int              timeout_ms;     /* per-request timeout; 0 = default */

    /* Optional mutual-TLS client identity (both set), PEM or DER. EST
     * /simplereenroll presents the cert being renewed instead. */
    const uint8_t*   client_cert;
    size_t           client_cert_len;
    const uint8_t*   client_key;
    size_t           client_key_len;

    /* Hard cap on a response body; 0 -> 64 KiB. */
    size_t           max_response_bytes;

    /* Options for the selected protocol; all zero keeps the defaults. Every
     * wolfcert_est_* and wolfcert_scep_* call returns WOLFCERT_ERR_BAD_ARG
     * when protocol does not match. */
    union {
        WolfCertEstServerOpts  est;
        WolfCertScepServerOpts scep;
    } proto_opts;

    /* Heap hint for internal allocations; NULL = default. */
    void*            heap;

    WolfCertTransport transport;
} WolfCertServerCfg;

/* Caller-owned byte buffer filled by the library. wolfcert_buffer_free()
 * releases data but not the struct itself. */
typedef struct {
    uint8_t* data;
    size_t   len;
    void*    heap;    /* heap used for `data`; NULL = default */
} WolfCertBuffer;

WOLFCERT_API void wolfcert_buffer_free(WolfCertBuffer* buf);

#ifdef __cplusplus
}
#endif

#endif /* WOLFCERT_TYPES_H */
