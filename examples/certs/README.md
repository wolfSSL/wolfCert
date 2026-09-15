<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Example certificates

Throwaway test PKIs for exercising the wolfcert CLI tools over TLS / mTLS.
**Do not use these anywhere real** — the private keys are committed in the clear.

Regenerate any time with [`gen-certs.sh`](gen-certs.sh) (needs OpenSSL >= 3.5
for ML-DSA).

Two algorithm families, each a self-signed CA plus a server and a client leaf:

| File | Role |
|------|------|
| `<alg>/ca-cert.pem` / `ca-key.pem` | self-signed CA — the trust anchor |
| `<alg>/server-cert.pem` / `server-key.pem` | TLS server leaf, SAN = `localhost`, `127.0.0.1`, `::1`, `10.0.2.2` |
| `<alg>/client-cert.pem` / `client-key.pem` | mTLS client leaf |

- `ecc/` — ECC P-256 (ECDSA-with-SHA256)
- `mldsa/` — ML-DSA-65 (negotiates over TLS 1.3)

## Use with the CLIs

Server-side TLS (optionally mutual TLS with `--tls-client-ca`):

```sh
build/wolfcert-server --proto est --listen 127.0.0.1:8443 \
    --tls-cert examples/certs/ecc/server-cert.pem \
    --tls-key  examples/certs/ecc/server-key.pem \
    --tls-client-ca examples/certs/ecc/ca-cert.pem      # mTLS only
```

Client side — `--trust` is the CA that signed the server cert; add
`--client-cert`/`--client-key` for mutual TLS:

```sh
build/wolfcert-client enroll --proto est \
    --url https://127.0.0.1:8443/.well-known/est \
    --trust examples/certs/ecc/ca-cert.pem \
    --client-cert examples/certs/ecc/client-cert.pem \
    --client-key  examples/certs/ecc/client-key.pem \
    --key-type ecc:256 --subject "CN=dev" \
    --out-key dev.key --out-cert dev.crt
```

Swap `ecc` for `mldsa` to drive the ML-DSA hierarchy.
