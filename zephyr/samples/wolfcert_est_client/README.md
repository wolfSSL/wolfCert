# wolfCert EST client sample

Enrolls one certificate over EST (RFC 7030) from a Zephyr target against a
`wolfcert-server` running on the host. Reads top to bottom: set the clock,
init, `wolfcert_client_enroll()`, print the result.

Only the client runs on target — see `zephyr/README.md` for why.

## Running it

Start the server on the host, from a wolfCert build with the CLIs enabled:

```sh
build/wolfcert-server --proto est --listen 0.0.0.0:8443 \
    --basic alice:hunter2 \
    --tls-cert examples/certs/ecc/server-cert.pem \
    --tls-key  examples/certs/ecc/server-key.pem
```

Then build and run the sample:

```sh
west build -b qemu_x86 <wolfcert>/zephyr/samples/wolfcert_est_client \
    -- -DEXTRA_ZEPHYR_MODULES=/path/to/wolfCert
west build -t run
```

Expected output:

```
enrolled: 733 bytes
```

The sample reaches the host at `10.0.2.2`, the QEMU SLIRP gateway. The
server's certificate carries that address in its SAN, so `verify_server` is
left on.

This needs a QEMU with the SLIRP backend, which the Zephyr SDK's build lacks;
`zephyr/README.md` has the one-line fix.

## Adapting it

- **Trust anchor.** `examples/certs/ecc/ca-cert.pem` is embedded by
  `generate_inc_file_for_target`. Swap in your CA and the URL to match.
- **RNG.** `CONFIG_TEST_RANDOM_GENERATOR=y` is not a real random source, and
  keys generated from it are predictable. Drop it and supply a hardware
  entropy source before generating a key you intend to keep.
- **Clock.** The sample fakes one from its build timestamp. A real device
  needs a real time source — `docs/EMBEDDED.md` section 8 explains why.
- **Keeping the key and certificate.** They are freed here. A real device
  writes them through a `WolfCertStoreOps` — on Zephyr, one over NVS or the
  settings subsystem.
