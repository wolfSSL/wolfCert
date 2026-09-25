# wolfCert Zephyr module

Zephyr integration for wolfCert. For what the library does and how its API
works see the top-level `README.md`, `docs/ARCHITECTURE.md` and the headers in
`wolfcert/`. This file covers only what is specific to building it under
Zephyr.

Only the client runs on target. wolfCert's in-tree test server drives sockets
directly rather than going through `WolfCertTransport`, so no Zephyr image
builds it; the on-target tests enrol against `wolfcert-server` on the host.

## Requirements

- Zephyr and its matching SDK; tested with Zephyr **v4.4.2** and SDK 1.0.1.
- wolfSSL from **master**: wolfCert calls `wc_SetDNSEntry()` and
  `wc_SetAltNamesFromList()`, which are not in the v5.9.2 release.

## Adding wolfCert to a west workspace

```yaml
manifest:
  remotes:
    - name: wolfssl
      url-base: https://github.com/wolfssl

  projects:
    - name: wolfssl
      path: modules/crypto/wolfssl
      revision: master
      remote: wolfssl
    - name: wolfCert
      path: modules/lib/wolfcert
      revision: main
      remote: wolfssl
```

To build from a local checkout without touching the manifest:

```sh
west build -b qemu_x86 <app> -- -DEXTRA_ZEPHYR_MODULES=/path/to/wolfCert
```

## Configuration

`CONFIG_WOLFCERT=y` enables the library; set `CONFIG_WOLFSSL=y` with it.
`menuconfig` lists the rest under **wolfCert Support**. The module renders
`wolfcert/options.h` from those symbols at build time, so wolfCert itself needs
no `user_settings.h`.

**wolfSSL's configuration stays yours.** wolfCert needs features the wolfSSL
module's Kconfig cannot switch on, such as PKCS#7 and certificate generation, so
point `CONFIG_WOLFSSL_SETTINGS_FILE` at a settings file that provides them.
`zephyr/wolfssl_user_settings.h` is one, and the tests and sample use it:

```
CONFIG_WOLFSSL_SETTINGS_FILE="zephyr/wolfssl_user_settings.h"
```

Without one the build stops with errors such as `wolfSSL is missing HAVE_PKCS7;
rebuild wolfSSL with --enable-pkcs7`. On Zephyr the fix is the settings file,
not a configure flag.

The Kconfig selects `NETWORKING` and `POSIX_API`. The built-in transport needs
the network stack, and wolfSSL needs `clock_gettime` from `POSIX_API` in every
image.

## Sizing

See `docs/EMBEDDED.md` section 8. The short version: build with
`CONFIG_HW_STACK_PROTECTION=y` while tuning `CONFIG_MAIN_STACK_SIZE`, because
a stack overflow here is reported as something else entirely.

## Sample

`samples/wolfcert_est_client/` — EST enrollment against a host server. Its
README covers running and adapting it.

## Running the tests

```sh
west twister -T <wolfcert>/zephyr/tests -p qemu_x86 \
    -x=EXTRA_ZEPHYR_MODULES=/path/to/wolfCert
```

That runs the unit suites only. The EST suite and the sample enrol against a
host `wolfcert-server` and are gated on a fixture, which twister skips — while
still reporting success — unless you pass it:

```sh
build/wolfcert-server --proto est --listen 0.0.0.0:8443 --basic alice:hunter2 \
    --tls-cert examples/certs/ecc/server-cert.pem \
    --tls-key  examples/certs/ecc/server-key.pem &
west twister -T <wolfcert>/zephyr/tests/wolfcert_est -T <wolfcert>/zephyr/samples \
    -p qemu_x86 -X wolfcert_est_server -x=EXTRA_ZEPHYR_MODULES=/path/to/wolfCert
```

A networked QEMU image defaults to SLIP and waits forever on `/tmp/slip.sock`.
The unit tests set `CONFIG_NET_TEST=y` to suppress that. An image that really
needs the network sets `CONFIG_NET_QEMU_USER=y` (SLIRP), which reaches the host
at `10.0.2.2` and needs no TAP device or root.

It needs a QEMU with the SLIRP backend. The Zephyr SDK's Linux build has one;
its macOS build does not, so there install QEMU from Homebrew and point Zephyr at
it with `QEMU_BIN_PATH=/opt/homebrew/bin`. `qemu-system-i386 -netdev help` lists
`user` when SLIRP is present.
