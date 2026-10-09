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
- wolfSSL **v5.9.4** or newer.

## Adding wolfCert to a west workspace

```yaml
manifest:
  remotes:
    - name: wolfssl
      url-base: https://github.com/wolfssl

  projects:
    - name: wolfssl
      path: modules/crypto/wolfssl
      revision: v5.9.4-stable
      remote: wolfssl
    - name: wolfCert
      path: modules/lib/wolfcert
      revision: main
      remote: wolfssl
```

To build from a local checkout without touching the manifest, pass it as an
extra module:

```sh
WOLFCERT=/path/to/wolfCert
west build -b qemu_x86 <app> -- -DEXTRA_ZEPHYR_MODULES=$WOLFCERT
```

The commands in this file run inside your west workspace, with `WOLFCERT` set
to wolfCert's absolute path: the local checkout, or the workspace's
`modules/lib/wolfcert` when the manifest adds it.

## Configuration

`CONFIG_WOLFCERT=y` enables the library; set `CONFIG_WOLFSSL=y` with it.
`menuconfig` lists the rest under **wolfCert Support**. The module renders
`wolfcert/options.h` from those symbols at build time, so wolfCert itself needs
no `user_settings.h`.

**wolfSSL's configuration stays yours.** wolfCert needs features the wolfSSL
module's Kconfig cannot switch on, such as PKCS#7 and certificate generation, so
point `CONFIG_WOLFSSL_SETTINGS_FILE` at a settings file that provides them.
`zephyr/wolfssl_user_settings.h` is one, and the tests use it:

```
CONFIG_WOLFSSL_SETTINGS_FILE="zephyr/wolfssl_user_settings.h"
```

To add options of your own, include it from a header in your application's
directory (or its `src/`), as the sample's `wolfcert_sample_settings.h` does,
and point the setting there.

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

## Networking on qemu_x86

A networked QEMU image defaults to SLIP and waits forever on `/tmp/slip.sock`.
The unit tests set `CONFIG_NET_TEST=y` to suppress that. An image that really
needs the network sets `CONFIG_NET_QEMU_USER=y` (SLIRP), which reaches the host
at `10.0.2.2` and needs no TAP device or root.

It needs a QEMU with the SLIRP backend. The Zephyr SDK's Linux build has one;
its macOS build does not, so there install QEMU from Homebrew and
`export QEMU_BIN_PATH=/opt/homebrew/bin` before building. Zephyr reads it when
the build is configured, so rebuild with `-p` after changing it.
`qemu-system-i386 -netdev help` lists `user` when SLIRP is present.

## EST client sample

`samples/wolfcert_est_client/` enrolls one certificate over EST (RFC 7030): it
generates an ECC P-256 key on the device, sends a certificate request over TLS
to `wolfcert-server` on a host, and prints the certificate it gets back. Its
`main()` reads top to bottom: set the clock, init, `wolfcert_client_enroll()`,
print the result.

| Board | Network | Entropy | In CI |
|---|---|---|---|
| `frdm_mcxn947/mcxn947/cpu0` | Ethernet (RJ45), DHCPv4 | the SoC's TRNG | built only; run on the board by hand |
| `qemu_x86` | SLIRP (see [Networking on qemu_x86](#networking-on-qemu_x86)) | test generator, not random | built and run against a host `wolfcert-server` |

### 1. Start an EST server on the host

Build wolfCert on the host with its CLIs (the default; see the top-level
[`README.md`](../README.md)), then start the server with a TLS certificate
whose SAN names the address the device uses to reach it. `0.0.0.0` listens on
every interface of the host, so the same command serves QEMU and the LAN:

```sh
$WOLFCERT/build/wolfcert-server --proto est --listen 0.0.0.0:8443 \
    --basic alice:hunter2 --tls-cert <cert> --tls-key <key>
```

| Device | Reaches the host at | `<cert>` / `<key>` |
|---|---|---|
| qemu_x86 | QEMU's gateway | `$WOLFCERT/examples/certs/ecc/server-cert.pem` / `server-key.pem` |
| a board on your LAN | the host's LAN address | a pair for that address from `examples/certs/gen-server-cert.sh` (see [`examples/certs/README.md`](../examples/certs/README.md)) |

The sample's default trust anchor accepts both.

### 2. Configure the sample

The server settings are options in the sample's `Kconfig`:

| Option | Default |
|---|---|
| `CONFIG_WOLFCERT_SAMPLE_EST_URL` | `https://10.0.2.2:8443/.well-known/est` |
| `CONFIG_WOLFCERT_SAMPLE_EST_USER` / `_EST_PASS` | `alice` / `hunter2` |
| `CONFIG_WOLFCERT_SAMPLE_SUBJECT` | `CN=zephyr-device` |
| `CONFIG_WOLFCERT_SAMPLE_CA_CERT` | empty: `examples/certs/ecc/ca-cert.pem` |

The defaults match the qemu_x86 server. An empty `_EST_USER` sends no
credentials. For another server, set the URL when you build
([step 3](#3-build-and-run)). To change several options, put them in a conf
file and pass its absolute path with `-DEXTRA_CONF_FILE=<file>`.

`CONFIG_WOLFCERT_SAMPLE_CA_CERT` is the CA that issued the server's TLS
certificate, as a PEM path, absolute or relative to the sample's directory. A
URL with a hostname rather than an address also needs `CONFIG_DNS_RESOLVER=y`
and a DNS server: DHCP supplies one, a static address needs
`CONFIG_DNS_SERVER_IP_ADDRESSES=y` and `CONFIG_DNS_SERVER1`.

### 3. Build and run

Set `BOARD` and `EST_URL` for your board, then build:

```sh
BOARD=frdm_mcxn947/mcxn947/cpu0
EST_URL=https://192.0.2.10:8443/.well-known/est
west build -p -b $BOARD $WOLFCERT/zephyr/samples/wolfcert_est_client \
    -- -DEXTRA_ZEPHYR_MODULES=$WOLFCERT \
    "-DCONFIG_WOLFCERT_SAMPLE_EST_URL=\"$EST_URL\""
```

| Board | `BOARD` | `EST_URL` host | Run |
|---|---|---|---|
| FRDM-MCXN947 | `frdm_mcxn947/mcxn947/cpu0` | the host's LAN address | `west flash -r linkserver` |
| qemu_x86 | `qemu_x86` | `10.0.2.2` | `west build -t run` |

**FRDM-MCXN947.** Connect the board's MCU-Link USB port to the host and its
RJ45 port to the same network as the server. `west flash` finds NXP LinkServer
on the `PATH`; otherwise pass its location with
`--linkserver=<path>/LinkServer`.
The board also supports `-r jlink` and `-r pyocd`. The console is the
MCU-Link's USB serial port at 115200 baud. The sample enrolls once, a few
seconds after reset, so open the console before flashing, or press RESET
afterwards.

**qemu_x86.** QEMU keeps running after the output; Ctrl-A X quits it.

Expected output; on the board the certificate appears a few seconds after the
banner, once DHCP has assigned an address:

```
*** Booting Zephyr OS build <version> ***
enrolled: <N> bytes
-----BEGIN CERTIFICATE-----
...
-----END CERTIFICATE-----
```

### Adding a board

Add `boards/<board>.conf` to the sample, plus a `.overlay` if the devicetree
needs changing. `prj.conf` leaves these to the board:

- **The network interface and how it gets an address** — DHCPv4, or a static
  `CONFIG_NET_CONFIG_MY_IPV4_ADDR`.
- **An entropy source.** The devicetree's `zephyr,entropy` usually provides
  one, as the SoC's TRNG does on FRDM-MCXN947. `CONFIG_TEST_RANDOM_GENERATOR`
  is for emulators only: keys generated from it are predictable.
- **Stack and heap sizes.** Start from the FRDM-MCXN947 file (see
  [Sizing](#sizing)).

### Troubleshooting

| Symptom | Cause |
|---|---|
| `peer ip address mismatch` or `peer subject name mismatch` | The server certificate's SAN does not name the host in the URL; issue one with `gen-server-cert.sh` |
| `enroll failed: TLS error ()`, or `ASN date error, current date is before start of validity` | The device clock is before a certificate's start date; the clock is the build time, so rebuild with `-p` |
| `ASN no signer error to confirm failure` | `CONFIG_WOLFCERT_SAMPLE_CA_CERT` is not the CA that issued the server's certificate; see [step 2](#2-configure-the-sample) |
| `enroll failed` once `CONFIG_NET_CONFIG_INIT_TIMEOUT` expires after the banner | No address: check the cable, and that DHCP answers on that network |
| `wolfSSL is missing HAVE_PKCS7` at build time | No wolfSSL settings file; see [Configuration](#configuration) |
| `wolfCert requires wolfSSL 5.9.4 or newer` at build time | wolfSSL is too old; pin `v5.9.4-stable` as in [Adding wolfCert to a west workspace](#adding-wolfcert-to-a-west-workspace), then `west update` |

### Adapting it

- **Clock.** A real device needs an RTC or SNTP in place of the build-time
  clock — [`docs/EMBEDDED.md` section 8](../docs/EMBEDDED.md#8-zephyr)
  explains why.
- **Keeping the key and certificate.** They are freed here. A real device
  writes them through a `WolfCertStoreOps` — on Zephyr, one over NVS or the
  settings subsystem.

## Running the tests

```sh
west twister -T $WOLFCERT/zephyr/tests -p qemu_x86 \
    -x=EXTRA_ZEPHYR_MODULES=$WOLFCERT
```

That runs the unit suites only. The EST suite and the sample enrol against a
host `wolfcert-server` and are gated on a fixture, which twister skips — while
still reporting success — unless you pass it. Start the qemu_x86 server from
the EST client sample's [step 1](#1-start-an-est-server-on-the-host), then:

```sh
west twister -T $WOLFCERT/zephyr/tests/wolfcert_est -T $WOLFCERT/zephyr/samples \
    -p qemu_x86 -X wolfcert_est_server -x=EXTRA_ZEPHYR_MODULES=$WOLFCERT
```

The FRDM-MCXN947 build, as CI's `mcxn` job runs it (needs the SDK's
`arm-zephyr-eabi` toolchain):

```sh
west twister --build-only -T $WOLFCERT/zephyr/samples \
    -p frdm_mcxn947/mcxn947/cpu0 -x=EXTRA_ZEPHYR_MODULES=$WOLFCERT
```
