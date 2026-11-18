# SBOM

wolfCert generates a Software Bill of Materials in CycloneDX 1.6 and SPDX 2.3 with the wolfSSL SBOM tooling, vendored in `tools/sbom/` from [wolfssl-compliance-tooling](https://github.com/wolfSSL/wolfssl-compliance-tooling).

## Host builds

```sh
# autoconf
./configure --with-wolfssl=/path/to/wolfssl/prefix
make sbom

# CMake
cmake -S . -B build -DWITH_WOLFSSL=/path/to/wolfssl/prefix
cmake --build build --target sbom
```

Both need `python3` and `pyspdxtools` (`pip install spdx-tools`). They write `wolfcert-<version>.cdx.json`, `wolfcert-<version>.spdx.json` and the SPDX tag-value file `wolfcert-<version>.spdx` to the build directory. `make install-sbom` installs the three files under `$(docdir)`. When wolfCert is built with `add_subdirectory()`, the CMake target is `wolfcert-sbom`.

The SBOM records:

- the SHA-256 of `libwolfcert` as `make install` or `cmake --install` lays it out, taken from a private install into `_sbom_staging/`;
- the feature set from `wolfcert/options.h`, or from `user_settings.h` as described below, as `wolfssl:build:WOLFCERT_*` properties;
- wolfSSL as a dependency, with the version of the wolfSSL headers the build compiled against. If the build cannot read it, the SBOM target fails; set it with `make sbom SBOM_WOLFSSL_VERSION=...` or `-DWOLFCERT_SBOM_WOLFSSL_VERSION=...`. The CMake value stays in the cache, so clear it after updating wolfSSL;
- the license, `GPL-3.0-or-later`. A commercial licensee can record another SPDX expression with `make sbom SBOM_LICENSE_OVERRIDE=...` or `-DWOLFCERT_SBOM_LICENSE=...`. A `LicenseRef-*` identifier also needs a file with the license text, passed as `SBOM_LICENSE_TEXT=<file>` or `-DWOLFCERT_SBOM_LICENSE_TEXT=<file>`.

`SOURCE_DATE_EPOCH` sets the creation timestamp. In a git checkout `make sbom` defaults it to the time of the last commit, so two runs over the same build give identical files. The CMake target uses the current time unless it is set.

In a `user_settings.h` build (`--enable-user-settings`, `WOLFCERT_USER_SETTINGS`), the feature set is the `WOLFCERT_*` macros that `user_settings.h` or the compiler command line define. `scripts/sbom-user-settings.py` reads them with the build's own compiler and flags, so the header's `#if` blocks resolve as they do for the library. The library tests each `WOLFCERT_HAVE_*` macro with `#ifdef`, so `#define WOLFCERT_HAVE_X 0` still enables the feature, and the SBOM records it with the value `0`. wolfSSL settings in a shared `user_settings.h` are left out, since the SBOM lists wolfSSL as a separate component. This needs GCC or Clang.

## Zephyr

```sh
west build -b <board> <app> -t wolfcert-sbom
```

This writes `wolfcert-<version>.cdx.json` and `wolfcert-<version>.spdx.json` to `build/modules/wolfcert/`. wolfCert is linked into the application image, so there is no library to hash: the SBOM lists the wolfCert sources the build compiles and a hash over them. The feature set comes from the `options.h` the module generates from Kconfig, and the wolfSSL version from the wolfSSL module's `wolfssl/version.h`. The `WOLFCERT_SBOM_*` variables of the CMake build work here too, passed after `--`.

Zephyr's own `west spdx` covers wolfCert too. It needs `CONFIG_BUILD_OUTPUT_META=y` and `west spdx --init` before the build:

```sh
west spdx --init -d build
west build -d build -b <board> <app> -- -DCONFIG_BUILD_OUTPUT_META=y
west spdx -d build
```

`modules-deps.spdx` then lists a `wolfcert-deps` package with the PURL `pkg:github/wolfssl/wolfcert@v<version>` from `zephyr/module.yml`, and with no CPE. That package has no `PackageVersion`, so a scanner reads the version from the PURL.

## Builds without autoconf or CMake

An IDE or RTOS project that compiles the wolfCert sources itself can produce the SBOM by hand. Run these in the wolfCert directory, with the compiler and flags the project uses:

```sh
python3 scripts/sbom-user-settings.py sbom-options.h \
    arm-none-eabi-gcc -DWOLFCERT_USER_SETTINGS -I/path/to/config
python3 tools/sbom/sbom-driver.py --name wolfcert \
    --version-file wolfcert/version.h --version-macro WOLFCERT_VERSION_STRING \
    --srcs-file srcs.txt --options-h sbom-options.h \
    --license-file LICENSE --license-override GPL-3.0-or-later \
    --dep-wolfssl yes --dep-version wolfssl=<wolfSSL version> \
    --cdx-out wolfcert.cdx.json --spdx-out wolfcert.spdx.json
```

`srcs.txt` lists the wolfCert sources the project compiles, one per line, relative to the wolfCert directory. The SBOM then hashes those sources, as on Zephyr. To hash a static library the project builds instead, pass `--lib <path>` in place of `--srcs-file`.

## Updating tools/sbom

Do not edit `tools/sbom/` by hand. Re-vendor it from a wolfssl-compliance-tooling checkout at the commit you want:

```sh
python3 /path/to/wolfssl-compliance-tooling/tools/wolfssl-compliance-tooling-sync --dest .
```

This rewrites the files and the pinned commit in `tools/sbom/.wolfssl-compliance-tooling-rev`. The SBOM workflow fails when `tools/sbom/` differs from that commit. If the toolkit added a file, add it to `EXTRA_DIST` in `Makefile.am`. If it removed one, delete it from `tools/sbom/` and `EXTRA_DIST` yourself: the sync script leaves it in place and the workflow does not notice.
