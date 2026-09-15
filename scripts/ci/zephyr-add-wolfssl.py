#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Add wolfSSL to a Zephyr west manifest.

Usage: zephyr-add-wolfssl.py <west.yml> <revision>

wolfCert needs wolfSSL features the upstream manifest does not carry, and
calls wc_SetDNSEntry(), which is in no release tag. Idempotent.
"""

import sys

REMOTE = """    - name: wolfssl
      url-base: https://github.com/wolfssl
"""

ANCHOR_REMOTE = """    - name: babblesim
      url-base: https://github.com/BabbleSim
"""

ANCHOR_PROJECT = "  # zephyr-keep-sorted-stop"


def main(path, revision):
    with open(path) as f:
        text = f.read()

    if "url-base: https://github.com/wolfssl" in text:
        print(f"{path}: wolfSSL already present")
        return 0

    if ANCHOR_REMOTE not in text or ANCHOR_PROJECT not in text:
        print(f"{path}: anchors not found; manifest layout changed", file=sys.stderr)
        return 1

    text = text.replace(ANCHOR_REMOTE, ANCHOR_REMOTE + REMOTE, 1)
    project = (
        f"{ANCHOR_PROJECT}\n"
        f"    - name: wolfssl\n"
        f"      revision: {revision}\n"
        f"      path: modules/crypto/wolfssl\n"
        f"      remote: wolfssl"
    )
    text = text.replace(ANCHOR_PROJECT, project, 1)

    with open(path, "w") as f:
        f.write(text)
    print(f"{path}: added wolfSSL at {revision}")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    sys.exit(main(sys.argv[1], sys.argv[2]))
