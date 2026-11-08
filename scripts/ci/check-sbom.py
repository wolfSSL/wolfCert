#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Check the content of a wolfCert SBOM against the build that produced it.

    check-sbom.py <cdx.json> <spdx.json> --options-h <options.h>
                  --wolfssl-version <X.Y.Z> [--sources | --lib <file>]
    check-sbom.py --compare <a.cdx.json> <b.cdx.json>
"""

import argparse
import hashlib
import json
import os
import re
import sys

import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(
    __file__))))
LICENSE = "GPL-3.0-or-later"
DEFINE = re.compile(r"^#define[ \t]+(\w+)(?:[ \t]+(.*?))?[ \t]*$", re.M)
ABS_PATH = re.compile(r"(^|[\s=,:\"'])(/|[A-Za-z]:\\)[^/\s]")

errors = []


def fail(msg):
    errors.append(msg)


def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def wolfcert_version():
    with open(os.path.join(ROOT, "wolfcert", "version.h")) as f:
        m = re.search(r'WOLFCERT_VERSION_STRING\s+"([^"]+)"', f.read())
    return m.group(1)


def module_yml_purls():
    with open(os.path.join(ROOT, "zephyr", "module.yml")) as f:
        doc = yaml.safe_load(f)
    refs = (doc.get("security") or {}).get("external-references") or []
    return [r for r in refs if isinstance(r, str)
            and r.lower().startswith("pkg:github/wolfssl/wolfcert@")]


def options_defines(path):
    with open(path) as f:
        text = f.read()
    return {name: (value or "") for name, value in DEFINE.findall(text)
            if name != "WOLFCERT_OPTIONS_H"}


def strings(node):
    if isinstance(node, dict):
        for v in node.values():
            yield from strings(v)
    elif isinstance(node, list):
        for v in node:
            yield from strings(v)
    elif isinstance(node, str):
        yield node


def props(component, prefix):
    return {p["name"][len(prefix):]: p.get("value", "")
            for p in component.get("properties", [])
            if p["name"].startswith(prefix)}


def identity(cdx):
    m = cdx["metadata"]["component"]
    deps = sorted((c["name"], c.get("version", ""), c.get("purl", ""),
                   c.get("cpe", "")) for c in cdx.get("components", []))
    return {
        "name": m.get("name"),
        "version": m.get("version"),
        "purl": m.get("purl"),
        "licenses": [l.get("license", {}).get("id")
                     for l in m.get("licenses", [])],
        "build": props(m, "wolfssl:build:"),
        "dependencies": deps,
    }


def check(args):
    cdx, spdx = load(args.cdx), load(args.spdx)
    version = wolfcert_version()
    m = cdx["metadata"]["component"]

    if m.get("name") != "wolfcert":
        fail(f"CDX name is {m.get('name')!r}")
    if m.get("version") != version:
        fail(f"CDX version {m.get('version')!r}, version.h says {version!r}")
    purl = f"pkg:github/wolfssl/wolfcert@v{version}"
    if m.get("purl") != purl:
        fail(f"CDX purl {m.get('purl')!r}, expected {purl!r}")
    zephyr_purls = module_yml_purls()
    if zephyr_purls != [purl]:
        fail(f"zephyr/module.yml PURLs {zephyr_purls}, expected [{purl!r}]")
    licenses = identity(cdx)["licenses"]
    if licenses != [LICENSE]:
        fail(f"CDX licenses {licenses}, expected [{LICENSE!r}]")
    if not any(h.get("alg") == "SHA-256" for h in m.get("hashes", [])):
        fail("CDX component has no SHA-256 hash")
    source = props(m, "wolfssl:sbom:").get("hash-source")
    want = "srcs" if args.sources else "lib"
    if source != want:
        fail(f"hash-source is {source!r}, expected {want!r}")

    if args.lib:
        with open(args.lib, "rb") as f:
            digest = hashlib.sha256(f.read()).hexdigest()
        cdx_hash = [h.get("content") for h in m.get("hashes", [])
                    if h.get("alg") == "SHA-256"]
        if cdx_hash != [digest]:
            fail(f"CDX SHA-256 {cdx_hash}, {args.lib} hashes to {digest}")
        pkg = next((p for p in spdx.get("packages", [])
                    if p["name"] == "wolfcert"), {})
        spdx_hash = [c.get("checksumValue") for c in pkg.get("checksums", [])
                     if c.get("algorithm") == "SHA256"]
        if spdx_hash != [digest]:
            fail(f"SPDX SHA256 {spdx_hash}, {args.lib} hashes to {digest}")

    want_build = options_defines(args.options_h)
    got_build = props(m, "wolfssl:build:")
    if got_build != want_build:
        changed = sorted(k for k in got_build.keys() & want_build.keys()
                         if got_build[k] != want_build[k])
        fail(f"build properties differ from {args.options_h}:\n"
             f"  only in SBOM:      {sorted(got_build.keys() - want_build)}\n"
             f"  only in options.h: {sorted(want_build.keys() - got_build)}\n"
             f"  value differs:     {changed}")

    dep = [c.get("version") for c in cdx.get("components", [])
           if c.get("name") == "wolfssl"]
    if dep != [args.wolfssl_version]:
        fail(f"CDX wolfssl dependency versions {dep}, expected "
             f"[{args.wolfssl_version!r}]")

    pkgs = {p["name"]: p for p in spdx.get("packages", [])}
    if pkgs.get("wolfssl", {}).get("versionInfo") != args.wolfssl_version:
        fail(f"SPDX wolfssl package version is "
             f"{pkgs.get('wolfssl', {}).get('versionInfo')!r}")
    rel = ("SPDXRef-Package-wolfcert", "DEPENDS_ON", "SPDXRef-Package-wolfssl")
    rels = {(r["spdxElementId"], r["relationshipType"],
             r["relatedSpdxElement"]) for r in spdx.get("relationships", [])}
    if rel not in rels:
        fail("SPDX has no wolfcert DEPENDS_ON wolfssl relationship")

    for path, doc in ((args.cdx, cdx), (args.spdx, spdx)):
        leaks = sorted({s for s in strings(doc) if ABS_PATH.search(s)})
        if leaks:
            fail(f"{path} records absolute paths: {leaks}")

    summary = (f"{m.get('name')} {m.get('version')}, {len(got_build)} build "
               f"properties, hash-source {source}, wolfssl "
               f"{args.wolfssl_version}")
    return summary


def compare(a_path, b_path):
    a, b = identity(load(a_path)), identity(load(b_path))
    for key in a:
        if a[key] != b[key]:
            fail(f"{key} differs:\n  {a_path}: {a[key]}\n  {b_path}: {b[key]}")
    return f"{a_path} and {b_path} record the same identity and configuration"


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("cdx", nargs="?")
    ap.add_argument("spdx", nargs="?")
    ap.add_argument("--options-h")
    ap.add_argument("--wolfssl-version")
    hash_src = ap.add_mutually_exclusive_group()
    hash_src.add_argument("--sources", action="store_true",
                          help="expect a source-inventory SBOM (Zephyr)")
    hash_src.add_argument("--lib", metavar="FILE",
                          help="the installed library the SBOM hash must "
                               "match")
    ap.add_argument("--compare", nargs=2, metavar="CDX",
                    help="fail if two SBOMs differ in identity, "
                         "configuration or dependencies (hash ignored)")
    args = ap.parse_args()

    if args.compare:
        summary = compare(*args.compare)
    elif args.cdx and args.spdx and args.options_h and args.wolfssl_version:
        summary = check(args)
    else:
        ap.error("pass <cdx> <spdx> --options-h --wolfssl-version, "
                 "or --compare <a> <b>")

    for e in errors:
        print(f"ERROR: {e}", file=sys.stderr)
    if errors:
        return 1
    print(f"SBOM OK: {summary}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
