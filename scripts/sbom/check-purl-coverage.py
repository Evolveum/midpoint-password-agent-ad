#!/usr/bin/env python3
"""
CI gate: fail if any component in a CycloneDX BOM has no PURL.

Dependency-Track routes a component to an analyzer based on its PURL (and, for
NVD, its CPE). A component without a PURL is inventory-only - it will never
produce a vulnerability finding. This check makes that failure mode loud.

Usage:
  python scripts/sbom/check-purl-coverage.py sbom/midpoint-password-agent-ad.cdx.json
  python scripts/sbom/check-purl-coverage.py sbom/*.cdx.json --warn-missing-cpe
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys


def iter_components(components):
    for comp in components or []:
        yield comp
        yield from iter_components(comp.get("components"))


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("boms", nargs="+")
    ap.add_argument("--warn-missing-cpe", action="store_true",
                    help="also report vcpkg components with no CPE (informational only)")
    args = ap.parse_args(argv)

    failed = False
    for name in args.boms:
        path = pathlib.Path(name)
        bom = json.loads(path.read_text(encoding="utf-8"))
        comps = list(iter_components(bom.get("components")))
        root = bom.get("metadata", {}).get("component")
        if root:
            comps.append(root)

        missing = [c.get("name", "<unnamed>") for c in comps if not c.get("purl")]
        no_cpe = [c.get("name") for c in comps
                  if str(c.get("purl", "")).startswith("pkg:vcpkg/") and not c.get("cpe")]

        print(f"{path}: {len(comps)} components, {len(comps) - len(missing)} with PURL")
        if missing:
            failed = True
            print(f"  ERROR missing PURL: {', '.join(sorted(missing))}", file=sys.stderr)
        if args.warn_missing_cpe and no_cpe:
            print(f"  WARN  vcpkg components without CPE (no NVD matching): {', '.join(sorted(no_cpe))}")

    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
