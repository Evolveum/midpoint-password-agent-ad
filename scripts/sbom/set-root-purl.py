#!/usr/bin/env python3
"""
Stamp a PURL / bom-ref (and optionally supplier + author) onto the
`metadata.component` of a CycloneDX BOM.

The CycloneDX .NET tool does not emit a PURL for the project it describes, so
Dependency-Track shows the root component without an identifier. Running this
after generation makes every node in the merged BOM addressable.

Usage:
  python scripts/sbom/set-root-purl.py sbom/sender.cdx.json \
      --purl "pkg:generic/midpoint-password-agent-sender@1.0.0" \
      --supplier "Evolveum s.r.o." --author "Evolveum"
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("bom", help="CycloneDX JSON file to patch in place")
    ap.add_argument("--purl", required=True)
    ap.add_argument("--supplier", default=None)
    ap.add_argument("--author", default=None)
    ap.add_argument("--description", default=None)
    args = ap.parse_args(argv)

    path = pathlib.Path(args.bom)
    bom = json.loads(path.read_text(encoding="utf-8"))
    meta = bom.setdefault("metadata", {})
    comp = meta.setdefault("component", {})

    old_ref = comp.get("bom-ref")
    comp["purl"] = args.purl
    comp["bom-ref"] = args.purl
    if args.description:
        comp["description"] = args.description
    if args.supplier:
        comp["supplier"] = {"name": args.supplier}
        meta["supplier"] = {"name": args.supplier}
    if args.author:
        meta["authors"] = [{"name": args.author}]

    # Keep the dependency graph consistent with the new root bom-ref.
    if old_ref and old_ref != args.purl:
        for dep in bom.get("dependencies", []):
            if dep.get("ref") == old_ref:
                dep["ref"] = args.purl
            dep["dependsOn"] = [args.purl if d == old_ref else d for d in dep.get("dependsOn", [])]

    path.write_text(json.dumps(bom, indent=2) + "\n", encoding="utf-8")
    print(f"patched {path}: metadata.component.purl = {args.purl}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
