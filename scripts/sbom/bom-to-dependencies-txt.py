#!/usr/bin/env python3
"""
Render the human-readable dependencies.txt from one or more CycloneDX BOMs.

This replaces listener/vcpkg-licenses.sh, which had to shell out to `jq` against
a local vcpkg ports checkout. Deriving the table from the BOM guarantees that
the text file and the machine-readable SBOM can never drift apart.

Usage:
  python scripts/sbom/bom-to-dependencies-txt.py sbom/listener.cdx.json --output listener/dependencies.txt
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


def license_of(comp: dict) -> str:
    out = []
    for entry in comp.get("licenses", []):
        if "expression" in entry:
            out.append(entry["expression"])
        elif "license" in entry:
            lic = entry["license"]
            out.append(lic.get("id") or lic.get("name") or "")
    return ", ".join(x for x in out if x) or "unknown"


def homepage_of(comp: dict) -> str:
    refs = {r.get("type"): r.get("url") for r in comp.get("externalReferences", [])}
    return refs.get("website") or refs.get("vcs") or refs.get("distribution") or "unknown"


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("boms", nargs="+")
    ap.add_argument("--output", required=True)
    ap.add_argument("--include-excluded", action="store_true",
                    help="also list components with scope=excluded (vcpkg build helpers)")
    args = ap.parse_args(argv)

    rows: dict[tuple[str, str], tuple[str, str, str]] = {}
    for name in args.boms:
        bom = json.loads(pathlib.Path(name).read_text(encoding="utf-8"))
        for comp in iter_components(bom.get("components")):
            if comp.get("scope") == "excluded" and not args.include_excluded:
                continue
            if not comp.get("purl"):
                continue
            key = (comp["name"], comp.get("version", ""))
            rows[key] = (comp.get("version", ""), license_of(comp), homepage_of(comp))

    lines = ["{:<40} {:<16} {:<16} {}".format("Package", "Version", "License", "HomePage"),
             "{:<40} {:<16} {:<16} {}".format("-------", "-------", "-------", "-------")]
    for (name, _), (version, lic, home) in sorted(rows.items(), key=lambda kv: kv[0][0].lower()):
        lines.append("{:<40} {:<16} {:<16} {}".format(name, version, lic, home))

    out = pathlib.Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {out} ({len(rows)} packages)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
