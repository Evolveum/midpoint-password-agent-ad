#!/usr/bin/env python3
"""
Convert the SPDX SBOM files that vcpkg emits per installed port into a single,
Dependency-Track-friendly CycloneDX 1.6 JSON document.

Why not `cyclonedx-cli convert`?
  A plain SPDX -> CycloneDX conversion of vcpkg output produces:
    * one document per port (no aggregation, no dependency graph),
    * three pseudo-components per port (port / binary / downloaded resource),
    * versions in vcpkg's "1.2.3#4" form, which Dependency-Track cannot
      version-compare,
    * license data buried in `properties` instead of `licenses`,
    * no CPE, so Dependency-Track's internal NVD analyzer never fires.
  This script emits exactly one component per port with a clean PURL, a
  normalised version, a real `licenses` entry and an optional CPE.

Usage:
  python scripts/sbom/vcpkg-cyclonedx.py \
      --installed-dir vcpkg_installed \
      --triplet x64-windows-static \
      --component-name MidPointPasswordAgentListener \
      --component-version 1.0.0 \
      --output sbom/listener.cdx.json
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import pathlib
import re
import sys
import uuid
from urllib.parse import quote

SPEC_VERSION = "1.6"
TOOL_NAME = "vcpkg-cyclonedx.py"
TOOL_VERSION = "1.0.0"

# Ports that are vcpkg's own build helpers. They ship no code into the final
# binary, so by default they are left out of the BOM.
BUILD_HELPER_RE = re.compile(r"^vcpkg-")


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--installed-dir", default="vcpkg_installed",
                   help="vcpkg install root (the --x-install-root value). Default: vcpkg_installed")
    p.add_argument("--triplet", required=True, help="e.g. x64-windows-static")
    p.add_argument("--output", required=True, help="output CycloneDX JSON path")
    p.add_argument("--component-name", required=True, help="name of the thing being described (root component)")
    p.add_argument("--component-version", default="0.0.0", help="version of the root component")
    p.add_argument("--component-type", default="library", choices=["library", "application", "firmware"])
    p.add_argument("--component-purl", default=None,
                   help="explicit PURL for the root component (default: pkg:generic/<name>@<version>)")
    p.add_argument("--cpe-map", default=None, help="JSON file mapping port name -> CPE template")
    p.add_argument("--include-build-tools", action="store_true",
                   help="also emit vcpkg-* helper ports (marked scope=excluded)")
    p.add_argument("--registry-url", default=None,
                   help="PURL repository_url qualifier for non-default registries")
    return p.parse_args(argv)


def split_version(version_info: str) -> tuple[str, str | None]:
    """'1.17.0#1' -> ('1.17.0', '1'); '2024-04-23' -> ('2024-04-23', None)"""
    if "#" in version_info:
        upstream, port_version = version_info.rsplit("#", 1)
        return upstream, port_version
    return version_info, None


def build_purl(name: str, upstream: str, port_version: str | None, triplet: str,
               registry_url: str | None) -> str:
    """Fallback PURL builder, used when vcpkg is too old to emit externalRefs."""
    qualifiers = []
    if port_version:
        qualifiers.append(("port_version", port_version))
    qualifiers.append(("triplet", triplet))
    if registry_url:
        qualifiers.append(("repository_url", registry_url))
    q = "&".join(f"{k}={quote(str(v), safe='')}" for k, v in qualifiers)
    return f"pkg:vcpkg/{quote(name, safe='')}@{quote(upstream, safe='')}" + (f"?{q}" if q else "")


def purl_from_spdx(port_pkg: dict) -> str | None:
    for ref in port_pkg.get("externalRefs", []):
        if ref.get("referenceType") == "purl":
            return ref.get("referenceLocator")
    return None


def read_status_depends(installed_dir: pathlib.Path, triplet: str) -> dict[str, list[str]]:
    """Parse vcpkg_installed/vcpkg/status into {port: [dependency ports]}."""
    status = installed_dir / "vcpkg" / "status"
    graph: dict[str, list[str]] = {}
    if not status.is_file():
        return graph
    for block in status.read_text(encoding="utf-8").split("\n\n"):
        fields = {}
        for line in block.splitlines():
            if ": " in line:
                k, v = line.split(": ", 1)
                fields[k.strip()] = v.strip()
        name = fields.get("Package")
        if not name or fields.get("Architecture") != triplet:
            continue
        deps = [d.strip().split("[")[0] for d in fields.get("Depends", "").split(",") if d.strip()]
        graph[name] = deps
    return graph


def source_hashes(packages: list[dict]) -> list[dict]:
    """SHA-512 of the upstream source artifacts recorded by vcpkg."""
    out = []
    for pkg in packages:
        if not str(pkg.get("SPDXID", "")).startswith("SPDXRef-resource"):
            continue
        for cs in pkg.get("checksums", []):
            alg = cs.get("algorithm", "").upper()
            if alg in {"SHA-512", "SHA512"}:
                out.append({"alg": "SHA-512", "content": cs["checksumValue"]})
            elif alg in {"SHA-256", "SHA256"}:
                out.append({"alg": "SHA-256", "content": cs["checksumValue"]})
    return out[:1]  # CycloneDX allows one hash per algorithm; keep the primary source


def upstream_vcs(packages: list[dict]) -> tuple[str, str | None] | None:
    """('https://github.com/fmtlib/fmt', '12.2.0') from 'git+https://...fmt@12.2.0'."""
    for pkg in packages:
        if str(pkg.get("SPDXID", "")).startswith("SPDXRef-resource"):
            loc = pkg.get("downloadLocation", "")
            if loc.startswith("git+"):
                url = loc[len("git+"):]
                if "@" in url.rsplit("/", 1)[-1]:
                    url, ref = url.rsplit("@", 1)
                    return url, ref
                return url, None
    return None


def make_component(spdx: dict, triplet: str, cpe_map: dict, registry_url: str | None,
                   include_build_tools: bool) -> dict | None:
    packages = spdx.get("packages", [])
    port = next((p for p in packages if p.get("SPDXID") == "SPDXRef-port"), None)
    if port is None:
        return None

    name = port["name"]
    is_helper = bool(BUILD_HELPER_RE.match(name))
    if is_helper and not include_build_tools:
        return None

    upstream, port_version = split_version(port.get("versionInfo", "0"))
    purl = purl_from_spdx(port) or build_purl(name, upstream, port_version, triplet, registry_url)

    comp: dict = {
        "bom-ref": purl,
        "type": "library",
        "name": name,
        "version": upstream,          # normalised: Dependency-Track can compare this
        "purl": purl,
    }
    if is_helper:
        comp["scope"] = "excluded"

    if port.get("description"):
        comp["description"] = port["description"]

    lic = port.get("licenseConcluded") or port.get("licenseDeclared")
    if lic and lic != "NOASSERTION":
        comp["licenses"] = [{"expression": lic}]

    cpe_tpl = cpe_map.get(name)
    if cpe_tpl:
        comp["cpe"] = cpe_tpl.replace("{version}", upstream)

    refs = []
    if port.get("homepage"):
        refs.append({"type": "website", "url": port["homepage"]})
    vcs = upstream_vcs(packages)
    if vcs:
        refs.append({"type": "vcs", "url": vcs[0]})
    refs.append({"type": "distribution", "url": port.get("downloadLocation", "")})
    comp["externalReferences"] = [r for r in refs if r.get("url") and r["url"] != "NONE"]

    hashes = source_hashes(packages)
    if hashes:
        comp["hashes"] = hashes

    props = [{"name": "vcpkg:triplet", "value": triplet}]
    if vcs and vcs[1]:
        props.append({"name": "vcpkg:source-ref", "value": vcs[1]})
    if port_version:
        props.append({"name": "vcpkg:port-version", "value": port_version})
    binary = next((p for p in packages if p.get("SPDXID") == "SPDXRef-binary"), None)
    if binary and binary.get("versionInfo"):
        props.append({"name": "vcpkg:abi-hash", "value": binary["versionInfo"]})
    comp["properties"] = props

    return comp


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    installed = pathlib.Path(args.installed_dir)
    share = installed / args.triplet / "share"
    if not share.is_dir():
        print(f"error: {share} not found - run `vcpkg install` first", file=sys.stderr)
        return 1

    cpe_map = {}
    if args.cpe_map:
        cpe_map = json.loads(pathlib.Path(args.cpe_map).read_text(encoding="utf-8"))

    components: list[dict] = []
    seen: set[str] = set()
    for spdx_file in sorted(share.glob("*/vcpkg.spdx.json")):
        spdx = json.loads(spdx_file.read_text(encoding="utf-8"))
        comp = make_component(spdx, args.triplet, cpe_map, args.registry_url, args.include_build_tools)
        if comp and comp["name"] not in seen:
            seen.add(comp["name"])
            components.append(comp)

    root_purl = args.component_purl or f"pkg:generic/{args.component_name}@{args.component_version}"
    root = {
        "bom-ref": root_purl,
        "type": args.component_type,
        "name": args.component_name,
        "version": args.component_version,
        "purl": root_purl,
    }

    by_name = {c["name"]: c["bom-ref"] for c in components}
    depends = read_status_depends(installed, args.triplet)
    dependencies = [{
        "ref": root_purl,
        "dependsOn": sorted({by_name[n] for n in by_name if n in depends and not BUILD_HELPER_RE.match(n)}),
    }]
    for comp in components:
        edges = sorted({by_name[d] for d in depends.get(comp["name"], []) if d in by_name})
        dependencies.append({"ref": comp["bom-ref"], "dependsOn": edges})

    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "tools": {"components": [{"type": "application", "name": TOOL_NAME, "version": TOOL_VERSION}]},
            "component": root,
        },
        "components": components,
        "dependencies": dependencies,
    }

    out = pathlib.Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(bom, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {out} ({len(components)} components)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
