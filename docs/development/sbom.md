# SBOM generation

This project ships a CycloneDX 1.6 Software Bill of Materials that can be uploaded to
[OWASP Dependency-Track](https://dependencytrack.org/) without any post-processing. Every
component in the BOM carries a [Package URL (PURL)](https://github.com/package-url/purl-spec),
which is what Dependency-Track uses to route a component to a vulnerability analyzer.

## What gets produced

| File | Covers | PURL type |
|---|---|---|
| `sbom/listener.cdx.json` | C++ listener, vcpkg ports | `pkg:vcpkg/...` |
| `sbom/sender.cdx.json` | C# Windows service, NuGet closure | `pkg:nuget/...` |
| `sbom/sender.DPAPI.cdx.json` | net48 WiX custom actions | `pkg:nuget/...` |
| `sbom/installer.cdx.json` | WiX toolset packages (optional) | `pkg:nuget/...` |
| `sbom/midpoint-password-agent-ad.cdx.json` | **aggregate**, hierarchical - upload this one | mixed |

## Manual build

Prerequisites (one-off):

```powershell
dotnet tool install --global CycloneDX                  # NuGet -> CycloneDX
winget install CycloneDX.cyclonedx-cli                  # merge/validate (or grab the release binary)
# Python 3.9+ must be on PATH; no third-party packages are required.
```

Then:

```powershell
just sbom                          # generates everything + merges + validates
just sbom version=1.0.1            # ... with an explicit version
just sbom-listener                 # C++ only
just sbom-sender                   # C# service only
just sbom-deps-txt                 # refresh the human-readable dependencies.txt files
just sbom-upload                   # POST to $DTRACK_URL using $DTRACK_API_KEY
```

The version defaults to `git describe --tags --always --abbrev=7` with the leading `v`
stripped, so on a release tag you get `1.0.1` and in between you get `1.0.1-3-g0625730`.
Dependency-Track treats each version as a separate project version, so the intermediate form
is a useful signal that someone uploaded a non-release build.

`just sbom` fails if the merged BOM does not validate, or if any component is missing a PURL.

## How the C++ side works

vcpkg writes an SPDX document per installed port to
`vcpkg_installed/<triplet>/share/<port>/vcpkg.spdx.json`, and recent vcpkg-tool releases
include a `pkg:vcpkg/...` PURL in the `externalRefs` of each port package.

`cyclonedx convert --input-format spdxjson` on those files is *not* good enough for
Dependency-Track:

* it produces one BOM per port, with no aggregation and no dependency graph;
* each port yields three pseudo-components (port recipe / built binary / downloaded source);
* versions keep vcpkg's `1.17.0#1` form, which Dependency-Track cannot version-compare;
* licenses end up in `properties`, not in `licenses`;
* no CPE is emitted.

`scripts/sbom/vcpkg-cyclonedx.py` reads the same SPDX files and emits one clean component per
port: normalised version, PURL, `licenses`, source SHA-512, upstream homepage/VCS links, the
`vcpkg:triplet` / `vcpkg:port-version` / `vcpkg:abi-hash` properties, and a dependency graph
derived from `vcpkg_installed/vcpkg/status`. vcpkg's own `vcpkg-*` helper ports are omitted by
default (`--include-build-tools` keeps them with `scope: excluded`).

### PURL vs CPE for C/C++

`pkg:vcpkg` is **not yet a registered PURL type** - the specification PR
([purl-spec#245](https://github.com/package-url/purl-spec/pull/245)) is still open. Dependency-Track
will happily store and display the PURL, and it gives components a stable identity for
inventory, dependency graphs and policy rules - but OSS Index, OSV and Snyk cannot resolve it,
so the PURL alone produces **no vulnerability findings** for native code today.

What does work is Dependency-Track's *internal* analyzer, which matches components against the
mirrored NVD data using [CPE](https://nvd.nist.gov/products/cpe). For that reason
`scripts/sbom/cpe-map.json` maps each vcpkg port to a verified CPE 2.3 string, and the generator
emits both `purl` and `cpe` on the same component.

**When adding a new vcpkg dependency, add its CPE to `scripts/sbom/cpe-map.json`.** Look the
vendor/product slug up in the [NVD CPE dictionary](https://nvd.nist.gov/products/cpe/search) -
guessing produces silent false negatives. Ports with no dictionary entry at all (currently `fmt`
and `cppcodec`) are intentionally left unmapped; `just sbom` prints them as a warning.

## Reproducibility

`listener/vcpkg.json` carries a `builtin-baseline` so that the resolved port versions - and
therefore the SBOM - are identical on every machine and in CI. Bump it deliberately, the same way
you would bump a NuGet version.

The CI job refreshes the runner's bundled vcpkg before installing, because the GitHub Windows
image can ship a vcpkg-tool that predates PURL emission.

## Dependency-Track setup

Repository variable `DEPENDENCYTRACK_HOSTNAME` and secret `DEPENDENCYTRACK_APIKEY` drive the
upload step in `.github/workflows/sbom.yml`. The API key's team needs `BOM_UPLOAD`,
`PROJECT_CREATION_UPLOAD` and `VIEW_PORTFOLIO`.

Because the aggregate BOM is hierarchical, Dependency-Track shows one project
(`midpoint-password-agent-ad`) with the listener, sender and custom-action assemblies as
top-level components and their dependencies nested underneath.
