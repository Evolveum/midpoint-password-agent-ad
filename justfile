set windows-shell := ["powershell.exe", "-NoLogo", "-Command"]

# Check whether the application is fully installed or removed
[windows]
check-installation:
  powershell.exe -ExecutionPolicy Bypass -File .\installation\CheckInstallation.ps1

# Install listener .dll and sender.exe into windows system
[windows]
install:
  powershell.exe -ExecutionPolicy Bypass -File .\installation\Install.ps1 -DllPath .\listener\build\MidPointPasswordAgentListener.dll -SenderExePath .\sender\bin\Release\net10.0\win-x64\publish\sender.exe

# Uninstall listener .dll and sender.exe from windows system
[windows]
uninstall:
  powershell.exe -ExecutionPolicy Bypass -File .\installation\Uninstall.ps1

# Import register file with values
[windows]
import-registers:
  reg import installation\MidPointPasswordAgent.reg

[windows]
change-password identity password:
  Set-ADAccountPassword -Identity {{identity}} -NewPassword (ConvertTo-SecureString {{password}} -AsPlainText -Force) -Reset

# Install listener .dll and sender.exe into windows system
[windows]
create-key:
  powershell.exe -ExecutionPolicy Bypass -File .\installation\CreateAESKeyInRegistry.ps1 -registryPath "HKLM:\\SOFTWARE\\Evolveum\\MidPointPasswordAgent\\Keys"

# Encode a plain-text password to base64 for use in config.json
[windows]
encode-password password:
  [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("{{password}}"))

# Create .msi installation file for entire app
[windows]
build-installer:
  dotnet restore Installer.wixproj
  dotnet build Installer.wixproj -c Release --no-restore -p:Platform=x64

############################################################################
################################# Listener #################################
############################################################################

# Build the listener DLL on macOS using MinGW cross-compilation
[macos, group("listener")]
listener-build:
  cmake -B listener/build \
    -S listener \
    -DCMAKE_TOOLCHAIN_FILE=$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake \
    -DVCPKG_CHAINLOAD_TOOLCHAIN_FILE=$(pwd)/cmake/toolchain-mingw64.cmake \
    -DVCPKG_TARGET_TRIPLET=x64-mingw-static \
    -DVCPKG_APPLOCAL_DEPS=OFF \
    -DVCPKG_INSTALLED_DIR=$(pwd)/vcpkg_installed \
    -DCMAKE_BUILD_TYPE=Release
  cmake --build listener/build

# Clean build folder
[macos, group("listener")]
listener-clean:
  rm -rf listener/build
  rm -rf listener/build-tests
  rm -rf listener/build-lint

# Generate compile_commands.json for clangd IDE support (src + tests)
# Run once after cloning or adding new files; does not affect the real build
[macos, group("listener")]
listener-ide:
  cmake -B listener/build \
    -S listener \
    -DCMAKE_TOOLCHAIN_FILE=$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake \
    -DVCPKG_CHAINLOAD_TOOLCHAIN_FILE=$(pwd)/cmake/toolchain-mingw64.cmake \
    -DVCPKG_TARGET_TRIPLET=x64-mingw-static \
    -DVCPKG_APPLOCAL_DEPS=OFF \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
  cmake -B listener/build-tests \
    -S listener/tests \
    -DCMAKE_TOOLCHAIN_FILE=$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake \
    -DVCPKG_CHAINLOAD_TOOLCHAIN_FILE=$(pwd)/cmake/toolchain-mingw64.cmake \
    -DVCPKG_TARGET_TRIPLET=x64-mingw-static \
    -DVCPKG_APPLOCAL_DEPS=OFF \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
    -DVCPKG_MANIFEST_DIR=listener

# Clean build folder
[windows, group("listener")]
listener-clean:
  Remove-Item -Recurse -Force listener\build
  Remove-Item -Recurse -Force listener\build-tests
  Remove-Item -Recurse -Force listener\build-lint

# Build the listener DLL on Windows using MSVC
# Requires MSVC environment initialized in PowerShell (see $PROFILE setup in docs)
[windows, group("listener")]
listener-build:
    cmake -B listener/build -S listener -G "Visual Studio 17 2022" -DCMAKE_BUILD_TYPE=Release "-DCMAKE_TOOLCHAIN_FILE=$env:VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake" -DVCPKG_TARGET_TRIPLET=x64-windows-static "-DVCPKG_INSTALLED_DIR=$(Get-Location)/vcpkg_installed" -DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded$<$<CONFIG:Release>:>$<$<CONFIG:Debug>:Debug>
    cmake --build listener/build --config Release

# Run clang-tidy static analysis on all listener source files
# Requires clang-tidy installed and on PATH (install via LLVM for Windows)
[windows, group("listener")]
listener-lint:
    cmake -B listener/build-lint -S listener -G "Visual Studio 17 2022" -DCMAKE_BUILD_TYPE=Debug -DENABLE_CLANG_TIDY=ON "-DCMAKE_TOOLCHAIN_FILE=$env:VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake"
    cmake --build listener/build-lint

# Build and run unit tests on Windows (standalone - no DLL build required)
# Requires MSVC environment initialized in PowerShell (see $PROFILE setup in docs)
[windows, group("listener")]
listener-test:
    cmake -B listener/build-tests -S listener/tests -G "Visual Studio 17 2022" "-DCMAKE_TOOLCHAIN_FILE=$env:VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake" -DVCPKG_MANIFEST_DIR=listener
    cmake --build listener/build-tests --config Debug
    ctest --test-dir listener/build-tests -C Debug --output-on-failure

# Generate compile_commands.json for clangd IDE support (src + tests)
# Run once after cloning or adding new files; does not affect the real build
[windows, group("listener")]
listener-ide:
    cmake -B listener/build -S listener -G Ninja "-DCMAKE_TOOLCHAIN_FILE=$env:VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake" -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
    cmake -B listener/build-tests -S listener/tests -G Ninja "-DCMAKE_TOOLCHAIN_FILE=$env:VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake" -DVCPKG_MANIFEST_DIR=listener -DCMAKE_EXPORT_COMPILE_COMMANDS=ON



############################################################################
################################## Sender ##################################
############################################################################

# Build sender module, using dotnet CLI tool
[group("sender")]
sender-build:
  dotnet build sender
  
# Publish sender module sender.exe file, using dotnet CLI tool
[group("sender")]
sender-publish:
  dotnet publish sender -c Release -r win-x64 --self-contained true -p:PublishTrimmed=true -p:Platform=AnyCPU

# Run test for sender module, using dotnet CLI tool
[group("sender")]
sender-test:
  dotnet test sender.Tests --logger "console;verbosity=normal"

# Run C# sender.exe application locally (sender.exe can be created with sender-publish recipe)
[windows, group("sender")]
sender-run-locally:
  .\sender\bin\Release\net10.0\win-x64\publish\sender.exe

# Delete Windows service for sender
[windows, group("sender")]
sender-delete-service:
  sc.exe delete MidPointPasswordAgentSender

# Run mock server
[group("sender")]
server-mock *args:
  dotnet run --project MockServer -- {{args}}


############################################################################
################################## Sender DPAPI lib ########################
############################################################################
[windows, group("sender-dpapi")]
sender-libs-build:
  dotnet publish sender.DPAPI -c Release -r win-x64 --self-contained true -p:Platform=AnyCPU


############################################################################
################################### SBOM ###################################
############################################################################
# Produces CycloneDX 1.6 BOMs in which every component carries a PURL, so the
# result can be uploaded to DependencyTrack as-is.
#   listener    -> pkg:vcpkg/...  (+ CPE from scripts/sbom/cpe-map.json)
#   sender      -> pkg:nuget/...
#   sender.DPAPI-> pkg:nuget/...
# See docs/development/sbom.md

# Version defaults to the current git tag (v1.0.1 -> 1.0.1); past a tag you get
# e.g. 1.0.1-3-g0625730. Override positionally: `just sbom 1.2.3`.
# Backticks, not shell(): shell() passes the command to the shell twice (as the
# script and as $0), and powershell -Command concatenates both copies, so git
# receives "git" as an extra revision argument.
sbom_version   := replace_regex(trim(`git describe --tags --always --abbrev=7`), '^v', '')
sbom_out       := "sbom"
sbom_triplet   := if os() == "windows" { "x64-windows-static" } else { "x64-mingw-static" }
sbom_installed := "vcpkg_installed"
sbom_group     := "com.evolveum"
sbom_product   := "midpoint-password-agent-ad"
sbom_supplier  := "Evolveum s.r.o."

# C++ listener: vcpkg SPDX -> CycloneDX (PURL + CPE)
[group("sbom")]
sbom-listener version=sbom_version:
  vcpkg install --x-manifest-root=listener --x-install-root={{sbom_installed}} --triplet={{sbom_triplet}}
  python scripts/sbom/vcpkg-cyclonedx.py \
    --installed-dir {{sbom_installed}} \
    --triplet {{sbom_triplet}} \
    --cpe-map scripts/sbom/cpe-map.json \
    --component-name MidPointPasswordAgentListener \
    --component-version {{version}} \
    --component-purl "pkg:generic/midpoint-password-agent-listener@{{version}}" \
    --output {{sbom_out}}/listener.cdx.json
  python scripts/sbom/set-root-purl.py {{sbom_out}}/listener.cdx.json \
    --purl "pkg:generic/midpoint-password-agent-listener@{{version}}" \
    --supplier "{{sbom_supplier}}" --author "Evolveum" \
    --description "midPoint Password Agent for AD - C++ LSA password notification filter"

# C# sender service
[group("sbom")]
sbom-sender version=sbom_version:
  dotnet-CycloneDX sender/sender.csproj -o {{sbom_out}} -fn sender.cdx.json \
    --output-format Json --spec-version 1.6 --exclude-dev --exclude-test-projects \
    -tfm net10.0 -rt win-x64 \
    --set-name sender --set-version {{version}} --set-type Application
  python scripts/sbom/set-root-purl.py {{sbom_out}}/sender.cdx.json \
    --purl "pkg:generic/midpoint-password-agent-sender@{{version}}" \
    --supplier "{{sbom_supplier}}" --author "Evolveum" \
    --description "midPoint Password Agent for AD - C# Windows service"

# C# installer custom actions (net48)
[group("sbom")]
sbom-sender-dpapi version=sbom_version:
  dotnet-CycloneDX sender.DPAPI/sender.DPAPI.csproj -o {{sbom_out}} -fn sender.DPAPI.cdx.json \
    --output-format Json --spec-version 1.6 --exclude-dev --exclude-test-projects \
    -tfm net48 \
    --set-name sender.DPAPI --set-version {{version}} --set-type Library
  python scripts/sbom/set-root-purl.py {{sbom_out}}/sender.DPAPI.cdx.json \
    --purl "pkg:generic/midpoint-password-agent-sender-dpapi@{{version}}" \
    --supplier "{{sbom_supplier}}" --author "Evolveum" \
    --description "midPoint Password Agent for AD - WiX DTF custom actions"

# WiX installer toolchain (requires access to the GitHub NuGet feed)
[windows, group("sbom")]
sbom-installer version=sbom_version:
  dotnet-CycloneDX Installer.wixproj -o {{sbom_out}} -fn installer.cdx.json \
    --output-format Json --spec-version 1.6 --exclude-dev \
    --set-name Installer --set-version {{version}} --set-type Application
  python scripts/sbom/set-root-purl.py {{sbom_out}}/installer.cdx.json \
    --purl "pkg:generic/midpoint-password-agent-installer@{{version}}" \
    --supplier "{{sbom_supplier}}" --author "Evolveum" \
    --description "midPoint Password Agent for AD - WiX installer"

# Everything, merged into one hierarchical product BOM
[group("sbom")]
sbom version=sbom_version: (sbom-listener version) (sbom-sender version) (sbom-sender-dpapi version)
  cyclonedx merge \
    --input-files {{sbom_out}}/listener.cdx.json {{sbom_out}}/sender.cdx.json {{sbom_out}}/sender.DPAPI.cdx.json \
    --input-format json --output-format json --output-version v1_6 --hierarchical \
    --group {{sbom_group}} --name {{sbom_product}} --version {{version}} \
    --output-file {{sbom_out}}/{{sbom_product}}.cdx.json
  python scripts/sbom/set-root-purl.py {{sbom_out}}/{{sbom_product}}.cdx.json \
    --purl "pkg:generic/{{sbom_product}}@{{version}}" \
    --supplier "{{sbom_supplier}}" --author "Evolveum" \
    --description "midPoint Password Agent for Active Directory"
  cyclonedx validate --input-file {{sbom_out}}/{{sbom_product}}.cdx.json --input-format json --fail-on-errors
  python scripts/sbom/check-purl-coverage.py {{sbom_out}}/{{sbom_product}}.cdx.json --warn-missing-cpe

# Refresh the human-readable dependency lists from the generated BOMs
[group("sbom")]
sbom-deps-txt:
  python scripts/sbom/bom-to-dependencies-txt.py {{sbom_out}}/listener.cdx.json --output listener/dependencies.txt
  python scripts/sbom/bom-to-dependencies-txt.py {{sbom_out}}/sender.cdx.json {{sbom_out}}/sender.DPAPI.cdx.json --output dependencies.txt

# Push the aggregate BOM to DependencyTrack
# Requires DTRACK_URL and DTRACK_API_KEY in the environment.
[group("sbom")]
sbom-upload version=sbom_version:
  curl -X POST "$DTRACK_URL/api/v1/bom" \
    -H "X-Api-Key: $DTRACK_API_KEY" \
    -F "autoCreate=true" \
    -F "projectName={{sbom_product}}" \
    -F "projectVersion={{version}}" \
    -F "bom=@{{sbom_out}}/{{sbom_product}}.cdx.json"

[group("sbom")]
sbom-clean:
  python -c "import shutil,pathlib; shutil.rmtree('{{sbom_out}}', ignore_errors=True)"
