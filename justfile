set windows-shell := ["powershell.exe", "-NoLogo", "-Command"]

# Check whether the application is fully installed or removed
[windows]
check-installation:
  powershell.exe -ExecutionPolicy Bypass -File .\installation\CheckInstallation.ps1

# Install listener .dll and sender.exe into windows system
[windows]
install: import-registers
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
    cmake -B listener/build -S listener -G "Visual Studio 17 2022" -DCMAKE_BUILD_TYPE=Release "-DCMAKE_TOOLCHAIN_FILE=$env:VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake" -DVCPKG_TARGET_TRIPLET=x64-windows-static -DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded$<$<CONFIG:Release>:>$<$<CONFIG:Debug>:Debug>
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

# Create Windows Service for sender module with path to binary(.exe) file
[windows, group("sender")]
sender-create-service path='Z:\ad-midpoint-password-sync\sender\bin\Release\net10.0\win-x64\publish\sender.exe':
  sc.exe create MidPointPasswordAgentSender binPath={{path}}

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