set(CMAKE_TOOLCHAIN_FILE "$ENV{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake" CACHE STRING "")

cmake_minimum_required(VERSION 3.20)
project(MidPointPasswordAgentListener CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Target Windows Server 2016+ (0x0A00 = Windows 10 / Server 2016)
add_compile_definitions(
    _WIN32_WINNT=0x0A00
    WINVER=0x0A00
    WIN32_LEAN_AND_MEAN
    NOMINMAX
)

set(SOURCES
    src/dllmain.cpp
    src/PasswordFilter.cpp
    src/logger/logger.cpp
    src/queue/password_event.cpp
    src/queue/queue_writer.cpp
    src/crypto/crypto.cpp
    src/config/config_watcher.cpp
    src/config/app_config.cpp
)

set(HEADERS
    src/pch.h
    src/Common.h
    src/PasswordFilter.h
    src/PasswordFilterHelpers.h
    src/logger/logger.h
    src/queue/password_event.h
    src/queue/queue_writer.h
    src/crypto/crypto.h
    src/config/config_watcher.h
)

add_library(MidPointPasswordAgentListener SHARED
    ${SOURCES}
    ${HEADERS}
)

set_target_properties(MidPointPasswordAgentListener PROPERTIES PREFIX "")

# ---------------------------------------------------------------------------
# Optional clang-tidy static analysis.
# Not part of the regular build — use the listener-lint just recipe instead.
# Skipped automatically when cross-compiling (MinGW from macOS).
# ---------------------------------------------------------------------------
option(ENABLE_CLANG_TIDY "Run clang-tidy on each source file during build" OFF)

if(ENABLE_CLANG_TIDY AND NOT CMAKE_CROSSCOMPILING)
  find_program(CLANG_TIDY_EXE NAMES clang-tidy REQUIRED)
  set_target_properties(MidPointPasswordAgentListener PROPERTIES
    CXX_CLANG_TIDY
    # --driver-mode=cl  interprets MSVC flags (/W4, /EHa …)
    # --target          sets the correct Windows x64 triple for header parsing
    "${CLANG_TIDY_EXE};\
    --extra-arg=--driver-mode=cl;\
    --extra-arg=--target=x86_64-pc-windows-msvc"
  )
endif()

# Use pre-compiled header to speed up builds.
# Skipped when clang-tidy is active or when exporting compile_commands.json —
# PCH causes /FI injection that prevents per-file include paths from appearing
# in compile_commands.json, which breaks clang-tidy header resolution.
if(NOT ENABLE_CLANG_TIDY AND NOT CMAKE_EXPORT_COMPILE_COMMANDS)
    target_precompile_headers(MidPointPasswordAgentListener PRIVATE src/pch.h)
endif()

# ---------------------------------------------------------------------------
# Compiler / linker flags — conditional on toolchain
# ---------------------------------------------------------------------------
if(MSVC)
    # Runtime library is determined by vcpkg triplet to avoid CRT mismatch
    # set_property(TARGET MidPointPasswordAgentListener PROPERTY
    #     MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

    target_compile_options(MidPointPasswordAgentListener PRIVATE
        /W4         # high warning level
        /WX         # warnings as errors
        /GS         # stack buffer security cookies
        /sdl        # additional SDL checks
        /EHa        # async (SEH) exception handling – required for __try/__except
        /Gy         # function-level linking
    )

    target_link_options(MidPointPasswordAgentListener PRIVATE
        /NXCOMPAT   # Data Execution Prevention
        /DYNAMICBASE # ASLR
    )

    # Pass the .def file to the MSVC linker for clean named exports
    target_sources(MidPointPasswordAgentListener PRIVATE PasswordFilter.def)

else()
    # MinGW-w64 cross-compilation (e.g. macOS → Windows x64)
    target_compile_options(MidPointPasswordAgentListener PRIVATE
        -Wall
        -Wextra
        -Werror
        -fstack-protector-strong  # equivalent of /GS
        -ffunction-sections       # equivalent of /Gy
        -fexceptions              # required for __try/__except with GCC on Windows
    )

    target_link_options(MidPointPasswordAgentListener PRIVATE
        -Wl,--nxcompat            # DEP
        -Wl,--dynamicbase         # ASLR
        -Wl,--gc-sections         # dead-code stripping
        -static-libgcc            # avoid runtime DLL dependency inside lsass.exe
        -static-libstdc++
        # Statically link libwinpthread so libwinpthread-1.dll is not required
        # on the target Windows Server. --whole-archive ensures all symbols
        # are pulled in even if not directly referenced.
        -Wl,-Bstatic,--whole-archive -lwinpthread -Wl,--no-whole-archive,-Bdynamic
        # Pass the .def file to the GNU linker for named exports
        "-Wl,${CMAKE_CURRENT_SOURCE_DIR}/PasswordFilter.def"
    )
endif()

# ---------------------------------------------------------------------------
# Link libraries (same on both toolchains)
# ---------------------------------------------------------------------------
find_package(spdlog CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)

target_link_libraries(MidPointPasswordAgentListener PRIVATE
    advapi32    # Registry, event log
    rpcrt4      # UuidCreate
    crypt32     # CryptUnprotectData (DPAPI)
    bcrypt      # BCryptEncrypt, BCryptGenRandom
    spdlog::spdlog
    nlohmann_json::nlohmann_json
)

# ---------------------------------------------------------------------------
# Tests — skipped when cross-compiling (MinGW toolchain from macOS) because
# the resulting Windows binary cannot be executed on the build host.
# Use the standalone build instead: cmake -B build-tests -S tests -A x64
# ---------------------------------------------------------------------------
if(NOT CMAKE_CROSSCOMPILING)
    enable_testing()
    add_subdirectory(tests)
endif()

# ---------------------------------------------------------------------------
# Install
# ---------------------------------------------------------------------------
# Output goes to System32 only during install (done by PowerShell script).
# During development the DLL lands in the build output directory.
install(TARGETS MidPointPasswordAgentListener
    RUNTIME DESTINATION "$ENV{SystemRoot}/System32")
