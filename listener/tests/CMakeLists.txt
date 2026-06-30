cmake_minimum_required(VERSION 3.20)

# Supports two build modes:
#   1. Standalone:    cmake -B listener/build-tests -S listener/tests -A x64
#   2. Subdirectory:  included from listener/CMakeLists.txt when not cross-compiling
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    project(MidPointPasswordAgentListenerTests CXX)
    set(CMAKE_CXX_STANDARD 17)
    set(CMAKE_CXX_STANDARD_REQUIRED ON)
    add_compile_definitions(
        _WIN32_WINNT=0x0A00
        WINVER=0x0A00
        WIN32_LEAN_AND_MEAN
        NOMINMAX
    )
endif()

# ---------------------------------------------------------------------------
# Catch2 via FetchContent
# ---------------------------------------------------------------------------
include(FetchContent)
FetchContent_Declare(
    Catch2
    GIT_REPOSITORY https://github.com/catchorg/Catch2.git
    GIT_TAG        v3.7.1
    GIT_SHALLOW    TRUE
)
FetchContent_MakeAvailable(Catch2)

# ---------------------------------------------------------------------------
# Test executable
#
# The test files #include the production .cpp files directly so that
# file-local (static) helpers are visible in the same translation unit.
# Those .cpp files must NOT be listed in SOURCES here to avoid duplicate
# symbol errors.
# ---------------------------------------------------------------------------
add_executable(MidPointPasswordAgentListenerTests
    test_password_filter.cpp
    test_queue_writer.cpp
    test_crypto_helper.cpp
    test_app_config.cpp
    test_config_watcher.cpp
    "${CMAKE_CURRENT_SOURCE_DIR}/../src/config/app_config.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/../src/PasswordFilter.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/../src/logger/logger.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/../src/queue/password_event.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/../src/queue/queue_writer.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/../src/crypto/crypto.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/../src/config/config_watcher.cpp"
)

# Production headers (pch.h, Common.h, …) must resolve from src/
target_include_directories(MidPointPasswordAgentListenerTests PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/../src"
)

find_package(spdlog CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)

target_link_libraries(MidPointPasswordAgentListenerTests PRIVATE
    Catch2::Catch2WithMain
    advapi32   # RegisterEventSource, ReportEvent
    rpcrt4     # UuidCreate
    crypt32    # CryptUnprotectData (DPAPI)
    bcrypt     # BCryptEncrypt, BCryptGenRandom
    spdlog::spdlog
    nlohmann_json::nlohmann_json
)

if(MSVC)
    target_compile_options(MidPointPasswordAgentListenerTests PRIVATE
        /W4
        /WX
        /GS
        /sdl
        /EHa    # required for __try/__except in PasswordFilter.cpp
    )

    target_link_options(MidPointPasswordAgentListenerTests PRIVATE
        /NXCOMPAT
        /DYNAMICBASE
    )
endif()

# ---------------------------------------------------------------------------
# CTest integration — auto-discovers TEST_CASE names
# ---------------------------------------------------------------------------
enable_testing()
list(APPEND CMAKE_MODULE_PATH "${catch2_SOURCE_DIR}/extras")
include(Catch)
catch_discover_tests(MidPointPasswordAgentListenerTests
    DISCOVERY_MODE PRE_TEST
)
