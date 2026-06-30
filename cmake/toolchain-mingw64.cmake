# Cross-compilation toolchain: macOS → Windows x64 using MinGW-w64
#
# Install on macOS:
#   brew install mingw-w64
#
# Usage:
#   cmake -B build -A x64 --toolchain ../cmake/toolchain-mingw64.cmake

set(CMAKE_SYSTEM_NAME      Windows)
set(CMAKE_SYSTEM_PROCESSOR x86_64)

set(MINGW_PREFIX "x86_64-w64-mingw32")

find_program(CMAKE_C_COMPILER   NAMES "${MINGW_PREFIX}-gcc"    REQUIRED)
find_program(CMAKE_CXX_COMPILER NAMES "${MINGW_PREFIX}-g++"    REQUIRED)
find_program(CMAKE_RC_COMPILER  NAMES "${MINGW_PREFIX}-windres")

# Do not search host (macOS) paths for libraries or headers –
# only the MinGW sysroot should be used.
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
