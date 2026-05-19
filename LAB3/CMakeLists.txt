cmake_minimum_required(VERSION 3.16)
project(rsa_lab3 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(MSVC)
  add_compile_options(/W3 /utf-8 /EHsc)
  add_definitions(-D_CRT_SECURE_NO_WARNINGS)
else()
  add_compile_options(-Wall -Wextra -O2)
endif()

# ---------------------------------------------------------------------------
# Send final artifacts to bin/<os>/ — keeps Windows and Linux binaries side by
# side in the same source tree so the submission archive can ship both.
# CMake intermediate files still live in the user's chosen -B <build_dir>.
# ---------------------------------------------------------------------------
if(WIN32)
  set(_RSA_BIN_DIR "${CMAKE_SOURCE_DIR}/bin/windows")
else()
  set(_RSA_BIN_DIR "${CMAKE_SOURCE_DIR}/bin/linux")
endif()
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${_RSA_BIN_DIR}")  # .exe / executable
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${_RSA_BIN_DIR}")  # .so / .dylib
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${_RSA_BIN_DIR}")  # .a / .lib / .dll.a
# Multi-config generators (MSVC) otherwise drop binaries into bin/<os>/Release.
foreach(_cfg DEBUG RELEASE RELWITHDEBINFO MINSIZEREL)
  set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_${_cfg} "${_RSA_BIN_DIR}")
  set(CMAKE_LIBRARY_OUTPUT_DIRECTORY_${_cfg} "${_RSA_BIN_DIR}")
  set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY_${_cfg} "${_RSA_BIN_DIR}")
endforeach()
message(STATUS "Binaries will be placed in: ${_RSA_BIN_DIR}")

# ---------------------------------------------------------------------------
# Locate Crypto++. Resolution order:
#   1) find_package(cryptopp CONFIG)                       — vcpkg / system
#   2) -DCRYPTOPP_INCLUDE_DIR=... -DCRYPTOPP_LIBRARY=...   — explicit
#   3) -DCRYPTOPP_ROOT=<root>                              — searches root/lib
#   4) Fallback hint paths for this course's layout, e.g.
#        D:/Study/NT219/CODE/Crypto++/include
#        D:/Study/NT219/CODE/Crypto++/lib/cryptopp/{msvc,gcc,clang}/
# ---------------------------------------------------------------------------
set(CRYPTOPP_TARGET "")
find_package(cryptopp CONFIG QUIET)
if(TARGET cryptopp::cryptopp)
  set(CRYPTOPP_TARGET cryptopp::cryptopp)
elseif(TARGET cryptopp-static)
  set(CRYPTOPP_TARGET cryptopp-static)
else()
  # Compiler-specific subdir matching the course's prebuilt layout.
  if(MSVC)
    set(_cpp_compiler_subdir "msvc")
  elseif(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    set(_cpp_compiler_subdir "clang")
  else()
    set(_cpp_compiler_subdir "gcc")
  endif()

  # Default hint roots — covers the user's local install without editing this
  # file. TA can still pass -DCRYPTOPP_ROOT=... to redirect.
  set(_cpp_hint_roots
      "${CRYPTOPP_ROOT}"
      "D:/Study/NT219/CODE/Crypto++"
      "C:/Crypto++"
      "$ENV{CRYPTOPP_ROOT}")

  if(NOT CRYPTOPP_INCLUDE_DIR)
    # The course's prebuilt layout places headers at <root>/include/cryptopp/.
    # Our sources use `#include "rsa.h"` so we point INCLUDE_DIR at that
    # leaf directory (find_path returns the directory that contains rsa.h).
    find_path(CRYPTOPP_INCLUDE_DIR
      NAMES rsa.h cryptlib.h
      HINTS ${_cpp_hint_roots}
      PATH_SUFFIXES include/cryptopp cryptopp include)
  endif()
  if(NOT CRYPTOPP_LIBRARY)
    find_library(CRYPTOPP_LIBRARY
      NAMES cryptopp cryptlib libcryptopp
      HINTS ${_cpp_hint_roots}
      PATH_SUFFIXES
        "lib/cryptopp/${_cpp_compiler_subdir}"
        "lib/${_cpp_compiler_subdir}"
        lib)
  endif()
  if(NOT CRYPTOPP_INCLUDE_DIR OR NOT CRYPTOPP_LIBRARY)
    message(FATAL_ERROR
      "Crypto++ not found. Provide one of:\n"
      "  -Dcryptopp_DIR=<vcpkg install share/cryptopp>, or\n"
      "  -DCRYPTOPP_ROOT=<install root>, or\n"
      "  -DCRYPTOPP_INCLUDE_DIR=... -DCRYPTOPP_LIBRARY=...\n"
      "Looked for compiler subdir: ${_cpp_compiler_subdir}")
  endif()
  add_library(cryptopp_imported UNKNOWN IMPORTED)
  set_target_properties(cryptopp_imported PROPERTIES
    IMPORTED_LOCATION "${CRYPTOPP_LIBRARY}"
    INTERFACE_INCLUDE_DIRECTORIES "${CRYPTOPP_INCLUDE_DIR}")
  set(CRYPTOPP_TARGET cryptopp_imported)
endif()
message(STATUS "Crypto++ include : ${CRYPTOPP_INCLUDE_DIR}")
message(STATUS "Crypto++ library : ${CRYPTOPP_LIBRARY}")
message(STATUS "Crypto++ target  : ${CRYPTOPP_TARGET}")

# ---------------------------------------------------------------------------
# Core (static) — used by CLI and by the shared lib.
# ---------------------------------------------------------------------------
add_library(rsa_core STATIC src/rsa_core.cpp)
target_include_directories(rsa_core PUBLIC src)
target_link_libraries(rsa_core PUBLIC ${CRYPTOPP_TARGET})

# Shared library exposing the flat C API for Python/C# GUI consumers.
add_library(rsa_core_shared SHARED src/rsa_core.cpp src/c_api.cpp)
target_include_directories(rsa_core_shared PUBLIC src)
target_compile_definitions(rsa_core_shared PRIVATE RSA_LAB_BUILD_DLL)
target_link_libraries(rsa_core_shared PUBLIC ${CRYPTOPP_TARGET})
set_target_properties(rsa_core_shared PROPERTIES
  OUTPUT_NAME rsa_core
  CXX_VISIBILITY_PRESET hidden
  VISIBILITY_INLINES_HIDDEN ON)

# CLI executable.
add_executable(rsatool src/cli.cpp)
target_link_libraries(rsatool PRIVATE rsa_core)

# Optional: install layout that matches the Python GUI's expectation
# (it looks for the shared library next to the package).
install(TARGETS rsatool rsa_core_shared
        RUNTIME DESTINATION bin
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib)
