cmake_minimum_required(VERSION 3.16)
project(sig_lab5 LANGUAGES CXX)

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
  set(_SIG_BIN_DIR "${CMAKE_SOURCE_DIR}/bin/windows")
else()
  set(_SIG_BIN_DIR "${CMAKE_SOURCE_DIR}/bin/linux")
endif()
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${_SIG_BIN_DIR}")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${_SIG_BIN_DIR}")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${_SIG_BIN_DIR}")
foreach(_cfg DEBUG RELEASE RELWITHDEBINFO MINSIZEREL)
  set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_${_cfg} "${_SIG_BIN_DIR}")
  set(CMAKE_LIBRARY_OUTPUT_DIRECTORY_${_cfg} "${_SIG_BIN_DIR}")
  set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY_${_cfg} "${_SIG_BIN_DIR}")
endforeach()
message(STATUS "Binaries will be placed in: ${_SIG_BIN_DIR}")

# ---------------------------------------------------------------------------
# Locate OpenSSL. Resolution order:
#   1) find_package(OpenSSL)                            — system / vcpkg
#   2) -DOPENSSL_ROOT_DIR=<root>                        — explicit
#   3) Fallback hint roots covering Win64 default install + MSYS2 mingw64
# ---------------------------------------------------------------------------
if(WIN32 AND NOT OPENSSL_ROOT_DIR)
  foreach(_hint
      "$ENV{OPENSSL_ROOT_DIR}"
      "C:/Program Files/OpenSSL-Win64"
      "C:/Program Files/OpenSSL"
      "C:/OpenSSL-Win64"
      "C:/msys64/mingw64")
    if(_hint AND EXISTS "${_hint}/include/openssl/evp.h")
      set(OPENSSL_ROOT_DIR "${_hint}")
      message(STATUS "OpenSSL hint root: ${OPENSSL_ROOT_DIR}")
      break()
    endif()
  endforeach()
endif()
find_package(OpenSSL REQUIRED)
message(STATUS "OpenSSL include : ${OPENSSL_INCLUDE_DIR}")
message(STATUS "OpenSSL crypto  : ${OPENSSL_CRYPTO_LIBRARY}")

# ---------------------------------------------------------------------------
# Core (static) — dùng chung cho CLI executables.
# ---------------------------------------------------------------------------
add_library(sig_core STATIC
    src/ecdsa_core.cpp
    src/rsapss_core.cpp)
target_include_directories(sig_core PUBLIC src)
target_link_libraries(sig_core PUBLIC OpenSSL::Crypto)

# Shared library exposing the flat C API for Python/C# GUI consumers.
add_library(sig_core_shared SHARED
    src/ecdsa_core.cpp
    src/rsapss_core.cpp
    src/c_api.cpp)
target_include_directories(sig_core_shared PUBLIC src)
target_compile_definitions(sig_core_shared PRIVATE SIG_BUILDING_DLL)
target_link_libraries(sig_core_shared PUBLIC OpenSSL::Crypto)
set_target_properties(sig_core_shared PROPERTIES
    OUTPUT_NAME sig_core
    PREFIX "lib"                          # ép Windows ra "libsig_core.dll" giống Linux
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON
    POSITION_INDEPENDENT_CODE ON)

# CLI executables.
add_executable(ECDSA  src/ecdsa_cli.cpp)
target_link_libraries(ECDSA  PRIVATE sig_core)

add_executable(RSAPSS src/rsapss_cli.cpp)
target_link_libraries(RSAPSS PRIVATE sig_core)

# GCC < 9 cần link stdc++fs cho std::filesystem.
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS 9)
    target_link_libraries(ECDSA  PRIVATE stdc++fs)
    target_link_libraries(RSAPSS PRIVATE stdc++fs)
endif()

# Install layout (đặt cùng kiểu Lab 3).
install(TARGETS ECDSA RSAPSS sig_core_shared
        RUNTIME DESTINATION bin
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib)
