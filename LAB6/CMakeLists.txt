cmake_minimum_required(VERSION 3.16)
project(pq_lab6 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(MSVC)
  add_compile_options(/W3 /utf-8 /EHsc)
  add_definitions(-D_CRT_SECURE_NO_WARNINGS)
else()
  add_compile_options(-Wall -Wextra -O2)
endif()

# Binary output: bin/<os>/ — parallel to Lab 3/5.
if(WIN32)
  set(_PQ_BIN_DIR "${CMAKE_SOURCE_DIR}/bin/windows")
else()
  set(_PQ_BIN_DIR "${CMAKE_SOURCE_DIR}/bin/linux")
endif()
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${_PQ_BIN_DIR}")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${_PQ_BIN_DIR}")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${_PQ_BIN_DIR}")
foreach(_cfg DEBUG RELEASE RELWITHDEBINFO MINSIZEREL)
  set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_${_cfg} "${_PQ_BIN_DIR}")
  set(CMAKE_LIBRARY_OUTPUT_DIRECTORY_${_cfg} "${_PQ_BIN_DIR}")
  set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY_${_cfg} "${_PQ_BIN_DIR}")
endforeach()
message(STATUS "Binaries → ${_PQ_BIN_DIR}")

# ---------------------------------------------------------------------------
# Locate liboqs (Open Quantum Safe). Resolution order:
#   1) find_package(liboqs CONFIG)                    — installed package
#   2) -DLIBOQS_ROOT=<root>                            — explicit
#   3) Hint paths: MSYS2 mingw64, /usr, vcpkg
# ---------------------------------------------------------------------------
set(LIBOQS_TARGET "")
find_package(liboqs CONFIG QUIET)
if(TARGET OQS::oqs)
  set(LIBOQS_TARGET OQS::oqs)
elseif(TARGET oqs)
  set(LIBOQS_TARGET oqs)
else()
  set(_oqs_hints
      "${LIBOQS_ROOT}"
      "$ENV{LIBOQS_ROOT}"
      "C:/msys64/mingw64"
      "C:/liboqs"
      "D:/liboqs"
      "D:/Study/NT219/CODE/liboqs"
      "/usr/local"
      "/usr")
  find_path(LIBOQS_INCLUDE_DIR
      NAMES oqs/oqs.h
      HINTS ${_oqs_hints}
      PATH_SUFFIXES include)
  find_library(LIBOQS_LIBRARY
      NAMES oqs liboqs
      HINTS ${_oqs_hints}
      PATH_SUFFIXES lib lib64)
  if(NOT LIBOQS_INCLUDE_DIR OR NOT LIBOQS_LIBRARY)
    message(FATAL_ERROR
      "liboqs not found. Cài bằng MSYS2 (pacman -S mingw-w64-x86_64-liboqs) "
      "hoặc build từ source và pass -DLIBOQS_ROOT=<root>.")
  endif()
  add_library(oqs_imported UNKNOWN IMPORTED)
  set_target_properties(oqs_imported PROPERTIES
    IMPORTED_LOCATION "${LIBOQS_LIBRARY}"
    INTERFACE_INCLUDE_DIRECTORIES "${LIBOQS_INCLUDE_DIR}")
  set(LIBOQS_TARGET oqs_imported)
endif()
message(STATUS "liboqs include : ${LIBOQS_INCLUDE_DIR}")
message(STATUS "liboqs library : ${LIBOQS_LIBRARY}")

# ---------------------------------------------------------------------------
# Core (static) — dùng chung cho 2 CLI.
# ---------------------------------------------------------------------------
add_library(pq_core STATIC src/pq_core.cpp)
target_include_directories(pq_core PUBLIC src)
target_link_libraries(pq_core PUBLIC ${LIBOQS_TARGET})

# Shared library cho GUI (PySide6 ctypes).
add_library(pq_core_shared SHARED src/pq_core.cpp src/c_api.cpp)
target_include_directories(pq_core_shared PUBLIC src)
target_compile_definitions(pq_core_shared PRIVATE PQ_LAB_BUILD_DLL)
target_link_libraries(pq_core_shared PUBLIC ${LIBOQS_TARGET})
set_target_properties(pq_core_shared PROPERTIES
    OUTPUT_NAME pq_core
    PREFIX "lib"
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON
    POSITION_INDEPENDENT_CODE ON)

# CLI executables.
add_executable(MLDSA src/mldsa_cli.cpp)
target_link_libraries(MLDSA PRIVATE pq_core)

add_executable(MLKEM src/mlkem_cli.cpp)
target_link_libraries(MLKEM PRIVATE pq_core)

# GCC < 9 cần link stdc++fs cho std::filesystem.
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS 9)
    target_link_libraries(MLDSA PRIVATE stdc++fs)
    target_link_libraries(MLKEM PRIVATE stdc++fs)
endif()

install(TARGETS MLDSA MLKEM pq_core_shared
        RUNTIME DESTINATION bin
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib)
