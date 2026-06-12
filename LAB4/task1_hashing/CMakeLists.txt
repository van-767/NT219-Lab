cmake_minimum_required(VERSION 3.16)
project(hashlab LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(MSVC)
  add_compile_options(/W3 /utf-8 /EHsc)
  add_definitions(-D_CRT_SECURE_NO_WARNINGS)
else()
  add_compile_options(-Wall -Wextra -O2)
endif()

# Binary output: bin/<os>/
if(WIN32)
  set(_HASH_BIN_DIR "${CMAKE_SOURCE_DIR}/bin/windows")
else()
  set(_HASH_BIN_DIR "${CMAKE_SOURCE_DIR}/bin/linux")
endif()
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${_HASH_BIN_DIR}")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${_HASH_BIN_DIR}")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${_HASH_BIN_DIR}")
foreach(_cfg DEBUG RELEASE RELWITHDEBINFO MINSIZEREL)
  set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_${_cfg} "${_HASH_BIN_DIR}")
  set(CMAKE_LIBRARY_OUTPUT_DIRECTORY_${_cfg} "${_HASH_BIN_DIR}")
  set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY_${_cfg} "${_HASH_BIN_DIR}")
endforeach()
message(STATUS "Binaries → ${_HASH_BIN_DIR}")

# ---------------------------------------------------------------------------
# Locate Crypto++. Tự dò D:/Study/NT219/CODE/Crypto++ trước, fallback các path khác.
# ---------------------------------------------------------------------------
set(CRYPTOPP_TARGET "")
find_package(cryptopp CONFIG QUIET)
if(TARGET cryptopp::cryptopp)
  set(CRYPTOPP_TARGET cryptopp::cryptopp)
elseif(TARGET cryptopp-static)
  set(CRYPTOPP_TARGET cryptopp-static)
else()
  if(MSVC)
    set(_cpp_compiler_subdir "msvc")
  elseif(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    set(_cpp_compiler_subdir "clang")
  else()
    set(_cpp_compiler_subdir "gcc")
  endif()
  set(_cpp_hint_roots
      "${CRYPTOPP_ROOT}"
      "D:/Study/NT219/CODE/Crypto++"
      "C:/Crypto++"
      "$ENV{CRYPTOPP_ROOT}")
  find_path(CRYPTOPP_INCLUDE_DIR
    NAMES sha.h cryptlib.h
    HINTS ${_cpp_hint_roots}
    PATH_SUFFIXES include/cryptopp cryptopp include)
  find_library(CRYPTOPP_LIBRARY
    NAMES cryptopp cryptlib libcryptopp
    HINTS ${_cpp_hint_roots}
    PATH_SUFFIXES
      "lib/cryptopp/${_cpp_compiler_subdir}"
      "lib/${_cpp_compiler_subdir}"
      lib)
  if(NOT CRYPTOPP_INCLUDE_DIR OR NOT CRYPTOPP_LIBRARY)
    message(FATAL_ERROR "Crypto++ not found. Pass -DCRYPTOPP_ROOT=...")
  endif()
  # Code dùng style #include <cryptopp/sha.h> nên include dir là parent của cryptopp/.
  get_filename_component(_cpp_inc_parent "${CRYPTOPP_INCLUDE_DIR}" DIRECTORY)
  add_library(cryptopp_imported UNKNOWN IMPORTED)
  set_target_properties(cryptopp_imported PROPERTIES
    IMPORTED_LOCATION "${CRYPTOPP_LIBRARY}"
    INTERFACE_INCLUDE_DIRECTORIES "${_cpp_inc_parent}")
  set(CRYPTOPP_TARGET cryptopp_imported)
endif()
message(STATUS "Crypto++ include : ${CRYPTOPP_INCLUDE_DIR}")
message(STATUS "Crypto++ library : ${CRYPTOPP_LIBRARY}")

# ---------------------------------------------------------------------------
# Targets
# ---------------------------------------------------------------------------
add_library(hash_core STATIC src/hash_core.cpp)
target_include_directories(hash_core PUBLIC src)
target_link_libraries(hash_core PUBLIC ${CRYPTOPP_TARGET})

# Shared lib cho GUI (PySide6 ctypes).
add_library(hash_core_shared SHARED src/hash_core.cpp src/c_api.cpp)
target_include_directories(hash_core_shared PUBLIC src)
target_compile_definitions(hash_core_shared PRIVATE HASH_LAB_BUILD_DLL)
target_link_libraries(hash_core_shared PUBLIC ${CRYPTOPP_TARGET})
set_target_properties(hash_core_shared PROPERTIES
    OUTPUT_NAME hash_core
    PREFIX "lib"
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON
    POSITION_INDEPENDENT_CODE ON)

add_executable(hashtool src/hashtool_cli.cpp)
target_link_libraries(hashtool PRIVATE hash_core)

if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS 9)
    target_link_libraries(hashtool PRIVATE stdc++fs)
endif()

install(TARGETS hashtool hash_core_shared
        RUNTIME DESTINATION bin
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib)
