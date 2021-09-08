cmake_minimum_required(VERSION 3.10)
include(CheckSymbolExists)

project(SSLProc)
option(BUILD_TESTS "Build tests" OFF)

check_symbol_exists(cocall "unistd.h" HAVE_COCALL)
if(HAVE_COCALL)
  add_compile_definitions(HAVE_COCALL)
endif()
option(USE_COCALL_SLOW "Use cocall_slow" OFF)
if(USE_COCALL_SLOW)
  add_compile_definitions(USE_COCALL_SLOW)
endif()

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)

add_compile_options(-Wall -Werror)

find_package(OpenSSL REQUIRED)

add_subdirectory(common)
add_subdirectory(sslproc)
add_subdirectory(libsslproc)

if(BUILD_TESTS)
  add_subdirectory(tests)
endif()
