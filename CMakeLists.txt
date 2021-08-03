cmake_minimum_required(VERSION 3.10)

project(SSLProc)
option(BUILD_TESTS "Build tests" OFF)

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
