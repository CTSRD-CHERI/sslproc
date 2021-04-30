cmake_minimum_required(VERSION 3.10)

project(SSLProc)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)

find_package(OpenSSL REQUIRED)

add_subdirectory(common)
add_subdirectory(sslproc)

install(FILES include/sslproc.h DESTINATION include)
