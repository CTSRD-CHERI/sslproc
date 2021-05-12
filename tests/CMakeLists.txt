add_executable(ssl_test sslproc_test.c)
target_link_libraries(ssl_test OpenSSL::SSL)

add_executable(sslproc_test sslproc_test.c)
target_compile_options(sslproc_test PRIVATE -DUSE_SSLPROC)
target_link_libraries(sslproc_test libsslproc OpenSSL::Crypto)
