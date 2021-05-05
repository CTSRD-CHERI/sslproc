add_executable(sslproc_test sslproc_test.c)
target_link_libraries(sslproc_test libsslproc OpenSSL::Crypto)
