add_executable(sslproc sslproc.cc ControlSocket.cc KEvent.cc
	       ProcMessageSocket.cc SSLSession.cc)
target_link_libraries(sslproc common OpenSSL::SSL)
target_include_directories(sslproc PUBLIC "${PROJECT_SOURCE_DIR}/include")

install(TARGETS sslproc DESTINATION bin)
