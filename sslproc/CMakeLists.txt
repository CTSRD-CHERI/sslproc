add_executable(sslproc sslproc.cc ControlSocket.cc KEvent.cc
	       ProcMessageSocket.cc SSLSession.cc)
target_link_libraries(sslproc common OpenSSL::SSL)

install(TARGETS sslproc DESTINATION bin)
