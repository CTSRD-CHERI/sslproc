add_executable(sslproc sslproc.cc CommandSocket.cc ControlSocket.cc KEvent.cc
	       ProcMessageSocket.cc)
target_link_libraries(sslproc common OpenSSL::SSL)

install(TARGETS sslproc DESTINATION bin)
