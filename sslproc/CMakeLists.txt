find_package(Threads REQUIRED)

add_executable(sslproc sslproc.cc CommandSocket.cc ControlSocket.cc
	       ProcMessageSocket.cc)
target_link_libraries(sslproc common OpenSSL::SSL Threads::Threads)

install(TARGETS sslproc DESTINATION bin)
