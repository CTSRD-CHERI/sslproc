add_executable(sslproc sslproc.cc ControlSocket.cc KEvent.cc
	       MessageBuffer.cc MessageSocket.cc SSLSession.cc)
target_link_libraries(sslproc OpenSSL::SSL)
target_include_directories(sslproc PUBLIC "${PROJECT_SOURCE_DIR}/include")

install(TARGETS sslproc DESTINATION bin)
