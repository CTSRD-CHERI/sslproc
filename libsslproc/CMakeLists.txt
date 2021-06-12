add_library(libsslproc SHARED libsslproc.cc CommandSocket.cc ControlSocket.cc
	    Cipher.cc Conf.cc Ctx.cc Err.cc LibMessageSocket.cc Method.cc
	    Session.cc)
set_target_properties(libsslproc PROPERTIES PREFIX "" SOVERSION 1)
target_include_directories(libsslproc
	INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}
	)
target_link_libraries(libsslproc common OpenSSL::Crypto)

install(TARGETS libsslproc)
install(FILES sslproc.h sslproc_namespace.h sslproc_unnamespace.h
	DESTINATION include)
