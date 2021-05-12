add_library(libsslproc SHARED libsslproc.cc ControlSocket.cc Ctx.cc Err.cc
	    LibMessageSocket.cc Method.cc Session.cc SSLSession.cc)
set_target_properties(libsslproc PROPERTIES PREFIX "" SOVERSION 1)
target_include_directories(libsslproc
	INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}
	)
target_link_libraries(libsslproc common)

install(TARGETS libsslproc)
install(FILES sslproc.h sslproc_namespace.h sslproc_unnamespace.h
	DESTINATION include)
