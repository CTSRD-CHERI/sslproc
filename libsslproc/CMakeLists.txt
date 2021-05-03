add_library(libsslproc SHARED libsslproc.cc ControlSocket.cc Ctx.cc
	    LibMessageSocket.cc Method.cc)
target_link_libraries(libsslproc common)

install(FILES sslproc.h sslproc_namespace.h sslproc_unnamespace.h
	DESTINATION include)
