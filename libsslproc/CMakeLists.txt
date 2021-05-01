add_library(libsslproc SHARED libsslproc.cc ControlSocket.cc LibMessageSocket.cc)
target_link_libraries(libsslproc common)

install(FILES sslproc.h sslproc_namespace.h sslproc_unnamespace.h
	DESTINATION include)
