add_library(common STATIC MessageBuffer.cc MessageSocket.cc)
target_include_directories(common
	INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}
	PUBLIC "${PROJECT_SOURCE_DIR}/include"
	)
