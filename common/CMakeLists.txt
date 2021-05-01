add_library(common STATIC MessageBuffer.cc MessageSocket.cc)
target_include_directories(common
	INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}
	)
set_property(TARGET common PROPERTY POSITION_INDEPENDENT_CODE ON)
