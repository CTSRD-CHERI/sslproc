if(HAVE_COCALL)
  list(APPEND SRCS MessageCoproc.cc)
else()
  list(APPEND SRCS MessageSocket.cc)
endif()
add_library(common STATIC MessageBuffer.cc MessageChannel.cc MessageHelpers.cc
			  Messages.cc TargetStore.cc ${SRCS})
target_include_directories(common
	INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}
	)
set_property(TARGET common PROPERTY POSITION_INDEPENDENT_CODE ON)
