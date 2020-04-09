#Add zlib library

# We first try to find zlib in the system
find_package(ZLIB QUIET)

# If not found, build from sources
if(NOT TARGET ZLIB::ZLIB)
	
	message(STATUS "Can't find Zlib, cloning and building it from sources")
    
    file(GLOB RESULT ${CMAKE_SOURCE_DIR}/3rdparty/zlib/examples)
    list(LENGTH RESULT RES_LEN)
    message(STATUS ${RES_LEN})
    if(RES_LEN EQUAL 0)
        message(STATUS "Zlib not found, cloning it...")
        execute_process(COMMAND git submodule update --init -- 3rdparty/zlib WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
    endif()
	
	set(ZLIB_SRC_PATH ${CMAKE_SOURCE_DIR}/3rdparty/zlib)
	set(ZLIB_BUILD_PATH ${CMAKE_BINARY_DIR}/3rdparty/zlib)
	
	file(MAKE_DIRECTORY ${ZLIB_BUILD_PATH})

	execute_process(
		COMMAND "cmake" "${ZLIB_SRC_PATH}" "-G" "${CMAKE_GENERATOR}" "-A" "${CMAKE_GENERATOR_PLATFORM}" "-DCMAKE_INSTALL_PREFIX=install" 
		WORKING_DIRECTORY ${ZLIB_BUILD_PATH})

	execute_process(COMMAND "cmake" "--build" "." "--target" "install" "--config" "Release" WORKING_DIRECTORY ${ZLIB_BUILD_PATH})

	# Find the freshly built library
	set(ZLIB_ROOT ${ZLIB_BUILD_PATH}/install)
	find_package(ZLIB QUIET)
endif()