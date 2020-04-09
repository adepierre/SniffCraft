# Check if asio folder is empty and clone submodule if needed
file(GLOB RESULT ${CMAKE_SOURCE_DIR}/3rdparty/asio/asio/include)
list(LENGTH RESULT RES_LEN)
if(RES_LEN EQUAL 0)
    message(STATUS "Asio not found, cloning it...")
    execute_process(COMMAND git submodule update --init -- 3rdparty/asio WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
endif()

add_library(asio INTERFACE IMPORTED)
set_property(TARGET asio PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${CMAKE_SOURCE_DIR}/3rdparty/asio/asio/include)