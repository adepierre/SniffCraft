#Download botcraft library

file(GLOB RESULT "${CMAKE_CURRENT_SOURCE_DIR}/3rdparty/botcraft/protocolCraft")
list(LENGTH RESULT RES_LEN)
if(RES_LEN EQUAL 0)
    message(STATUS "Botcraft not found, cloning it...")
    execute_process(COMMAND git submodule update --init -- 3rdparty/botcraft WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}")
endif()

set(BOTCRAFT_OUTPUT_DIR "${CMAKE_SOURCE_DIR}" CACHE PATH "Base output build path for protocolCraft")
