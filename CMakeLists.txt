cmake_minimum_required(VERSION 3.4)

project(SniffCraft)

set_property(GLOBAL PROPERTY USE_FOLDERS ON)

# Add Asio
include(${CMAKE_SOURCE_DIR}/cmake/asio.cmake)

# Add picoJson
include(${CMAKE_SOURCE_DIR}/cmake/picoJson.cmake)

# Add Zlib
include(${CMAKE_SOURCE_DIR}/cmake/zlib.cmake)

# Add Botcraft
include(${CMAKE_SOURCE_DIR}/cmake/botcraft.cmake)

# Check pthreads
find_package(Threads)

# Version selection stuffs
set(GAME_VERSION "1.12.2" CACHE STRING "Each version of the game uses a specific protocol. Make sure this matches the version of your server.")
set(GameVersionValues "1.12.2;1.13;1.13.1;1.13.2;1.14;1.14.1;1.14.2;1.14.3;1.14.4;1.15;1.15.1;1.15.2;1.16;1.16.1;1.16.2;1.16.3;Other")
set(ProtocolVersionValues "340;393;401;404;477;480;485;490;498;573;575;578;735;736;751;753;-1")
set_property(CACHE GAME_VERSION PROPERTY STRINGS ${GameVersionValues})

if(GAME_VERSION STREQUAL "Other")
    message(SEND_ERROR "You must specify an actual value for GAME_VERSION")
else()
    list(FIND GameVersionValues ${GAME_VERSION} game_version_index)
    list(GET ProtocolVersionValues ${game_version_index} PROTOCOL_VERSION)
    message(STATUS "Selected game version: " ${GAME_VERSION} " || Protocol: " ${PROTOCOL_VERSION})
endif()

add_subdirectory(3rdparty/botcraft/protocolCraft)
add_subdirectory(sniffcraft)