cmake_minimum_required(VERSION 3.10)

project(SniffCraft)

set_property(GLOBAL PROPERTY USE_FOLDERS ON)

option(WITH_ENCRYPTION "Activate for online mode support" ON)

# Add Asio
include(${CMAKE_SOURCE_DIR}/cmake/asio.cmake)

# Add json
include(${CMAKE_SOURCE_DIR}/cmake/json.cmake)

# Add Zlib
include(${CMAKE_SOURCE_DIR}/cmake/zlib.cmake)

# Add OpenSSL
if(WITH_ENCRYPTION)
    include(${CMAKE_SOURCE_DIR}/cmake/openssl.cmake)
endif(WITH_ENCRYPTION)

# Add ProtocolCraft
include(${CMAKE_SOURCE_DIR}/cmake/botcraft.cmake)

# Check pthreads
find_package(Threads)

# Version selection stuffs
set(GAME_VERSION "latest" CACHE STRING "Each version of the game uses a specific protocol. Make sure this matches the version of your server.")
set(GameVersionValues "1.12.2;1.13;1.13.1;1.13.2;1.14;1.14.1;1.14.2;1.14.3;1.14.4;1.15;1.15.1;1.15.2;1.16;1.16.1;1.16.2;1.16.3;1.16.4;1.16.5;1.17;1.17.1;latest")
set(ProtocolVersionValues "340;393;401;404;477;480;485;490;498;573;575;578;735;736;751;753;754;754;755;756")
set_property(CACHE GAME_VERSION PROPERTY STRINGS ${GameVersionValues})

if(GAME_VERSION STREQUAL "latest")
    list(GET GameVersionValues -2 GAME_VERSION)
endif()

list(FIND GameVersionValues ${GAME_VERSION} game_version_index)
list(GET ProtocolVersionValues ${game_version_index} PROTOCOL_VERSION)
message(STATUS "Selected game version: " ${GAME_VERSION} " || Protocol: " ${PROTOCOL_VERSION})


add_subdirectory(3rdparty/botcraft/protocolCraft)
add_subdirectory(sniffcraft)