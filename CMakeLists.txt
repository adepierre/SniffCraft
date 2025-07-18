cmake_minimum_required(VERSION 3.15)

project(SniffCraft)

set_property(GLOBAL PROPERTY USE_FOLDERS ON)

option(SNIFFCRAFT_WITH_ENCRYPTION "Activate for online mode support" ON)
option(SNIFFCRAFT_WITH_GUI "Activate for GUI support" ON)
option(SNIFFCRAFT_FORCE_LOCAL_ZLIB "Force using a local install of zlib even if already present on the system" OFF)
option(SNIFFCRAFT_FORCE_LOCAL_OPENSSL "Force using a local install of openSSL even if already present on the system" OFF)

# Add Asio
include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/asio.cmake")

# Add Zlib
include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/zlib.cmake")

# Add OpenSSL
if(SNIFFCRAFT_WITH_ENCRYPTION)
    include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/openssl.cmake")
endif(SNIFFCRAFT_WITH_ENCRYPTION)

# Add ProtocolCraft
include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/botcraft.cmake")

# Add GUI related dependencies
if(SNIFFCRAFT_WITH_GUI)
    set(FETCHCONTENT_QUIET TRUE)
    include(FetchContent)
    include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/glad.cmake")
    include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/opengl.cmake")
    include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/glfw.cmake")
    include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/imgui.cmake")
endif(SNIFFCRAFT_WITH_GUI)

# Check pthreads
find_package(Threads)

# Version selection stuffs
set(GAME_VERSION "latest" CACHE STRING "Each version of the game uses a specific protocol. Make sure this matches the version of your server.")
set(GameVersionValues "1.12.2;1.13;1.13.1;1.13.2;1.14;1.14.1;1.14.2;1.14.3;1.14.4;1.15;1.15.1;1.15.2;1.16;1.16.1;1.16.2;1.16.3;1.16.4;1.16.5;1.17;1.17.1;1.18;1.18.1;1.18.2;1.19;1.19.1;1.19.2;1.19.3;1.19.4;1.20;1.20.1;1.20.2;1.20.3;1.20.4;1.20.5;1.20.6;1.21;1.21.1;1.21.2;1.21.3;1.21.4;1.21.5;1.21.6;1.21.7;1.21.8;latest")
set(ProtocolVersionValues "340;393;401;404;477;480;485;490;498;573;575;578;735;736;751;753;754;754;755;756;757;757;758;759;760;760;761;762;763;763;764;765;765;766;766;767;767;768;768;769;770;771;772;772")
set_property(CACHE GAME_VERSION PROPERTY STRINGS ${GameVersionValues})

if(GAME_VERSION STREQUAL "latest")
    list(GET GameVersionValues -2 GAME_VERSION)
endif()

list(FIND GameVersionValues ${GAME_VERSION} game_version_index)
list(GET ProtocolVersionValues ${game_version_index} PROTOCOL_VERSION)
message(STATUS "Selected game version: " ${GAME_VERSION} " || Protocol: " ${PROTOCOL_VERSION})
file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/version.txt" ${GAME_VERSION})
file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/protocol.txt" ${PROTOCOL_VERSION})


add_subdirectory(3rdparty/botcraft/protocolCraft)
add_subdirectory(sniffcraft)