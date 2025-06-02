#Add zlib library

# We first try to find zlib in the system
if (NOT SNIFFCRAFT_FORCE_LOCAL_ZLIB)
    find_package(ZLIB QUIET)
endif(NOT SNIFFCRAFT_FORCE_LOCAL_ZLIB)

# If not found, build from sources
if(NOT TARGET ZLIB::ZLIB)
    set(ZLIB_SRC_PATH "${CMAKE_CURRENT_SOURCE_DIR}/3rdparty/zlib/")
    set(ZLIB_BUILD_PATH "${CMAKE_CURRENT_BINARY_DIR}/3rdparty/zlib")

    file(GLOB RESULT "${ZLIB_BUILD_PATH}/install")
    list(LENGTH RESULT RES_LEN)
    if(RES_LEN EQUAL 0)
        message(STATUS "Can't find Zlib, cloning and building it from sources")

        file(GLOB RESULT "${ZLIB_SRC_PATH}")
        list(LENGTH RESULT RES_LEN)
        if(RES_LEN EQUAL 0)
            execute_process(COMMAND git submodule update --init -- 3rdparty/zlib WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}")
        endif()

        file(MAKE_DIRECTORY "${ZLIB_BUILD_PATH}")

        execute_process(
            COMMAND "${CMAKE_COMMAND}" "${ZLIB_SRC_PATH}" "-G" "${CMAKE_GENERATOR}" "-DCMAKE_BUILD_TYPE=Release" "-A" "${CMAKE_GENERATOR_PLATFORM}" "-DCMAKE_MAKE_PROGRAM=${CMAKE_MAKE_PROGRAM}" "-DCMAKE_INSTALL_PREFIX=install"  "-DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded" "-DCMAKE_POLICY_DEFAULT_CMP0091=NEW" "-DZLIB_BUILD_SHARED=OFF"
            WORKING_DIRECTORY "${ZLIB_BUILD_PATH}")

        execute_process(COMMAND "${CMAKE_COMMAND}" "--build" "." "--target" "install" "--config" "Release" "--parallel" "2" WORKING_DIRECTORY "${ZLIB_BUILD_PATH}")
    endif()

    # Find the freshly built library

    # From 3.24 there is a cmake option to find zlib static
    # but before, we need to do it in a more manual way
    if(${CMAKE_VERSION} VERSION_LESS "3.24.0")
        set(_CMAKE_FIND_LIBRARY_SUFFIXES ${CMAKE_FIND_LIBRARY_SUFFIXES})
        set(CMAKE_FIND_LIBRARY_SUFFIXES "static.lib" "s.lib" ".a")
    else()
        set(ZLIB_USE_STATIC_LIBS "ON")
    endif()

    find_package(ZLIB QUIET NO_DEFAULT_PATH PATHS "${ZLIB_BUILD_PATH}/install")

    # We link to ZLIB::ZLIB so we need an alias if we're using the static local version
    add_library(ZLIB::ZLIB ALIAS ZLIB::ZLIBSTATIC)

    if(${CMAKE_VERSION} VERSION_LESS "3.24.0")
        set(CMAKE_FIND_LIBRARY_SUFFIXES ${_CMAKE_FIND_LIBRARY_SUFFIXES})
        unset(_CMAKE_FIND_LIBRARY_SUFFIXES)
    endif()
endif()
