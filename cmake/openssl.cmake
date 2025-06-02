# We first try to find OpenSSL in the system
if (NOT SNIFFCRAFT_FORCE_LOCAL_OPENSSL)
    find_package(OpenSSL QUIET)
endif(NOT SNIFFCRAFT_FORCE_LOCAL_OPENSSL)

set(OPENSSL_SRC_PATH "${CMAKE_CURRENT_SOURCE_DIR}/3rdparty/openssl")
set(OPENSSL_BUILD_PATH "${CMAKE_CURRENT_BINARY_DIR}/3rdparty/openssl")

file(GLOB RESULT "${OPENSSL_BUILD_PATH}/install/lib/*")
list(LENGTH RESULT RES_LEN)

# If not found, build from sources
if (NOT OPENSSL_FOUND AND RES_LEN EQUAL 0)
    message(STATUS "OpenSSL not found, cloning and building it from sources...")

    file(GLOB RESULT "${CMAKE_CURRENT_SOURCE_DIR}/3rdparty/openssl/include")
    list(LENGTH RESULT RES_LEN)
    if(RES_LEN EQUAL 0)
        execute_process(COMMAND git submodule update --init -- 3rdparty/openssl WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}")
    endif()

    file(MAKE_DIRECTORY "${OPENSSL_BUILD_PATH}")

    execute_process(
        COMMAND "${CMAKE_COMMAND}" "${OPENSSL_SRC_PATH}" "-G" "${CMAKE_GENERATOR}" "-A" "${CMAKE_GENERATOR_PLATFORM}" "-DCMAKE_MAKE_PROGRAM=${CMAKE_MAKE_PROGRAM}" "-DCMAKE_BUILD_TYPE=Release" "-DCMAKE_INSTALL_PREFIX=install" "-DWITH_APPS=OFF" "-DCPACK_SOURCE_7Z=OFF" "-DCPACK_SOURCE_ZIP=OFF" "-DMSVC_DYNAMIC_RUNTIME=OFF" "-DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded" "-DCMAKE_POSITION_INDEPENDENT_CODE=ON"
        WORKING_DIRECTORY "${OPENSSL_BUILD_PATH}")

    execute_process(COMMAND "${CMAKE_COMMAND}" "--build" "." "--target" "install" "--config" "Release" "--parallel" "2" WORKING_DIRECTORY "${OPENSSL_BUILD_PATH}")

    set(OPENSSL_FOUND ON CACHE INTERNAL "")
endif()

if(NOT TARGET OpenSSL::SSL OR NOT TARGET OpenSSL::Crypto)
    # Create imported targets
    file(GLOB ssl_lib_file "${OPENSSL_BUILD_PATH}/install/lib/*libssl*")
    add_library(OpenSSL::SSL STATIC IMPORTED)
    set_property(TARGET OpenSSL::SSL PROPERTY INTERFACE_INCLUDE_DIRECTORIES "${OPENSSL_BUILD_PATH}/install/include")
    set_target_properties(OpenSSL::SSL PROPERTIES IMPORTED_LOCATION "${ssl_lib_file}")

    file(GLOB crypto_lib_file "${OPENSSL_BUILD_PATH}/install/lib/*libcrypto*")
    add_library(OpenSSL::Crypto STATIC IMPORTED)
    set_property(TARGET OpenSSL::Crypto PROPERTY INTERFACE_INCLUDE_DIRECTORIES "${OPENSSL_BUILD_PATH}/install/include")
    set_target_properties(OpenSSL::Crypto PROPERTIES IMPORTED_LOCATION "${crypto_lib_file}")
    target_link_libraries(OpenSSL::Crypto INTERFACE ${CMAKE_DL_LIBS})
endif()
