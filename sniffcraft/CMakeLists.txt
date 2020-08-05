project(sniffcraft)

set(sniffcraft_PUBLIC_HDR 
    include/sniffcraft/Compression.hpp
    include/sniffcraft/enums.hpp
    include/sniffcraft/FileUtilities.hpp
    include/sniffcraft/Handler.hpp
    include/sniffcraft/Logger.hpp
    include/sniffcraft/MinecraftProxy.hpp
    include/sniffcraft/server.hpp
)

set(sniffcraft_SRC
    src/Compression.cpp
    src/FileUtilities.cpp
    src/Logger.cpp
    src/MinecraftProxy.cpp
    src/server.cpp
    src/main.cpp
)

# To have a nice files structure in Visual Studio
if(MSVC)
    foreach(source IN LISTS sniffcraft_PUBLIC_HDR)
        get_filename_component(source_path_header "${source}" PATH)
        string(REPLACE "include/sniffcraft" "Header Files/public" source_path_header "${source_path_header}")
        string(REPLACE "/" "\\" source_path_msvc "${source_path_header}")
        source_group("${source_path_msvc}" FILES "${source}")
    endforeach()

    foreach(source IN LISTS sniffcraft_SRC)
        get_filename_component(source_path "${source}" PATH)
        string(REPLACE "src" "Source Files" source_path "${source_path}")
        string(REPLACE "/" "\\" source_path_msvc "${source_path}")
        source_group("${source_path_msvc}" FILES "${source}")
    endforeach()
endif()

add_executable(sniffcraft ${sniffcraft_SRC} ${sniffcraft_PUBLIC_HDR})
set_property(TARGET sniffcraft PROPERTY CXX_STANDARD 11)
set_target_properties(sniffcraft PROPERTIES DEBUG_POSTFIX "_d")
set_target_properties(sniffcraft PROPERTIES RELWITHDEBINFO_POSTFIX "_rd")

if(MSVC)
    # To avoid having folder for each configuration when building with Visual
    set_target_properties(sniffcraft PROPERTIES RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_SOURCE_DIR}/bin")
    set_target_properties(sniffcraft PROPERTIES RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_SOURCE_DIR}/bin")
    set_target_properties(sniffcraft PROPERTIES RUNTIME_OUTPUT_DIRECTORY_RELWITHDEBINFO "${CMAKE_SOURCE_DIR}/bin")
    set_target_properties(sniffcraft PROPERTIES RUNTIME_OUTPUT_DIRECTORY_MINSIZEREL "${CMAKE_SOURCE_DIR}/bin")
    set_target_properties(sniffcraft PROPERTIES LIBRARY_OUTPUT_DIRECTORY_DEBUG "${CMAKE_SOURCE_DIR}/bin")
    set_target_properties(sniffcraft PROPERTIES LIBRARY_OUTPUT_DIRECTORY_RELEASE "${CMAKE_SOURCE_DIR}/bin")
    set_target_properties(sniffcraft PROPERTIES LIBRARY_OUTPUT_DIRECTORY_RELWITHDEBINFO "${CMAKE_SOURCE_DIR}/bin")
    set_target_properties(sniffcraft PROPERTIES LIBRARY_OUTPUT_DIRECTORY_MINSIZEREL "${CMAKE_SOURCE_DIR}/bin")
    set_target_properties(sniffcraft PROPERTIES ARCHIVE_OUTPUT_DIRECTORY_DEBUG "${CMAKE_SOURCE_DIR}/lib")
    set_target_properties(sniffcraft PROPERTIES ARCHIVE_OUTPUT_DIRECTORY_RELEASE "${CMAKE_SOURCE_DIR}/lib")
    set_target_properties(sniffcraft PROPERTIES ARCHIVE_OUTPUT_DIRECTORY_RELWITHDEBINFO "${CMAKE_SOURCE_DIR}/lib")
    set_target_properties(sniffcraft PROPERTIES ARCHIVE_OUTPUT_DIRECTORY_MINSIZEREL "${CMAKE_SOURCE_DIR}/lib")
else()
    set_target_properties(sniffcraft PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin")
    set_target_properties(sniffcraft PROPERTIES LIBRARY_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin")
    set_target_properties(sniffcraft PROPERTIES ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/lib")
endif(MSVC)

target_include_directories(sniffcraft PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

# Add Asio
target_link_libraries(sniffcraft PUBLIC asio)
target_compile_definitions(sniffcraft PUBLIC ASIO_STANDALONE)

# Add Zlib
target_link_libraries(sniffcraft PUBLIC ZLIB::ZLIB)

# Add threads support
target_link_libraries(sniffcraft PUBLIC Threads::Threads)

# Add protocolCraft
target_link_libraries(sniffcraft PUBLIC protocolCraft)

