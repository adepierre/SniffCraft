project(sniffcraft)

set(sniffcraft_PUBLIC_HDR
    include/sniffcraft/BaseProxy.hpp
    include/sniffcraft/Compression.hpp
    include/sniffcraft/conf.hpp
    include/sniffcraft/Connection.hpp
    include/sniffcraft/DataProcessor.hpp
    include/sniffcraft/enums.hpp
    include/sniffcraft/Logger.hpp
    include/sniffcraft/LogItem.hpp
    include/sniffcraft/MinecraftEncryptionDataProcessor.hpp
    include/sniffcraft/MinecraftProxy.hpp
    include/sniffcraft/NetworkRecapItem.hpp
    include/sniffcraft/PacketUtilities.hpp
    include/sniffcraft/ReplayModLogger.hpp
    include/sniffcraft/server.hpp

    ../3rdparty/botcraft/botcraft/private_include/botcraft/Network/DNS/DNSMessage.hpp
    ../3rdparty/botcraft/botcraft/private_include/botcraft/Network/DNS/DNSQuestion.hpp
    ../3rdparty/botcraft/botcraft/private_include/botcraft/Network/DNS/DNSResourceRecord.hpp
    ../3rdparty/botcraft/botcraft/private_include/botcraft/Network/DNS/DNSSrvData.hpp

    ../3rdparty/botcraft/botcraft/private_include/botcraft/Network/Authentifier.hpp
    ../3rdparty/botcraft/botcraft/private_include/botcraft/Network/AESEncrypter.hpp
    ../3rdparty/botcraft/botcraft/include/botcraft/Network/LastSeenMessagesTracker.hpp

    ../3rdparty/botcraft/botcraft/include/botcraft/Utilities/Logger.hpp
    ../3rdparty/botcraft/botcraft/private_include/botcraft/Utilities/StringUtilities.hpp

    include/sniffcraft/Zip/DosTime.hpp
    include/sniffcraft/Zip/ZeptoZip.hpp
)

set(sniffcraft_SRC
    src/BaseProxy.cpp
    src/Compression.cpp
    src/conf.cpp
    src/Connection.cpp
    src/Logger.cpp
    src/MinecraftEncryptionDataProcessor.cpp
    src/MinecraftProxy.cpp
    src/ReplayModLogger.cpp
    src/server.cpp
    src/main.cpp

    src/Zip/ZeptoZip.cpp

    ../3rdparty/botcraft/botcraft/src/Network/Authentifier.cpp
    ../3rdparty/botcraft/botcraft/src/Network/AESEncrypter.cpp
    ../3rdparty/botcraft/botcraft/src/Network/LastSeenMessagesTracker.cpp
    ../3rdparty/botcraft/botcraft/src/Utilities/Logger.cpp
    ../3rdparty/botcraft/botcraft/src/Utilities/StringUtilities.cpp
)

# To have a nice files structure in Visual Studio
if(MSVC)
    foreach(source IN LISTS sniffcraft_PUBLIC_HDR)
        get_filename_component(source_path_header "${source}" PATH)
        string(REPLACE "../3rdparty/botcraft/botcraft/private_include/botcraft/Network" "Header Files/public/botcraft" source_path_header "${source_path_header}")
        string(REPLACE "../3rdparty/botcraft/botcraft/private_include/botcraft/Utilities" "Header Files/public/botcraft" source_path_header "${source_path_header}")
        string(REPLACE "../3rdparty/botcraft/botcraft/include/botcraft/Utilities" "Header Files/public/botcraft" source_path_header "${source_path_header}")
        string(REPLACE "../3rdparty/botcraft/botcraft/include/botcraft/Network" "Header Files/public/botcraft" source_path_header "${source_path_header}")
        string(REPLACE "include/sniffcraft" "Header Files/public" source_path_header "${source_path_header}")
        string(REPLACE "/" "\\" source_path_msvc "${source_path_header}")
        source_group("${source_path_msvc}" FILES "${source}")
    endforeach()

    foreach(source IN LISTS sniffcraft_SRC)
        get_filename_component(source_path "${source}" PATH)
        string(REPLACE "../3rdparty/botcraft/botcraft/src" "Source Files/botcraft" source_path "${source_path}")
        string(REPLACE "src" "Source Files" source_path "${source_path}")
        string(REPLACE "/" "\\" source_path_msvc "${source_path}")
        source_group("${source_path_msvc}" FILES "${source}")
    endforeach()
endif()

add_executable(${PROJECT_NAME} ${sniffcraft_SRC} ${sniffcraft_PUBLIC_HDR})
set_property(TARGET ${PROJECT_NAME} PROPERTY CXX_STANDARD 17)
set_target_properties(${PROJECT_NAME} PROPERTIES DEBUG_POSTFIX "_d")
set_target_properties(${PROJECT_NAME} PROPERTIES RELWITHDEBINFO_POSTFIX "_rd")

if(MSVC)
    # To avoid having folder for each configuration when building with Visual
    set_target_properties(${PROJECT_NAME} PROPERTIES RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_SOURCE_DIR}/bin")
    set_target_properties(${PROJECT_NAME} PROPERTIES RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_SOURCE_DIR}/bin")
    set_target_properties(${PROJECT_NAME} PROPERTIES RUNTIME_OUTPUT_DIRECTORY_RELWITHDEBINFO "${CMAKE_SOURCE_DIR}/bin")
    set_target_properties(${PROJECT_NAME} PROPERTIES RUNTIME_OUTPUT_DIRECTORY_MINSIZEREL "${CMAKE_SOURCE_DIR}/bin")
    set_target_properties(${PROJECT_NAME} PROPERTIES LIBRARY_OUTPUT_DIRECTORY_DEBUG "${CMAKE_SOURCE_DIR}/bin")
    set_target_properties(${PROJECT_NAME} PROPERTIES LIBRARY_OUTPUT_DIRECTORY_RELEASE "${CMAKE_SOURCE_DIR}/bin")
    set_target_properties(${PROJECT_NAME} PROPERTIES LIBRARY_OUTPUT_DIRECTORY_RELWITHDEBINFO "${CMAKE_SOURCE_DIR}/bin")
    set_target_properties(${PROJECT_NAME} PROPERTIES LIBRARY_OUTPUT_DIRECTORY_MINSIZEREL "${CMAKE_SOURCE_DIR}/bin")
    set_target_properties(${PROJECT_NAME} PROPERTIES ARCHIVE_OUTPUT_DIRECTORY_DEBUG "${CMAKE_SOURCE_DIR}/lib")
    set_target_properties(${PROJECT_NAME} PROPERTIES ARCHIVE_OUTPUT_DIRECTORY_RELEASE "${CMAKE_SOURCE_DIR}/lib")
    set_target_properties(${PROJECT_NAME} PROPERTIES ARCHIVE_OUTPUT_DIRECTORY_RELWITHDEBINFO "${CMAKE_SOURCE_DIR}/lib")
    set_target_properties(${PROJECT_NAME} PROPERTIES ARCHIVE_OUTPUT_DIRECTORY_MINSIZEREL "${CMAKE_SOURCE_DIR}/lib")

    set_property(TARGET ${PROJECT_NAME} PROPERTY VS_DEBUGGER_WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}/bin")
else()
    set_target_properties(${PROJECT_NAME} PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin")
    set_target_properties(${PROJECT_NAME} PROPERTIES LIBRARY_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin")
    set_target_properties(${PROJECT_NAME} PROPERTIES ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/lib")
endif(MSVC)

target_include_directories(${PROJECT_NAME} PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_include_directories(${PROJECT_NAME} PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/../3rdparty/botcraft/botcraft/private_include")
target_include_directories(${PROJECT_NAME} PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/../3rdparty/botcraft/botcraft/include")

if (MSVC)
    set_target_properties(${PROJECT_NAME} PROPERTIES MSVC_RUNTIME_LIBRARY "MultiThreaded")
endif(MSVC)

# Add Asio
target_link_libraries(${PROJECT_NAME} PUBLIC asio)
target_compile_definitions(${PROJECT_NAME} PUBLIC ASIO_STANDALONE)

# Add Zlib
target_link_libraries(${PROJECT_NAME} PUBLIC ZLIB::ZLIB)

# Add OpenSSL
if(SNIFFCRAFT_WITH_ENCRYPTION)
    target_link_libraries(${PROJECT_NAME} PUBLIC OpenSSL::SSL)
    target_link_libraries(${PROJECT_NAME} PUBLIC OpenSSL::Crypto)
    target_compile_definitions(${PROJECT_NAME} PUBLIC USE_ENCRYPTION=1)
endif(SNIFFCRAFT_WITH_ENCRYPTION)

# Add threads support
target_link_libraries(${PROJECT_NAME} PUBLIC Threads::Threads)

# Add protocolCraft
target_link_libraries(${PROJECT_NAME} PUBLIC protocolCraft)

if (SNIFFCRAFT_WITH_GUI)
	target_link_libraries(${PROJECT_NAME} PRIVATE glfw ${OPENGL_LIBRARIES} glad imgui)
    target_compile_definitions(${PROJECT_NAME} PRIVATE WITH_GUI)
endif()
