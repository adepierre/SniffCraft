add_library(glad STATIC ${CMAKE_CURRENT_SOURCE_DIR}/3rdparty/glad/src/glad.c)
target_include_directories(glad PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/3rdparty/glad/include)
if(MSVC)
    set_target_properties(glad PROPERTIES MSVC_RUNTIME_LIBRARY "MultiThreaded")
endif()
