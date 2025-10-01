cmake_minimum_required(VERSION 3.10)
project(MyDLLProject)

add_library(mylib SHARED src/mylib.cpp)
target_include_directories(mylib PUBLIC include)

# if(MSVC)
#     set_property(TARGET mylib PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
# endif()

add_executable(mylibtest src/mylibtest.cpp)
target_include_directories(mylibtest PUBLIC include)

# if(MSVC)
#     set_property(TARGET mylibtest PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
# endif()
if(MSVC)
    # Use static runtime (/MT or /MTd)
    foreach(flag_var CMAKE_C_FLAGS CMAKE_C_FLAGS_DEBUG CMAKE_C_FLAGS_RELEASE
                     CMAKE_CXX_FLAGS CMAKE_CXX_FLAGS_DEBUG CMAKE_CXX_FLAGS_RELEASE)
        string(REPLACE "/MD" "/MT" ${flag_var} "${${flag_var}}")
    endforeach()
endif()
