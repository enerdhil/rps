## - Global definitions 
cmake_minimum_required(VERSION 3.4)
cmake_policy(SET CMP0079 NEW)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_BUILD_TYPE "Release")

project(rps)

set(TARGET "x86_64" CACHE STRING "Build target (x86_64)")
set_property(CACHE TARGET PROPERTY STRINGS "x86_64")

if (CMAKE_SOURCE_DIR STREQUAL CMAKE_BINARY_DIR)
    message(FATAL_ERROR "Don't use 'cmake .' Create a build folder first")
endif (CMAKE_SOURCE_DIR STREQUAL CMAKE_BINARY_DIR)

include_directories(${CMAKE_SOURCE_DIR})

find_program(GO_COMPILER go)
if (${GO_COMPILER} STREQUAL "")
    message(FATAL_ERROR "The Golang binary was not found in the path")
else ()
    execute_process(COMMAND ${GO_COMPILER} "version" OUTPUT_VARIABLE GO_VERSION)
    if (NOT ${GO_VERSION} MATCHES ".*go1\.(19|20|21).*")
        message(FATAL_ERROR "The Golang version is not supported (not 1.19.* or 1.20.* or 1.21.*)")
    endif ()
endif ()

## -- Subdirectories includes

add_subdirectory(CMake)
add_subdirectory(src)
