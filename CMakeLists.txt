cmake_minimum_required(VERSION 3.17)
project(trap)

set(CMAKE_CXX_STANDARD 14)

set(CMAKE_POSITION_INDEPENDENT_CODE TRUE)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/lib)

set(ZYDIS_BUILD_TOOLS OFF CACHE BOOL "disable disassembler tools")
set(ZYDIS_BUILD_EXAMPLES OFF CACHE BOOL "disable disassembler examples")

include(FetchContent)

FetchContent_Declare(
        zydis
        GIT_REPOSITORY    https://github.com/zyantific/zydis
        GIT_TAG           v3.1.0
)

FetchContent_MakeAvailable(zydis)

FetchContent_Declare(
        zero
        GIT_REPOSITORY https://github.com/Hackerl/zero
        GIT_TAG 22525f041a6d2eb4ae727be7a61fd57e2b6f32f9
)

FetchContent_MakeAvailable(zero)

add_library(trap STATIC src/trap.cpp)

target_include_directories(trap PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(trap zero Zydis)