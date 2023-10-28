cmake_minimum_required (VERSION 3.11)
project (drogonkvm CXX)
#set (CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(WARN "-Wall -Wextra -Wno-unused-parameter -Wno-deprecated-declarations -fdiagnostics-color")
set(CMAKE_CXX_FLAGS "${WARN} -march=native -std=c++20 -O2 -g3")

option(LTO          "Enable Link-Time Optimizations" OFF)
option(USE_JEMALLOC "Use jemalloc as system allocator" ON)
option(SANITIZE     "Use sanitizers" OFF)

if (LTO)
    if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -flto")
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -flto -fuse-ld=lld")
		set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -flto -fuse-ld=lld")
    else()
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -flto")
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -flto=8")
    endif()
endif()

if (SANITIZE)
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g3 -O0 -fsanitize=address,undefined")
endif()

option(USE_SQLITE3 "" OFF)
option(BUILD_EXAMPLES "" OFF)
add_subdirectory(drogon)
add_subdirectory(src/sandbox sandbox)

set(SOURCES
	src/main.cpp
	src/compute.cpp
)

add_executable(dvm ${SOURCES})
target_link_libraries(dvm PRIVATE drogon kvm)

if (USE_JEMALLOC AND NOT SANITIZE)
    target_link_libraries(dvm PRIVATE jemalloc)
endif()
