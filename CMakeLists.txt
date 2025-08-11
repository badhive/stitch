cmake_minimum_required(VERSION 3.31)
project(stitch)

set(CMAKE_CXX_STANDARD 23)
set(LIBSTITCH stitch)

option(STITCH_BUILD_SHARED "Build shared library" OFF)
option(STITCH_BUILD_TESTS "Build tests" ON)
option(STITCH_BUILD_EXAMPLES "Build examples" ON)

set(STITCH_SRC src/pe.cc
        src/x86.cc
        src/shellcode.cc
)

if (STITCH_BUILD_SHARED)
    add_library(${LIBSTITCH} SHARED ${STITCH_SRC})
else ()
    add_library(${LIBSTITCH} STATIC ${STITCH_SRC})
endif ()

target_include_directories(${LIBSTITCH} PUBLIC include)

# dependencies
add_subdirectory(deps)

include(CTest)

set(STITCH_TEST_DIR ${CMAKE_SOURCE_DIR}/unittests/testdata)

macro(stitch_add_test TEST_NAME)
    add_executable(${TEST_NAME} ${TEST_NAME}.cc)
    target_link_libraries(${TEST_NAME} PRIVATE ${LIBSTITCH})
    add_test(NAME ${TEST_NAME} COMMAND ${TEST_NAME} WORKING_DIRECTORY ${STITCH_TEST_DIR})
endmacro()

macro(stitch_add_test_with_sources TEST_NAME)
    add_executable(${TEST_NAME} ${ARGN})
    target_link_libraries(${TEST_NAME} PRIVATE ${LIBSTITCH})
    add_test(NAME ${TEST_NAME} COMMAND ${TEST_NAME} WORKING_DIRECTORY ${STITCH_TEST_DIR})
endmacro()

add_subdirectory(unittests)
add_subdirectory(examples)
