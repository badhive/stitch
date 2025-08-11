cmake_minimum_required(VERSION 3.31)
project(stitch)

set(CMAKE_CXX_STANDARD 23)
set(STITCH_STATIC stitch)
option(STITCH_BUILD_EXAMPLES "Build examples" ON)

set(STITCH_SRC src/pe.cc
        src/x86.cc
        src/shellcode.cc
)

add_library(${STITCH_STATIC} STATIC ${STITCH_SRC})
target_include_directories(${STITCH_STATIC} PUBLIC include)

# dependencies
add_subdirectory(deps)

include(CTest)

set(STITCH_TEST_DIR ${CMAKE_SOURCE_DIR}/unittests/testdata)

macro(stitch_add_test TEST_NAME)
    add_executable(${TEST_NAME} ${TEST_NAME}.cc)
    target_link_libraries(${TEST_NAME} PRIVATE ${STITCH_STATIC})
    add_test(NAME ${TEST_NAME} COMMAND ${TEST_NAME} WORKING_DIRECTORY ${STITCH_TEST_DIR})
endmacro()

macro(stitch_add_test_with_sources TEST_NAME)
    add_executable(${TEST_NAME} ${ARGN})
    target_link_libraries(${TEST_NAME} PRIVATE ${STITCH_STATIC})
    add_test(NAME ${TEST_NAME} COMMAND ${TEST_NAME} WORKING_DIRECTORY ${STITCH_TEST_DIR})
endmacro()

add_subdirectory(unittests)
add_subdirectory(examples)
