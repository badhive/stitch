cmake_minimum_required(VERSION 3.31)
project(stitch)

set(CMAKE_CXX_STANDARD 23)
set(STITCH_STATIC_LIB stitch)
option(STITCH_BUILD_EXAMPLES "Build examples" ON)

# dependencies
add_subdirectory(deps)

include_directories(
        include
)

set(STITCH_SRC
        src/binary/pe.cc
)

add_library(${STITCH_STATIC_LIB} STATIC ${STITCH_SRC})

macro(stitch_add_target)
    if (${ARGC} LESS 1)
        message(FATAL_ERROR "stitch_add_target expects at least 1 source file")
    endif ()
    foreach (ARG IN ITEMS ${ARGN})
        set(STITCH_SRC ${STITCH_SRC} ${CMAKE_CURRENT_SOURCE_DIR}/${ARG} PARENT_SCOPE)
    endforeach ()
endmacro()

macro(stitch_add_deps)
    if (${ARGC} LESS 1)
        message(FATAL_ERROR "stitch_add_deps expects at least 1 dependency")
    endif ()
    target_link_libraries(${STITCH_STATIC_LIB} PUBLIC ${ARGN})
endmacro()

add_subdirectory(src/target)

target_sources(${STITCH_STATIC_LIB} PRIVATE ${STITCH_SRC})

include(CTest)

set(STITCH_TEST_DIR ${CMAKE_SOURCE_DIR}/unittests/testdata)

macro(stitch_add_test TEST_NAME)
    add_executable(${TEST_NAME} ${TEST_NAME}.cc)
    target_link_libraries(${TEST_NAME} PRIVATE ${STITCH_STATIC_LIB})
    add_test(NAME ${TEST_NAME} COMMAND ${TEST_NAME} WORKING_DIRECTORY ${STITCH_TEST_DIR})
endmacro()

macro(stitch_add_test_with_sources TEST_NAME)
    add_executable(${TEST_NAME} ${ARGN})
    target_link_libraries(${TEST_NAME} PRIVATE ${STITCH_STATIC_LIB})
    add_test(NAME ${TEST_NAME} COMMAND ${TEST_NAME} WORKING_DIRECTORY ${STITCH_TEST_DIR})
endmacro()

add_subdirectory(unittests)
add_subdirectory(examples)
