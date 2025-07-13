include(CTest)

set(STITCH_TEST_DIR ${CMAKE_CURRENT_SOURCE_DIR}/testdata)
option(STITCH_BUILD_TARGET_TESTS "Build target tests" ON)

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

add_subdirectory(binary)
if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/target)
    add_subdirectory(target)
endif ()
