cmake_minimum_required(VERSION 3.31)
project(stitch)

set(CMAKE_CXX_STANDARD 23)
set(STITCH_STATIC_LIB stitch)

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

add_subdirectory(unittests)
