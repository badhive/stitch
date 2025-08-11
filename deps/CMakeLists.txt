include(FetchContent)

message(STATUS "Fetching zyantific/zasm @ c239a78...")
FetchContent_Declare(zasm
        GIT_REPOSITORY "https://github.com/zyantific/zasm"
        GIT_TAG c239a78
)
option(ZASM_BUILD_TESTS "" OFF)
option(ZASM_BUILD_BENCHMARKS "" OFF)
option(ZASM_BUILD_EXAMPLES "" OFF)
FetchContent_MakeAvailable(zasm)

target_link_libraries(${LIBSTITCH} PUBLIC zasm)
