cmake_minimum_required(VERSION 3.22)
project(Sources C)

set(CMAKE_C_STANDARD 17)

include(FetchContent)
FetchContent_Declare(
        dc_utils
        GIT_REPOSITORY git@github.com:KarelChanivecky/BCIT_datacomm_C_language_data_structures.git
        GIT_TAG main
)
FetchContent_MakeAvailable(dc_utils)

set(CPLIB_BUILD_TYPE ${BUILD_TYPE})
message("BUILD_TYPE:  ${BUILD_TYPE}")
if (NOT CPLIB_BUILD_TYPE)
    set(CPLIB_BUILD_TYPE CPLIB_RELEASE)
endif ()

set(BUILD_TYPE_COMPILER_FLAG "-D${CPLIB_BUILD_TYPE}")

message("CPLIB_BUILD_TYPE: ${BUILD_TYPE_COMPILER_FLAG}")

include_directories(
        ./src/ciphrameworklib/include
        src/example/include
)

add_library(
        ciphramework SHARED
        src/ciphrameworklib/cplib_mem.c
        src/ciphrameworklib/base_objects.c
        src/ciphrameworklib/cplib_utils.c
        src/ciphrameworklib/cipher_driver.c
)

target_compile_options(ciphramework PRIVATE -Wpedantic -Wall -Wextra -fms-extensions -D${CPLIB_BUILD_TYPE})

set(CMAKE_SHARED_LIBRARY_PREFIX "")
# CIPHERS
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/ciphers)

add_library(
        feisty SHARED
        src/example/ciphers/feisty.c
)

target_compile_options(feisty PRIVATE -Wpedantic -Wall -Wextra -fms-extensions -D${CPLIB_BUILD_TYPE})
target_link_libraries(feisty ciphramework)

add_library(
        xor SHARED
        src/example/ciphers/xor.c
)

target_compile_options(xor PRIVATE -Wpedantic -Wall -Wextra -fms-extensions -D${CPLIB_BUILD_TYPE})
target_link_libraries(xor ciphramework)

# MODES
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/modes)

add_library(
        ECB SHARED
        src/example/modes/ECB.c
)

target_compile_options(ECB PRIVATE -Wpedantic -Wall -Wextra -fms-extensions -D${CPLIB_BUILD_TYPE})
target_link_libraries(ECB ciphramework)


# KCRYPT
add_executable(
        kcrypt
        src/example/main.c
        src/example/kcrypt_utils.c
)

target_link_libraries(kcrypt ciphramework dc_utils dl)

target_compile_options(kcrypt PRIVATE -Wpedantic -Wall -Wextra -fms-extensions -D${CPLIB_BUILD_TYPE})

add_dependencies(kcrypt ciphramework feisty xor  ECB)