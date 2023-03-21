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
        src/ciphramework/include
        src/kcrypt/include
)

add_library(
        ciphramework SHARED
        src/ciphramework/cplib_mem.c
        src/ciphramework/base_objects.c
        src/ciphramework/cplib_utils.c
        src/ciphramework/cipher_driver.c
)

target_compile_options(ciphramework PRIVATE -Wpedantic -Wall -Wextra -fms-extensions -D${CPLIB_BUILD_TYPE})

set(CMAKE_SHARED_LIBRARY_PREFIX "")
# CIPHERS
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/ciphers)

add_library(
        feisty.no_round_key SHARED
        src/ciphers/feisty.no_round_key.c
)

target_compile_options(feisty.no_round_key PRIVATE -Wpedantic -Wall -Wextra -fms-extensions -D${CPLIB_BUILD_TYPE})
target_link_libraries(feisty.no_round_key ciphramework)

add_library(
        feisty.configurable_round_key SHARED
        src/ciphers/feisty.configurable_round_key.c
)

target_compile_options(feisty.configurable_round_key PRIVATE -Wpedantic -Wall -Wextra -fms-extensions -D${CPLIB_BUILD_TYPE})
target_link_libraries(feisty.configurable_round_key ciphramework)

add_library(
        xor SHARED
        src/ciphers/xor.c
)

target_compile_options(xor PRIVATE -Wpedantic -Wall -Wextra -fms-extensions -D${CPLIB_BUILD_TYPE})
target_link_libraries(xor ciphramework)

# MODES
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/modes)

add_library(
        ECB SHARED
        src/modes/ECB.c
)

target_compile_options(ECB PRIVATE -Wpedantic -Wall -Wextra -fms-extensions -D${CPLIB_BUILD_TYPE})
target_link_libraries(ECB ciphramework)

add_library(
        CBC SHARED
        src/modes/CBC.c
)

target_compile_options(CBC PRIVATE -Wpedantic -Wall -Wextra -fms-extensions -D${CPLIB_BUILD_TYPE})
target_link_libraries(CBC ciphramework)

add_library(
        CTR SHARED
        src/modes/CTR.c
)

target_compile_options(CTR PRIVATE -Wpedantic -Wall -Wextra -fms-extensions -D${CPLIB_BUILD_TYPE})
target_link_libraries(CTR ciphramework)

# KCRYPT
add_executable(
        kcrypt
        src/kcrypt/main.c
        src/kcrypt/kcrypt_utils.c
)

target_link_libraries(kcrypt ciphramework dc_utils dl)

target_compile_options(kcrypt PRIVATE -Wpedantic -Wall -Wextra -fms-extensions -D${CPLIB_BUILD_TYPE})

add_dependencies(
        kcrypt
        ciphramework
        feisty.no_round_key
        feisty.configurable_round_key
        xor
        ECB
        CBC
        CTR)