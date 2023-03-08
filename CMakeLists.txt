cmake_minimum_required(VERSION 3.22)
project(Sources C)

set(CMAKE_C_STANDARD 17)

set(CPLIB_BUILD_TYPE ${BUILD_TYPE})
message("BUILD_TYPE:  ${BUILD_TYPE}")
if (NOT CPLIB_BUILD_TYPE)
    set(CPLIB_BUILD_TYPE CPLIB_RELEASE)
endif()

set(BUILD_TYPE_COMPILER_FLAG "-D${CPLIB_BUILD_TYPE}")

message("CPLIB_BUILD_TYPE: ${BUILD_TYPE_COMPILER_FLAG}")

include_directories(
        ./src/ciphrameworklib/include
        ./src/sample_implementation/include
)

add_library(
        ciphramework STATIC
        src/ciphrameworklib/cplib_mem.c
        src/ciphrameworklib/base_objects.c
        src/ciphrameworklib/cplib_utils.c
        src/ciphrameworklib/cipher_driver.c
)

target_compile_options(ciphramework PRIVATE -Wpedantic -Wall -Wextra -fms-extensions -D${CPLIB_BUILD_TYPE})

add_executable(
        kcrypt
        src/sample_implementation/main.c
        src/sample_implementation/xor_cipher.c
)

target_link_libraries(kcrypt ciphramework)

target_compile_options(kcrypt PRIVATE -Wpedantic -Wall -Wextra -fms-extensions -D${CPLIB_BUILD_TYPE})
