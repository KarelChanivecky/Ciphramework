cmake_minimum_required(VERSION 3.22)
project(Sources C)

set(CMAKE_C_STANDARD 17)

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

target_compile_options(ciphramework PRIVATE -Wpedantic -Wall -Wextra -fms-extensions -DCPLIB_DEBUG)

add_executable(
        kcrypt
        src/sample_implementation/main.c
        src/sample_implementation/xor_cipher.c
)

target_link_libraries(kcrypt ciphramework)

target_compile_options(kcrypt PRIVATE -Wpedantic -Wall -Wextra -fms-extensions -DCPLIB_DEBUG)
