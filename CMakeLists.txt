cmake_minimum_required(VERSION 3.22)
project(Sources C)

set(CMAKE_C_STANDARD 11)

include_directories(./src/ciphrameworklib/include)

add_library(
        ciphramework STATIC
        src/ciphrameworklib/mem_chunk.c
        src/ciphrameworklib/include/log.h
        src/ciphrameworklib/include/ciphrameworklib.h src/ciphrameworklib/base_objects.c src/ciphrameworklib/base_objects.c src/ciphrameworklib/cplib_helper_implementations.c src/ciphrameworklib/include/cplib_helper_implementations.h src/ciphrameworklib/cipher_driver.c)
target_compile_options(ciphramework PRIVATE -Wpedantic -Wall -Wextra -fms-extensions -DCPLIB_DEBUG)

add_executable(Sources src/main.c)
