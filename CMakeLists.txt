cmake_minimum_required(VERSION 3.22)
project(Sources C)

set(CMAKE_C_STANDARD 11)

include_directories(./ciphrameworklib/include)

add_library(ciphramework STATIC ciphrameworklib/mem_chunk.c ciphrameworklib/mem_chunk.c ciphrameworklib/log.c)
target_compile_options(ciphramework PRIVATE -Wpedantic -Wall -Wextra -fms-extensions)

add_executable(Sources main.c)
