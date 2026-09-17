cmake_minimum_required(VERSION 3.22)
project(exp)

enable_language(ASM)

set(CMAKE_ASM_FLAGS "${CMAKE_ASM_FLAGS} -I${CMAKE_SOURCE_DIR}")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${C_FLAGS} -I${CMAKE_SOURCE_DIR}  -Wall -Wextra -Wmost -fno-stack-protector -fomit-frame-pointer")

add_library(exp SHARED exp.c stage1.S elf_parser.c)

target_link_libraries(exp log)
