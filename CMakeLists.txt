cmake_minimum_required(VERSION 3.18)
project(TP_Protos C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS "-std=c11 -pedantic -pedantic-errors -g -Wall -Werror -Wextra -D_POSIX_C_SOURCE=200112L -fsanitize=address -Wno-unused-parameter -Wno-unused-variable -Wno-unused-function -pthread")

add_executable(TP_Protos src/main.c
        src/lib/args.c
        src/lib/selector.c
        src/smtp.c
        src/smtp.h
        src/lib/stm.c
        src/lib/headers/stm.h)