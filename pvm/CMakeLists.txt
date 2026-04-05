cmake_minimum_required(VERSION 3.20)
project(pvm C)

set(CMAKE_C_STANDARD 11)

add_library(pvm STATIC src/pvm.c)
target_include_directories(pvm PUBLIC include)
