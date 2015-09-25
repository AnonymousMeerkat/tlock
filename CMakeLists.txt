cmake_minimum_required(VERSION 2.6)
project(tlock)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra --std=gnu11")

add_subdirectory(src)
