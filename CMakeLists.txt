cmake_minimum_required(VERSION 3.28)

project(sep3-c C)

add_library(sep3-c STATIC sep3.c)
target_include_directories(sep3-c PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>)
target_link_libraries(sep3-c PUBLIC framer7b-c safe-c)
target_compile_features(sep3-c PUBLIC c_std_17)
target_compile_options(sep3-c PRIVATE -Wall -Wextra -Werror -Wpedantic -Wno-attributes)
