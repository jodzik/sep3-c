cmake_minimum_required(VERSION 3.28)

project(sep3-c C)

add_library(sep3-c STATIC sep3.c)
target_include_directories(sep3-c PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>)
target_link_libraries(sep3-c PUBLIC crc-c framer7b-c safe-c)
target_compile_features(sep3-c PUBLIC c_std_17)
target_compile_options(sep3-c PRIVATE -Wall -Wextra -Werror -Wpedantic -Wno-attributes)

if(NOT DEFINED SEP3_MAX_PAYLOAD_SIZE AND DEFINED CONFIG_SEP3_MAX_PAYLOAD_SIZE)
    set(SEP3_MAX_PAYLOAD_SIZE "${CONFIG_SEP3_MAX_PAYLOAD_SIZE}")
endif()

if(NOT DEFINED SEP3_MAX_PAYLOAD_SIZE)
    if(DEFINED ENV{SEP3_MAX_PAYLOAD_SIZE})
        set(SEP3_MAX_PAYLOAD_SIZE "$ENV{SEP3_MAX_PAYLOAD_SIZE}")
    else()
        set(SEP3_MAX_PAYLOAD_SIZE 244)
    endif()
endif()

if(NOT SEP3_MAX_PAYLOAD_SIZE MATCHES "^[0-9]+$")
    message(FATAL_ERROR "SEP3_MAX_PAYLOAD_SIZE must be an integer: ${SEP3_MAX_PAYLOAD_SIZE}")
endif()

if(SEP3_MAX_PAYLOAD_SIZE LESS 64 OR SEP3_MAX_PAYLOAD_SIZE GREATER 2046)
    message(FATAL_ERROR "SEP3_MAX_PAYLOAD_SIZE must be in range 64..2046: ${SEP3_MAX_PAYLOAD_SIZE}")
endif()

set(SEP3_MAX_PAYLOAD_SIZE "${SEP3_MAX_PAYLOAD_SIZE}" CACHE STRING "Maximum SEP3 payload size")
target_compile_definitions(sep3-c PUBLIC "CONFIG_SEP3_MAX_PAYLOAD_SIZE=${SEP3_MAX_PAYLOAD_SIZE}")
