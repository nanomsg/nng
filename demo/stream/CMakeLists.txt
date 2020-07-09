#
# Copyright 2020 Hugo Lindström <hugolm84@gmail.com>
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.

cmake_minimum_required (VERSION 2.8.7)

project(stream)

find_package(nng CONFIG REQUIRED)

add_executable(${PROJECT_NAME})

target_sources(${PROJECT_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/stream.c)

if (CMAKE_SYSTEM_NAME MATCHES "Linux")
    target_sources(${PROJECT_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/platform/posix/server.c)
endif()

if (CMAKE_SYSTEM_NAME MATCHES "Windows")
    target_sources(${PROJECT_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/platform/windows/server.c)
endif()

target_link_libraries(stream nng::nng)
