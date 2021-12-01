#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.

cmake_minimum_required (VERSION 2.8.7)

project(mqtt_client)

find_package(nng CONFIG REQUIRED)

find_package(Threads)

add_executable(mqtt_client mqtt_client.c)
target_link_libraries(mqtt_client nng)
target_link_libraries(mqtt_client ${CMAKE_THREAD_LIBS_INIT})
