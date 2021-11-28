#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.

cmake_minimum_required (VERSION 2.8.7)

project(mqtt_async)

find_package(nng CONFIG REQUIRED)
find_package(Threads)
find_package(MbedTLS)

add_executable(mqtt_async mqtt_async.c)
target_link_libraries(mqtt_async nng )
target_link_libraries(mqtt_async mbedtls mbedx509 mbedcrypto)
target_link_libraries(mqtt_async ${CMAKE_THREAD_LIBS_INIT})
