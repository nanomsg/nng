#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.

cmake_minimum_required (VERSION 2.8.12)

project(mqtt_async)

find_package(nng CONFIG REQUIRED)
find_package(Threads)

add_executable(mqtt_async mqtt_async.c)
target_link_libraries(mqtt_async nng)
target_link_libraries(mqtt_async ${CMAKE_THREAD_LIBS_INIT})

if(NNG_ENABLE_TLS)
    find_package(MbedTLS)
    target_link_libraries(mqtt_async mbedtls mbedx509 mbedcrypto)
    add_definitions(-DNNG_SUPP_TLS)
endif()

target_compile_definitions(mqtt_async PRIVATE NNG_ELIDE_DEPRECATED)