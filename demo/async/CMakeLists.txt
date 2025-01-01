#
# Copyright 2025 Staysail Systems, Inc. <info@staysail.tech>
# Copyright 2018 Capitar IT Group BV <info@capitar.com>
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.

# This CMakeLists file assumes you have INSTALLED NNG.
# It does not work from the NNG source tree directly.

cmake_minimum_required (VERSION 3.15)

project(nng-asyncdemo)

set(PARALLEL 128 CACHE STRING "Parallelism (min 4, max 1000)")

# Call this from your own project's makefile.
find_package(nng CONFIG REQUIRED)

add_executable(server server.c)
target_link_libraries(server nng::nng)
target_compile_definitions(server PRIVATE NNG_ELIDE_DEPRECATED PARALLEL=${PARALLEL})

add_executable(client client.c)
target_link_libraries(client nng::nng)
target_compile_definitions(client PRIVATE NNG_ELIDE_DEPRECATED)
