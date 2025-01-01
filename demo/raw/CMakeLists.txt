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

project(raw)

set(PARALLEL 128 CACHE STRING "Parallelism (min 4, max 1000)")

find_package(nng CONFIG REQUIRED)

add_executable(raw raw.c)
target_link_libraries(raw nng::nng)
target_compile_definitions(raw PRIVATE NNG_ELIDE_DEPRECATED PARALLEL=${PARALLEL})
