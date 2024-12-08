#
# Copyright 2021 Staysail Systems, Inc. <info@staystail.tech>
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.
#

nng_directory(sp)

add_subdirectory(protocol)
add_subdirectory(transport)

nng_sources(
        protocol.c
        transport.c
        transport.h
)

nng_test(reconnect_stress_test)
