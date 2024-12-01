#
# Copyright 2024 Staysail Systems, Inc. <info@staystail.tech>
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

nng_test(pipe_test)
nng_test(device_test)
nng_test(multistress_test)
nng_test(nonblock_test)
nng_test(scalability_test)
