#
# Copyright 2020 Staysail Systems, Inc. <info@staystail.tech>
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.
#

#  Protocols.
nng_directory(testing`)

target_sources(nng_testing PRIVATE
        certs.c
        marry.c
        streams.c
        util.c)

target_include_directories(nng_testing PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
