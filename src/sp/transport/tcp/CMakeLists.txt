#
# Copyright 2025 Staysail Systems, Inc. <info@staysail.tech>
# Copyright 2018 Capitar IT Group BV <info@capitar.com>
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.
#

# TCP protocol
nng_directory(tcp)

if (NNG_TRANSPORT_TCP)
    nng_sources(tcp.c)
    nng_defines(NNG_TRANSPORT_TCP)
    nng_test(tcp_test)
endif()
