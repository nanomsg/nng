#
# Copyright 2025 Staysail Systems, Inc. <info@staysail.tech>
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.
#

# UDP transport
nng_directory(udp)

if (NNG_TRANSPORT_UDP)
    nng_sources(udp.c)
    nng_defines(NNG_TRANSPORT_UDP)
    nng_test(udp_tran_test)
endif()
