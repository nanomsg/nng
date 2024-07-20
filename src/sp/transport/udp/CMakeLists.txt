#
# Copyright 2024 Staysail Systems, Inc. <info@staysail.tech>
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.
#

# UDP transport
nng_directory(udp)

nng_sources_if(NNG_TRANSPORT_UDP udp.c)
nng_defines_if(NNG_TRANSPORT_UDP NNG_TRANSPORT_UDP)
nng_test_if(NNG_TRANSPORT_UDP udp_tran_test)
