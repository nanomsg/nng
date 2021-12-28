#
# Copyright 2021 Staysail Systems, Inc. <info@staysail.tech>
# Copyright 2018 Capitar IT Group BV <info@capitar.com>
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.
#

#  Bus protocol
nng_directory(bus0)

nng_sources_if(NNG_PROTO_BUS0 bus.c)
nng_headers_if(NNG_PROTO_BUS0 nng/protocol/bus0/bus.h)
nng_defines_if(NNG_PROTO_BUS0 NNG_HAVE_BUS0)

nng_test(bus_test)