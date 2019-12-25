#
# Copyright 2019 Staysail Systems, Inc. <info@staysail.tech>
# Copyright 2018 Capitar IT Group BV <info@capitar.com>
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.
#

# TCP protocol
option (NNG_TRANSPORT_TCP "Enable TCP transport." ON)
mark_as_advanced(NNG_TRANSPORT_TCP)

nng_sources_if(NNG_TRANSPORT_TCP tcp.c)
nng_headers_if(NNG_TRANSPORT_TCP nng/transport/tcp/tcp.h)
nng_defines_if(NNG_TRANSPORT_TCP NNG_TRANSPORT_TCP)