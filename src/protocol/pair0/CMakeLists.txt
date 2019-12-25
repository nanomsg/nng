#
# Copyright 2019 Staysail Systems, Inc. <info@staysail.tech>
# Copyright 2018 Capitar IT Group BV <info@capitar.com>
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.
#

#  PAIRv0 protocol
option (NNG_PROTO_PAIR0 "Enable PAIRv0 protocol." ON)
mark_as_advanced(NNG_PROTO_PAIR0)

nng_sources_if(NNG_PROTO_PAIR0 pair.c)
nng_headers_if(NNG_PROTO_PAIR0 nng/protocol/pair0/pair.h)
nng_defines_if(NNG_PROTO_PAIR0 NNG_HAVE_PAIR0)