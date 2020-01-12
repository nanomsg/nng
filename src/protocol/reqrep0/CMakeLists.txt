#
# Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
# Copyright 2018 Capitar IT Group BV <info@capitar.com>
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.
#

#  Req/Rep protocol
option(NNG_PROTO_REQ0 "Enable REQv0 protocol." ON)
mark_as_advanced(NNG_PROTO_REQ0)

option(NNG_PROTO_REP0 "Enable REPv0 protocol." ON)
mark_as_advanced(NNG_PROTO_REP0)

nng_sources_if(NNG_PROTO_REQ0 req.c xreq.c)
nng_headers_if(NNG_PROTO_REQ0 nng/protocol/reqrep0/req.h)
nng_defines_if(NNG_PROTO_REQ0 NNG_HAVE_REQ0)

nng_sources_if(NNG_PROTO_REP0 rep.c xrep.c)
nng_headers_if(NNG_PROTO_REP0 nng/protocol/reqrep0/rep.h)
nng_defines_if(NNG_PROTO_REP0 NNG_HAVE_REP0)

nng_test(req_test)
nng_test(rep_test)
nng_test(xrep_test)
nng_test(xreq_test)
