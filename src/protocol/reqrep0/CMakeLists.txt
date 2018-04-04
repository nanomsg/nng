#
# Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
# Copyright 2018 Capitar IT Group BV <info@capitar.com>
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.
#

#  Req/Rep protocol

if (NNG_PROTO_REQ0)
    set(REQ0_SOURCES protocol/reqrep0/req.c protocol/reqrep0/xreq.c
    protocol/reqrep0/req.h)
    set(REQ0_HEADERS protocol/reqrep0/req.h)
endif()

if (NNG_PROTO_REP0)
    set(REP0_SOURCES protocol/reqrep0/rep.c protocol/reqrep0/xrep.c
    protocol/reqrep0/rep.h)
    set(REP0_HEADERS protocol/reqrep0/rep.h)
endif()

set(NNG_SOURCES ${NNG_SOURCES} ${REQ0_SOURCES} ${REP0_SOURCES} PARENT_SCOPE)
set(NNG_HEADERS ${NNG_HEADERS} ${REQ0_HEADERS} ${REP0_HEADERS} PARENT_SCOPE)
