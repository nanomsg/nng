#
# Copyright 2017 Garrett D'Amore <garrett@damore.org>
# Copyright 2017 Capitar IT Group BV <info@capitar.com>
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.
#

#  Req/Rep protocol

if (NNG_PROTO_REQ0)
    set(REQ0_SOURCES protocol/reqrep0/req.c protocol/reqrep0/req.h)
    install(FILES req.h DESTINATION include/nng/protocol/reqrep0)
endif()

if (NNG_PROTO_REP0)
    set(REP0_SOURCES protocol/reqrep0/rep.c protocol/reqrep0/rep.h)
    install(FILES rep.h DESTINATION include/nng/protocol/reqrep0)
endif()

set(NNG_SOURCES ${NNG_SOURCES} ${REQ0_SOURCES} ${REP0_SOURCES} PARENT_SCOPE)