#
# Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
# Copyright 2018 Capitar IT Group BV <info@capitar.com>
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.
#

#  Bus protocol

if (NNG_PROTO_BUS0)
    set(BUS0_SOURCES protocol/bus0/bus.c protocol/bus0/bus.h)
    set(BUS0_HEADERS protocol/bus0/bus.h)
endif()

set(NNG_SOURCES ${NNG_SOURCES} ${BUS0_SOURCES} PARENT_SCOPE)
set(NNG_HEADERS ${NNG_HEADERS} ${BUS0_HEADERS} PARENT_SCOPE)
