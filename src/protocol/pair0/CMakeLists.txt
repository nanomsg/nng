#
# Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
# Copyright 2018 Capitar IT Group BV <info@capitar.com>
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.
#

#  PAIRv0 protocol

if (NNG_PROTO_PAIR0)
    set(PAIR0_SOURCES protocol/pair0/pair.c protocol/pair0/pair.h)
    set(PAIR0_HEADERS protocol/pair0/pair.h)
endif()

set(NNG_SOURCES ${NNG_SOURCES} ${PAIR0_SOURCES} PARENT_SCOPE)
set(NNG_HEADERS ${NNG_HEADERS} ${PAIR0_HEADERS} PARENT_SCOPE)
