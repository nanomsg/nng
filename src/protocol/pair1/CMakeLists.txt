#
# Copyright 2018 Staysail Systems, Inc. <info@staystail.tech>
# Copyright 2018 Capitar IT Group BV <info@capitar.com>
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.
#

#  PAIRv1 protocol

if (NNG_PROTO_PAIR1)
    set(PAIR1_SOURCES protocol/pair1/pair.c protocol/pair1/pair.h)
    set(PAIR1_HEADERS protocol/pair1/pair.h)
endif()

set(NNG_SOURCES ${NNG_SOURCES} ${PAIR1_SOURCES} PARENT_SCOPE)
set(NNG_HEADERS ${NNG_HEADERS} ${PAIR1_HEADERS} PARENT_SCOPE)
