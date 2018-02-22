#
# Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
# Copyright 2018 Capitar IT Group BV <info@capitar.com>
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.
#

#  Pub/Sub protocol

if (NNG_PROTO_PUSH0)
    set(PUSH0_SOURCES protocol/pipeline0/push.c protocol/pipeline0/push.h)
    set(PUSH0_HEADERS protocol/pipeline0/push.h)
endif()

if (NNG_PROTO_PULL0)
    set(PULL0_SOURCES protocol/pipeline0/pull.c protocol/pipeline0/pull.h)
    set(PULL0_HEADERS protocol/pipeline0/pull.h)
endif()

set(NNG_SOURCES ${NNG_SOURCES} ${PUSH0_SOURCES} ${PULL0_SOURCES} PARENT_SCOPE)
set(NNG_HEADERS ${NNG_HEADERS} ${PUSH0_HEADERS} ${PULL0_HEADERS} PARENT_SCOPE)
