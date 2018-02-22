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

if (NNG_PROTO_PUB0)
    set(PUB0_SOURCES protocol/pubsub0/pub.c protocol/pubsub0/pub.h)
    set(PUB0_HEADERS protocol/pubsub0/pub.h)
endif()

if (NNG_PROTO_SUB0)
    set(SUB0_SOURCES protocol/pubsub0/sub.c protocol/pubsub0/sub.h)
    set(SUB0_HEADERS protocol/pubsub0/sub.h)
endif()

set(NNG_SOURCES ${NNG_SOURCES} ${PUB0_SOURCES} ${SUB0_SOURCES} PARENT_SCOPE)
set(NNG_HEADERS ${NNG_HEADERS} ${PUB0_HEADERS} ${SUB0_HEADERS} PARENT_SCOPE)
