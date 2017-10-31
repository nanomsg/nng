#
# Copyright 2017 Garrett D'Amore <garrett@damore.org>
# Copyright 2017 Capitar IT Group BV <info@capitar.com>
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.
#

#  Pub/Sub protocol

if (NNG_PROTO_PUB0)
    set(PUB0_SOURCES protocol/pubsub0/pub.c protocol/pubsub0/pub.h)
    install(FILES pub.h DESTINATION include/nng/protocol/pubsub0)
endif()

if (NNG_PROTO_SUB0)
    set(SUB0_SOURCES protocol/pubsub0/sub.c protocol/pubsub0/sub.h)
    install(FILES sub.h DESTINATION include/nng/protocol/pubsub0)
endif()

set(NNG_SOURCES ${NNG_SOURCES} ${PUB0_SOURCES} ${SUB0_SOURCES} PARENT_SCOPE)