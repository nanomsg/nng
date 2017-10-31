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

if (NNG_PROTO_PUSH0)
    set(PUSH0_SOURCES protocol/pipeline0/push.c protocol/pipeline0/push.h)
    install(FILES push.h DESTINATION include/nng/protocol/pipeline0)
endif()

if (NNG_PROTO_PULL0)
    set(PULL0_SOURCES protocol/pipeline0/pull.c protocol/pipeline0/pull.h)
    install(FILES pull.h DESTINATION include/nng/protocol/pipeline0)
endif()

set(NNG_SOURCES ${NNG_SOURCES} ${PUSH0_SOURCES} ${PULL0_SOURCES} PARENT_SCOPE)