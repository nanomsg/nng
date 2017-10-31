#
# Copyright 2017 Garrett D'Amore <garrett@damore.org>
# Copyright 2017 Capitar IT Group BV <info@capitar.com>
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.
#

#  PAIRv0 protocol

if (NNG_PROTO_PAIR0)
    set(PAIR0_SOURCES protocol/pair0/pair.c protocol/pair0/pair.h)
    install(FILES pair.h DESTINATION include/nng/protocol/pair0)
endif()

set(NNG_SOURCES ${NNG_SOURCES} ${PAIR0_SOURCES} PARENT_SCOPE)
