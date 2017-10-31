#
# Copyright 2017 Garrett D'Amore <garrett@damore.org>
# Copyright 2017 Capitar IT Group BV <info@capitar.com>
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.
#

#  Bus protocol

if (NNG_PROTO_BUS0)
    set(BUS0_SOURCES protocol/bus0/bus.c protocol/bus0/bus.h)
    install(FILES bus.h DESTINATION include/nng/protocol/bus0)
endif()

set(NNG_SOURCES ${NNG_SOURCES} ${BUS0_SOURCES} PARENT_SCOPE)
