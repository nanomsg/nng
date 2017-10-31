#
# Copyright 2017 Garrett D'Amore <garrett@damore.org>
# Copyright 2017 Capitar IT Group BV <info@capitar.com>
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.
#

# TCP protocol

if (NNG_TRANSPORT_TCP)
    set(TCP_SOURCES transport/tcp/tcp.c transport/tcp/tcp.h)
    install(FILES tcp.h DESTINATION include/nng/transport/tcp)
endif()

set(NNG_SOURCES ${NNG_SOURCES} ${TCP_SOURCES} PARENT_SCOPE)
