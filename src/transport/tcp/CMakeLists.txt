#
# Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
# Copyright 2018 Capitar IT Group BV <info@capitar.com>
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.
#

# TCP protocol

if (NNG_TRANSPORT_TCP)
    set(TCP_SOURCES transport/tcp/tcp.c transport/tcp/tcp.h)
    set(TCP_HEADERS transport/tcp/tcp.h)
endif()

set(NNG_SOURCES ${NNG_SOURCES} ${TCP_SOURCES} PARENT_SCOPE)
set(NNG_HEADERS ${NNG_HEADERS} ${TCP_HEADERS} PARENT_SCOPE)
