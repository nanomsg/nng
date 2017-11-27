#
# Copyright 2017 Staysail Systems, Inc. <info@staysail.tech>
# Copyright 2017 Capitar IT Group BV <info@capitar.com>
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.
#

# WebSocket transport

if (NNG_TRANSPORT_WS)
    set(WS_SOURCES transport/ws/websocket.c transport/ws/websocket.h)
    install(FILES websocket.h DESTINATION include/nng/transport/ws)
    
endif()

set(NNG_SOURCES ${NNG_SOURCES} ${WS_SOURCES} PARENT_SCOPE)
