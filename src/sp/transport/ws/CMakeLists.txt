#
# Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
# Copyright 2018 Capitar IT Group BV <info@capitar.com>
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.
#

# WebSocket transport
nng_directory(ws)

if (NNG_TRANSPORT_WS OR NNG_TRANSPORT_WSS)
    set(WS_ON ON)
endif()

nng_defines_if(NNG_TRANSPORT_WS NNG_TRANSPORT_WS)
nng_defines_if(NNG_TRANSPORT_WSS NNG_TRANSPORT_WSS)
nng_sources_if(WS_ON websocket.c)
nng_headers_if(WS_ON nng/transport/ws/websocket.h)
nng_test_if(WS_ON ws_test)


