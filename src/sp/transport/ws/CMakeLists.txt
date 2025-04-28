#
# Copyright 2025 Staysail Systems, Inc. <info@staysail.tech>
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
    nng_sources(websocket.c)
endif()

if (NNG_TRANSPORT_WS)
    nng_defines(NNG_TRANSPORT_WS)
    nng_test(ws_test)
endif()
if (NNG_TRANSPORT_WSS)
    nng_defines(NNG_TRANSPORT_WSS)
    nng_test(wss_test)
endif()
