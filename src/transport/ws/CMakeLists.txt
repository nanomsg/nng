#
# Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
# Copyright 2018 Capitar IT Group BV <info@capitar.com>
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.
#

# WebSocket transport
option (NNG_TRANSPORT_WS "Enable WebSocket transport." ON)
mark_as_advanced(NNG_TRANSPORT_WS)

CMAKE_DEPENDENT_OPTION(NNG_TRANSPORT_WSS "Enable WSS transport" ON
    "NNG_ENABLE_TLS" OFF)
mark_as_advanced(NNG_TRANSPORT_WSS)

set(_DEFS)

if (NNG_TRANSPORT_WS)
    list(APPEND _DEFS -DNNG_TRANSPORT_WS)
endif()
if (NNG_TRANSPORT_WSS)
    list(APPEND _DEFS -DNNG_TRANSPORT_WSS)
endif()

if (NNG_TRANSPORT_WS OR NNG_TRANSPORT_WSS)

    # Make sure things we *MUST* have are enabled.
    set(NNG_SUPP_WEBSOCKET ON PARENT_SCOPE)
    set(NNG_SUPP_HTTP ON PARENT_SCOPE)
    set(NNG_SUPP_BASE64 ON PARENT_SCOPE)
    set(NNG_SUPP_SHA1 ON PARENT_SCOPE)

    set(_SRCS transport/ws/websocket.c ${PROJECT_SOURCE_DIR}/include/nng/transport/ws/websocket.h)
    set(NNG_DEFS ${NNG_DEFS} ${_DEFS} PARENT_SCOPE)
    set(NNG_SRCS ${NNG_SRCS} ${_SRCS} PARENT_SCOPE)
endif()
