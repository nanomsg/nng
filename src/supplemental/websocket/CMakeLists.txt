#
# Copyright 2017 Capitar IT Group BV <info@capitar.com>
# Copyright 2017 Staysail Systems, Inc. <info@staysail.tech>
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.
#

if (NNG_SUPP_WEBSOCKET)
        set(WEBSOCKET_SOURCES
                supplemental/websocket/websocket.c
                supplemental/websocket/websocket.h)
endif()
set(NNG_SOURCES ${NNG_SOURCES} ${WEBSOCKET_SOURCES} PARENT_SCOPE)
