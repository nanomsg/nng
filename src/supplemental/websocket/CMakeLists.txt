#
# Copyright 2017 Capitar IT Group BV <info@capitar.com>
# Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.
#

if (NNG_SUPP_WEBSOCKET)
        set(_SRCS
                supplemental/websocket/websocket.c
                supplemental/websocket/websocket.h)
else()
	set(_SRCS supplemental/websocket/stubs.c)
endif()
set(NNG_SRCS ${NNG_SRCS} ${_SRCS} PARENT_SCOPE)
