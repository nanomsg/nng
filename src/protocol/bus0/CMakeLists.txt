#
# Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
# Copyright 2018 Capitar IT Group BV <info@capitar.com>
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.
#

#  Bus protocol
option (NNG_PROTO_BUS0 "Enable BUSv0 protocol." ON)
mark_as_advanced(NNG_PROTO_BUS0)

if (NNG_PROTO_BUS0)
    set(_DEFS -DNNG_HAVE_BUS0)
    set(_SRCS protocol/bus0/bus.c ${PROJECT_SOURCE_DIR}/include/nng/protocol/bus0/bus.h)

    set(NNG_DEFS ${NNG_DEFS} ${_DEFS} PARENT_SCOPE)
    set(NNG_SRCS ${NNG_SRCS} ${_SRCS} PARENT_SCOPE)
endif()
