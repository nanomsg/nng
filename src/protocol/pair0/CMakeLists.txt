#
# Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
# Copyright 2018 Capitar IT Group BV <info@capitar.com>
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.
#

#  PAIRv0 protocol
option (NNG_PROTO_PAIR0 "Enable PAIRv0 protocol." ON)
mark_as_advanced(NNG_PROTO_PAIR0)

if (NNG_PROTO_PAIR0)
    set(_DEFS -DNNG_HAVE_PAIR0)
    set(_SRCS protocol/pair0/pair.c ${PROJECT_SOURCE_DIR}/include/nng/protocol/pair0/pair.h)

    set(NNG_DEFS ${NNG_DEFS} ${_DEFS} PARENT_SCOPE)
    set(NNG_SRCS ${NNG_SRCS} ${_SRCS} PARENT_SCOPE)
endif()
