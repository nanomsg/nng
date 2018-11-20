#
# Copyright 2018 Staysail Systems, Inc. <info@staystail.tech>
# Copyright 2018 Capitar IT Group BV <info@capitar.com>
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.
#

#  PAIRv1 protocol
option (NNG_PROTO_PAIR1 "Enable PAIRv1 protocol." ON)
mark_as_advanced(NNG_PROTO_PAIR1)

if (NNG_PROTO_PAIR1)
    set(_DEFS -DNNG_HAVE_PAIR1)
    set(_SRCS protocol/pair1/pair.c ${PROJECT_SOURCE_DIR}/include/nng/protocol/pair1/pair.h)

    set(NNG_DEFS ${NNG_DEFS} ${_DEFS} PARENT_SCOPE)
    set(NNG_SRCS ${NNG_SRCS} ${_SRCS} PARENT_SCOPE)
endif()
