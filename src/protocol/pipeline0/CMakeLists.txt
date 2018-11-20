#
# Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
# Copyright 2018 Capitar IT Group BV <info@capitar.com>
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.
#

#  Pipeline protocol
option (NNG_PROTO_PUSH0 "Enable PUSHv0 protocol." ON)
mark_as_advanced(NNG_PROTO_PUSH0)

option (NNG_PROTO_PULL0 "Enable PULLv0 protocol." ON)
mark_as_advanced(NNG_PROTO_PULL0)

set(_DEFS)
set(_SRCS)

if (NNG_PROTO_PUSH0)
    list(APPEND _SRCS protocol/pipeline0/push.c ${PROJECT_SOURCE_DIR}/include/nng/protocol/pipeline0/push.h)
   
    list(APPEND _DEFS -DNNG_HAVE_PUSH0)
endif()

if (NNG_PROTO_PULL0)
    list(APPEND _SRCS protocol/pipeline0/pull.c ${PROJECT_SOURCE_DIR}/include/nng/protocol/pipeline0/pull.h)
   
    list(APPEND _DEFS -DNNG_HAVE_PULL0)
endif()

set(NNG_DEFS ${NNG_DEFS} ${_DEFS} PARENT_SCOPE)
set(NNG_SRCS ${NNG_SRCS} ${_SRCS} PARENT_SCOPE)
