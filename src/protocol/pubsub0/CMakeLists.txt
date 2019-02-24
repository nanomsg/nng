#
# Copyright 2019 Staysail Systems, Inc. <info@staysail.tech>
# Copyright 2018 Capitar IT Group BV <info@capitar.com>
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.
#

#  Pub/Sub protocol
option (NNG_PROTO_PUB0 "Enable PUBv0 protocol." ON)
mark_as_advanced(NNG_PROTO_PUB0)

option (NNG_PROTO_SUB0 "Enable SUBv0 protocol." ON)
mark_as_advanced(NNG_PROTO_SUB0)

set(_DEFS)
set(_SRCS)

if (NNG_PROTO_PUB0)
    list(APPEND _DEFS -DNNG_HAVE_PUB0)
    list(APPEND _SRCS protocol/pubsub0/pub.c ${PROJECT_SOURCE_DIR}/include/nng/protocol/pubsub0/pub.h)
   
endif()

if (NNG_PROTO_SUB0)
    list(APPEND _DEFS -DNNG_HAVE_SUB0)
    list(APPEND _SRCS
    	protocol/pubsub0/sub.c
	protocol/pubsub0/xsub.c
    	${PROJECT_SOURCE_DIR}/include/nng/protocol/pubsub0/sub.h)
   
endif()

set(NNG_DEFS ${NNG_DEFS} ${_DEFS} PARENT_SCOPE)
set(NNG_SRCS ${NNG_SRCS} ${_SRCS} PARENT_SCOPE)
