#
# Copyright 2018 Capitar IT Group BV <info@capitar.com>
# Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.
#

set(COMPAT_SOURCES compat/nanomsg/nn.c)
set(COMPAT_HEADERS compat/nanomsg/nn.h
        compat/nanomsg/bus.h
        compat/nanomsg/inproc.h
        compat/nanomsg/ipc.h
        compat/nanomsg/pair.h
        compat/nanomsg/pipeline.h
        compat/nanomsg/pubsub.h
        compat/nanomsg/reqrep.h
        compat/nanomsg/survey.h
        compat/nanomsg/tcp.h
        compat/nanomsg/ws.h
)

set(NNG_SRCS ${NNG_SRCS} ${COMPAT_SOURCES} PARENT_SCOPE)
set(NNG_HDRS ${NNG_HDRS} ${COMPAT_HEADERS} PARENT_SCOPE)
