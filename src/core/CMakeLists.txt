#
# Copyright 2020 Staysail Systems, Inc. <info@staystail.tech>
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.
#

#  Core.

nng_check_sym(strlcpy string.h NNG_HAVE_STRLCPY)
nng_check_sym(strnlen string.h NNG_HAVE_STRNLEN)
nng_check_sym(strcasecmp string.h NNG_HAVE_STRCASECMP)
nng_check_sym(strncasecmp string.h NNG_HAVE_STRNCASECMP)

nng_sources(
        defs.h

        aio.c
        aio.h
        clock.c
        clock.h
        device.c
        device.h
        dialer.c
        dialer.h
        file.c
        file.h
        idhash.c
        idhash.h
        init.c
        init.h
        list.c
        list.h
        listener.c
        listener.h
        lmq.c
        lmq.h
        message.c
        message.h
        msgqueue.c
        msgqueue.h
        nng_impl.h
        options.c
        options.h
        pollable.c
        pollable.h
        panic.c
        panic.h
        pipe.c
        pipe.h
        platform.h
        protocol.c
        protocol.h
        reap.c
        reap.h
        socket.c
        socket.h
        sockimpl.h
        stats.c
        stats.h
        stream.c
        stream.h
        strs.c
        strs.h
        taskq.c
        taskq.h
        thread.c
        thread.h
        timer.c
        timer.h
        transport.c
        transport.h
        url.c
        url.h
)
