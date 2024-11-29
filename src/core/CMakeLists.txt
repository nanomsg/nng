#
# Copyright 2024 Staysail Systems, Inc. <info@staystail.tech>
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.
#

#  Core.
nng_directory(core)

nng_check_sym(strlcpy string.h NNG_HAVE_STRLCPY)
nng_check_sym(strnlen string.h NNG_HAVE_STRNLEN)
nng_check_sym(strcasecmp string.h NNG_HAVE_STRCASECMP)
nng_check_sym(strncasecmp string.h NNG_HAVE_STRNCASECMP)
nng_check_sym(localtime_r time.h NNG_HAVE_LOCALTIME_R)

nng_sources(
        defs.h

        aio.c
        aio.h
        device.c
        device.h
        dialer.c
        dialer.h
        sockfd.c
        sockfd.h
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
        log.c
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
        protocol.h
        reap.c
        reap.h
        refcnt.c
        refcnt.h
        sockaddr.c
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
        tcp.c
        tcp.h
        thread.c
        thread.h
        url.c
        url.h
)

nng_test(aio_test)
nng_test(buf_size_test)
nng_test(errors_test)
nng_test(id_test)
nng_test(init_test)
nng_test(list_test)
nng_test(log_test)
nng_test(message_test)
nng_test(reconnect_test)
nng_test(sock_test)
nng_test(sockaddr_test)
nng_test(synch_test)
nng_test(stats_test)
nng_test(url_test)
