#
# Copyright 2020 Staysail Systems, Inc. <info@staystail.tech>
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.
#

#  Windows.

# We cannot use nng_sources_if because these tests don't go into
# the static library unless they also go into the dynamic.
if (NNG_PLATFORM_WINDOWS)
nng_sources(
        win_impl.h
        win_ipc.h
        win_tcp.h
        win_clock.c
        win_debug.c
        win_file.c
        win_io.c
        win_ipcconn.c
        win_ipcdial.c
        win_ipclisten.c
        win_pipe.c
        win_rand.c
        win_resolv.c
        win_sockaddr.c
        win_tcp.c
        win_tcpconn.c
        win_tcpdial.c
        win_tcplisten.c
        win_thread.c
        win_udp.c
        )
endif()