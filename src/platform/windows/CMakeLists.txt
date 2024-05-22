#
# Copyright 2024 Staysail Systems, Inc. <info@staystail.tech>
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
    nng_check_sym(InitializeConditionVariable windows.h NNG_HAVE_CONDVAR)
    nng_check_sym(timespec_get time.h NNG_HAVE_TIMESPEC_GET)
    nng_check_sym(snprintf stdio.h NNG_HAVE_SNPRINTF)
    if (NOT NNG_HAVE_CONDVAR OR NOT NNG_HAVE_SNPRINTF OR NOT NNG_HAVE_TIMESPEC_GET)
        message(FATAL_ERROR
                "Modern Windows API support is missing. "
                "Versions of Windows prior to Vista are not supported.  "
                "Further, the legacy MinGW environments are not supported. "
                "Ensure you have at least Windows Vista or newer, and are "
                "using either Visual Studio 2013 or compatible compiler, "
                "and are also using the universal C runtime (UCRT).")
    endif ()
    nng_link_libraries(ws2_32 mswsock advapi32)

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
            win_socketpair.c
            win_tcp.c
            win_tcpconn.c
            win_tcpdial.c
            win_tcplisten.c
            win_thread.c
            win_udp.c
    )

    nng_test(win_ipc_sec_test)

endif ()
