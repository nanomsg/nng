//
// Copyright 2025 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef PLATFORM_POSIX_POLLQ_H
#define PLATFORM_POSIX_POLLQ_H

#ifdef NNG_PLATFORM_POSIX

// This file defines structures we will use for emulating asynchronous I/O
// on POSIX.  POSIX lacks the support for callback based asynchronous I/O
// that we have on Windows, although it has a non-widely support aio layer
// that is not very performant on many systems.   So we emulate this using
// one of several possible different backends.

#if defined(NNG_POLLQ_KQUEUE)
#include "posix_pollq_kqueue.h"
#elif defined(NNG_POLLQ_PORTS)
#include "posix_pollq_port.h"
#elif defined(NNG_POLLQ_EPOLL)
#include "posix_pollq_epoll.h"
#elif defined(NNG_POLLQ_POLL)
#include "posix_pollq_poll.h"
#elif defined(NNG_POLLQ_SELECT)
#include "posix_pollq_select.h"
#else
#error "No suitable poller defined"
#endif

extern void nni_posix_pfd_init(nni_posix_pfd *, int, nni_posix_pfd_cb, void *);
extern void nni_posix_pfd_fini(nni_posix_pfd *);
extern void nni_posix_pfd_stop(nni_posix_pfd *);
extern int  nni_posix_pfd_arm(nni_posix_pfd *, unsigned);
extern int  nni_posix_pfd_fd(nni_posix_pfd *);
extern void nni_posix_pfd_close(nni_posix_pfd *);

#endif // NNG_PLATFORM_POSIX

#endif // PLATFORM_POSIX_POLLQ_H
