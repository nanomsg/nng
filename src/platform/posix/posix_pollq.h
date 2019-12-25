//
// Copyright 2019 Staysail Systems, Inc. <info@staysail.tech>
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

#include "core/nng_impl.h"
#include <poll.h>

typedef struct nni_posix_pfd nni_posix_pfd;
typedef void (*nni_posix_pfd_cb)(nni_posix_pfd *, unsigned, void *);

extern int  nni_posix_pfd_init(nni_posix_pfd **, int);
extern void nni_posix_pfd_fini(nni_posix_pfd *);
extern int  nni_posix_pfd_arm(nni_posix_pfd *, unsigned);
extern int  nni_posix_pfd_fd(nni_posix_pfd *);
extern void nni_posix_pfd_close(nni_posix_pfd *);
extern void nni_posix_pfd_set_cb(nni_posix_pfd *, nni_posix_pfd_cb, void *);

#define NNI_POLL_IN ((unsigned) POLLIN)
#define NNI_POLL_OUT ((unsigned) POLLOUT)
#define NNI_POLL_HUP ((unsigned) POLLHUP)
#define NNI_POLL_ERR ((unsigned) POLLERR)
#define NNI_POLL_INVAL ((unsigned) POLLNVAL)

#endif // NNG_PLATFORM_POSIX

#endif // PLATFORM_POSIX_POLLQ_H
