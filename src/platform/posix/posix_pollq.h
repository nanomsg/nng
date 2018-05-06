//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
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

typedef struct nni_posix_pollq_node nni_posix_pollq_node;
typedef struct nni_posix_pollq      nni_posix_pollq;

struct nni_posix_pollq_node {
	nni_list_node    node;    // linkage into the pollq list
	nni_posix_pollq *pq;      // associated pollq
	int              index;   // used by the poller impl
	int              armed;   // used by the poller impl
	int              fd;      // file descriptor to poll
	int              events;  // events to watch for
	int              revents; // events received
	void *           data;    // user data
	nni_cb           cb;      // user callback on event
	nni_mtx          mx;
	nni_cv           cv;
};

extern nni_posix_pollq *nni_posix_pollq_get(int);
extern int              nni_posix_pollq_sysinit(void);
extern void             nni_posix_pollq_sysfini(void);

extern int  nni_posix_pollq_init(nni_posix_pollq_node *);
extern void nni_posix_pollq_fini(nni_posix_pollq_node *);
extern int  nni_posix_pollq_add(nni_posix_pollq_node *);
extern void nni_posix_pollq_remove(nni_posix_pollq_node *);
extern void nni_posix_pollq_arm(nni_posix_pollq_node *, int);

#endif // NNG_PLATFORM_POSIX

#endif // PLATFORM_POSIX_POLLQ_H
