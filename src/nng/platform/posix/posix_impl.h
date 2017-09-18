//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef PLATFORM_POSIX_IMPL_H
#define PLATFORM_POSIX_IMPL_H

// Some dependency notes:
//
// NNG_PLATFORM_POSIX_THREAD depends on NNG_PLATFORM_POSIX_CLOCK.  Also,
// when using NNG_PLATFORM_POSIX_CLOCK, your condition variable timeouts need
// to use the same base clock values.  Normally these should be used
// together.  Almost everything depends on NNG_PLATFORM_POSIX_DEBUG.
#ifdef NNG_PLATFORM_POSIX
#define NNG_PLATFORM_POSIX_ALLOC
#define NNG_PLATFORM_POSIX_DEBUG
#define NNG_PLATFORM_POSIX_CLOCK
#define NNG_PLATFORM_POSIX_IPC
#define NNG_PLATFORM_POSIX_TCP
#define NNG_PLATFORM_POSIX_PIPE
#define NNG_PLATFORM_POSIX_RANDOM
#define NNG_PLATFORM_POSIX_SOCKET
#define NNG_PLATFORM_POSIX_THREAD
#define NNG_PLATFORM_POSIX_PIPEDESC
#define NNG_PLATFORM_POSIX_EPDESC
#define NNG_PLATFORM_POSIX_SOCKADDR
#define NNG_PLATFORM_POSIX_UDP

#include "platform/posix/posix_config.h"
#endif

#ifdef NNG_PLATFORM_POSIX_SOCKADDR
#include <sys/socket.h>
extern int nni_posix_sockaddr2nn(nni_sockaddr *, const void *);
extern int nni_posix_nn2sockaddr(void *, const nni_sockaddr *);
#endif

#ifdef NNG_PLATFORM_POSIX_DEBUG
extern int nni_plat_errno(int);

#endif

// Define types that this platform uses.
#ifdef NNG_PLATFORM_POSIX_THREAD

#include <pthread.h>

// These types are provided for here, to permit them to be directly inlined
// elsewhere.

struct nni_plat_mtx {
	pthread_t       owner;
	pthread_mutex_t mtx;
	int             fallback;
	int             flags;
};

struct nni_plat_cv {
	pthread_cond_t cv;
	nni_plat_mtx * mtx;
	int            fallback;
	int            flags;
	int            gen;
	int            wake;
};

struct nni_plat_thr {
	pthread_t tid;
	void (*func)(void *);
	void *arg;
};

#endif

extern int  nni_posix_pollq_sysinit(void);
extern void nni_posix_pollq_sysfini(void);
extern int  nni_posix_resolv_sysinit(void);
extern void nni_posix_resolv_sysfini(void);

#endif // PLATFORM_POSIX_IMPL_H
