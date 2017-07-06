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
// PLATFORM_POSIX_THREAD depends on PLATFORM_POSIX_CLOCK.  Furthermore,
// when using PLATFORM_POSIX_CLOCK, your condition variable timeouts need
// to use the same base clock values.  Normally these should be used
// together.  Almost everything depends on PLATFORM_POSIX_DEBUG.
#ifdef  PLATFORM_POSIX
#define PLATFORM_POSIX_ALLOC
#define PLATFORM_POSIX_DEBUG
#define PLATFORM_POSIX_CLOCK
#define PLATFORM_POSIX_IPC
#define PLATFORM_POSIX_NET
#define PLATFORM_POSIX_PIPE
#define PLATFORM_POSIX_RANDOM
#define PLATFORM_POSIX_SOCKET
#define PLATFORM_POSIX_THREAD
#define PLATFORM_POSIX_PIPEDESC
#define PLATFORM_POSIX_EPDESC

#include "platform/posix/posix_config.h"
#endif

#ifdef PLATFORM_POSIX_DEBUG
extern int nni_plat_errno(int);

#endif

// Define types that this platform uses.
#ifdef PLATFORM_POSIX_THREAD

extern int nni_plat_devnull;    // open descriptor on /dev/null

#include <pthread.h>

// These types are provided for here, to permit them to be directly inlined
// elsewhere.

struct nni_plat_mtx {
	int		init;
	pthread_t	owner;
	pthread_mutex_t mtx;
};

struct nni_plat_thr {
	pthread_t	tid;
	void		(*func)(void *);
	void *		arg;
};

struct nni_plat_cv {
	pthread_cond_t	cv;
	nni_plat_mtx *	mtx;
};

#endif


extern int nni_posix_pollq_sysinit(void);
extern void nni_posix_pollq_sysfini(void);
extern int nni_posix_resolv_sysinit(void);
extern void nni_posix_resolv_sysfini(void);

#endif // PLATFORM_POSIX_IMPL_H
