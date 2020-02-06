//
// Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
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
extern int    nni_posix_sockaddr2nn(nni_sockaddr *, const void *);
extern size_t nni_posix_nn2sockaddr(void *, const nni_sockaddr *);
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
	pthread_mutex_t mtx;
};

struct nni_plat_cv {
	pthread_cond_t cv;
	nni_plat_mtx * mtx;
};

struct nni_plat_thr {
	pthread_t tid;
	void (*func)(void *);
	void *arg;
};

struct nni_plat_flock {
	int fd;
};

#define NNG_PLATFORM_DIR_SEP "/"

#ifdef NNG_HAVE_STDATOMIC

#include <stdatomic.h>

struct nni_atomic_flag {
	atomic_flag f;
};

struct nni_atomic_int {
	atomic_int v;
};

struct nni_atomic_u64 {
	atomic_uint_fast64_t v;
};

struct nni_atomic_bool {
	atomic_bool v;
};

#else // NNG_HAVE_C11_ATOMIC
struct nni_atomic_flag {
	bool f;
};

struct nni_atomic_bool {
	bool b;
};

struct nni_atomic_int {
	int v;
};

struct nni_atomic_u64 {
	uint64_t v;
};

#endif

#endif

extern int  nni_posix_pollq_sysinit(void);
extern void nni_posix_pollq_sysfini(void);
extern int  nni_posix_resolv_sysinit(void);
extern void nni_posix_resolv_sysfini(void);

#endif // PLATFORM_POSIX_IMPL_H
