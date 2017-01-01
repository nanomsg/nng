//
// Copyright 2016 Garrett D'Amore <garrett@damore.org>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

// POSIX threads.

#include "core/nng_impl.h"

#ifdef PLATFORM_POSIX_THREAD

#include <pthread.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

struct nni_thread {
	pthread_t	tid;
	void *		arg;
	void		(*func)(void *);
};

static pthread_mutex_t nni_plat_lock = PTHREAD_MUTEX_INITIALIZER;
static int nni_plat_inited = 0;
static int nni_plat_forked = 0;
static int nni_plat_next = 0;

pthread_condattr_t nni_cvattr;
pthread_mutexattr_t nni_mxattr;

uint32_t
nni_plat_nextid(void)
{
	uint32_t id;

	pthread_mutex_lock(&nni_plat_lock);
	id = nni_plat_next++;
	pthread_mutex_unlock(&nni_plat_lock);
	return (id);
}


static void *
nni_thrfunc(void *arg)
{
	nni_thread *thr = arg;

	thr->func(thr->arg);
	return (NULL);
}


int
nni_thread_create(nni_thread **tp, void (*fn)(void *), void *arg)
{
	nni_thread *thr;
	int rv;

	if ((thr = nni_alloc(sizeof (*thr))) == NULL) {
		return (NNG_ENOMEM);
	}
	thr->func = fn;
	thr->arg = arg;

	if ((rv = pthread_create(&thr->tid, NULL, nni_thrfunc, thr)) != 0) {
		nni_free(thr, sizeof (*thr));
		return (NNG_ENOMEM);
	}
	*tp = thr;
	return (0);
}


void
nni_thread_reap(nni_thread *thr)
{
	int rv;

	if ((rv = pthread_join(thr->tid, NULL)) != 0) {
		nni_panic("pthread_thread: %s", strerror(rv));
	}
	nni_free(thr, sizeof (*thr));
}


int
nni_plat_mtx_init(nni_plat_mtx *mtx)
{
	int rv;

	if ((rv = pthread_mutex_init(&mtx->mtx, &nni_mxattr)) != 0) {
		switch (rv) {
		case EAGAIN:
		case ENOMEM:
			return (NNG_ENOMEM);

		default:
			nni_panic("pthread_mutex_init: %s", strerror(rv));
		}
	}
	return (0);
}


void
nni_plat_mtx_fini(nni_plat_mtx *mtx)
{
	int rv;

	if ((rv = pthread_mutex_destroy(&mtx->mtx)) != 0) {
		nni_panic("pthread_mutex_fini: %s", strerror(rv));
	}
}


void
nni_plat_mtx_lock(nni_plat_mtx *mtx)
{
	int rv;

	if ((rv = pthread_mutex_lock(&mtx->mtx)) != 0) {
		nni_panic("pthread_mutex_lock: %s", strerror(rv));
	}
}


void
nni_plat_mtx_unlock(nni_plat_mtx *mtx)
{
	int rv;

	if ((rv = pthread_mutex_unlock(&mtx->mtx)) != 0) {
		nni_panic("pthread_mutex_unlock: %s", strerror(rv));
	}
}


int
nni_plat_mtx_trylock(nni_plat_mtx *mtx)
{
	int rv;

	if ((rv = pthread_mutex_trylock(&mtx->mtx)) == EBUSY) {
		return (NNG_EBUSY);
	}
	if (rv != 0) {
		nni_panic("pthread_mutex_trylock: %s", strerror(rv));
	}
	return (0);
}


int
nni_plat_cv_init(nni_plat_cv *cv, nni_plat_mtx *mtx)
{
	int rv;

	if ((rv = pthread_cond_init(&cv->cv, &nni_cvattr)) != 0) {
		switch (rv) {
		case ENOMEM:
		case EAGAIN:
			return (NNG_ENOMEM);

		default:
			nni_panic("pthread_cond_init: %s", strerror(rv));
		}
	}
	cv->mtx = &mtx->mtx;
	return (0);
}


void
nni_plat_cv_wake(nni_plat_cv *cv)
{
	int rv;

	if ((rv = pthread_cond_broadcast(&cv->cv)) != 0) {
		nni_panic("pthread_cond_broadcast: %s", strerror(rv));
	}
}


void
nni_plat_cv_wait(nni_plat_cv *cv)
{
	int rv;

	if ((rv = pthread_cond_wait(&cv->cv, cv->mtx)) != 0) {
		nni_panic("pthread_cond_wait: %s", strerror(rv));
	}
}


int
nni_plat_cv_until(nni_plat_cv *cv, nni_time until)
{
	struct timespec ts;
	int rv;

	// Our caller has already guaranteed a sane value for until.
	ts.tv_sec = until / 1000000;
	ts.tv_nsec = (until % 1000000) * 1000;

	rv = pthread_cond_timedwait(&cv->cv, cv->mtx, &ts);
	if (rv == ETIMEDOUT) {
		if (nni_clock() < until) {
			// Buggy pthreads implementation!!  Seen with
			// CLOCK_MONOTONIC on macOS Sierra.
			nni_panic("nni_plat_cv_until: Premature wake up!");
		}
		return (NNG_ETIMEDOUT);
	} else if (rv != 0) {
		nni_panic("pthread_cond_timedwait: %d", rv);
	}
	return (0);
}


void
nni_plat_cv_fini(nni_plat_cv *cv)
{
	int rv;

	if ((rv = pthread_cond_destroy(&cv->cv)) != 0) {
		nni_panic("pthread_cond_destroy: %s", strerror(rv));
	}
}


int
nni_plat_thr_init(nni_plat_thr *thr, void (*fn)(void *), void *arg)
{
	int rv;

	// POSIX wants functions to return a void *, but we don't care.
	if ((rv = pthread_create(&thr->tid, NULL, (void *) fn, arg)) != 0) {
		//nni_printf("pthread_create: %s", strerror(rv));
		return (NNG_ENOMEM);
	}
	return (0);
}


void
nni_plat_thr_fini(nni_plat_thr *thr)
{
	int rv;

	if ((rv = pthread_join(thr->tid, NULL))) {
		nni_panic("pthread_join: %s", strerror(rv));
	}
}


void
nni_atfork_child(void)
{
	nni_plat_forked = 1;
}


int
nni_plat_init(int (*helper)(void))
{
	int rv;

	if (nni_plat_forked) {
		nni_panic("nng is fork-reentrant safe");
	}
	if (nni_plat_inited) {
		return (0);     // fast path
	}
	pthread_mutex_lock(&nni_plat_lock);
	if (nni_plat_inited) {        // check again under the lock to be sure
		pthread_mutex_unlock(&nni_plat_lock);
		return (0);
	}
	if (pthread_condattr_init(&nni_cvattr) != 0) {
		pthread_mutex_unlock(&nni_plat_lock);
		return (NNG_ENOMEM);
	}
#if !defined(NNG_USE_GETTIMEOFDAY) && NNG_USE_CLOCKID != CLOCK_REALTIME
	if (pthread_condattr_setclock(&nni_cvattr, NNG_USE_CLOCKID) != 0) {
		pthread_mutex_unlock(&nni_plat_lock);
		return (NNG_ENOMEM);
	}
#endif

	if (pthread_mutexattr_init(&nni_mxattr) != 0) {
		pthread_mutex_unlock(&nni_plat_lock);
		return (NNG_ENOMEM);
	}

	rv = pthread_mutexattr_settype(&nni_mxattr, PTHREAD_MUTEX_ERRORCHECK);
	if (rv != 0) {
		pthread_mutex_unlock(&nni_plat_lock);
		return (NNG_ENOMEM);
	}

	// Generate a starting ID (used for Pipe IDs)
#ifdef NNG_HAVE_ARC4RANDOM
	nni_plat_next = arc4random();
#else
	while (nni_plat_next == 0) {
		uint16_t xsub[3];
		nni_time now = nni_clock();
		pid_t pid = getpid();

		xsub[0] = (uint16_t) now;
		xsub[1] = (uint16_t) (now >> 16);
		xsub[2] = (uint16_t) (now >> 24);
		xsub[0] ^= (uint16_t) pid;
		xsub[1] ^= (uint16_t) (pid >> 16);
		xsub[2] ^= (uint16_t) (pid >> 24);
		nni_plat_next = nrand48(xsub);
	}
#endif

	if (pthread_atfork(NULL, NULL, nni_atfork_child) != 0) {
		pthread_mutex_unlock(&nni_plat_lock);
		return (NNG_ENOMEM);
	}
	if ((rv = helper()) == 0) {
		nni_plat_inited = 1;
	}
	pthread_mutex_unlock(&nni_plat_lock);

	return (rv);
}


void
nni_plat_fini(void)
{
	pthread_mutex_lock(&nni_plat_lock);
	if (nni_plat_inited) {
		pthread_mutexattr_destroy(&nni_mxattr);
		pthread_condattr_destroy(&nni_cvattr);
		nni_plat_inited = 0;
	}
	pthread_mutex_unlock(&nni_plat_lock);
}


#endif
