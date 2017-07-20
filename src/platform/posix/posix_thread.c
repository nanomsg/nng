//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

// POSIX threads.

#include "core/nng_impl.h"

#ifdef PLATFORM_POSIX_THREAD

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

static pthread_mutex_t nni_plat_lock   = PTHREAD_MUTEX_INITIALIZER;
static int             nni_plat_inited = 0;
static int             nni_plat_forked = 0;

pthread_condattr_t    nni_cvattr;
pthread_mutexattr_t   nni_mxattr;
static pthread_attr_t nni_pthread_attr;

// We open a /dev/null file descriptor so that we can dup2() it to
// cause MacOS X to wakeup.  This gives us a "safe" close semantic.

int nni_plat_devnull = -1;

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
	mtx->init = 1;
	return (0);
}

void
nni_plat_mtx_fini(nni_plat_mtx *mtx)
{
	int rv;

	if (!mtx->init) {
		return;
	}
	pthread_mutex_lock(&mtx->mtx);
	pthread_mutex_unlock(&mtx->mtx);
	if ((rv = pthread_mutex_destroy(&mtx->mtx)) != 0) {
		nni_panic("pthread_mutex_fini: %s", strerror(rv));
	}
	mtx->init = 0;
}

void
nni_plat_mtx_lock(nni_plat_mtx *mtx)
{
	int rv;

	if ((rv = pthread_mutex_lock(&mtx->mtx)) != 0) {
		nni_panic("pthread_mutex_lock: %s", strerror(rv));
	}
	mtx->owner = pthread_self();
}

void
nni_plat_mtx_unlock(nni_plat_mtx *mtx)
{
	int rv;

	NNI_ASSERT(mtx->owner == pthread_self());
	mtx->owner = 0;
	if ((rv = pthread_mutex_unlock(&mtx->mtx)) != 0) {
		nni_panic("pthread_mutex_unlock: %s", strerror(rv));
	}
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
	cv->mtx = mtx;
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

	NNI_ASSERT(cv->mtx->owner == pthread_self());
	if ((rv = pthread_cond_wait(&cv->cv, &cv->mtx->mtx)) != 0) {
		nni_panic("pthread_cond_wait: %s", strerror(rv));
	}
	cv->mtx->owner = pthread_self();
}

int
nni_plat_cv_until(nni_plat_cv *cv, nni_time until)
{
	struct timespec ts;
	int             rv;

	NNI_ASSERT(cv->mtx->owner == pthread_self());

	// Our caller has already guaranteed a sane value for until.
	ts.tv_sec  = until / 1000000;
	ts.tv_nsec = (until % 1000000) * 1000;

	rv             = pthread_cond_timedwait(&cv->cv, &cv->mtx->mtx, &ts);
	cv->mtx->owner = pthread_self();
	if (rv == ETIMEDOUT) {
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

	if (cv->mtx == NULL) {
		return;
	}
	if ((rv = pthread_cond_destroy(&cv->cv)) != 0) {
		nni_panic("pthread_cond_destroy: %s", strerror(rv));
	}
	cv->mtx = NULL;
}

static void *
nni_plat_thr_main(void *arg)
{
	nni_plat_thr *thr = arg;
	sigset_t      set;

	// Suppress (block) SIGPIPE for this thread.
	sigemptyset(&set);
	sigaddset(&set, SIGPIPE);
	(void) pthread_sigmask(SIG_BLOCK, &set, NULL);

	thr->func(thr->arg);
	return (NULL);
}

int
nni_plat_thr_init(nni_plat_thr *thr, void (*fn)(void *), void *arg)
{
	int rv;

	thr->func = fn;
	thr->arg  = arg;

	// POSIX wants functions to return a void *, but we don't care.
	rv = pthread_create(
	    &thr->tid, &nni_pthread_attr, nni_plat_thr_main, thr);
	if (rv != 0) {
		// nni_printf("pthread_create: %s", strerror(rv));
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
	int devnull;

	if (nni_plat_forked) {
		nni_panic("nng is not fork-reentrant safe");
	}
	if (nni_plat_inited) {
		return (0); // fast path
	}
	if ((devnull = open("/dev/null", O_RDONLY)) < 0) {
		return (nni_plat_errno(errno));
	}

	pthread_mutex_lock(&nni_plat_lock);
	if (nni_plat_inited) { // check again under the lock to be sure
		pthread_mutex_unlock(&nni_plat_lock);
		close(devnull);
		return (0);
	}
	if (pthread_condattr_init(&nni_cvattr) != 0) {
		pthread_mutex_unlock(&nni_plat_lock);
		(void) close(devnull);
		return (NNG_ENOMEM);
	}
#if !defined(NNG_USE_GETTIMEOFDAY) && NNG_USE_CLOCKID != CLOCK_REALTIME
	if (pthread_condattr_setclock(&nni_cvattr, NNG_USE_CLOCKID) != 0) {
		pthread_mutex_unlock(&nni_plat_lock);
		(void) close(devnull);
		return (NNG_ENOMEM);
	}
#endif

	if (pthread_mutexattr_init(&nni_mxattr) != 0) {
		pthread_mutex_unlock(&nni_plat_lock);
		pthread_condattr_destroy(&nni_cvattr);
		(void) close(devnull);
		return (NNG_ENOMEM);
	}

	rv = pthread_mutexattr_settype(&nni_mxattr, PTHREAD_MUTEX_ERRORCHECK);
	if (rv != 0) {
		pthread_mutex_unlock(&nni_plat_lock);
		(void) close(devnull);
		pthread_mutexattr_destroy(&nni_mxattr);
		pthread_condattr_destroy(&nni_cvattr);
		return (NNG_ENOMEM);
	}

	rv = pthread_attr_init(&nni_pthread_attr);
	if (rv != 0) {
		pthread_mutex_unlock(&nni_plat_lock);
		(void) close(nni_plat_devnull);
		pthread_mutexattr_destroy(&nni_mxattr);
		pthread_condattr_destroy(&nni_cvattr);
		return (NNG_ENOMEM);
	}

	// We don't force this, but we want to have it small... we could
	// probably get by with even just 8k, but Linux usually wants 16k
	// as a minimum.  If this fails, its not fatal, just we won't be
	// as scalable / thrifty with our use of VM.
	//(void) pthread_attr_setstacksize(&nni_pthread_attr, 16384);

	if ((rv = nni_posix_pollq_sysinit()) != 0) {
		pthread_mutex_unlock(&nni_plat_lock);
		(void) close(nni_plat_devnull);
		pthread_mutexattr_destroy(&nni_mxattr);
		pthread_condattr_destroy(&nni_cvattr);
		pthread_attr_destroy(&nni_pthread_attr);
		return (rv);
	}

	if ((rv = nni_posix_resolv_sysinit()) != 0) {
		pthread_mutex_unlock(&nni_plat_lock);
		nni_posix_pollq_sysfini();
		(void) close(nni_plat_devnull);
		pthread_mutexattr_destroy(&nni_mxattr);
		pthread_condattr_destroy(&nni_cvattr);
		pthread_attr_destroy(&nni_pthread_attr);
		return (rv);
	}

	if (pthread_atfork(NULL, NULL, nni_atfork_child) != 0) {
		pthread_mutex_unlock(&nni_plat_lock);
		nni_posix_resolv_sysfini();
		nni_posix_pollq_sysfini();
		(void) close(devnull);
		pthread_mutexattr_destroy(&nni_mxattr);
		pthread_condattr_destroy(&nni_cvattr);
		pthread_attr_destroy(&nni_pthread_attr);
		return (NNG_ENOMEM);
	}
	if ((rv = helper()) == 0) {
		nni_plat_inited = 1;
	}
	nni_plat_devnull = devnull;
	pthread_mutex_unlock(&nni_plat_lock);

	return (rv);
}

void
nni_plat_fini(void)
{
	pthread_mutex_lock(&nni_plat_lock);
	if (nni_plat_inited) {
		nni_posix_resolv_sysfini();
		nni_posix_pollq_sysfini();
		pthread_mutexattr_destroy(&nni_mxattr);
		pthread_condattr_destroy(&nni_cvattr);
		pthread_attr_destroy(&nni_pthread_attr);
		(void) close(nni_plat_devnull);
		nni_plat_devnull = -1;
		nni_plat_inited  = 0;
	}
	pthread_mutex_unlock(&nni_plat_lock);
}

#else

// Suppress empty symbols warnings in ranlib.
int nni_posix_thread_not_used = 0;

#endif
