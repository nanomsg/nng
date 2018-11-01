//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

// POSIX threads.

#include "core/nng_impl.h"

#ifdef NNG_PLATFORM_POSIX

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#ifdef NNG_SETSTACKSIZE
#include <limits.h>
#include <sys/resource.h>
#endif

static pthread_mutex_t nni_plat_init_lock = PTHREAD_MUTEX_INITIALIZER;
static int             nni_plat_inited    = 0;
static int             nni_plat_forked    = 0;

pthread_condattr_t  nni_cvattr;
pthread_mutexattr_t nni_mxattr;
pthread_attr_t      nni_thrattr;

void
nni_plat_mtx_init(nni_plat_mtx *mtx)
{
	// On most platforms, pthread_mutex_init cannot ever fail, when
	// given NULL attributes.  Linux and Solaris fall into this category.
	// BSD platforms (including OpenBSD, FreeBSD, and macOS) seem to
	// attempt to allocate memory during mutex initialization.

	// An earlier design worked around failures here by using a global
	// fallback lock, but this was potentially racy, complex, and led
	// to some circumstances where we were simply unable to provide
	// adequate debug.

	// If you find you're spending time in this function, consider
	// adding more memory, reducing consumption, or moving to an
	// operating system that doesn't need to do heap allocations
	// to create mutexes.

	// The symptom will be an apparently stuck application spinning
	// every 10 ms trying to allocate this lock.

	while ((pthread_mutex_init(&mtx->mtx, &nni_mxattr) != 0) &&
	    (pthread_mutex_init(&mtx->mtx, NULL) != 0)) {
		// We must have memory exhaustion -- ENOMEM, or
		// in some cases EAGAIN.  Wait a bit before we try to
		// give things a chance to settle down.
		nni_msleep(10);
	}
}

void
nni_plat_mtx_fini(nni_plat_mtx *mtx)
{
	(void) pthread_mutex_destroy(&mtx->mtx);
}

static void
nni_pthread_mutex_lock(pthread_mutex_t *m)
{
	int rv;

	if ((rv = pthread_mutex_lock(m)) != 0) {
		nni_panic("pthread_mutex_lock: %s", strerror(rv));
	}
}

static void
nni_pthread_mutex_unlock(pthread_mutex_t *m)
{
	int rv;

	if ((rv = pthread_mutex_unlock(m)) != 0) {
		nni_panic("pthread_mutex_unlock: %s", strerror(rv));
	}
}

static void
nni_pthread_cond_broadcast(pthread_cond_t *c)
{
	int rv;

	if ((rv = pthread_cond_broadcast(c)) != 0) {
		nni_panic("pthread_cond_broadcast: %s", strerror(rv));
	}
}

static void
nni_pthread_cond_signal(pthread_cond_t *c)
{
	int rv;
	if ((rv = pthread_cond_signal(c)) != 0) {
		nni_panic("pthread_cond_signal: %s", strerror(rv));
	}
}

static void
nni_pthread_cond_wait(pthread_cond_t *c, pthread_mutex_t *m)
{
	int rv;

	if ((rv = pthread_cond_wait(c, m)) != 0) {
		nni_panic("pthread_cond_wait: %s", strerror(rv));
	}
}

static int
nni_pthread_cond_timedwait(
    pthread_cond_t *c, pthread_mutex_t *m, struct timespec *ts)
{
	int rv;

	switch ((rv = pthread_cond_timedwait(c, m, ts))) {
	case 0:
		return (0);
	case ETIMEDOUT:
	case EAGAIN:
		return (NNG_ETIMEDOUT);
	}
	nni_panic("pthread_cond_timedwait: %s", strerror(rv));
	return (NNG_EINVAL);
}

void
nni_plat_mtx_lock(nni_plat_mtx *mtx)
{
	nni_pthread_mutex_lock(&mtx->mtx);
}

void
nni_plat_mtx_unlock(nni_plat_mtx *mtx)
{
	nni_pthread_mutex_unlock(&mtx->mtx);
}

void
nni_plat_cv_init(nni_plat_cv *cv, nni_plat_mtx *mtx)
{
	// See the comments in nni_plat_mtx_init.  Almost everywhere this
	// simply does not/cannot fail.

	while (pthread_cond_init(&cv->cv, &nni_cvattr) != 0) {
		nni_msleep(10);
	}
	cv->mtx = mtx;
}

void
nni_plat_cv_wake(nni_plat_cv *cv)
{
	nni_pthread_cond_broadcast(&cv->cv);
}

void
nni_plat_cv_wake1(nni_plat_cv *cv)
{
	nni_pthread_cond_signal(&cv->cv);
}

void
nni_plat_cv_wait(nni_plat_cv *cv)
{
	nni_pthread_cond_wait(&cv->cv, &cv->mtx->mtx);
}

int
nni_plat_cv_until(nni_plat_cv *cv, nni_time until)
{
	struct timespec ts;

	// Our caller has already guaranteed a sane value for until.
	ts.tv_sec  = until / 1000;
	ts.tv_nsec = (until % 1000) * 1000000;

	return (nni_pthread_cond_timedwait(&cv->cv, &cv->mtx->mtx, &ts));
}

void
nni_plat_cv_fini(nni_plat_cv *cv)
{
	int rv;

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
	rv = pthread_create(&thr->tid, &nni_thrattr, nni_plat_thr_main, thr);
	if (rv != 0) {
		// nni_printf("pthread_create: %s",
		// strerror(rv));
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

bool
nni_plat_thr_is_self(nni_plat_thr *thr)
{
	return (pthread_self() == thr->tid);
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
		nni_panic("nng is not fork-reentrant safe");
	}
	if (nni_plat_inited) {
		return (0); // fast path
	}

	pthread_mutex_lock(&nni_plat_init_lock);
	if (nni_plat_inited) { // check again under the lock to be sure
		pthread_mutex_unlock(&nni_plat_init_lock);
		return (0);
	}

	if ((pthread_mutexattr_init(&nni_mxattr) != 0) ||
	    (pthread_condattr_init(&nni_cvattr) != 0) ||
	    (pthread_attr_init(&nni_thrattr) != 0)) {
		// Technically this is leaking, but it should never
		// occur, so really not worried about it.
		pthread_mutex_unlock(&nni_plat_init_lock);
		return (NNG_ENOMEM);
	}

#if !defined(NNG_USE_GETTIMEOFDAY) && NNG_USE_CLOCKID != CLOCK_REALTIME
	if (pthread_condattr_setclock(&nni_cvattr, NNG_USE_CLOCKID) != 0) {
		pthread_mutex_unlock(&nni_plat_init_lock);
		pthread_mutexattr_destroy(&nni_mxattr);
		pthread_condattr_destroy(&nni_cvattr);
		pthread_attr_destroy(&nni_thrattr);
		return (NNG_ENOMEM);
	}
#endif

#if defined(NNG_SETSTACKSIZE)
	struct rlimit rl;
	if ((getrlimit(RLIMIT_STACK, &rl) == 0) &&
	    (rl.rlim_cur != RLIM_INFINITY) &&
	    (rl.rlim_cur >= PTHREAD_STACK_MIN) &&
	    (pthread_attr_setstacksize(&nni_thrattr, rl.rlim_cur) != 0)) {
		pthread_mutex_unlock(&nni_plat_init_lock);
		pthread_mutexattr_destroy(&nni_mxattr);
		pthread_condattr_destroy(&nni_cvattr);
		pthread_attr_destroy(&nni_thrattr);
		return (NNG_ENOMEM);
	}
#endif

	// if this one fails we don't care.
	(void) pthread_mutexattr_settype(
	    &nni_mxattr, PTHREAD_MUTEX_ERRORCHECK);

	if ((rv = nni_posix_pollq_sysinit()) != 0) {
		pthread_mutex_unlock(&nni_plat_init_lock);
		pthread_mutexattr_destroy(&nni_mxattr);
		pthread_condattr_destroy(&nni_cvattr);
		pthread_attr_destroy(&nni_thrattr);
		return (rv);
	}

	if ((rv = nni_posix_resolv_sysinit()) != 0) {
		pthread_mutex_unlock(&nni_plat_init_lock);
		nni_posix_pollq_sysfini();
		pthread_mutexattr_destroy(&nni_mxattr);
		pthread_condattr_destroy(&nni_cvattr);
		pthread_attr_destroy(&nni_thrattr);
		return (rv);
	}

	if (pthread_atfork(NULL, NULL, nni_atfork_child) != 0) {
		pthread_mutex_unlock(&nni_plat_init_lock);
		nni_posix_resolv_sysfini();
		nni_posix_pollq_sysfini();
		pthread_mutexattr_destroy(&nni_mxattr);
		pthread_condattr_destroy(&nni_cvattr);
		pthread_attr_destroy(&nni_thrattr);
		return (NNG_ENOMEM);
	}
	if ((rv = helper()) == 0) {
		nni_plat_inited = 1;
	}
	pthread_mutex_unlock(&nni_plat_init_lock);

	return (rv);
}

void
nni_plat_fini(void)
{
	pthread_mutex_lock(&nni_plat_init_lock);
	if (nni_plat_inited) {
		nni_posix_resolv_sysfini();
		nni_posix_pollq_sysfini();
		pthread_mutexattr_destroy(&nni_mxattr);
		pthread_condattr_destroy(&nni_cvattr);
		nni_plat_inited = 0;
	}
	pthread_mutex_unlock(&nni_plat_init_lock);
}

int
nni_plat_ncpu(void)
{
	// POSIX specifies sysconf exists, but not the value
	// _SC_NPROCESSORS_ONLN.  Nonetheless, everybody implements it.
	// If you don't we'll assume you only have a single logical CPU.
#ifdef _SC_NPROCESSORS_ONLN
	return (sysconf(_SC_NPROCESSORS_ONLN));
#else
	return (1);
#endif
}

#endif // NNG_PLATFORM_POSIX
