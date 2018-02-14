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

static pthread_mutex_t nni_plat_init_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t nni_plat_lock      = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  nni_plat_cond_cond = PTHREAD_COND_INITIALIZER;
static pthread_cond_t  nni_plat_lock_cond = PTHREAD_COND_INITIALIZER;
static int             nni_plat_inited    = 0;
static int             nni_plat_forked    = 0;

pthread_condattr_t  nni_cvattr;
pthread_mutexattr_t nni_mxattr;

#ifndef NDEBUG
int nni_plat_sync_fallback = 0;
#endif

enum nni_plat_sync_flags {
	NNI_PLAT_SYNC_INIT   = 0x01,
	NNI_PLAT_SYNC_LOCKED = 0x04,
	NNI_PLAT_SYNC_WAIT   = 0x08,
};

void
nni_plat_mtx_init(nni_plat_mtx *mtx)
{
	if (pthread_mutex_init(&mtx->mtx, &nni_mxattr) != 0) {
		mtx->fallback = 1;
	} else {
		mtx->flags = NNI_PLAT_SYNC_INIT;
	}
#ifndef NDEBUG
	if (nni_plat_sync_fallback || getenv("NNG_SYNC_FALLBACK")) {
		mtx->fallback = 1;
	}
#endif
}

void
nni_plat_mtx_fini(nni_plat_mtx *mtx)
{
	if (mtx->flags & NNI_PLAT_SYNC_INIT) {
		int rv;
		// Locking and unlocking makes valgrind/helgrind happier.
		pthread_mutex_lock(&mtx->mtx);
		pthread_mutex_unlock(&mtx->mtx);
		if ((rv = pthread_mutex_destroy(&mtx->mtx)) != 0) {
			nni_panic("pthread_mutex_destroy: %s", strerror(rv));
		}
	}
	mtx->flags = 0;
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

static void
nni_plat_mtx_lock_fallback_locked(nni_plat_mtx *mtx)
{
	while (mtx->flags & NNI_PLAT_SYNC_LOCKED) {
		mtx->flags |= NNI_PLAT_SYNC_WAIT;
		nni_pthread_cond_wait(&nni_plat_lock_cond, &nni_plat_lock);
	}
	mtx->flags |= NNI_PLAT_SYNC_LOCKED;
	mtx->owner = pthread_self();
}

static void
nni_plat_mtx_unlock_fallback_locked(nni_plat_mtx *mtx)
{
	NNI_ASSERT(mtx->flags & NNI_PLAT_SYNC_LOCKED);
	mtx->flags &= ~NNI_PLAT_SYNC_LOCKED;
	if (mtx->flags & NNI_PLAT_SYNC_WAIT) {
		mtx->flags &= ~NNI_PLAT_SYNC_WAIT;
		pthread_cond_broadcast(&nni_plat_lock_cond);
	}
}

static void
nni_plat_mtx_lock_fallback(nni_plat_mtx *mtx)
{
	nni_pthread_mutex_lock(&nni_plat_lock);
	nni_plat_mtx_lock_fallback_locked(mtx);
	nni_pthread_mutex_unlock(&nni_plat_lock);
}

static void
nni_plat_mtx_unlock_fallback(nni_plat_mtx *mtx)
{
	nni_pthread_mutex_lock(&nni_plat_lock);
	nni_plat_mtx_unlock_fallback_locked(mtx);
	nni_pthread_mutex_unlock(&nni_plat_lock);
}

static void
nni_plat_cv_wake_fallback(nni_cv *cv)
{
	nni_pthread_mutex_lock(&nni_plat_lock);
	if (cv->flags & NNI_PLAT_SYNC_WAIT) {
		cv->gen++;
		cv->wake = 0;
		nni_pthread_cond_broadcast(&nni_plat_cond_cond);
	}
	nni_pthread_mutex_unlock(&nni_plat_lock);
}

static void
nni_plat_cv_wake1_fallback(nni_cv *cv)
{
	nni_pthread_mutex_lock(&nni_plat_lock);
	if (cv->flags & NNI_PLAT_SYNC_WAIT) {
		cv->wake++;
		nni_pthread_cond_broadcast(&nni_plat_cond_cond);
	}
	nni_pthread_mutex_unlock(&nni_plat_lock);
}

static void
nni_plat_cv_wait_fallback(nni_cv *cv)
{
	int gen;

	nni_pthread_mutex_lock(&nni_plat_lock);
	if (!cv->mtx->fallback) {
		// transform the mutex to a fallback one.  we have it held.
		cv->mtx->fallback = 1;
		cv->mtx->flags |= NNI_PLAT_SYNC_LOCKED;
		nni_pthread_mutex_unlock(&cv->mtx->mtx);
	}

	NNI_ASSERT(cv->mtx->owner == pthread_self());
	NNI_ASSERT(cv->mtx->flags & NNI_PLAT_SYNC_LOCKED);
	gen = cv->gen;
	while ((cv->gen == gen) && (cv->wake == 0)) {
		nni_plat_mtx_unlock_fallback_locked(cv->mtx);
		cv->flags |= NNI_PLAT_SYNC_WAIT;
		nni_pthread_cond_wait(&nni_plat_cond_cond, &nni_plat_lock);

		nni_plat_mtx_lock_fallback_locked(cv->mtx);
	}
	if (cv->wake > 0) {
		cv->wake--;
	}
	nni_pthread_mutex_unlock(&nni_plat_lock);
}

static int
nni_plat_cv_until_fallback(nni_cv *cv, struct timespec *ts)
{
	int gen;
	int rv = 0;

	if (!cv->mtx->fallback) {
		// transform the mutex to a fallback one.  we have it held.
		cv->mtx->fallback = 1;
		cv->mtx->flags |= NNI_PLAT_SYNC_LOCKED;
		nni_pthread_mutex_unlock(&cv->mtx->mtx);
	}

	nni_pthread_mutex_lock(&nni_plat_lock);
	gen = cv->gen;
	while ((cv->gen == gen) && (cv->wake == 0)) {
		nni_plat_mtx_unlock_fallback_locked(cv->mtx);
		cv->flags |= NNI_PLAT_SYNC_WAIT;
		rv = nni_pthread_cond_timedwait(
		    &nni_plat_cond_cond, &nni_plat_lock, ts);
		nni_plat_mtx_lock_fallback_locked(cv->mtx);
		if (rv != 0) {
			break;
		}
	}
	if ((rv == 0) && (cv->wake > 0)) {
		cv->wake--;
	}
	nni_pthread_mutex_unlock(&nni_plat_lock);
	return (rv);
}

void
nni_plat_mtx_lock(nni_plat_mtx *mtx)
{
	if (!mtx->fallback) {
		nni_pthread_mutex_lock(&mtx->mtx);

		// We might have changed to a fallback lock; make
		// sure this did not occur.  Note that transitions to
		// fallback locks only happen when a thread accesses
		// a condition variable already holding this lock,
		// so this is guranteed to be safe.
		if (!mtx->fallback) {
			mtx->owner = pthread_self();
			return;
		}
		nni_pthread_mutex_unlock(&mtx->mtx);
	}

	// Fallback mode
	nni_plat_mtx_lock_fallback(mtx);
}

void
nni_plat_mtx_unlock(nni_plat_mtx *mtx)
{
	NNI_ASSERT(mtx->owner == pthread_self());
	mtx->owner = 0;

	if (mtx->fallback) {
		nni_plat_mtx_unlock_fallback(mtx);
	} else {
		nni_pthread_mutex_unlock(&mtx->mtx);
	}
}

void
nni_plat_cv_init(nni_plat_cv *cv, nni_plat_mtx *mtx)
{
	if (mtx->fallback || (pthread_cond_init(&cv->cv, &nni_cvattr) != 0)) {
		cv->fallback = 1;
	} else {
		cv->flags = NNI_PLAT_SYNC_INIT;
	}
#ifndef NDEBUG
	if (nni_plat_sync_fallback || getenv("NNG_SYNC_FALLBACK")) {
		cv->fallback = 1;
	}
#endif
	cv->mtx = mtx;
}

void
nni_plat_cv_wake(nni_plat_cv *cv)
{
	if (cv->fallback) {
		nni_plat_cv_wake_fallback(cv);
	} else {
		nni_pthread_cond_broadcast(&cv->cv);
	}
}

void
nni_plat_cv_wake1(nni_plat_cv *cv)
{
	if (cv->fallback) {
		nni_plat_cv_wake1_fallback(cv);
	} else {
		nni_pthread_cond_signal(&cv->cv);
	}
}

void
nni_plat_cv_wait(nni_plat_cv *cv)
{
	NNI_ASSERT(cv->mtx->owner == pthread_self());
	if (cv->fallback) {
		nni_plat_cv_wait_fallback(cv);
	} else {
		nni_pthread_cond_wait(&cv->cv, &cv->mtx->mtx);
		cv->mtx->owner = pthread_self();
	}
}

int
nni_plat_cv_until(nni_plat_cv *cv, nni_time until)
{
	struct timespec ts;
	int             rv;

	NNI_ASSERT(cv->mtx->owner == pthread_self());

	// Our caller has already guaranteed a sane value for until.
	ts.tv_sec  = until / 1000;
	ts.tv_nsec = (until % 1000) * 1000000;

	if (cv->fallback) {
		rv = nni_plat_cv_until_fallback(cv, &ts);
	} else {
		rv = nni_pthread_cond_timedwait(&cv->cv, &cv->mtx->mtx, &ts);
		cv->mtx->owner = pthread_self();
	}
	return (rv);
}

void
nni_plat_cv_fini(nni_plat_cv *cv)
{
	int rv;

	if ((cv->flags & NNI_PLAT_SYNC_INIT) &&
	    ((rv = pthread_cond_destroy(&cv->cv)) != 0)) {
		nni_panic("pthread_cond_destroy: %s", strerror(rv));
	}
	cv->flags = 0;
	cv->mtx   = NULL;
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
	rv = pthread_create(&thr->tid, NULL, nni_plat_thr_main, thr);
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
	if (pthread_condattr_init(&nni_cvattr) != 0) {
		pthread_mutex_unlock(&nni_plat_init_lock);
		return (NNG_ENOMEM);
	}
#if !defined(NNG_USE_GETTIMEOFDAY) && NNG_USE_CLOCKID != CLOCK_REALTIME
	if (pthread_condattr_setclock(&nni_cvattr, NNG_USE_CLOCKID) != 0) {
		pthread_mutex_unlock(&nni_plat_init_lock);
		return (NNG_ENOMEM);
	}
#endif

	if (pthread_mutexattr_init(&nni_mxattr) != 0) {
		pthread_mutex_unlock(&nni_plat_init_lock);
		pthread_condattr_destroy(&nni_cvattr);
		return (NNG_ENOMEM);
	}

	// if this one fails we don't care.
	(void) pthread_mutexattr_settype(
	    &nni_mxattr, PTHREAD_MUTEX_ERRORCHECK);

	if ((rv = nni_posix_pollq_sysinit()) != 0) {
		pthread_mutex_unlock(&nni_plat_init_lock);
		pthread_mutexattr_destroy(&nni_mxattr);
		pthread_condattr_destroy(&nni_cvattr);
		return (rv);
	}

	if ((rv = nni_posix_resolv_sysinit()) != 0) {
		pthread_mutex_unlock(&nni_plat_init_lock);
		nni_posix_pollq_sysfini();
		pthread_mutexattr_destroy(&nni_mxattr);
		pthread_condattr_destroy(&nni_cvattr);
		return (rv);
	}

	if (pthread_atfork(NULL, NULL, nni_atfork_child) != 0) {
		pthread_mutex_unlock(&nni_plat_init_lock);
		nni_posix_resolv_sysfini();
		nni_posix_pollq_sysfini();
		pthread_mutexattr_destroy(&nni_mxattr);
		pthread_condattr_destroy(&nni_cvattr);
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

#endif // NNG_PLATFORM_POSIX
