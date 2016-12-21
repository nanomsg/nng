/*
 * Copyright 2016 Garrett D'Amore <garrett@damore.org>
 *
 * This software is supplied under the terms of the MIT License, a
 * copy of which should be located in the distribution where this
 * file was obtained (LICENSE.txt).  A copy of the license may also be
 * found online at https://opensource.org/licenses/MIT.
 */

/*
 * This is more of a direct #include of a .c rather than .h file.
 * But having it be a .h makes compiler rules work out properly.  Do
 * not include this more than once into your program, or you will
 * get multiple symbols defined.
 */

/*
 * POSIX threads.
 */

#include "core/nng_impl.h"

#ifdef PLATFORM_POSIX_THREAD

#include <pthread.h>
#include <time.h>
#include <string.h>

struct nni_thread {
	pthread_t	tid;
	void *		arg;
	void		(*func)(void *);
};

static pthread_mutex_t plat_lock = PTHREAD_MUTEX_INITIALIZER;
static int plat_init = 0;
static int plat_fork = 0;

static void *
thrfunc(void *arg)
{
	nni_thread_t thr = arg;

	thr->func(thr->arg);
	return (NULL);
}


int
nni_thread_create(nni_thread_t *tp, void (*fn)(void *), void *arg)
{
	nni_thread_t thr;
	int rv;

	if ((thr = nni_alloc(sizeof (*thr))) == NULL) {
		return (NNG_ENOMEM);
	}
	thr->func = fn;
	thr->arg = arg;

	if ((rv = pthread_create(&thr->tid, NULL, thrfunc, thr)) != 0) {
		nni_free(thr, sizeof (*thr));
		return (NNG_ENOMEM);
	}
	*tp = thr;
	return (0);
}


void
nni_thread_reap(nni_thread_t thr)
{
	int rv;

	if ((rv = pthread_join(thr->tid, NULL)) != 0) {
		nni_panic("pthread_thread: %s", strerror(errno));
	}
	nni_free(thr, sizeof (*thr));
}


void
atfork_child(void)
{
	plat_fork = 1;
}


int
nni_plat_init(int (*helper)(void))
{
	int rv;

	if (plat_fork) {
		nni_panic("nng is fork-reentrant safe");
	}
	if (plat_init) {
		return (0);     /* fast path */
	}
	pthread_mutex_lock(&plat_lock);
	if (plat_init) {        /* check again under the lock to be sure */
		pthread_mutex_unlock(&plat_lock);
		return (0);
	}
	if (pthread_atfork(NULL, NULL, atfork_child) != 0) {
		pthread_mutex_unlock(&plat_lock);
		return (NNG_ENOMEM);
	}
	if ((rv = helper()) == 0) {
		plat_init = 1;
	}
	pthread_mutex_unlock(&plat_lock);

	return (rv);
}


void
nni_plat_fini(void)
{
	/* XXX: NOTHING *YET* */
}


#endif
