/*
 * Copyright 2016 Garrett D'Amore <garrett@damore.org>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom
 * the Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
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
	void *arg;
	void (*func)(void *);
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
		return (0);	/* fast path */
	}
	pthread_mutex_lock(&plat_lock);
	if (plat_init) {	/* check again under the lock to be sure */
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