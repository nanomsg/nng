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
 * POSIX synchronization (mutexes and condition variables).  This uses
 * pthreads.
 */

#include "core/nng_impl.h"

#ifdef PLATFORM_POSIX_SYNCH

#include <pthread.h>
#include <time.h>

struct nni_mutex {
	pthread_mutex_t	mx;
};

struct nni_cond {
	pthread_cond_t	cv;
	pthread_mutex_t	*mx;
};

int
nni_mutex_create(nni_mutex_t *mp)
{
	struct nni_mutex *m;
	pthread_mutexattr_t attr;
	int rv;

	if ((m = nni_alloc(sizeof (*m))) == NULL) {
		return (NNG_ENOMEM);
	}

	/* We ask for more error checking... */
	if (pthread_mutexattr_init(&attr) != 0) {
		nni_free(m, sizeof (*m));
		return (NNG_ENOMEM);
	}

	if (pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK) != 0) {
		nni_panic("pthread_mutexattr_settype failed");
	}

	rv = pthread_mutex_init(&m->mx, &attr);

	if (pthread_mutexattr_destroy(&attr) != 0) {
		nni_panic("pthread_mutexattr_destroy failed");
	}

	if (rv != 0) {
		nni_free(m, sizeof (*m));
		return (NNG_ENOMEM);
	}
	*mp = m;
	return (0);
}

void
nni_mutex_destroy(nni_mutex_t m)
{
	if (pthread_mutex_destroy(&m->mx) != 0) {
		nni_panic("pthread_mutex_destroy failed");
	}
	nni_free(m, sizeof (*m));
}

void
nni_mutex_enter(nni_mutex_t m)
{
	if (pthread_mutex_lock(&m->mx) != 0) {
		nni_panic("pthread_mutex_lock failed");
	}
}

void
nni_mutex_exit(nni_mutex_t m)
{
	if (pthread_mutex_unlock(&m->mx) != 0) {
		nni_panic("pthread_mutex_unlock failed");
	}
}

int
nni_mutex_tryenter(nni_mutex_t m)
{
	if (pthread_mutex_trylock(&m->mx) != 0) {
		return (NNG_EBUSY);
	}
	return (0);
}

int
cond_attr(pthread_condattr_t **attrpp)
{
#if defined(NNG_USE_GETTIMEOFDAY) || NNG_USE_CLOCKID == CLOCK_REALTIME
	*attrpp = NULL;
	return (0);
#else
	/* In order to make this fast, avoid reinitializing attrs. */
	static pthread_condattr_t attr;
	static pthread_mutex_t mx = PTHREAD_MUTEX_INITIALIZER;
	static int init = 0;
	int rv;

	/*
	 * For efficiency's sake, we try to reuse the same attr for the
	 * life of the library.  This avoids many reallocations.  Technically
	 * this means that we will leak the attr on exit(), but this is
	 * preferable to constantly allocating and reallocating it.
	 */
	if (init) {
		*attrpp = &attr;
		return (0);
	}

	(void) pthread_mutex_lock(&mx);
	while (!init) {
		if ((rv = pthread_condattr_init(&attr)) != 0) {
			(void) pthread_mutex_unlock(&mx);
			return (NNG_ENOMEM);
		}
		rv = pthread_condattr_setclock(&attr, NNG_USE_CLOCKID);
		if (rv != 0) {
			nni_panic("condattr_setclock: %s", strerror(rv));
		}
		init = 1;
	}
	(void) pthread_mutex_unlock(&mx);
	*attrpp = &attr;
	return (0);
#endif
}

int
nni_cond_create(nni_cond_t *cvp, nni_mutex_t mx)
{
	/*
	 * By preference, we use a CLOCK_MONOTONIC version of condition
	 * variables, which insulates us from changes to the system time.
	 */
	struct nni_cond *c;
	pthread_condattr_t *attrp;
	int rv;

	if ((rv = cond_attr(&attrp)) != 0) {
		return (rv);
	}
	if ((c = nni_alloc(sizeof (*c))) == NULL) {
		return (NNG_ENOMEM);
	}
	c->mx = &mx->mx;
	if (pthread_cond_init(&c->cv, attrp) != 0) {
		/* In theory could be EAGAIN, but handle like ENOMEM */
		nni_free(c, sizeof (*c));
		return (NNG_ENOMEM);
	}
	*cvp = c;
	return (0);
}

void
nni_cond_destroy(nni_cond_t c)
{
	if (pthread_cond_destroy(&c->cv) != 0) {
		nni_panic("pthread_cond_destroy failed");
	}
	nni_free(c, sizeof (*c));
}

void
nni_cond_signal(nni_cond_t c)
{
	if (pthread_cond_signal(&c->cv) != 0) {
		nni_panic("pthread_cond_signal failed");
	}
}

void
nni_cond_broadcast(nni_cond_t c)
{
	if (pthread_cond_broadcast(&c->cv) != 0) {
		nni_panic("pthread_cond_broadcast failed");
	}
}

void
nni_cond_wait(nni_cond_t c)
{
	if (pthread_cond_wait(&c->cv, c->mx) != 0) {
		nni_panic("pthread_cond_wait failed");
	}
}

int
nni_cond_timedwait(nni_cond_t c, uint64_t usec)
{
	struct timespec ts;
	int rv;

	usec += nni_clock();

	ts.tv_sec = usec / 1000000;
	ts.tv_nsec = (usec % 10000) * 1000;

	rv = pthread_cond_timedwait(&c->cv, c->mx, &ts);

	if (rv == ETIMEDOUT) {
		return (NNG_ETIMEDOUT);
	} else if (rv != 0) {
		nni_panic("pthread_cond_timedwait returned %d", rv);
	}
	return (0);
}

#endif