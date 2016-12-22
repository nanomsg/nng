//
// Copyright 2016 Garrett D'Amore <garrett@damore.org>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

// POSIX synchronization (mutexes and condition variables).  This uses
// pthreads.

#include "core/nng_impl.h"

#ifdef PLATFORM_POSIX_SYNCH

#include <pthread.h>
#include <time.h>
#include <string.h>

extern pthread_condattr_t nni_condattr;
extern pthread_mutexattr_t nni_mutexattr;

int
nni_mutex_init(nni_mutex *mp)
{
	if (pthread_mutex_init(&mp->mx, &nni_mutexattr) != 0) {
		return (NNG_ENOMEM);
	}
	return (0);
}


void
nni_mutex_fini(nni_mutex *mp)
{
	int rv;

	if ((rv = pthread_mutex_destroy(&mp->mx)) != 0) {
		nni_panic("pthread_mutex_destroy failed: %s", strerror(rv));
	}
}


// XXX: REMOVE THIS FUNCTION
int
nni_mutex_create(nni_mutex_t *mp)
{
	struct nni_mutex *m;
	pthread_mutexattr_t attr;
	int rv;

	if ((m = nni_alloc(sizeof (*m))) == NULL) {
		return (NNG_ENOMEM);
	}

	// We ask for more error checking...
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


// XXX: REMOVE THIS FUNCTION
void
nni_mutex_destroy(nni_mutex_t m)
{
	if (pthread_mutex_destroy(&m->mx) != 0) {
		nni_panic("pthread_mutex_destroy failed");
	}
	nni_free(m, sizeof (*m));
}


void
nni_mutex_enter(nni_mutex *m)
{
	if (pthread_mutex_lock(&m->mx) != 0) {
		nni_panic("pthread_mutex_lock failed");
	}
}


void
nni_mutex_exit(nni_mutex *m)
{
	if (pthread_mutex_unlock(&m->mx) != 0) {
		nni_panic("pthread_mutex_unlock failed");
	}
}


int
nni_mutex_tryenter(nni_mutex *m)
{
	if (pthread_mutex_trylock(&m->mx) != 0) {
		return (NNG_EBUSY);
	}
	return (0);
}


int
nni_cond_init(nni_cond *c, nni_mutex *m)
{
	if (pthread_cond_init(&c->cv, &nni_condattr) != 0) {
		// In theory could be EAGAIN, but handle like ENOMEM
		nni_free(c, sizeof (*c));
		return (NNG_ENOMEM);
	}
	c->mx = &m->mx;
	return (0);
}


void
nni_cond_fini(nni_cond *c)
{
	if (pthread_cond_destroy(&c->cv) != 0) {
		nni_panic("pthread_cond_destroy failed");
	}
}


// XXXX: REMOVE THIS FUNCTION
static int
nni_cond_attr(pthread_condattr_t **attrpp)
{
	*attrpp = NULL;
	return (0);
}


// XXX: REMOVE THIS FUNCTION
int
nni_cond_create(nni_cond **cvp, nni_mutex *mx)
{
	/*
	 * By preference, we use a CLOCK_MONOTONIC version of condition
	 * variables, which insulates us from changes to the system time.
	 */
	struct nni_cond *c;
	pthread_condattr_t *attrp;
	int rv;

	if ((rv = nni_cond_attr(&attrp)) != 0) {
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


// XXX: REMOVE THIS FUNCTION
void
nni_cond_destroy(nni_cond *c)
{
	if (pthread_cond_destroy(&c->cv) != 0) {
		nni_panic("pthread_cond_destroy failed");
	}
	nni_free(c, sizeof (*c));
}


void
nni_cond_signal(nni_cond *c)
{
	if (pthread_cond_signal(&c->cv) != 0) {
		nni_panic("pthread_cond_signal failed");
	}
}


void
nni_cond_broadcast(nni_cond *c)
{
	if (pthread_cond_broadcast(&c->cv) != 0) {
		nni_panic("pthread_cond_broadcast failed");
	}
}


void
nni_cond_wait(nni_cond *c)
{
	if (pthread_cond_wait(&c->cv, c->mx) != 0) {
		nni_panic("pthread_cond_wait failed");
	}
}


int
nni_cond_waituntil(nni_cond *c, uint64_t usec)
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


int
nni_cond_timedwait(nni_cond *c, int usec)
{
	if (usec < 0) {
		nni_cond_wait(c);
		return (0);
	}
	return (nni_cond_waituntil(c, ((uint64_t) usec) + nni_clock()));
}


#endif
