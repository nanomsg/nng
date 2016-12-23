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


#endif
