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
 * POSIX synchronization (mutexes and condition variables).
 */

#include <pthread.h>

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
	/*
	 * If destroy fails for some reason, we can't really do
	 * anything about it.  This would actually represent a programming
	 * bug, and the right thing to do here would be to panic.
	 */
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
nni_cond_create(nni_cond_t *cvp, nni_mutex_t mx)
{
	struct nni_cond *c;
	if ((c = nni_alloc(sizeof (*c))) == NULL) {
		return (NNG_ENOMEM);
	}
	c->mx = &mx->mx;
	if (pthread_cond_init(&c->cv, NULL) != 0) {
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
