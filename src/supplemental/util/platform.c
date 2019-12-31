//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <stdlib.h>
#include <string.h>

#include "core/nng_impl.h"
#include "nng/supplemental/util/platform.h"

nng_time
nng_clock(void)
{
	(void) nni_init();
	return (nni_plat_clock());
}

// Sleep for specified msecs.
void
nng_msleep(nng_duration dur)
{
	(void) nni_init();
	nni_msleep(dur);
}

// Create and start a thread.  Note that on some platforms, this might
// actually be a coroutine, with limitations about what system APIs
// you can call.  Therefore, these threads should only be used with the
// I/O APIs provided by nng.  The thread runs until completion.
int
nng_thread_create(nng_thread **thrp, void (*func)(void *), void *arg)
{
	nni_thr *thr;
	int      rv;

	(void) nni_init();

	if ((thr = NNI_ALLOC_STRUCT(thr)) == NULL) {
		return (NNG_ENOMEM);
	}
	*thrp = (void *) thr;
	if ((rv = nni_thr_init(thr, func, arg)) != 0) {
		return (rv);
	}
	nni_thr_run(thr);
	return (0);
}

// Destroy a thread (waiting for it to complete.)  When this function
// returns all resources for the thread are cleaned up.
void
nng_thread_destroy(nng_thread *thrp)
{
	nni_thr *t = (void *) thrp;
	nni_thr_fini(t);
	NNI_FREE_STRUCT(t);
}

struct nng_mtx {
	nni_mtx m;
};

int
nng_mtx_alloc(nng_mtx **mpp)
{
	nng_mtx *mp;

	(void) nni_init();

	if ((mp = NNI_ALLOC_STRUCT(mp)) == NULL) {
		return (NNG_ENOMEM);
	}
	nni_mtx_init(&mp->m);
	*mpp = mp;
	return (0);
}

void
nng_mtx_free(nng_mtx *mp)
{
	if (mp != NULL) {
		nni_mtx_fini(&mp->m);
		NNI_FREE_STRUCT(mp);
	}
}

void
nng_mtx_lock(nng_mtx *mp)
{
	nni_mtx_lock(&mp->m);
}

void
nng_mtx_unlock(nng_mtx *mp)
{
	nni_mtx_unlock(&mp->m);
}

struct nng_cv {
	nni_cv c;
};

int
nng_cv_alloc(nng_cv **cvp, nng_mtx *mx)
{
	nng_cv *cv;

	if ((cv = NNI_ALLOC_STRUCT(cv)) == NULL) {
		return (NNG_ENOMEM);
	}
	nni_cv_init(&cv->c, &mx->m);
	*cvp = cv;
	return (0);
}

void
nng_cv_free(nng_cv *cv)
{
	if (cv != NULL) {
		nni_cv_fini(&cv->c);
		NNI_FREE_STRUCT(cv);
	}
}

void
nng_cv_wait(nng_cv *cv)
{
	nni_cv_wait(&cv->c);
}

int
nng_cv_until(nng_cv *cv, nng_time when)
{
	return (nni_cv_until(&cv->c, (nni_time) when));
}

void
nng_cv_wake(nng_cv *cv)
{
	nni_cv_wake(&cv->c);
}

void
nng_cv_wake1(nng_cv *cv)
{
	nni_cv_wake1(&cv->c);
}

uint32_t
nng_random(void)
{
	(void) nni_init();
	return (nni_random());
}
