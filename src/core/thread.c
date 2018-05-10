//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/nng_impl.h"

void
nni_mtx_init(nni_mtx *mtx)
{
	nni_plat_mtx_init(mtx);
}

void
nni_mtx_fini(nni_mtx *mtx)
{
	nni_plat_mtx_fini(mtx);
}

void
nni_mtx_lock(nni_mtx *mtx)
{
	nni_plat_mtx_lock(mtx);
}

void
nni_mtx_unlock(nni_mtx *mtx)
{
	nni_plat_mtx_unlock(mtx);
}

void
nni_cv_init(nni_cv *cv, nni_mtx *mtx)
{
	nni_plat_cv_init(cv, mtx);
}

void
nni_cv_fini(nni_cv *cv)
{
	nni_plat_cv_fini(cv);
}

void
nni_cv_wait(nni_cv *cv)
{
	nni_plat_cv_wait(cv);
}

int
nni_cv_until(nni_cv *cv, nni_time until)
{
	// Some special cases for times.  Catching these here means that
	// platforms can assume a valid time is presented to them.
	if (until == NNI_TIME_NEVER) {
		nni_plat_cv_wait(cv);
		return (0);
	}
	if (until == NNI_TIME_ZERO) {
		return (NNG_EAGAIN);
	}

	return (nni_plat_cv_until(cv, until));
}

void
nni_cv_wake(nni_cv *cv)
{
	nni_plat_cv_wake(cv);
}

void
nni_cv_wake1(nni_cv *cv)
{
	nni_plat_cv_wake1(cv);
}

static void
nni_thr_wrap(void *arg)
{
	nni_thr *thr = arg;
	int      start;

	nni_plat_mtx_lock(&thr->mtx);
	while (((start = thr->start) == 0) && (thr->stop == 0)) {
		nni_plat_cv_wait(&thr->cv);
	}
	nni_plat_mtx_unlock(&thr->mtx);
	if ((start) && (thr->fn != NULL)) {
		thr->fn(thr->arg);
	}
	nni_plat_mtx_lock(&thr->mtx);
	thr->done = 1;
	nni_plat_cv_wake(&thr->cv);
	nni_plat_mtx_unlock(&thr->mtx);
}

int
nni_thr_init(nni_thr *thr, nni_thr_func fn, void *arg)
{
	int rv;

	thr->done  = 0;
	thr->start = 0;
	thr->stop  = 0;
	thr->fn    = fn;
	thr->arg   = arg;

	nni_plat_mtx_init(&thr->mtx);
	nni_plat_cv_init(&thr->cv, &thr->mtx);

	if (fn == NULL) {
		thr->init = 1;
		thr->done = 1;
		return (0);
	}
	if ((rv = nni_plat_thr_init(&thr->thr, nni_thr_wrap, thr)) != 0) {
		thr->done = 1;
		nni_plat_cv_fini(&thr->cv);
		nni_plat_mtx_fini(&thr->mtx);
		return (rv);
	}
	thr->init = 1;
	return (0);
}

void
nni_thr_run(nni_thr *thr)
{
	nni_plat_mtx_lock(&thr->mtx);
	thr->start = 1;
	nni_plat_cv_wake(&thr->cv);
	nni_plat_mtx_unlock(&thr->mtx);
}

void
nni_thr_wait(nni_thr *thr)
{
	if (!thr->init) {
		return;
	}
	nni_plat_mtx_lock(&thr->mtx);
	thr->stop = 1;
	nni_plat_cv_wake(&thr->cv);
	while (!thr->done) {
		nni_plat_cv_wait(&thr->cv);
	}
	nni_plat_mtx_unlock(&thr->mtx);
}

void
nni_thr_fini(nni_thr *thr)
{
	if (!thr->init) {
		return;
	}
	nni_plat_mtx_lock(&thr->mtx);
	thr->stop = 1;
	nni_plat_cv_wake(&thr->cv);
	while (!thr->done) {
		nni_plat_cv_wait(&thr->cv);
	}
	nni_plat_mtx_unlock(&thr->mtx);
	if (thr->fn != NULL) {
		nni_plat_thr_fini(&thr->thr);
	}

	nni_plat_cv_fini(&thr->cv);
	nni_plat_mtx_fini(&thr->mtx);
	thr->init = 0;
}

bool
nni_thr_is_self(nni_thr *thr)
{
	if (!thr->init) {
		return (false);
	}
	return (nni_plat_thr_is_self(&thr->thr));
}
