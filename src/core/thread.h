//
// Copyright 2016 Garrett D'Amore <garrett@damore.org>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef CORE_THREAD_H
#define CORE_THREAD_H

#include "core/nng_impl.h"

typedef struct {
	nni_plat_mtx mtx;
} nni_mtx;

typedef struct {
	nni_plat_cv cv;
} nni_cv;

typedef void (*nni_thr_func)(void *);

typedef struct {
	nni_plat_thr	thr;
	nni_plat_mtx	mtx;
	nni_plat_cv	cv;
	nni_thr_func	fn;
	void *		arg;
	int		start;
	int		stop;
	int		done;
} nni_thr;

extern int nni_mtx_init(nni_mtx *mtx);
extern void nni_mtx_fini(nni_mtx *mtx);
extern void nni_mtx_lock(nni_mtx *mtx);
extern void nni_mtx_unlock(nni_mtx *mtx);
extern int nni_mtx_trylock(nni_mtx *mtx);

extern int nni_cv_init(nni_cv *cv, nni_mtx *);
extern void nni_cv_fini(nni_cv *cv);
extern void nni_cv_wake(nni_cv *cv);
extern void nni_cv_wait(nni_cv *cv);
extern int nni_cv_until(nni_cv *cv, nni_time when);

extern int nni_thr_init(nni_thr *thr, nni_thr_func fn, void *arg);
extern void nni_thr_fini(nni_thr *thr);
extern void nni_thr_run(nni_thr *thr);

#endif CORE_THREAD_H
