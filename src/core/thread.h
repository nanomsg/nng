//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
// Copyright 2017 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef CORE_THREAD_H
#define CORE_THREAD_H

#include "core/defs.h"
#include "core/platform.h"

struct nni_thr {
	nni_plat_thr thr;
	nni_plat_mtx mtx;
	nni_plat_cv  cv;
	nni_thr_func fn;
	void *       arg;
	int          start;
	int          stop;
	int          done;
	int          init;
};

// nni_mtx_init initializes the mutex.
extern void nni_mtx_init(nni_mtx *mtx);

// nni_mtx_fini destroys the mutex and releases any resources used by it.
extern void nni_mtx_fini(nni_mtx *mtx);

// nni_mtx_lock locks the given mutex, waiting if necessary.  Recursive
// entry is not supported; attempts to do so will result in undefined
// behavior.
extern void nni_mtx_lock(nni_mtx *mtx);

// nni_mutex_unlock unlocks the given mutex.  The mutex must be
// owned by the calling thread.
extern void nni_mtx_unlock(nni_mtx *mtx);

// nni_cv_init initializes the condition variable.  The mutex supplied
// must always be locked with the condition variable.
extern void nni_cv_init(nni_cv *cv, nni_mtx *);

// nni_cv_fini releases resources associated with the condition variable,
// which must not be in use at the time.
extern void nni_cv_fini(nni_cv *cv);

// nni_cv_wake wakes all waiters on the condition variable.
extern void nni_cv_wake(nni_cv *cv);

// nni_cv_wake wakes just one waiter on the condition variable.
extern void nni_cv_wake1(nni_cv *cv);

// nni_cv_wait waits until nni_cv_wake is called on the condition variable.
// The wait is indefinite.  Premature wakeups are possible, so the caller
// must verify any related condition.
extern void nni_cv_wait(nni_cv *cv);

// nni_cv_until waits until the condition variable is signaled with
// nni_cv_wake the system indicated is reached.  If the time expires,
// the return will be NNG_ETIMEDOUT.
extern int nni_cv_until(nni_cv *cv, nni_time when);

// nni_thr_init creates the thread, but the thread starts "stalled", until
// it is either run, or a wait or or fini is called.
extern int nni_thr_init(nni_thr *thr, nni_thr_func fn, void *arg);

// nni_thr_fini waits for the thread to finish (if it s running), then
// reclaims any resources associated with it.
extern void nni_thr_fini(nni_thr *thr);

// nni_thr_run runs the given thread, which must have been initialized.
extern void nni_thr_run(nni_thr *thr);

// nni_thr_wait waits for the thread to complete execution, but does not
// release resources associated with it.  It is idempotent.  If the this
// is called before nni_thr_run is called, then the thread will not run
// at all.
extern void nni_thr_wait(nni_thr *thr);

// nni_thr_is_self returns true if the caller is the named thread.
extern bool nni_thr_is_self(nni_thr *thr);

#endif // CORE_THREAD_H
