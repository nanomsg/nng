//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
// Copyright 2017 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/nng_impl.h"
#include <string.h>

enum nni_aio_flags {
	NNI_AIO_WAKE = 0x1,
	NNI_AIO_DONE = 0x2,
	NNI_AIO_FINI = 0x4,
};

// These are used for expiration.
static nni_mtx  nni_aio_expire_mtx;
static nni_cv   nni_aio_expire_cv;
static int      nni_aio_expire_exit;
static nni_list nni_aio_expire_aios;
static nni_thr  nni_aio_expire_thr;
static nni_aio *nni_aio_expire_current;

static void nni_aio_expire_add(nni_aio *);
static void nni_aio_expire_remove(nni_aio *);

int
nni_aio_init(nni_aio *aio, nni_cb cb, void *arg)
{
	int rv;

	if (cb == NULL) {
		cb  = (nni_cb) nni_aio_wake;
		arg = aio;
	}
	memset(aio, 0, sizeof(*aio));
	if ((rv = nni_mtx_init(&aio->a_lk)) != 0) {
		return (rv);
	}
	if ((rv = nni_cv_init(&aio->a_cv, &aio->a_lk)) != 0) {
		nni_mtx_fini(&aio->a_lk);
		return (rv);
	}
	aio->a_cb     = cb;
	aio->a_cbarg  = arg;
	aio->a_expire = NNI_TIME_NEVER;
	aio->a_flags  = 0;
	nni_task_init(NULL, &aio->a_task, cb, arg);

	return (0);
}

void
nni_aio_fini(nni_aio *aio)
{
	nni_aio_stop(aio);

	// At this point the AIO is done.
	nni_cv_fini(&aio->a_cv);
	nni_mtx_fini(&aio->a_lk);

	if ((aio->a_naddrs != 0) && (aio->a_addrs != NULL)) {
		NNI_FREE_STRUCTS(aio->a_addrs, aio->a_naddrs);
	}
}

// nni_aio_stop cancels any oustanding operation, and waits for the
// callback to complete, if still running.  It also marks the AIO as
// stopped, preventing further calls to nni_aio_start from succeeding.
// To correctly tear down an AIO, call stop, and make sure any other
// calles are not also stopped, before calling nni_aio_fini to release
// actual memory.
void
nni_aio_stop(nni_aio *aio)
{
	if ((aio->a_cb == NULL) && (aio->a_cbarg == NULL)) {
		// Never initialized, so nothing should have happened.
		return;
	}
	nni_mtx_lock(&aio->a_lk);
	aio->a_flags |= NNI_AIO_FINI; // this prevents us from being scheduled
	nni_mtx_unlock(&aio->a_lk);

	nni_aio_cancel(aio, NNG_ECANCELED);

	// Wait for any outstanding task to complete.  We won't schedule
	// new stuff because nni_aio_start will fail (due to AIO_FINI).
	nni_task_wait(&aio->a_task);
}

int
nni_aio_result(nni_aio *aio)
{
	int rv;

	nni_mtx_lock(&aio->a_lk);
	rv = aio->a_result;
	nni_mtx_unlock(&aio->a_lk);
	return (rv);
}

size_t
nni_aio_count(nni_aio *aio)
{
	return (aio->a_count);
}

void
nni_aio_wake(nni_aio *aio)
{
	nni_mtx_lock(&aio->a_lk);
	aio->a_flags |= NNI_AIO_WAKE;
	nni_cv_wake(&aio->a_cv);
	nni_mtx_unlock(&aio->a_lk);
}

void
nni_aio_wait(nni_aio *aio)
{
	nni_mtx_lock(&aio->a_lk);
	while ((aio->a_flags & (NNI_AIO_WAKE | NNI_AIO_FINI)) == 0) {
		nni_cv_wait(&aio->a_cv);
	}
	nni_mtx_unlock(&aio->a_lk);
}

int
nni_aio_start(nni_aio *aio, void (*cancel)(nni_aio *), void *data)
{
	nni_mtx_lock(&aio->a_lk);
	aio->a_flags &= ~(NNI_AIO_DONE | NNI_AIO_WAKE);
	if (aio->a_flags & NNI_AIO_FINI) {
		// We should not reschedule anything at this point.
		nni_mtx_unlock(&aio->a_lk);
		return (NNG_ECANCELED);
	}
	aio->a_result      = 0;
	aio->a_count       = 0;
	aio->a_prov_cancel = cancel;
	aio->a_prov_data   = data;
	if (aio->a_expire != NNI_TIME_NEVER) {
		nni_aio_expire_add(aio);
	}
	nni_mtx_unlock(&aio->a_lk);
	return (0);
}

void
nni_aio_cancel(nni_aio *aio, int rv)
{
	void (*cancelfn)(nni_aio *);

	nni_mtx_lock(&aio->a_lk);
	if (aio->a_flags & NNI_AIO_DONE) {
		// The operation already completed - so there's nothing
		// left for us to do.
		nni_mtx_unlock(&aio->a_lk);
		return;
	}
	aio->a_flags |= NNI_AIO_DONE;
	aio->a_result      = rv;
	cancelfn           = aio->a_prov_cancel;
	aio->a_prov_cancel = NULL;

	aio->a_refcnt++;
	nni_mtx_unlock(&aio->a_lk);

	// Guaraneed to just be a list operation.
	nni_aio_expire_remove(aio);

	// Stop any I/O at the provider level.
	if (cancelfn != NULL) {
		cancelfn(aio);
	}

	nni_mtx_lock(&aio->a_lk);

	aio->a_refcnt--;
	if (aio->a_refcnt == 0) {
		nni_cv_wake(&aio->a_cv);
	}

	// These should have already been cleared by the cancel function.
	aio->a_prov_data   = NULL;
	aio->a_prov_cancel = NULL;

	nni_task_dispatch(&aio->a_task);
	nni_mtx_unlock(&aio->a_lk);
}

// I/O provider related functions.

int
nni_aio_finish(nni_aio *aio, int result, size_t count)
{
	nni_mtx_lock(&aio->a_lk);
	if (aio->a_flags & NNI_AIO_DONE) {
		// Operation already done (canceled or timed out?)
		nni_mtx_unlock(&aio->a_lk);
		return (NNG_ESTATE);
	}
	aio->a_flags |= NNI_AIO_DONE;

	aio->a_result      = result;
	aio->a_count       = count;
	aio->a_prov_cancel = NULL;
	aio->a_prov_data   = NULL;

	// This is guaranteed to just be a list operation at this point,
	// because done wasn't set.
	nni_aio_expire_remove(aio);
	aio->a_expire = NNI_TIME_NEVER;

	nni_task_dispatch(&aio->a_task);
	nni_mtx_unlock(&aio->a_lk);
	return (0);
}

int
nni_aio_finish_pipe(nni_aio *aio, int result, void *pipe)
{
	nni_mtx_lock(&aio->a_lk);
	if (aio->a_flags & NNI_AIO_DONE) {
		// Operation already done (canceled or timed out?)
		nni_mtx_unlock(&aio->a_lk);
		return (NNG_ESTATE);
	}
	aio->a_flags |= NNI_AIO_DONE;

	aio->a_result      = result;
	aio->a_count       = 0;
	aio->a_prov_cancel = NULL;
	aio->a_prov_data   = NULL;
	aio->a_pipe        = pipe;

	// This is guaranteed to just be a list operation at this point,
	// because done wasn't set.
	nni_aio_expire_remove(aio);
	aio->a_expire = NNI_TIME_NEVER;

	nni_task_dispatch(&aio->a_task);
	nni_mtx_unlock(&aio->a_lk);
	return (0);
}

void
nni_aio_list_init(nni_list *list)
{
	NNI_LIST_INIT(list, nni_aio, a_prov_node);
}

void
nni_aio_list_append(nni_list *list, nni_aio *aio)
{
	nni_aio_list_remove(aio);
	nni_list_append(list, aio);
}

void
nni_aio_list_remove(nni_aio *aio)
{
	nni_list_node_remove(&aio->a_prov_node);
}

int
nni_aio_list_active(nni_aio *aio)
{
	return (nni_list_node_active(&aio->a_prov_node));
}

static void
nni_aio_expire_add(nni_aio *aio)
{
	nni_mtx * mtx  = &nni_aio_expire_mtx;
	nni_cv *  cv   = &nni_aio_expire_cv;
	nni_list *list = &nni_aio_expire_aios;
	nni_aio * naio;

	nni_mtx_lock(mtx);
	// This is a reverse walk of the list.  We're more likely to find
	// a match at the end of the list.
	for (naio = nni_list_last(list); naio != NULL;
	     naio = nni_list_prev(list, naio)) {
		if (aio->a_expire >= naio->a_expire) {
			nni_list_insert_after(list, aio, naio);
			break;
		}
	}
	if (naio == NULL) {
		// This has the shortest time, so insert at the start.
		nni_list_prepend(list, aio);
		// And, as we are the latest, kick the thing.
		nni_cv_wake(cv);
	}
	nni_mtx_unlock(mtx);
}

static void
nni_aio_expire_remove(nni_aio *aio)
{
	nni_mtx * mtx  = &nni_aio_expire_mtx;
	nni_cv *  cv   = &nni_aio_expire_cv;
	nni_list *list = &nni_aio_expire_aios;

	nni_mtx_lock(mtx);
	if (nni_list_active(list, aio)) {
		nni_list_remove(list, aio);
	}
	while (aio == nni_aio_expire_current) {
		nni_cv_wait(cv);
	}
	nni_mtx_unlock(mtx);
}

static void
nni_aio_expire_loop(void *arg)
{
	nni_mtx * mtx  = &nni_aio_expire_mtx;
	nni_cv *  cv   = &nni_aio_expire_cv;
	nni_list *aios = &nni_aio_expire_aios;
	nni_aio * aio;
	nni_time  now;

	void (*cancelfn)(nni_aio *);

	NNI_ARG_UNUSED(arg);

	for (;;) {
		nni_mtx_lock(mtx);

		// If we are resuming this loop after processing an AIO,
		// note that we are done with it, and wake anyone waiting
		// for that to clear up.
		if ((aio = nni_aio_expire_current) != NULL) {
			nni_aio_expire_current = NULL;
			nni_cv_wake(cv);
		}

		if (nni_aio_expire_exit) {
			nni_mtx_unlock(mtx);
			return;
		}

		if ((aio = nni_list_first(aios)) == NULL) {
			nni_cv_wait(cv);
			nni_mtx_unlock(mtx);
			continue;
		}

		now = nni_clock();
		if (now < aio->a_expire) {
			// Unexpired; the list is ordered, so we just wait.
			nni_cv_until(cv, aio->a_expire);
			nni_mtx_unlock(mtx);
			continue;
		}

		// This aio's time has come.  Expire it, canceling any
		// outstanding I/O.

		nni_list_remove(aios, aio);
		nni_aio_expire_current = aio;
		nni_mtx_unlock(mtx);

		cancelfn = NULL;

		nni_mtx_lock(&aio->a_lk);
		if ((aio->a_flags & (NNI_AIO_DONE | NNI_AIO_FINI)) != 0) {
			nni_mtx_unlock(&aio->a_lk);
			continue;
		}

		aio->a_flags |= NNI_AIO_DONE;

		aio->a_result      = NNG_ETIMEDOUT;
		cancelfn           = aio->a_prov_cancel;
		aio->a_prov_cancel = NULL;
		nni_mtx_unlock(&aio->a_lk);

		// Cancel any outstanding activity.
		if (cancelfn != NULL) {
			cancelfn(aio);
		}

		// Arguably we could avoid dispatching, and execute the
		// callback inline here as we are already on a separate
		// thread.  But keeping it separate is clearer, and more
		// consistent with other uses.  And this should not be a
		// hot code path.
		nni_task_dispatch(&aio->a_task);
	}
}

int
nni_aio_sys_init(void)
{
	int      rv;
	nni_mtx *mtx = &nni_aio_expire_mtx;
	nni_cv * cv  = &nni_aio_expire_cv;
	nni_thr *thr = &nni_aio_expire_thr;

	if (((rv = nni_mtx_init(mtx)) != 0) ||
	    ((rv = nni_cv_init(cv, mtx)) != 0) ||
	    ((rv = nni_thr_init(thr, nni_aio_expire_loop, NULL)) != 0)) {
		goto fail;
	}
	NNI_LIST_INIT(&nni_aio_expire_aios, nni_aio, a_expire_node);
	nni_thr_run(thr);
	return (0);

fail:
	nni_thr_fini(thr);
	nni_cv_fini(cv);
	nni_mtx_fini(mtx);
	return (rv);
}

void
nni_aio_sys_fini(void)
{
	nni_mtx *mtx = &nni_aio_expire_mtx;
	nni_cv * cv  = &nni_aio_expire_cv;
	nni_thr *thr = &nni_aio_expire_thr;

	nni_mtx_lock(mtx);
	nni_aio_expire_exit = 1;
	nni_cv_wake(cv);
	nni_mtx_unlock(mtx);

	nni_thr_fini(thr);
	nni_cv_fini(cv);
	nni_mtx_fini(mtx);
}