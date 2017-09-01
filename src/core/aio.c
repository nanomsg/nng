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

static nni_mtx nni_aio_lk;
// These are used for expiration.
static nni_cv   nni_aio_expire_cv;
static int      nni_aio_expire_run;
static nni_thr  nni_aio_expire_thr;
static nni_list nni_aio_expire_aios;

// Design notes.
//
// AIOs are only ever "completed" by the provider, which must call
// one of the nni_aio_finish variants.  Until this occurs, the provider
// guarantees that the AIO is valid.  The provider must guarantee that
// an AIO will be "completed" (with a call to nni_aio_finish & friends)
// exactly once.
//
// Note that the cancellation routine may be called by the framework
// several times.  The framework (or the consumer) guarantees that the
// AIO will remain valid across these calls, so that the provider is
// free to examine the aio for list membership, etc.  The provider must
// not call finish more than once though.
//
// A single lock, nni_aio_lk, is used to protect the flags on the AIO,
// as well as the expire list on the AIOs.  We will not permit an AIO
// to be marked done if an expiration is outstanding.
//
// In order to synchronize with the expiration, we set a flag when we
// are going to cancel due to expiration, and then let the expiration
// thread dispatch the notification to the user (after ensuring that
// the provider is done with the aio.)  This ensures that the completion
// task will be dispatch *exactly* once, and only after nothing in
// the provider or the framework is using it further.  (The consumer
// will probably still be using, but if the consumer calls nni_aio_wait
// or nni_aio_stop, then the consumer will have exclusive access to it.
// Provided, of course, that the consumer does not reuse the aio for
// another operation in the callback.)
//
// In order to guard against aio reuse during teardown, we set a fini
// flag.  Any attempt to initialize for a new operation after that point
// will fail and the caller will get NNG_ESTATE indicating this.  The
// provider that calls nni_aio_start() MUST check the return value, and
// if it comes back nonzero (NNG_ESTATE) then it must simply discard the
// request and return.

static void nni_aio_expire_add(nni_aio *);

int
nni_aio_init(nni_aio **aiop, nni_cb cb, void *arg)
{
	nni_aio *aio;

	if ((aio = NNI_ALLOC_STRUCT(aio)) == NULL) {
		return (NNG_ENOMEM);
	}
	memset(aio, 0, sizeof(*aio));
	nni_cv_init(&aio->a_cv, &nni_aio_lk);
	aio->a_expire = NNI_TIME_NEVER;
	aio->a_init   = 1;
	nni_task_init(NULL, &aio->a_task, cb, arg);
	*aiop = aio;
	return (0);
}

void
nni_aio_fini(nni_aio *aio)
{
	if (aio != NULL) {
		nni_aio_stop(aio);

		// At this point the AIO is done.
		nni_cv_fini(&aio->a_cv);

		NNI_FREE_STRUCT(aio);
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
	if (!aio->a_init) {
		// Never initialized, so nothing should have happened.
		return;
	}
	nni_mtx_lock(&nni_aio_lk);
	aio->a_fini = 1;
	nni_mtx_unlock(&nni_aio_lk);

	nni_aio_cancel(aio, NNG_ECANCELED);

	nni_aio_wait(aio);
}

void
nni_aio_set_timeout(nni_aio *aio, nni_time when)
{
	aio->a_expire = when;
}

void
nni_aio_set_msg(nni_aio *aio, nni_msg *msg)
{
	aio->a_msg = msg;
}

nni_msg *
nni_aio_get_msg(nni_aio *aio)
{
	return (aio->a_msg);
}

void
nni_aio_set_pipe(nni_aio *aio, void *p)
{
	aio->a_pipe = p;
}

void *
nni_aio_get_pipe(nni_aio *aio)
{
	return (aio->a_pipe);
}

void
nni_aio_set_ep(nni_aio *aio, void *ep)
{
	aio->a_endpt = ep;
}

void *
nni_aio_get_ep(nni_aio *aio)
{
	return (aio->a_endpt);
}

void
nni_aio_set_data(nni_aio *aio, void *data)
{
	aio->a_data = data;
}

void *
nni_aio_get_data(nni_aio *aio)
{
	return (aio->a_data);
}

int
nni_aio_result(nni_aio *aio)
{
	return (aio->a_result);
}

size_t
nni_aio_count(nni_aio *aio)
{
	return (aio->a_count);
}

void
nni_aio_wait(nni_aio *aio)
{
	nni_mtx_lock(&nni_aio_lk);
	while ((aio->a_active) && (!aio->a_done)) {
		aio->a_waiting = 1;
		nni_cv_wait(&aio->a_cv);
	}
	nni_mtx_unlock(&nni_aio_lk);
	nni_task_wait(&aio->a_task);
}

int
nni_aio_start(nni_aio *aio, nni_aio_cancelfn cancelfn, void *data)
{
	nni_mtx_lock(&nni_aio_lk);
	if (aio->a_fini) {
		// We should not reschedule anything at this point.
		aio->a_active = 0;
		aio->a_result = NNG_ECANCELED;
		nni_mtx_unlock(&nni_aio_lk);
		return (NNG_ECANCELED);
	}
	aio->a_done        = 0;
	aio->a_pend        = 0;
	aio->a_result      = 0;
	aio->a_count       = 0;
	aio->a_prov_cancel = cancelfn;
	aio->a_prov_data   = data;
	aio->a_active      = 1;
	if (aio->a_expire != NNI_TIME_NEVER) {
		nni_aio_expire_add(aio);
	}
	nni_mtx_unlock(&nni_aio_lk);
	return (0);
}

// nni_aio_cancel is called by a consumer which guarantees that the aio
// is still valid.
void
nni_aio_cancel(nni_aio *aio, int rv)
{
	nni_aio_cancelfn cancelfn;

	nni_mtx_lock(&nni_aio_lk);
	cancelfn = aio->a_prov_cancel;
	nni_mtx_unlock(&nni_aio_lk);

	// Stop any I/O at the provider level.
	if (cancelfn != NULL) {
		cancelfn(aio, rv);
	}
}

// I/O provider related functions.

static void
nni_aio_finish_impl(
    nni_aio *aio, int result, size_t count, void *pipe, nni_msg *msg)
{
	nni_mtx_lock(&nni_aio_lk);

	NNI_ASSERT(aio->a_pend == 0); // provider only calls us *once*

	nni_list_node_remove(&aio->a_expire_node);
	aio->a_pend        = 1;
	aio->a_result      = result;
	aio->a_count       = count;
	aio->a_prov_cancel = NULL;
	if (pipe) {
		aio->a_pipe = pipe;
	}
	if (msg) {
		aio->a_msg = msg;
	}

	aio->a_expire = NNI_TIME_NEVER;

	// If we are expiring, then we rely on the expiration thread to
	// complete this; we must not because the expiration thread is
	// still holding the reference.
	if (!aio->a_expiring) {
		aio->a_done = 1;
		if (aio->a_waiting) {
			aio->a_waiting = 0;
			nni_cv_wake(&aio->a_cv);
		}
		nni_task_dispatch(&aio->a_task);
	}
	nni_mtx_unlock(&nni_aio_lk);
}

void
nni_aio_finish(nni_aio *aio, int result, size_t count)
{
	nni_aio_finish_impl(aio, result, count, NULL, NULL);
}

void
nni_aio_finish_error(nni_aio *aio, int result)
{
	nni_aio_finish_impl(aio, result, 0, NULL, NULL);
}

void
nni_aio_finish_pipe(nni_aio *aio, void *pipe)
{
	NNI_ASSERT(pipe != NULL);
	nni_aio_finish_impl(aio, 0, 0, pipe, NULL);
}

void
nni_aio_finish_msg(nni_aio *aio, nni_msg *msg)
{
	NNI_ASSERT(msg != NULL);
	nni_aio_finish_impl(aio, 0, nni_msg_len(msg), NULL, msg);
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
	nni_list *list = &nni_aio_expire_aios;
	nni_aio * naio;

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
		nni_cv_wake(&nni_aio_expire_cv);
	}
}

static void
nni_aio_expire_loop(void *arg)
{
	nni_list *       aios = &nni_aio_expire_aios;
	nni_aio *        aio;
	nni_time         now;
	nni_aio_cancelfn cancelfn;

	NNI_ARG_UNUSED(arg);

	for (;;) {
		nni_mtx_lock(&nni_aio_lk);

		if (nni_aio_expire_run == 0) {
			nni_mtx_unlock(&nni_aio_lk);
			return;
		}

		if ((aio = nni_list_first(aios)) == NULL) {
			nni_cv_wait(&nni_aio_expire_cv);
			nni_mtx_unlock(&nni_aio_lk);
			continue;
		}

		now = nni_clock();
		if (now < aio->a_expire) {
			// Unexpired; the list is ordered, so we just wait.
			nni_cv_until(&nni_aio_expire_cv, aio->a_expire);
			nni_mtx_unlock(&nni_aio_lk);
			continue;
		}

		// This aio's time has come.  Expire it, canceling any
		// outstanding I/O.
		nni_list_remove(aios, aio);

		// Mark it as expiring.  This acts as a hold on
		// the aio, similar to the consumers.  The actual taskq
		// dispatch on completion won't occur until this is cleared,
		// and the done flag won't be set either.
		aio->a_expiring = 1;
		cancelfn        = aio->a_prov_cancel;

		// Cancel any outstanding activity.  This is always non-NULL
		// for a valid aio, and becomes NULL only when an AIO is
		// already being canceled or finished.
		if (cancelfn != NULL) {
			nni_mtx_unlock(&nni_aio_lk);
			cancelfn(aio, NNG_ETIMEDOUT);
			nni_mtx_lock(&nni_aio_lk);
		}

		NNI_ASSERT(aio->a_pend); // nni_aio_finish was run
		NNI_ASSERT(aio->a_prov_cancel == NULL);
		aio->a_expiring = 0;
		aio->a_done     = 1;
		if (aio->a_waiting) {
			aio->a_waiting = 0;
			nni_cv_wake(&aio->a_cv);
		}
		nni_task_dispatch(&aio->a_task);
		nni_mtx_unlock(&nni_aio_lk);
	}
}

void
nni_aio_sys_fini(void)
{
	nni_mtx *mtx = &nni_aio_lk;
	nni_cv * cv  = &nni_aio_expire_cv;
	nni_thr *thr = &nni_aio_expire_thr;

	if (nni_aio_expire_run) {
		nni_mtx_lock(mtx);
		nni_aio_expire_run = 0;
		nni_cv_wake(cv);
		nni_mtx_unlock(mtx);
	}

	nni_thr_fini(thr);
	nni_cv_fini(cv);
	nni_mtx_fini(mtx);
}

int
nni_aio_sys_init(void)
{
	int      rv;
	nni_mtx *mtx = &nni_aio_lk;
	nni_cv * cv  = &nni_aio_expire_cv;
	nni_thr *thr = &nni_aio_expire_thr;

	NNI_LIST_INIT(&nni_aio_expire_aios, nni_aio, a_expire_node);
	nni_mtx_init(mtx);
	nni_cv_init(cv, mtx);

	if ((rv = nni_thr_init(thr, nni_aio_expire_loop, NULL)) != 0) {
		nni_aio_sys_fini();
		return (rv);
	}

	nni_aio_expire_run = 1;
	nni_thr_run(thr);
	return (0);
}
