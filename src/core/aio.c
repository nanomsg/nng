//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
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
// will fail and the caller will get NNG_ECANCELED indicating this.  The
// provider that calls nni_aio_begin() MUST check the return value, and
// if it comes back nonzero (NNG_ECANCELED) then it must simply discard the
// request and return.

// An nni_aio is an async I/O handle.
struct nng_aio {
	int          a_result;  // Result code (nng_errno)
	size_t       a_count;   // Bytes transferred (I/O only)
	nni_time     a_expire;  // Absolute timeout
	nni_duration a_timeout; // Relative timeout

	// These fields are private to the aio framework.
	nni_cv   a_cv;
	bool     a_fini : 1;     // shutting down (no new operations)
	bool     a_done : 1;     // operation has completed
	bool     a_pend : 1;     // completion routine pending
	bool     a_active : 1;   // aio was started
	bool     a_expiring : 1; // expiration callback in progress
	bool     a_waiting : 1;  // a thread is waiting for this to finish
	bool     a_synch : 1;    // run completion synchronously
	bool     a_sleep : 1;    // sleeping with no action
	nni_task a_task;

	// Read/write operations.
	nni_iov *a_iov;
	unsigned a_niov;
	nni_iov  a_iovinl[4]; // inline IOVs - when the IOV list is short
	nni_iov *a_iovalloc;  // dynamically allocated IOVs
	unsigned a_niovalloc; // number of allocated IOVs

	// Message operations.
	nni_msg *a_msg;

	// User scratch data.  Consumers may store values here, which
	// must be preserved by providers and the framework.
	void *a_user_data[4];

	// Operation inputs & outputs.  Up to 4 inputs and 4 outputs may be
	// specified.  The semantics of these will vary, and depend on the
	// specific operation.
	void *a_inputs[4];
	void *a_outputs[4];

	// Provider-use fields.
	nni_aio_cancelfn a_prov_cancel;
	void *           a_prov_data;
	nni_list_node    a_prov_node;
	void *           a_prov_extra[4]; // Extra data used by provider

	// Expire node.
	nni_list_node a_expire_node;
};

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
	aio->a_expire    = NNI_TIME_NEVER;
	aio->a_timeout   = NNG_DURATION_INFINITE;
	aio->a_iov       = aio->a_iovinl;
	aio->a_niovalloc = 0;
	if (arg == NULL) {
		arg = aio;
	}
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

		if (aio->a_niovalloc > 0) {
			NNI_FREE_STRUCTS(aio->a_iovalloc, aio->a_niovalloc);
		}

		NNI_FREE_STRUCT(aio);
	}
}

int
nni_aio_set_iov(nni_aio *aio, unsigned niov, const nni_iov *iov)
{
	// Sometimes we are resubmitting our own io vector, with
	// just a smaller niov.
	if (aio->a_iov != iov) {
		if ((niov > NNI_NUM_ELEMENTS(aio->a_iovinl)) &&
		    (niov > aio->a_niovalloc)) {
			nni_iov *newiov = NNI_ALLOC_STRUCTS(newiov, niov);
			if (newiov == NULL) {
				return (NNG_ENOMEM);
			}
			if (aio->a_niovalloc > 0) {
				NNI_FREE_STRUCTS(
				    aio->a_iovalloc, aio->a_niovalloc);
			}
			aio->a_iov       = newiov;
			aio->a_iovalloc  = newiov;
			aio->a_niovalloc = niov;
		}
		if (niov <= NNI_NUM_ELEMENTS(aio->a_iovinl)) {
			aio->a_iov = aio->a_iovinl;
		} else {
			aio->a_iov = aio->a_iovalloc;
		}
		memcpy(aio->a_iov, iov, niov * sizeof(nni_iov));
	}
	aio->a_niov = niov;
	return (0);
}

void
nni_aio_fini_cb(nni_aio *aio)
{
	nni_cv_fini(&aio->a_cv);
	NNI_FREE_STRUCT(aio);
}

// nni_aio_stop cancels any oustanding operation, and waits for the
// callback to complete, if still running.  It also marks the AIO as
// stopped, preventing further calls to nni_aio_begin from succeeding.
// To correctly tear down an AIO, call stop, and make sure any other
// calles are not also stopped, before calling nni_aio_fini to release
// actual memory.
void
nni_aio_stop(nni_aio *aio)
{
	if (aio != NULL) {
		nni_mtx_lock(&nni_aio_lk);
		aio->a_fini = true;
		nni_mtx_unlock(&nni_aio_lk);

		nni_aio_abort(aio, NNG_ECANCELED);

		nni_aio_wait(aio);
	}
}

void
nni_aio_set_timeout(nni_aio *aio, nni_duration when)
{
	aio->a_timeout = when;
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
nni_aio_set_data(nni_aio *aio, unsigned index, void *data)
{
	if (index < NNI_NUM_ELEMENTS(aio->a_user_data)) {
		aio->a_user_data[index] = data;
	}
}

void *
nni_aio_get_data(nni_aio *aio, unsigned index)
{
	if (index < NNI_NUM_ELEMENTS(aio->a_user_data)) {
		return (aio->a_user_data[index]);
	}
	return (NULL);
}

void
nni_aio_set_input(nni_aio *aio, unsigned index, void *data)
{
	if (index < NNI_NUM_ELEMENTS(aio->a_inputs)) {
		aio->a_inputs[index] = data;
	}
}

void *
nni_aio_get_input(nni_aio *aio, unsigned index)
{
	if (index < NNI_NUM_ELEMENTS(aio->a_inputs)) {
		return (aio->a_inputs[index]);
	}
	return (NULL);
}

void
nni_aio_set_output(nni_aio *aio, unsigned index, void *data)
{
	if (index < NNI_NUM_ELEMENTS(aio->a_outputs)) {
		aio->a_outputs[index] = data;
	}
}

void *
nni_aio_get_output(nni_aio *aio, unsigned index)
{
	if (index < NNI_NUM_ELEMENTS(aio->a_outputs)) {
		return (aio->a_outputs[index]);
	}
	return (NULL);
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
	// Wait until we're done, and the synchronous completion flag
	// is cleared (meaning any synch completion is finished).
	while ((aio->a_active) && ((!aio->a_done) || (aio->a_synch))) {
		aio->a_waiting = true;
		nni_cv_wait(&aio->a_cv);
	}
	nni_mtx_unlock(&nni_aio_lk);
	nni_task_wait(&aio->a_task);
}

int
nni_aio_begin(nni_aio *aio)
{
	nni_mtx_lock(&nni_aio_lk);
	// We should not reschedule anything at this point.
	if (aio->a_fini) {
		aio->a_active = false;
		aio->a_result = NNG_ECANCELED;
		nni_mtx_unlock(&nni_aio_lk);
		return (NNG_ECANCELED);
	}
	aio->a_done        = false;
	aio->a_pend        = false;
	aio->a_result      = 0;
	aio->a_count       = 0;
	aio->a_prov_cancel = NULL;
	aio->a_prov_data   = NULL;
	aio->a_active      = true;
	for (unsigned i = 0; i < NNI_NUM_ELEMENTS(aio->a_outputs); i++) {
		aio->a_outputs[i] = NULL;
	}
	nni_mtx_unlock(&nni_aio_lk);
	return (0);
}

void
nni_aio_schedule(nni_aio *aio, nni_aio_cancelfn cancelfn, void *data)
{
	if (!aio->a_sleep) {
		// Convert the relative timeout to an absolute timeout.
		switch (aio->a_timeout) {
		case NNG_DURATION_ZERO:
			aio->a_expire = nni_clock();
			break;
		case NNG_DURATION_INFINITE:
		case NNG_DURATION_DEFAULT:
			aio->a_expire = NNI_TIME_NEVER;
			break;
		default:
			aio->a_expire = nni_clock() + aio->a_timeout;
			break;
		}
	}

	nni_mtx_lock(&nni_aio_lk);
	aio->a_prov_cancel = cancelfn;
	aio->a_prov_data   = data;
	if (aio->a_expire != NNI_TIME_NEVER) {
		nni_aio_expire_add(aio);
	}
	nni_mtx_unlock(&nni_aio_lk);
}

int
nni_aio_schedule_verify(nni_aio *aio, nni_aio_cancelfn cancelfn, void *data)
{

	if ((!aio->a_sleep) && (aio->a_timeout == NNG_DURATION_ZERO)) {
		return (NNG_ETIMEDOUT);
	}
	nni_aio_schedule(aio, cancelfn, data);
	return (0);
}

// nni_aio_abort is called by a consumer which guarantees that the aio
// is still valid.
void
nni_aio_abort(nni_aio *aio, int rv)
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
    nni_aio *aio, int rv, size_t count, nni_msg *msg, bool synch)
{
	nni_mtx_lock(&nni_aio_lk);

	NNI_ASSERT(!aio->a_pend); // provider only calls us *once*

	nni_list_node_remove(&aio->a_expire_node);

	aio->a_pend        = true;
	aio->a_result      = rv;
	aio->a_count       = count;
	aio->a_prov_cancel = NULL;
	if (msg) {
		aio->a_msg = msg;
	}

	aio->a_expire = NNI_TIME_NEVER;
	aio->a_sleep  = false;

	// If we are expiring, then we rely on the expiration thread to
	// complete this; we must not because the expiration thread is
	// still holding the reference.

	if (aio->a_expiring) {
		nni_mtx_unlock(&nni_aio_lk);
		return;
	}

	aio->a_done  = true;
	aio->a_synch = synch;

	if (synch) {
		if (aio->a_task.task_cb != NULL) {
			nni_mtx_unlock(&nni_aio_lk);
			aio->a_task.task_cb(aio->a_task.task_arg);
			nni_mtx_lock(&nni_aio_lk);
		}
	} else {
		nni_task_dispatch(&aio->a_task);
	}
	aio->a_synch = false;

	if (aio->a_waiting) {
		aio->a_waiting = false;
		nni_cv_wake(&aio->a_cv);
	}

	// This has to be done with the lock still held, in order
	// to prevent taskq wait from returning prematurely.
	nni_mtx_unlock(&nni_aio_lk);
}

void
nni_aio_finish(nni_aio *aio, int result, size_t count)
{
	nni_aio_finish_impl(aio, result, count, NULL, false);
}

void
nni_aio_finish_synch(nni_aio *aio, int result, size_t count)
{
	nni_aio_finish_impl(aio, result, count, NULL, true);
}

void
nni_aio_finish_error(nni_aio *aio, int result)
{
	nni_aio_finish_impl(aio, result, 0, NULL, false);
}

void
nni_aio_finish_msg(nni_aio *aio, nni_msg *msg)
{
	NNI_ASSERT(msg != NULL);
	nni_aio_finish_impl(aio, 0, nni_msg_len(msg), msg, false);
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
nni_aio_list_prepend(nni_list *list, nni_aio *aio)
{
	nni_aio_list_remove(aio);
	nni_list_prepend(list, aio);
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
	int              rv;

	NNI_ARG_UNUSED(arg);

	for (;;) {
		now = nni_clock();

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
		aio->a_expiring = true;
		cancelfn        = aio->a_prov_cancel;
		rv              = aio->a_sleep ? 0 : NNG_ETIMEDOUT;
		aio->a_sleep    = false;

		// Cancel any outstanding activity.  This is always non-NULL
		// for a valid aio, and becomes NULL only when an AIO is
		// already being canceled or finished.
		if (cancelfn != NULL) {
			nni_mtx_unlock(&nni_aio_lk);
			cancelfn(aio, rv);
			nni_mtx_lock(&nni_aio_lk);
		} else {
			aio->a_pend   = true;
			aio->a_result = rv;
		}

		NNI_ASSERT(aio->a_pend); // nni_aio_finish was run
		NNI_ASSERT(aio->a_prov_cancel == NULL);
		aio->a_expiring = false;
		aio->a_done     = true;

		nni_task_dispatch(&aio->a_task);

		if (aio->a_waiting) {
			aio->a_waiting = false;
			nni_cv_wake(&aio->a_cv);
		}
		nni_mtx_unlock(&nni_aio_lk);
	}
}

void *
nni_aio_get_prov_data(nni_aio *aio)
{
	return (aio->a_prov_data);
}

void
nni_aio_set_prov_data(nni_aio *aio, void *data)
{
	aio->a_prov_data = data;
}

void *
nni_aio_get_prov_extra(nni_aio *aio, unsigned index)
{
	return (aio->a_prov_extra[index]);
}

void
nni_aio_set_prov_extra(nni_aio *aio, unsigned index, void *data)
{
	aio->a_prov_extra[index] = data;
}

void
nni_aio_get_iov(nni_aio *aio, unsigned *niovp, nni_iov **iovp)
{
	*niovp = aio->a_niov;
	*iovp  = aio->a_iov;
}

void
nni_aio_normalize_timeout(nni_aio *aio, nng_duration dur)
{
	if (aio->a_timeout == NNG_DURATION_DEFAULT) {
		aio->a_timeout = dur;
	}
}

void
nni_aio_bump_count(nni_aio *aio, size_t n)
{
	aio->a_count += n;
}

size_t
nni_aio_iov_count(nni_aio *aio)
{
	size_t resid = 0;

	for (unsigned i = 0; i < aio->a_niov; i++) {
		resid += aio->a_iov[i].iov_len;
	}
	return (resid);
}

size_t
nni_aio_iov_advance(nni_aio *aio, size_t n)
{
	size_t resid = n;
	while (n) {
		NNI_ASSERT(aio->a_niov != 0);
		if (aio->a_iov[0].iov_len > n) {
			aio->a_iov[0].iov_len -= n;
			NNI_INCPTR(aio->a_iov[0].iov_buf, n);
			return (0); // we used all of "n"
		}
		resid -= aio->a_iov[0].iov_len;
		n -= aio->a_iov[0].iov_len;
		aio->a_iov = &aio->a_iov[1];
		aio->a_niov--;
	}
	return (resid); // we might not have used all of n for this iov
}

void
nni_sleep_aio(nng_duration ms, nng_aio *aio)
{
	if (nni_aio_begin(aio) != 0) {
		return;
	}
	switch (aio->a_timeout) {
	case NNG_DURATION_DEFAULT:
	case NNG_DURATION_INFINITE:
		// No premature timeout, honor our expected values.
		break;
	default:
		// If the timeout on the aio is shorter than our sleep time,
		// then let it still wake up early, but with NNG_ETIMEDOUT.
		if (ms > aio->a_timeout) {
			aio->a_sleep = false;
			(void) nni_aio_schedule(aio, NULL, NULL);
			return;
		}
	}
	aio->a_sleep  = true;
	aio->a_expire = nni_clock() + ms;

	// There is no cancellation, apart from just unexpiring.
	nni_aio_schedule(aio, NULL, NULL);
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
