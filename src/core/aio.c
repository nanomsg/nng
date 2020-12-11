//
// Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
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
static bool     nni_aio_expire_exit;
static nni_thr  nni_aio_expire_thr;
static nni_list nni_aio_expire_list;
static nni_aio *nni_aio_expire_aio;

// Reaping items.
static nni_thr  nni_aio_reap_thr;
static nni_aio *nni_aio_reap_list;
static nni_mtx  nni_aio_reap_lk;
static nni_cv   nni_aio_reap_cv;
static bool     nni_aio_reap_exit;

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
// In order to synchronize with the expiration, we record the aio as
// expiring, and wait for that record to be cleared (or at least not
// equal to the aio) before destroying it.
//
// The aio framework is tightly bound up with the task framework. We
// "prepare" the task for an aio when a caller marks an aio as starting
// (with nni_aio_begin), and that marks the task as busy. Then, all we have
// to do is wait for the task to complete (the busy flag to be cleared)
// when we want to know if the operation itself is complete.
//
// In order to guard against aio reuse during teardown, we set the a_stop
// flag.  Any attempt to initialize for a new operation after that point
// will fail and the caller will get NNG_ECANCELED indicating this.  The
// provider that calls nni_aio_begin() MUST check the return value, and
// if it comes back nonzero (NNG_ECANCELED) then it must simply discard the
// request and return.
//
// Calling nni_aio_wait waits for the current outstanding operation to
// complete, but does not block another one from being started on the
// same aio.  To synchronously stop the aio and prevent any further
// operations from starting on it, call nni_aio_stop.  To prevent the
// operations from starting, without waiting for any existing one to
// complete, call nni_aio_close.

static void nni_aio_expire_add(nni_aio *);

void
nni_aio_init(nni_aio *aio, nni_cb cb, void *arg)
{
	memset(aio, 0, sizeof(*aio));
	nni_task_init(&aio->a_task, NULL, cb, arg);
	aio->a_expire  = NNI_TIME_NEVER;
	aio->a_timeout = NNG_DURATION_INFINITE;
}

void
nni_aio_fini(nni_aio *aio)
{
	nni_aio_cancel_fn fn;
	void *            arg;

	// TODO: This probably could just use nni_aio_stop.

	// This is like aio_close, but we don't want to dispatch
	// the task.  And unlike aio_stop, we don't want to wait
	// for the task.  (Because we implicitly do task_fini.)
	nni_mtx_lock(&nni_aio_lk);
	fn                = aio->a_cancel_fn;
	arg               = aio->a_cancel_arg;
	aio->a_cancel_fn  = NULL;
	aio->a_cancel_arg = NULL;
	aio->a_stop       = true;
	nni_mtx_unlock(&nni_aio_lk);

	if (fn != NULL) {
		fn(aio, arg, NNG_ECLOSED);
	}

	// Wait for the aio to be "done"; this ensures that we don't
	// destroy an aio from a "normal" completion callback while
	// the expiration thread is working.

	nni_mtx_lock(&nni_aio_lk);
	while (nni_aio_expire_aio == aio) {
		// TODO: It should be possible to remove this check!
		if (nni_thr_is_self(&nni_aio_expire_thr)) {
			nni_aio_expire_aio = NULL;
			break;
		}
		nni_cv_wait(&nni_aio_expire_cv);
	}
	nni_mtx_unlock(&nni_aio_lk);
	nni_task_fini(&aio->a_task);
}

int
nni_aio_alloc(nni_aio **aio_p, nni_cb cb, void *arg)
{
	nni_aio *aio;

	if ((aio = NNI_ALLOC_STRUCT(aio)) == NULL) {
		return (NNG_ENOMEM);
	}
	nni_aio_init(aio, cb, arg);
	*aio_p = aio;
	return (0);
}

void
nni_aio_free(nni_aio *aio)
{
	if (aio != NULL) {
		nni_aio_fini(aio);
		NNI_FREE_STRUCT(aio);
	}
}

void
nni_aio_reap(nni_aio *aio)
{
	if (aio != NULL) {
		nni_mtx_lock(&nni_aio_reap_lk);
		aio->a_reap_next = nni_aio_reap_list;
		nni_aio_reap_list = aio;
		nni_cv_wake1(&nni_aio_reap_cv);
		nni_mtx_unlock(&nni_aio_reap_lk);
	}
}

int
nni_aio_set_iov(nni_aio *aio, unsigned nio, const nni_iov *iov)
{

	if (nio > NNI_NUM_ELEMENTS((aio->a_iov))) {
		return (NNG_EINVAL);
	}

	// Sometimes we are resubmitting our own io vector, with
	// just a smaller count.  We copy them only if we are not.
	if (iov != &aio->a_iov[0]) {
		for (unsigned i = 0; i < nio; i++) {
			aio->a_iov[i] = iov[i];
		}
	}
	aio->a_nio = nio;
	return (0);
}

// nni_aio_stop cancels any outstanding operation, and waits for the
// callback to complete, if still running.  It also marks the AIO as
// stopped, preventing further calls to nni_aio_begin from succeeding.
// To correctly tear down an AIO, call stop, and make sure any other
// callers are not also stopped, before calling nni_aio_free to release
// actual memory.
void
nni_aio_stop(nni_aio *aio)
{
	if (aio != NULL) {
		nni_aio_cancel_fn fn;
		void *            arg;

		nni_mtx_lock(&nni_aio_lk);
		fn                = aio->a_cancel_fn;
		arg               = aio->a_cancel_arg;
		aio->a_cancel_fn  = NULL;
		aio->a_cancel_arg = NULL;
		aio->a_stop       = true;
		nni_mtx_unlock(&nni_aio_lk);

		if (fn != NULL) {
			fn(aio, arg, NNG_ECANCELED);
		}

		nni_aio_wait(aio);
	}
}

void
nni_aio_close(nni_aio *aio)
{
	if (aio != NULL) {
		nni_aio_cancel_fn fn;
		void *            arg;

		nni_mtx_lock(&nni_aio_lk);
		fn                = aio->a_cancel_fn;
		arg               = aio->a_cancel_arg;
		aio->a_cancel_fn  = NULL;
		aio->a_cancel_arg = NULL;
		aio->a_stop       = true;
		nni_mtx_unlock(&nni_aio_lk);

		if (fn != NULL) {
			fn(aio, arg, NNG_ECLOSED);
		}
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
	nni_task_wait(&aio->a_task);
}

int
nni_aio_begin(nni_aio *aio)
{
	nni_mtx_lock(&nni_aio_lk);
	// We should not reschedule anything at this point.
	if (aio->a_stop) {
		aio->a_result = NNG_ECANCELED;
		aio->a_count  = 0;
		nni_list_node_remove(&aio->a_expire_node);
		aio->a_cancel_fn  = NULL;
		aio->a_cancel_arg = NULL;
		aio->a_expire     = NNI_TIME_NEVER;
		aio->a_sleep      = false;
		aio->a_expire_ok  = false;
		nni_mtx_unlock(&nni_aio_lk);

		nni_task_dispatch(&aio->a_task);
		return (NNG_ECANCELED);
	}
	aio->a_result     = 0;
	aio->a_count      = 0;
	aio->a_cancel_fn  = NULL;
	aio->a_cancel_arg = NULL;
	for (unsigned i = 0; i < NNI_NUM_ELEMENTS(aio->a_outputs); i++) {
		aio->a_outputs[i] = NULL;
	}
	nni_task_prep(&aio->a_task);
	nni_mtx_unlock(&nni_aio_lk);
	return (0);
}

int
nni_aio_schedule(nni_aio *aio, nni_aio_cancel_fn cancel, void *data)
{
	if (!aio->a_sleep) {
		// Convert the relative timeout to an absolute timeout.
		switch (aio->a_timeout) {
		case NNG_DURATION_ZERO:
			nni_task_abort(&aio->a_task);
			return (NNG_ETIMEDOUT);
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
	if (aio->a_stop) {
		nni_task_abort(&aio->a_task);
		nni_mtx_unlock(&nni_aio_lk);
		return (NNG_ECLOSED);
	}

	NNI_ASSERT(aio->a_cancel_fn == NULL);
	aio->a_cancel_fn  = cancel;
	aio->a_cancel_arg = data;

	if (aio->a_expire != NNI_TIME_NEVER) {
		nni_aio_expire_add(aio);
	}
	nni_mtx_unlock(&nni_aio_lk);
	return (0);
}

// nni_aio_abort is called by a consumer which guarantees that the aio
// is still valid.
void
nni_aio_abort(nni_aio *aio, int rv)
{
	nni_aio_cancel_fn fn;
	void *            arg;

	nni_mtx_lock(&nni_aio_lk);
	fn                = aio->a_cancel_fn;
	arg               = aio->a_cancel_arg;
	aio->a_cancel_fn  = NULL;
	aio->a_cancel_arg = NULL;
	nni_mtx_unlock(&nni_aio_lk);

	// Stop any I/O at the provider level.
	if (fn != NULL) {
		fn(aio, arg, rv);
	}
}

// I/O provider related functions.

static void
nni_aio_finish_impl(
    nni_aio *aio, int rv, size_t count, nni_msg *msg, bool sync)
{
	nni_mtx_lock(&nni_aio_lk);

	nni_list_node_remove(&aio->a_expire_node);

	aio->a_result     = rv;
	aio->a_count      = count;
	aio->a_cancel_fn  = NULL;
	aio->a_cancel_arg = NULL;
	if (msg) {
		aio->a_msg = msg;
	}

	aio->a_expire = NNI_TIME_NEVER;
	aio->a_sleep  = false;
	nni_mtx_unlock(&nni_aio_lk);

	if (sync) {
		nni_task_exec(&aio->a_task);
	} else {
		nni_task_dispatch(&aio->a_task);
	}
}

void
nni_aio_finish(nni_aio *aio, int result, size_t count)
{
	nni_aio_finish_impl(aio, result, count, NULL, false);
}

void
nni_aio_finish_sync(nni_aio *aio, int result, size_t count)
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
	nni_list *list = &nni_aio_expire_list;
	nni_aio * prev;

	// This is a reverse walk of the list.  We're more likely to find
	// a match at the end of the list.
	for (prev = nni_list_last(list); prev != NULL;
	     prev = nni_list_prev(list, prev)) {
		if (aio->a_expire >= prev->a_expire) {
			nni_list_insert_after(list, aio, prev);
			break;
		}
	}
	if (prev == NULL) {
		// This has the shortest time, so insert at the start.
		nni_list_prepend(list, aio);
		// And, as we are the latest, kick the thing.
		nni_cv_wake(&nni_aio_expire_cv);
	}
}

static void
nni_aio_expire_loop(void *unused)
{
	nni_list *list = &nni_aio_expire_list;

	NNI_ARG_UNUSED(unused);

	nni_thr_set_name(NULL, "nng:aio:expire");

	for (;;) {
		nni_aio_cancel_fn fn;
		nni_time          now;
		nni_aio *         aio;
		int               rv;

		now = nni_clock();

		nni_mtx_lock(&nni_aio_lk);

		if ((aio = nni_list_first(list)) == NULL) {

			if (nni_aio_expire_exit) {
				nni_mtx_unlock(&nni_aio_lk);
				return;
			}

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

		// The time has come for this aio.  Expire it, canceling any
		// outstanding I/O.
		nni_list_remove(list, aio);
		rv = aio->a_expire_ok ? 0 : NNG_ETIMEDOUT;

		if ((fn = aio->a_cancel_fn) != NULL) {
			void *arg         = aio->a_cancel_arg;
			aio->a_cancel_fn  = NULL;
			aio->a_cancel_arg = NULL;
			// Place a temporary hold on the aio.  This prevents it
			// from being destroyed.
			nni_aio_expire_aio = aio;

			// We let the cancel function handle the completion.
			// If there is no cancellation function, then we cannot
			// terminate the aio - we've tried, but it has to run
			// to it's natural conclusion.
			nni_mtx_unlock(&nni_aio_lk);
			fn(aio, arg, rv);
			nni_mtx_lock(&nni_aio_lk);

			nni_aio_expire_aio = NULL;
			nni_cv_wake(&nni_aio_expire_cv);
		}
		nni_mtx_unlock(&nni_aio_lk);
	}
}

static void
nni_aio_reap_loop(void *unused)
{
	NNI_ARG_UNUSED(unused);

	nni_thr_set_name(NULL, "nng:aio:reap");

	nni_mtx_lock(&nni_aio_reap_lk);

	for (;;) {
		nni_aio *aio;

		if ((aio = nni_aio_reap_list) == NULL) {
			if (nni_aio_reap_exit) {
				break;
			}

			nni_cv_wait(&nni_aio_reap_cv);
			continue;
		}
		nni_aio_reap_list = NULL;
		nni_mtx_unlock(&nni_aio_reap_lk);

		while (aio != NULL) {
			nni_aio *old = aio;
			aio = aio->a_reap_next;
			nni_aio_free(old);
		}

		nni_mtx_lock(&nni_aio_reap_lk);
	}

	nni_mtx_unlock(&nni_aio_reap_lk);
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
nni_aio_get_iov(nni_aio *aio, unsigned *nio_p, nni_iov **iov_p)
{
	*nio_p = aio->a_nio;
	*iov_p = aio->a_iov;
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
	size_t residual = 0;

	for (unsigned i = 0; i < aio->a_nio; i++) {
		residual += aio->a_iov[i].iov_len;
	}
	return (residual);
}

size_t
nni_aio_iov_advance(nni_aio *aio, size_t n)
{
	size_t residual = n;
	while (n) {
		NNI_ASSERT(aio->a_nio != 0);
		if (aio->a_iov[0].iov_len > n) {
			aio->a_iov[0].iov_len -= n;
			NNI_INCPTR(aio->a_iov[0].iov_buf, n);
			return (0); // we used all of "n"
		}
		residual -= aio->a_iov[0].iov_len;
		n -= aio->a_iov[0].iov_len;
		aio->a_nio--;
		for (unsigned i = 0; i < aio->a_nio; i++) {
			aio->a_iov[i] = aio->a_iov[i + 1];
		}
	}
	return (residual); // we might not have used all of n for this iov
}

static void
nni_sleep_cancel(nng_aio *aio, void *arg, int rv)
{
	NNI_ARG_UNUSED(arg);

	nni_mtx_lock(&nni_aio_lk);
	if (!aio->a_sleep) {
		nni_mtx_unlock(&nni_aio_lk);
		return;
	}

	aio->a_sleep = false;
	nni_list_node_remove(&aio->a_expire_node);
	nni_mtx_unlock(&nni_aio_lk);

	nni_aio_finish_error(aio, rv);
}

void
nni_sleep_aio(nng_duration ms, nng_aio *aio)
{
	int rv;
	if (nni_aio_begin(aio) != 0) {
		return;
	}
	aio->a_expire_ok = true;
	aio->a_sleep     = true;
	switch (aio->a_timeout) {
	case NNG_DURATION_DEFAULT:
	case NNG_DURATION_INFINITE:
		// No premature timeout, honor our expected values.
		break;
	default:
		// If the timeout on the aio is shorter than our sleep time,
		// then let it still wake up early, but with NNG_ETIMEDOUT.
		if (ms > aio->a_timeout) {
			aio->a_expire_ok = false;
			ms               = aio->a_timeout;
		}
	}
	aio->a_expire = nni_clock() + ms;

	if ((rv = nni_aio_schedule(aio, nni_sleep_cancel, NULL)) != 0) {
		nni_aio_finish_error(aio, rv);
	}
}

void
nni_aio_sys_fini(void)
{
	nni_mtx *mtx1 = &nni_aio_lk;
	nni_cv * cv1  = &nni_aio_expire_cv;
	nni_thr *thr1 = &nni_aio_expire_thr;
	nni_mtx *mtx2 = &nni_aio_reap_lk;
	nni_cv * cv2  = &nni_aio_reap_cv;
	nni_thr *thr2 = &nni_aio_reap_thr;

	if (!nni_aio_expire_exit) {
		nni_mtx_lock(mtx1);
		nni_aio_expire_exit = true;
		nni_cv_wake(cv1);
		nni_mtx_unlock(mtx1);
	}

	if (!nni_aio_reap_exit) {
		nni_mtx_lock(mtx2);
		nni_aio_reap_exit = true;
		nni_cv_wake(cv2);
		nni_mtx_unlock(mtx2);
	}

	nni_thr_fini(thr1);
	nni_cv_fini(cv1);
	nni_mtx_fini(mtx1);

	nni_thr_fini(thr2);
	nni_cv_fini(cv2);
	nni_mtx_fini(mtx2);
}

int
nni_aio_sys_init(void)
{
	int      rv, rv1, rv2;
	nni_thr *thr1 = &nni_aio_expire_thr;
	nni_thr *thr2 = &nni_aio_reap_thr;

	NNI_LIST_INIT(&nni_aio_expire_list, nni_aio, a_expire_node);
	nni_mtx_init(&nni_aio_lk);
	nni_cv_init(&nni_aio_expire_cv, &nni_aio_lk);
	nni_mtx_init(&nni_aio_reap_lk);
	nni_cv_init(&nni_aio_reap_cv, &nni_aio_reap_lk);

	nni_aio_expire_exit = false;
	nni_aio_reap_exit = false;

	rv1 = nni_thr_init(thr1, nni_aio_expire_loop, NULL);
	rv2 = nni_thr_init(thr2, nni_aio_reap_loop, NULL);
	if (((rv = rv1) != 0) || ((rv = rv2) != 0)) {
		nni_aio_sys_fini();
		return (rv);
	}

	nni_thr_run(thr1);
	nni_thr_run(thr2);
	return (0);
}
