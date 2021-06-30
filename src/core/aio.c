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

struct nni_aio_expire_q {
	nni_mtx   eq_mtx;
	nni_cv    eq_cv;
	nni_aio **eq_list;
	uint32_t  eq_len;
	uint32_t  eq_cap;
	nni_aio * eq_aio; // currently expiring (task dispatch)
	nni_thr   eq_thr;
	bool      eq_exit;
};

static nni_aio_expire_q **nni_aio_expire_q_list;
static int                nni_aio_expire_q_cnt;

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
// We use an array of expiration queues, each with it's own lock and
// condition variable, and expiration thread.  By default this is one
// per CPU core present -- the goal being to reduce overall pressure
// caused by a single lock.  The number of queues (and threads) can
// be tuned using the NNG_EXPIRE_THREADS tunable.
//
// We will not permit an AIO
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

// In some places we want to check that an aio is not in use.
// Technically if these checks pass, then they should not need
// to be done with a lock, because the caller should have the only
// references to them.  However, race detectors can't necessarily
// know about this semantic, and may complain about potential data
// races.  To suppress false positives, define NNG_RACE_DETECTOR.
// Note that this will cause extra locks to be acquired, affecting
// performance, so don't use it in production.
#ifdef __has_feature
#if __has_feature(thread_sanitizer)
#define NNG_RACE_DETECTOR
#endif
#endif

#ifdef NNG_RACE_DETECTOR
#define aio_safe_lock(l) nni_mtx_lock(l)
#define aio_safe_unlock(l) nni_mtx_unlock(l)
#else
#define aio_safe_lock(l)
#define aio_safe_unlock(l)
#endif

static nni_reap_list aio_reap_list = {
	.rl_offset = offsetof(nni_aio, a_reap_node),
	.rl_func   = (nni_cb) nni_aio_free,
};

static void nni_aio_expire_add(nni_aio *);
static void nni_aio_expire_rm(nni_aio *);

void
nni_aio_init(nni_aio *aio, nni_cb cb, void *arg)
{
	memset(aio, 0, sizeof(*aio));
	nni_task_init(&aio->a_task, NULL, cb, arg);
	aio->a_expire  = NNI_TIME_NEVER;
	aio->a_timeout = NNG_DURATION_INFINITE;
	aio->a_expire_q =
	    nni_aio_expire_q_list[nni_random() % nni_aio_expire_q_cnt];
}

void
nni_aio_fini(nni_aio *aio)
{
	nni_aio_cancel_fn fn;
	void *            arg;
	nni_aio_expire_q *eq = aio->a_expire_q;

	// This is like aio_close, but we don't want to dispatch
	// the task.  And unlike aio_stop, we don't want to wait
	// for the task.  (Because we implicitly do task_fini.)
	// We also wait if the aio is being expired.
	nni_mtx_lock(&eq->eq_mtx);
	aio->a_stop = true;
	nni_aio_expire_rm(aio);
	while (eq->eq_aio == aio) {
		nni_cv_wait(&eq->eq_cv);
	}
	fn                = aio->a_cancel_fn;
	arg               = aio->a_cancel_arg;
	aio->a_cancel_fn  = NULL;
	aio->a_cancel_arg = NULL;
	nni_mtx_unlock(&eq->eq_mtx);

	if (fn != NULL) {
		fn(aio, arg, NNG_ECLOSED);
	}

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
		nni_reap(&aio_reap_list, aio);
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
		nni_aio_expire_q *eq = aio->a_expire_q;

		nni_mtx_lock(&eq->eq_mtx);
		nni_aio_expire_rm(aio);
		fn                = aio->a_cancel_fn;
		arg               = aio->a_cancel_arg;
		aio->a_cancel_fn  = NULL;
		aio->a_cancel_arg = NULL;
		aio->a_stop       = true;
		nni_mtx_unlock(&eq->eq_mtx);

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
		nni_aio_expire_q *eq = aio->a_expire_q;

		nni_mtx_lock(&eq->eq_mtx);
		nni_aio_expire_rm(aio);
		fn                = aio->a_cancel_fn;
		arg               = aio->a_cancel_arg;
		aio->a_cancel_fn  = NULL;
		aio->a_cancel_arg = NULL;
		aio->a_stop       = true;
		nni_mtx_unlock(&eq->eq_mtx);

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
	// If any of these triggers then the caller has a defect because
	// it means that the aio is already in use.  This is always
	// a bug in the caller.  These checks are not technically thread
	// safe in the event that they are false.  Users of race detectors
	// checks may wish ignore or suppress these checks.
	nni_aio_expire_q *eq = aio->a_expire_q;

	aio_safe_lock(&eq->eq_mtx);

	NNI_ASSERT(!nni_aio_list_active(aio));
	NNI_ASSERT(aio->a_cancel_fn == NULL);
	NNI_ASSERT(!nni_list_node_active(&aio->a_expire_node));

	// Some initialization can be done outside of the lock, because
	// we must have exclusive access to the aio.
	for (unsigned i = 0; i < NNI_NUM_ELEMENTS(aio->a_outputs); i++) {
		aio->a_outputs[i] = NULL;
	}
	aio->a_result    = 0;
	aio->a_count     = 0;
	aio->a_cancel_fn = NULL;

	aio_safe_unlock(&eq->eq_mtx);

	nni_mtx_lock(&eq->eq_mtx);
	// We should not reschedule anything at this point.
	if (aio->a_stop) {
		aio->a_result    = NNG_ECANCELED;
		aio->a_cancel_fn = NULL;
		aio->a_expire    = NNI_TIME_NEVER;
		aio->a_sleep     = false;
		aio->a_expire_ok = false;
		nni_mtx_unlock(&eq->eq_mtx);

		nni_task_dispatch(&aio->a_task);
		return (NNG_ECANCELED);
	}
	nni_task_prep(&aio->a_task);
	nni_mtx_unlock(&eq->eq_mtx);
	return (0);
}

int
nni_aio_schedule(nni_aio *aio, nni_aio_cancel_fn cancel, void *data)
{
	nni_aio_expire_q *eq = aio->a_expire_q;

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

	nni_mtx_lock(&eq->eq_mtx);
	if (aio->a_stop) {
		nni_task_abort(&aio->a_task);
		nni_mtx_unlock(&eq->eq_mtx);
		return (NNG_ECLOSED);
	}

	NNI_ASSERT(aio->a_cancel_fn == NULL);
	aio->a_cancel_fn  = cancel;
	aio->a_cancel_arg = data;

	// We only schedule expiration if we have a way for the expiration
	// handler to actively cancel it.
	if ((aio->a_expire != NNI_TIME_NEVER) && (cancel != NULL)) {
		nni_aio_expire_add(aio);
	}
	nni_mtx_unlock(&eq->eq_mtx);
	return (0);
}

// nni_aio_abort is called by a consumer which guarantees that the aio
// is still valid.
void
nni_aio_abort(nni_aio *aio, int rv)
{
	nni_aio_cancel_fn fn;
	void *            arg;
	nni_aio_expire_q *eq = aio->a_expire_q;

	nni_mtx_lock(&eq->eq_mtx);
	nni_aio_expire_rm(aio);
	fn                = aio->a_cancel_fn;
	arg               = aio->a_cancel_arg;
	aio->a_cancel_fn  = NULL;
	aio->a_cancel_arg = NULL;
	nni_mtx_unlock(&eq->eq_mtx);

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
	nni_aio_expire_q *eq = aio->a_expire_q;

	nni_mtx_lock(&eq->eq_mtx);

	nni_aio_expire_rm(aio);
	aio->a_result     = rv;
	aio->a_count      = count;
	aio->a_cancel_fn  = NULL;
	aio->a_cancel_arg = NULL;
	if (msg) {
		aio->a_msg = msg;
	}

	aio->a_expire = NNI_TIME_NEVER;
	aio->a_sleep  = false;
	nni_mtx_unlock(&eq->eq_mtx);

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
	nni_aio_expire_q *eq = aio->a_expire_q;
	if (eq->eq_len >= eq->eq_cap) {
		nni_aio **new_list =
		    nni_zalloc(eq->eq_cap * 2 * sizeof(nni_aio *));
		for (uint32_t i = 0; i < eq->eq_len; i++) {
			new_list[i] = eq->eq_list[i];
		}
		nni_free(eq->eq_list, eq->eq_cap * sizeof(nni_aio *));
		eq->eq_list = new_list;
		eq->eq_cap *= 2;
	}
	eq->eq_list[eq->eq_len++] = aio;
	if (eq->eq_len == 1) {
		nni_cv_wake(&eq->eq_cv);
	}
}

static void
nni_aio_expire_rm(nni_aio *aio)
{
	uint32_t          aio_idx = 0;
	nni_aio_expire_q *eq      = aio->a_expire_q;
	for (aio_idx = 0; aio_idx < eq->eq_len; aio_idx++) {
		if (aio == eq->eq_list[aio_idx]) {
			eq->eq_list[aio_idx] = eq->eq_list[eq->eq_len - 1];
			eq->eq_len--;
			break;
		}
	}

	if (eq->eq_len < eq->eq_cap / 4 && eq->eq_cap > NNI_EXPIRE_Q_SIZE) {
		nni_aio **new_list =
		    nni_zalloc(eq->eq_cap * sizeof(nni_aio *) / 4);
		for (uint32_t i = 0; i < eq->eq_len; i++) {
			new_list[i] = eq->eq_list[i];
		}
		nni_free(eq->eq_list, eq->eq_cap * sizeof(nni_aio *));
		eq->eq_list = new_list;
		eq->eq_cap /= 2;
	}
}

static void
nni_aio_expire_loop(void *arg)
{
	nni_aio_expire_q *q    = arg;
	nni_aio **        list = q->eq_list;
	nni_mtx *         mtx  = &q->eq_mtx;
	nni_cv *          cv   = &q->eq_cv;
	nni_time          now;
	uint32_t          aio_idx;

	nni_thr_set_name(NULL, "nng:aio:expire");

	now = nni_clock();
	nni_mtx_lock(mtx);

	for (;;) {
		nni_aio *aio;
		int      rv;

		if (q->eq_len == 0) {

			if (q->eq_exit) {
				nni_mtx_unlock(mtx);
				return;
			}

			nni_cv_wait(cv);

			now = nni_clock();
			continue;
		}

		// Find the timer with min expire time.
		list    = q->eq_list;
		aio_idx = 0;
		aio     = list[aio_idx];
		for (uint32_t i = 0; i < q->eq_len; i++) {
			if (list[i]->a_expire < aio->a_expire) {
				aio     = list[i];
				aio_idx = i;
			}
		}
		if (now < aio->a_expire) {
			// Unexpired; we just wait for the next expired aio.
			nni_cv_until(cv, aio->a_expire);
			now = nni_clock();
			continue;
		}

		// The time has come for this aio.  Expire it, canceling any
		// outstanding I/O.
		list[aio_idx] = list[q->eq_len - 1];
		q->eq_len--;
		rv = aio->a_expire_ok ? 0 : NNG_ETIMEDOUT;

		nni_aio_cancel_fn cancel_fn  = aio->a_cancel_fn;
		void *            cancel_arg = aio->a_cancel_arg;

		aio->a_cancel_fn  = NULL;
		aio->a_cancel_arg = NULL;
		// Place a temporary hold on the aio.  This prevents it
		// from being destroyed.
		q->eq_aio = aio;

		// We let the cancel function handle the completion.
		// If there is no cancellation function, then we cannot
		// terminate the aio - we've tried, but it has to run
		// to it's natural conclusion.
		nni_mtx_unlock(mtx);
		cancel_fn(aio, cancel_arg, rv);

		// Get updated time before reacquiring lock.
		now = nni_clock();

		nni_mtx_lock(mtx);

		q->eq_aio = NULL;
		nni_cv_wake(cv);
	}
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
	nni_aio_expire_q *eq = aio->a_expire_q;

	nni_mtx_lock(&eq->eq_mtx);
	if (!aio->a_sleep) {
		nni_mtx_unlock(&eq->eq_mtx);
		return;
	}

	aio->a_sleep = false;
	nni_aio_expire_rm(aio);
	nni_mtx_unlock(&eq->eq_mtx);

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

static void
nni_aio_expire_q_free(nni_aio_expire_q *eq)
{
	if (eq == NULL) {
		return;
	}
	if (!eq->eq_exit) {
		nni_mtx_lock(&eq->eq_mtx);
		eq->eq_exit = true;
		nni_cv_wake(&eq->eq_cv);
		nni_mtx_unlock(&eq->eq_mtx);
	}

	nni_free(eq->eq_list, eq->eq_cap * sizeof(nni_aio *));
	nni_thr_fini(&eq->eq_thr);
	nni_cv_fini(&eq->eq_cv);
	nni_mtx_fini(&eq->eq_mtx);
	NNI_FREE_STRUCT(eq);
}

static nni_aio_expire_q *
nni_aio_expire_q_alloc(void)
{
	nni_aio_expire_q *eq;

	if ((eq = NNI_ALLOC_STRUCT(eq)) == NULL) {
		return (NULL);
	}
	nni_mtx_init(&eq->eq_mtx);
	nni_cv_init(&eq->eq_cv, &eq->eq_mtx);
	eq->eq_cap  = NNI_EXPIRE_Q_SIZE;
	eq->eq_len  = 0;
	eq->eq_list = nni_zalloc(eq->eq_cap * sizeof(nni_aio *));
	eq->eq_exit = false;

	if (nni_thr_init(&eq->eq_thr, nni_aio_expire_loop, eq) != 0) {
		nni_aio_expire_q_free(eq);
		return (NULL);
	}

	nni_thr_run(&eq->eq_thr);
	return (eq);
}

void
nni_aio_sys_fini(void)
{
	for (int i = 0; i < nni_aio_expire_q_cnt; i++) {
		nni_aio_expire_q_free(nni_aio_expire_q_list[i]);
	}
	nni_free(nni_aio_expire_q_list,
	    sizeof(nni_aio_expire_q *) * nni_aio_expire_q_cnt);
	nni_aio_expire_q_cnt  = 0;
	nni_aio_expire_q_list = NULL;
}

int
nni_aio_sys_init(void)
{
	int num_thr;

	// We create a thread per CPU core for expiration by default.
#ifndef NNG_EXPIRE_THREADS
	num_thr = nni_plat_ncpu();
#else
	num_thr = NNG_EXPIRE_THREADS;
#endif
	if (num_thr > 256) {
		num_thr = 256;
	}

	nni_aio_expire_q_list =
	    nni_zalloc(sizeof(nni_aio_expire_q *) * num_thr);
	nni_aio_expire_q_cnt = num_thr;
	for (int i = 0; i < num_thr; i++) {
		nni_aio_expire_q *eq;
		if ((eq = nni_aio_expire_q_alloc()) == NULL) {
			nni_aio_sys_fini();
			return (NNG_ENOMEM);
		}
		nni_aio_expire_q_list[i] = eq;
	}

	return (0);
}
