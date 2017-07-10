//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/nng_impl.h"
#include <string.h>

#define NNI_AIO_WAKE (1 << 0)
#define NNI_AIO_DONE (1 << 1)
#define NNI_AIO_FINI (1 << 2)
#define NNI_AIO_STOP (1 << 3)

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
	nni_taskq_ent_init(&aio->a_tqe, cb, arg);

	return (0);
}

void
nni_aio_fini(nni_aio *aio)
{
	void (*cancelfn)(nni_aio *);

	nni_mtx_lock(&aio->a_lk);
	aio->a_flags |= NNI_AIO_FINI; // this prevents us from being scheduled
	cancelfn = aio->a_prov_cancel;
	nni_cv_wake(&aio->a_cv);
	nni_mtx_unlock(&aio->a_lk);

	// Cancel the AIO if it was scheduled.
	if (cancelfn != NULL) {
		cancelfn(aio);
	}

	// if the task is already dispatched, cancel it (or wait for it to
	// complete).  No further dispatches will happen because of the
	// above logic to set NNI_AIO_FINI.
	nni_taskq_cancel(NULL, &aio->a_tqe);

	// At this point the AIO is done.
	nni_cv_fini(&aio->a_cv);
	nni_mtx_fini(&aio->a_lk);

	if ((aio->a_naddrs != 0) && (aio->a_addrs != NULL)) {
		NNI_FREE_STRUCTS(aio->a_addrs, aio->a_naddrs);
	}
}

int
nni_aio_result(nni_aio *aio)
{
	int rv;

	nni_mtx_lock(&aio->a_lk);
	rv = aio->a_result;
	if (aio->a_flags & (NNI_AIO_FINI | NNI_AIO_STOP)) {
		rv = NNG_ECANCELED;
	}
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
	NNI_ASSERT(aio->a_prov_data == NULL);
	NNI_ASSERT(aio->a_prov_cancel == NULL);

	nni_mtx_lock(&aio->a_lk);
	aio->a_flags &= ~(NNI_AIO_DONE | NNI_AIO_WAKE);
	if (aio->a_flags & (NNI_AIO_FINI | NNI_AIO_STOP)) {
		// We should not reschedule anything at this point.
		nni_mtx_unlock(&aio->a_lk);
		return (NNG_ECANCELED);
	}
	aio->a_result      = 0;
	aio->a_count       = 0;
	aio->a_prov_cancel = cancel;
	aio->a_prov_data   = data;
	nni_mtx_unlock(&aio->a_lk);
	return (0);
}

void
nni_aio_stop(nni_aio *aio)
{
	void (*cancelfn)(nni_aio *);

	nni_mtx_lock(&aio->a_lk);
	aio->a_flags |= NNI_AIO_DONE | NNI_AIO_STOP;
	cancelfn = aio->a_prov_cancel;
	nni_mtx_unlock(&aio->a_lk);

	// This unregisters the AIO from the provider.
	if (cancelfn != NULL) {
		cancelfn(aio);
	}

	nni_mtx_lock(&aio->a_lk);
	aio->a_prov_data   = NULL;
	aio->a_prov_cancel = NULL;
	nni_cv_wake(&aio->a_cv);
	nni_mtx_unlock(&aio->a_lk);

	// This either aborts the task, or waits for it to complete if already
	// dispatched.
	nni_taskq_cancel(NULL, &aio->a_tqe);
}

void
nni_aio_cancel(nni_aio *aio)
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
	aio->a_result = NNG_ECANCELED;
	cancelfn      = aio->a_prov_cancel;
	nni_mtx_unlock(&aio->a_lk);

	// This unregisters the AIO from the provider.
	if (cancelfn != NULL) {
		cancelfn(aio);
	}

	nni_mtx_lock(&aio->a_lk);
	// These should have already been cleared by the cancel function.
	aio->a_prov_data   = NULL;
	aio->a_prov_cancel = NULL;

	if (!(aio->a_flags & (NNI_AIO_FINI | NNI_AIO_STOP))) {
		nni_taskq_dispatch(NULL, &aio->a_tqe);
	}
	nni_mtx_unlock(&aio->a_lk);
}

// I/O provider related functions.

void
nni_aio_finish(nni_aio *aio, int result, size_t count)
{
	nni_mtx_lock(&aio->a_lk);
	if (aio->a_flags & NNI_AIO_DONE) {
		// Operation already done (canceled or timed out?)
		nni_mtx_unlock(&aio->a_lk);
		return;
	}
	aio->a_flags |= NNI_AIO_DONE;
	aio->a_result      = result;
	aio->a_count       = count;
	aio->a_prov_cancel = NULL;
	aio->a_prov_data   = NULL;

	if (!(aio->a_flags & (NNI_AIO_FINI | NNI_AIO_STOP))) {
		nni_taskq_dispatch(NULL, &aio->a_tqe);
	}
	nni_mtx_unlock(&aio->a_lk);
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
