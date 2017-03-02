//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <string.h>
#include "core/nng_impl.h"

#define NNI_AIO_WAKE    (1<<0)

void
nni_aio_init(nni_aio *aio, nni_cb cb, void *arg)
{
	if (cb == NULL) {
		cb = (nni_cb) nni_aio_wake;
		arg = aio;
	}
	memset(aio, 0, sizeof (*aio));
	nni_mtx_init(&aio->a_lk);
	nni_cv_init(&aio->a_cv, &aio->a_lk);
	aio->a_cb = cb;
	aio->a_cbarg = arg;
	nni_taskq_ent_init(&aio->a_tqe, cb, arg);
}


void
nni_aio_fini(nni_aio *aio)
{
	nni_cv_fini(&aio->a_cv);
	nni_mtx_fini(&aio->a_lk);
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
	while ((aio->a_flags & NNI_AIO_WAKE) == 0) {
		nni_cv_wait(&aio->a_cv);
	}
	nni_mtx_unlock(&aio->a_lk);
}


// I/O provider related functions.

void
nni_aio_finish(nni_aio *aio, int result, size_t count)
{
	nni_cb cb;
	void *arg;

	nni_mtx_lock(&aio->a_lk);
	aio->a_result = result;
	aio->a_count = count;
	cb = aio->a_cb;
	arg = aio->a_cbarg;
	nni_cv_wake(&aio->a_cv);
	nni_mtx_unlock(&aio->a_lk);

	nni_taskq_dispatch(NULL, &aio->a_tqe);
}
