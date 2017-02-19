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

#define NNI_IOEV_DONE		(1<<0)
#define NNI_IOEV_BUSY		(1<<1)
#define NNI_IOEV_CANCEL		(1<<2)
#define NNI_IOEV_WAKE		(1<<3)

void
nni_ioev_init(nni_ioev *ioev, nni_cb cb, void *arg)
{
	if (cb == NULL) {
		cb = (nni_cb) nni_ioev_wake;
		arg = ioev;
	}
	memset(ioev, 0, sizeof (*ioev));
	nni_mtx_init(&ioev->ie_lk);
	nni_cv_init(&ioev->ie_cv, &ioev->ie_lk);
	ioev->ie_cb = cb;
	ioev->ie_cbarg = arg;
}


void
nni_ioev_fini(nni_ioev *ioev)
{
	nni_cv_fini(&ioev->ie_cv);
	nni_mtx_fini(&ioev->ie_lk);
}


void
nni_ioev_cancel(nni_ioev *ioev)
{
	nni_cb cb;
	void *arg;

	nni_mtx_lock(&ioev->ie_lk);
	while ((ioev->ie_flags & NNI_IOEV_BUSY) != 0) {
		nni_cv_wait(&ioev->ie_cv);
	}
	if ((ioev->ie_flags & NNI_IOEV_DONE) != 0) {
		// Already finished the IO.
		nni_mtx_unlock(&ioev->ie_lk);
		return;
	}
	ioev->ie_flags |= NNI_IOEV_CANCEL;
	nni_mtx_unlock(&ioev->ie_lk);

	// Do not hold the lock across the provider!  The provider
	// must not run on this because we have set the cancel flag,
	// therefore "nni_ioev_start" will return failure.  The provider
	// is responsible for dealing with any linked list issues or such,
	// and freeing any provider data at this point.
	ioev->ie_prov_ops.ip_cancel(ioev->ie_prov_data);

	nni_mtx_lock(&ioev->ie_lk);
	ioev->ie_result = NNG_ECANCELED;
	cb = ioev->ie_cb;
	arg = ioev->ie_cbarg;
	nni_mtx_unlock(&ioev->ie_lk);

	// Call the callback.  If none was registered, this will instead
	// raise the done signal and wake anything blocked in nni_ioev_wait.
	// (Because cb will be nni_ioev_wake, and arg will be the ioev itself.)
	cb(arg);
}


int
nni_ioev_result(nni_ioev *ioev)
{
	return (ioev->ie_result);
}


size_t
nni_ioev_count(nni_ioev *ioev)
{
	return (ioev->ie_count);
}


void
nni_ioev_wake(nni_ioev *ioev)
{
	nni_mtx_lock(&ioev->ie_lk);
	ioev->ie_flags |= NNI_IOEV_WAKE;
	nni_cv_wake(&ioev->ie_cv);
	nni_mtx_unlock(&ioev->ie_lk);
}


void
nni_ioev_wait(nni_ioev *ioev)
{
	nni_mtx_lock(&ioev->ie_lk);
	while ((ioev->ie_flags & NNI_IOEV_WAKE) == 0) {
		nni_cv_wait(&ioev->ie_cv);
	}
	nni_mtx_unlock(&ioev->ie_lk);
}


// I/O provider related functions.
void
nni_ioev_set_ops(nni_ioev *ioev, nni_ioev_ops *ops, void *data)
{
	memcpy(&ioev->ie_prov_ops, ops, sizeof (*ops));
	ioev->ie_prov_data = data;
}


// nni_ioev_busy effectively "locks" the IOEV.  We'd like to use the
// underlying mutex, and that would be faster, but the completion might
// be executed by a thread other than the one that marked it busy, so we
// use our own flags.
int
nni_ioev_busy(nni_ioev *ioev)
{
	nni_mtx_lock(&ioev->ie_lk);
	if ((ioev->ie_flags & NNI_IOEV_CANCEL) != 0) {
		nni_mtx_unlock(&ioev->ie_lk);
		return (NNG_ECANCELED);
	}

	ioev->ie_flags |= NNI_IOEV_BUSY;
	nni_mtx_unlock(&ioev->ie_lk);
	return (0);
}


void
nni_ioev_unbusy(nni_ioev *ioev)
{
	nni_mtx_lock(&ioev->ie_lk);
	ioev->ie_flags &= ~(NNI_IOEV_BUSY);
	nni_cv_wake(&ioev->ie_cv);
	nni_mtx_unlock(&ioev->ie_lk);
}


void
nni_ioev_finish(nni_ioev *ioev, int result, size_t count)
{
	nni_cb cb;
	void *arg;

	nni_mtx_lock(&ioev->ie_lk);
	ioev->ie_result = result;
	ioev->ie_count = count;
	ioev->ie_flags &= ~(NNI_IOEV_BUSY);
	ioev->ie_flags |= NNI_IOEV_DONE;
	cb = ioev->ie_cb;
	arg = ioev->ie_cbarg;
	nni_cv_wake(&ioev->ie_cv);
	nni_mtx_unlock(&ioev->ie_lk);

	cb(arg);
}
