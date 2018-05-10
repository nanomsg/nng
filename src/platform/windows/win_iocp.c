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

#ifdef NNG_PLATFORM_WINDOWS

#define NNI_WIN_IOCP_NTHREADS 4
#include <stdio.h>

// Windows IO Completion Port support.  We basically create a single
// IO completion port, then start threads on it.  Handles are added
// to the port on an as needed basis.  We use a single IO completion
// port for pretty much everything.

static HANDLE  nni_win_global_iocp = NULL;
static nni_thr nni_win_iocp_thrs[NNI_WIN_IOCP_NTHREADS];
static nni_mtx nni_win_iocp_mtx;

static void nni_win_event_start(nni_win_event *);

static void
nni_win_event_finish(nni_win_event *evt)
{
	nni_aio *aio;
	evt->run = 0;

	if ((aio = evt->active) != NULL) {
		evt->active = NULL;
		evt->ops.wev_finish(evt, aio);
	}
	if (evt->fini) {
		nni_cv_wake(&evt->cv);
	}
}

static void
nni_win_iocp_handler(void *arg)
{
	HANDLE         iocp;
	DWORD          cnt;
	ULONG_PTR      key;
	OVERLAPPED *   olpd;
	nni_win_event *evt;
	BOOL           ok;

	NNI_ARG_UNUSED(arg);

	iocp = nni_win_global_iocp;

	for (;;) {
		key  = 0;
		olpd = NULL;

		ok = GetQueuedCompletionStatus(
		    iocp, &cnt, &key, &olpd, INFINITE);

		if (olpd == NULL) {
			// Completion port closed...
			NNI_ASSERT(ok == FALSE);
			break;
		}

		evt = CONTAINING_RECORD(olpd, nni_win_event, olpd);

		nni_mtx_lock(&evt->mtx);

		if (ok) {
			evt->status = 0;
		} else if (evt->status == 0) {
			evt->status = nni_win_error(GetLastError());
		}

		evt->count = cnt;

		nni_win_event_finish(evt);
		nni_win_event_start(evt);
		nni_mtx_unlock(&evt->mtx);
	}
}

static void
nni_win_event_cancel(nni_aio *aio, int rv)
{
	nni_win_event *evt = nni_aio_get_prov_data(aio);

	nni_mtx_lock(&evt->mtx);
	if (aio == evt->active) {
		evt->status = rv;

		// Use provider specific cancellation.
		evt->ops.wev_cancel(evt);
	} else if (nni_aio_list_active(aio)) {
		nni_aio_list_remove(aio);
		nni_aio_finish_error(aio, rv);
	}
	nni_mtx_unlock(&evt->mtx);
}

void
nni_win_event_start(nni_win_event *evt)
{
	nni_aio *aio;

	// Lock held.

	if (evt->run) {
		// Already running.
		return;
	}

	// Abort operation -- no further activity.
	if (evt->fini || evt->closed) {
		while ((aio = nni_list_first(&evt->aios)) != NULL) {
			nni_aio_list_remove(aio);
			nni_aio_finish_error(aio, NNG_ECLOSED);
		}
		return;
	}

	if ((aio = nni_list_first(&evt->aios)) == NULL) {
		return;
	}

	nni_aio_list_remove(aio);
	evt->active = aio;
	evt->status = 0;
	evt->count  = 0;
	if (!ResetEvent(evt->olpd.hEvent)) {
		evt->active = NULL;
		nni_aio_finish_error(aio, nni_win_error(GetLastError()));
		return;
	}

	evt->run = 1;
	if (evt->ops.wev_start(evt, aio) != 0) {
		// Start completed synchronously.  It will have stored
		// the count and status in the evt.
		nni_win_event_finish(evt);
	}
}
void
nni_win_event_resubmit(nni_win_event *evt, nni_aio *aio)
{
	nni_aio_list_prepend(&evt->aios, aio);
}

void
nni_win_event_submit(nni_win_event *evt, nni_aio *aio)
{
	int rv;
	if (nni_aio_begin(aio) != 0) {
		return;
	}
	nni_mtx_lock(&evt->mtx);
	if ((rv = nni_aio_schedule(aio, nni_win_event_cancel, evt)) != 0) {
		nni_mtx_unlock(&evt->mtx);
		nni_aio_finish_error(aio, rv);
		return;
	}
	nni_aio_list_append(&evt->aios, aio);
	nni_win_event_start(evt);
	nni_mtx_unlock(&evt->mtx);
}

void
nni_win_event_complete(nni_win_event *evt, int cnt)
{
	PostQueuedCompletionStatus(nni_win_global_iocp, cnt, 0, &evt->olpd);
}

void
nni_win_event_close(nni_win_event *evt)
{
	nni_aio *aio;

	if (evt->ptr == NULL) {
		return; // Never initialized
	}
	nni_mtx_lock(&evt->mtx);
	evt->closed = 1;
	evt->status = NNG_ECLOSED;
	evt->ops.wev_cancel(evt);
	while ((aio = nni_list_first(&evt->aios)) != NULL) {
		nni_aio_list_remove(aio);
		nni_aio_finish_error(aio, NNG_ECLOSED);
	}
	nni_mtx_unlock(&evt->mtx);
}

int
nni_win_iocp_register(HANDLE h)
{
	if (CreateIoCompletionPort(h, nni_win_global_iocp, 0, 0) == NULL) {
		return (nni_win_error(GetLastError()));
	}
	return (0);
}

int
nni_win_event_init(nni_win_event *evt, nni_win_event_ops *ops, void *ptr)
{
	ZeroMemory(&evt->olpd, sizeof(evt->olpd));
	nni_mtx_init(&evt->mtx);
	nni_cv_init(&evt->cv, &evt->mtx);
	nni_aio_list_init(&evt->aios);
	evt->ops  = *ops;
	evt->ptr  = ptr;
	evt->fini = 0;
	evt->run  = 0;

	evt->olpd.hEvent = CreateEvent(NULL, TRUE, TRUE, NULL);
	if (evt->olpd.hEvent == NULL) {
		return (nni_win_error(GetLastError()));
	}

	return (0);
}

void
nni_win_event_fini(nni_win_event *evt)
{
	nni_aio *aio;

	if (evt->ptr == NULL) {
		return; // Never initialized
	}
	nni_mtx_lock(&evt->mtx);

	evt->fini = 1;

	// Use provider specific cancellation.
	evt->ops.wev_cancel(evt);

	// Wait for everything to stop referencing this.
	while (evt->run) {
		nni_cv_wait(&evt->cv);
	}

	while ((aio = nni_list_first(&evt->aios)) != NULL) {
		nni_aio_list_remove(aio);
		nni_aio_finish_error(aio, NNG_ECLOSED);
	}

	if (evt->olpd.hEvent != NULL) {
		(void) CloseHandle(evt->olpd.hEvent);
		evt->olpd.hEvent = NULL;
	}
	nni_mtx_unlock(&evt->mtx);
	nni_cv_fini(&evt->cv);
	nni_mtx_fini(&evt->mtx);
}

int
nni_win_iocp_sysinit(void)
{
	HANDLE h;
	int    i;
	int    rv;

	h = CreateIoCompletionPort(
	    INVALID_HANDLE_VALUE, NULL, 0, NNI_WIN_IOCP_NTHREADS);
	if (h == NULL) {
		return (nni_win_error(GetLastError()));
	}
	nni_win_global_iocp = h;
	for (i = 0; i < NNI_WIN_IOCP_NTHREADS; i++) {
		rv = nni_thr_init(
		    &nni_win_iocp_thrs[i], nni_win_iocp_handler, NULL);
		if (rv != 0) {
			goto fail;
		}
	}
	nni_mtx_init(&nni_win_iocp_mtx);
	for (i = 0; i < NNI_WIN_IOCP_NTHREADS; i++) {
		nni_thr_run(&nni_win_iocp_thrs[i]);
	}
	return (0);

fail:
	if ((h = nni_win_global_iocp) != NULL) {
		CloseHandle(h);
		nni_win_global_iocp = NULL;
	}
	for (i = 0; i < NNI_WIN_IOCP_NTHREADS; i++) {
		nni_thr_fini(&nni_win_iocp_thrs[i]);
	}
	return (rv);
}

void
nni_win_iocp_sysfini(void)
{
	int    i;
	HANDLE h;

	if ((h = nni_win_global_iocp) != NULL) {
		CloseHandle(h);
		nni_win_global_iocp = NULL;
	}
	for (i = 0; i < NNI_WIN_IOCP_NTHREADS; i++) {
		nni_thr_fini(&nni_win_iocp_thrs[i]);
	}
	nni_mtx_fini(&nni_win_iocp_mtx);
}

#endif // NNG_PLATFORM_WINDOWS
