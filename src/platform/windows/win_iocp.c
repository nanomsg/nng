//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/nng_impl.h"

#ifdef PLATFORM_WINDOWS

#define NNI_WIN_IOCP_NTHREADS 4
#include <stdio.h>

// Windows IO Completion Port support.  We basically creaet a single
// IO completion port, then start threads on it.  Handles are added
// to the port on an as needed basis.  We use a single IO completion
// port for pretty much everything.

static HANDLE  nni_win_global_iocp = NULL;
static nni_thr nni_win_iocp_thrs[NNI_WIN_IOCP_NTHREADS];
static nni_mtx nni_win_iocp_mtx;

static void
nni_win_iocp_handler(void *arg)
{
	HANDLE         iocp;
	DWORD          cnt;
	ULONG_PTR      key;
	OVERLAPPED *   olpd;
	nni_win_event *evt;
	int            rv;
	BOOL           ok;
	nni_aio *      aio;

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
			rv = ERROR_SUCCESS;
		} else {
			rv = GetLastError();
		}

		aio         = evt->aio;
		evt->aio    = NULL;
		evt->status = rv;
		evt->count  = cnt;

		// Aborted operations don't get the finish callback done.
		// All others do.
		evt->flags &= ~NNI_WIN_EVENT_RUNNING;
		if (evt->flags & NNI_WIN_EVENT_ABORT) {
			nni_cv_wake(&evt->cv);
		} else if ((rv != ERROR_OPERATION_ABORTED) && (aio != NULL)) {
			evt->ops.wev_finish(evt, aio);
		}
		nni_mtx_unlock(&evt->mtx);
	}
}

static void
nni_win_event_cancel(nni_aio *aio)
{
	nni_win_event *evt = aio->a_prov_data;

	nni_mtx_lock(&evt->mtx);
	evt->flags |= NNI_WIN_EVENT_ABORT;
	evt->aio = NULL;

	// Use provider specific cancellation.
	evt->ops.wev_cancel(evt);

	// Wait for everything to stop referencing this.
	while (evt->flags & NNI_WIN_EVENT_RUNNING) {
		nni_cv_wait(&evt->cv);
	}
	nni_mtx_unlock(&evt->mtx);
}

void
nni_win_event_resubmit(nni_win_event *evt, nni_aio *aio)
{
	// This is just continuation of a pre-existing AIO operation.
	// For example, continuing I/O of a multi-buffer s/g operation.
	// The lock is held.

	// Abort operation -- no further activity.
	if (evt->flags & NNI_WIN_EVENT_ABORT) {
		return;
	}

	evt->status = ERROR_SUCCESS;
	evt->count  = 0;
	if (!ResetEvent(evt->olpd.hEvent)) {
		evt->status = GetLastError();
		evt->count  = 0;

		evt->ops.wev_finish(evt, aio);
		return;
	}

	evt->aio = aio;
	evt->flags |= NNI_WIN_EVENT_RUNNING;
	if (evt->ops.wev_start(evt, aio) != 0) {
		// Start completed synchronously.  It will have stored
		// the count and status in the evt.
		evt->flags &= ~NNI_WIN_EVENT_RUNNING;
		evt->aio = NULL;
		evt->ops.wev_finish(evt, aio);
	}
}

void
nni_win_event_submit(nni_win_event *evt, nni_aio *aio)
{
	nni_mtx_lock(&evt->mtx);
	if (nni_aio_start(aio, nni_win_event_cancel, evt) != 0) {
		// the aio was aborted
		nni_mtx_unlock(&evt->mtx);
		return;
	}
	nni_win_event_resubmit(evt, aio);
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

	if (evt->ptr != NULL) {
		nni_mtx_lock(&evt->mtx);
		evt->flags |= NNI_WIN_EVENT_ABORT;
		evt->ops.wev_cancel(evt);
		if ((aio = evt->aio) != NULL) {
			evt->aio = NULL;
			// We really don't care if we transferred data or not.
			// The caller indicates they have closed the pipe.
			evt->status = ERROR_INVALID_HANDLE;
			evt->count  = 0;
			evt->ops.wev_finish(evt, aio);
		}
		nni_mtx_unlock(&evt->mtx);
	}
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
	int rv;

	ZeroMemory(&evt->olpd, sizeof(evt->olpd));
	evt->olpd.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	if (evt->olpd.hEvent == NULL) {
		return (nni_win_error(GetLastError()));
	}
	if (((rv = nni_mtx_init(&evt->mtx)) != 0) ||
	    ((rv = nni_cv_init(&evt->cv, &evt->mtx)) != 0)) {
		return (rv); // NB: This will never happen on Windows.
	}
	evt->ops = *ops;
	evt->aio = NULL;
	evt->ptr = ptr;
	return (0);
}

void
nni_win_event_fini(nni_win_event *evt)
{
	nni_aio *aio;

	if (evt->ptr != NULL) {
		nni_mtx_lock(&evt->mtx);
		if ((aio = evt->aio) != NULL) {
			evt->flags |= NNI_WIN_EVENT_ABORT;
			evt->aio = NULL;

			// Use provider specific cancellation.
			evt->ops.wev_cancel(evt);

			// Wait for everything to stop referencing this.
			while (evt->flags & NNI_WIN_EVENT_RUNNING) {
				nni_cv_wait(&evt->cv);
			}
		}
		nni_mtx_unlock(&evt->mtx);
	}

	if (evt->olpd.hEvent != NULL) {
		(void) CloseHandle(evt->olpd.hEvent);
		evt->olpd.hEvent = NULL;
	}
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
	if ((rv = nni_mtx_init(&nni_win_iocp_mtx)) != 0) {
		goto fail;
	}
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

#else

// Suppress empty symbols warnings in ranlib.
int nni_win_iocp_not_used = 0;

#endif // PLATFORM_WINDOWS
