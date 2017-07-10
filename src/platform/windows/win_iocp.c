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
	int            status;
	BOOL           rv;

	NNI_ARG_UNUSED(arg);

	iocp = nni_win_global_iocp;

	for (;;) {
		key    = 0;
		olpd   = NULL;
		status = 0;
		cnt    = 0;

		rv = GetQueuedCompletionStatus(
		    iocp, &cnt, &key, &olpd, INFINITE);

		if (rv == FALSE) {
			if (olpd == NULL) {
				// Completion port bailed...
				break;
			}
		}

		NNI_ASSERT(olpd != NULL);
		evt = (void *) olpd;

		NNI_ASSERT(evt->cb != NULL);
		evt->cb(evt->ptr);
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
nni_win_event_init(nni_win_event *evt, nni_cb cb, void *ptr, HANDLE h)
{
	ZeroMemory(&evt->olpd, sizeof(evt->olpd));
	evt->olpd.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	if (evt->olpd.hEvent == NULL) {
		return (nni_win_error(GetLastError()));
	}
	nni_aio_list_init(&evt->aios);
	evt->ptr = ptr;
	evt->cb  = cb;
	evt->h   = h;
	return (0);
}

void
nni_win_event_fini(nni_win_event *evt)
{
	if (evt->olpd.hEvent != NULL) {
		(void) CloseHandle(evt->olpd.hEvent);
		evt->olpd.hEvent = NULL;
	}
}

int
nni_win_event_reset(nni_win_event *evt)
{
	if (!ResetEvent(evt->olpd.hEvent)) {
		return (nni_win_error(GetLastError()));
	}
	return (0);
}

OVERLAPPED *
nni_win_event_overlapped(nni_win_event *evt)
{
	return (&evt->olpd);
}

void
nni_win_event_cancel(nni_win_event *evt)
{
	int   rv;
	DWORD cnt;

	// Try to cancel the event...
	if (!CancelIoEx(evt->h, &evt->olpd)) {
		// None was found.  That's good.
		if ((rv = GetLastError()) == ERROR_NOT_FOUND) {
			// Nothing queued.  We may in theory be running
			// the callback via the completion port handler;
			// caller must synchronize that separately.
			return;
		}

		// It's unclear why we would ever fail in this
		// circumstance.  Is there a kind of "uncancellable I/O"
		// here, or somesuch?  In this case we just wait hard
		// using the success case -- its the best we can do.
	}

	// This basically just waits for the canceled I/O to complete.
	// The end result can be either success or ERROR_OPERATION_ABORTED.
	// It turns out we don't much care either way; we just want to make
	// sure that we don't have any I/O pending on the overlapped
	// structure before we release it or reuse it.
	GetOverlappedResult(evt->h, &evt->olpd, &cnt, TRUE);
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
