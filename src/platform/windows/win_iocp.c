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

#define NNI_WIN_IOCP_NTHREADS    4
#include <stdio.h>

// Windows IO Completion Port support.  We basically creaet a single
// IO completion port, then start threads on it.  Handles are added
// to the port on an as needed basis.  We use a single IO completion
// port for pretty much everything.

static HANDLE nni_win_global_iocp = NULL;
static nni_win_event nni_win_iocp_exit;
static nni_thr nni_win_iocp_thrs[NNI_WIN_IOCP_NTHREADS];

static void
nni_win_iocp_handler(void *arg)
{
	HANDLE iocp;
	DWORD nbytes;
	ULONG_PTR key;
	OVERLAPPED *olpd;
	nni_win_event *evt;
	int status;
	BOOL rv;

	NNI_ARG_UNUSED(arg);

	iocp = nni_win_global_iocp;

	for (;;) {
		key = 0;
		olpd = NULL;
		status = 0;
		rv = GetQueuedCompletionStatus(iocp, &nbytes, &key, &olpd,
			INFINITE);

		if (rv == FALSE) {
			if (olpd == NULL) {
				// Completion port bailed...
				break;
			}
			nbytes = 0;
			key = 0;
			status = nni_win_error(GetLastError());
		}

		NNI_ASSERT(olpd != NULL);
		evt = (void *) olpd;
		if (evt == &nni_win_iocp_exit) {
			// Exit requested.
			break;
		}

		NNI_ASSERT(evt->cb != NULL);
		evt->nbytes = nbytes;
		evt->status = status;
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
nni_win_iocp_sysinit(void)
{
	HANDLE h;
	int i;
	int rv;

	ZeroMemory(&nni_win_iocp_exit, sizeof (nni_win_iocp_exit));
	h = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0,
		NNI_WIN_IOCP_NTHREADS);
	if (h == NULL) {
		return (nni_win_error(GetLastError()));
	}
	nni_win_global_iocp = h;
	for (i = 0; i < NNI_WIN_IOCP_NTHREADS; i++) {
		rv = nni_thr_init(&nni_win_iocp_thrs[i], nni_win_iocp_handler,
			NULL);
		if (rv != 0) {
			goto fail;
		}
	}
	for (i = 0; i < NNI_WIN_IOCP_NTHREADS; i++) {
		nni_thr_run(&nni_win_iocp_thrs[i]);
	}
	return (0);

fail:
	if ((h = nni_win_global_iocp) != NULL) {
		PostQueuedCompletionStatus(h, 0, 0, &nni_win_iocp_exit.olpd);
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
	int i;
	HANDLE h;

	if ((h = nni_win_global_iocp) != NULL) {
		// Signal the iocp poller to exit.
		PostQueuedCompletionStatus(h, 0, 0, &nni_win_iocp_exit.olpd);
		CloseHandle(h);
		nni_win_global_iocp = NULL;
		for (i = 0; i < NNI_WIN_IOCP_NTHREADS; i++) {
			nni_thr_fini(&nni_win_iocp_thrs[i]);
		}
	}
}


#else

// Suppress empty symbols warnings in ranlib.
int nni_win_iocp_not_used = 0;

#endif // PLATFORM_WINDOWS
