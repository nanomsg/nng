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

#include <stdio.h>

// Windows IO Completion Port support.  We basically create a single
// IO completion port, then start threads on it.  Handles are added
// to the port on an as needed basis.  We use a single IO completion
// port for pretty much everything.

static int      win_io_nthr = 0;
static HANDLE   win_io_h    = NULL;
static nni_thr *win_io_thrs;

static void
win_io_handler(void *arg)
{
	NNI_ARG_UNUSED(arg);

	for (;;) {
		DWORD       cnt;
		BOOL        ok;
		nni_win_io *item;
		OVERLAPPED *olpd = NULL;
		ULONG_PTR   key  = 0;
		int         rv;

		ok = GetQueuedCompletionStatus(
		    win_io_h, &cnt, &key, &olpd, INFINITE);

		if (olpd == NULL) {
			// Completion port closed...
			NNI_ASSERT(ok == FALSE);
			break;
		}

		item = CONTAINING_RECORD(olpd, nni_win_io, olpd);
		rv   = ok ? 0 : nni_win_error(GetLastError());
		item->cb(item, rv, (size_t) cnt);
	}
}

int
nni_win_io_register(HANDLE h)
{
	if (CreateIoCompletionPort(h, win_io_h, 0, 0) == NULL) {
		return (nni_win_error(GetLastError()));
	}
	return (0);
}

int
nni_win_io_init(nni_win_io *io, nni_win_io_cb cb, void *ptr)
{
	ZeroMemory(&io->olpd, sizeof(io->olpd));

	io->cb          = cb;
	io->ptr         = ptr;
	io->aio         = NULL;
	io->olpd.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
	if (io->olpd.hEvent == NULL) {
		return (nni_win_error(GetLastError()));
	}
	return (0);
}

void
nni_win_io_fini(nni_win_io *io)
{
	if (io->olpd.hEvent != NULL) {
		CloseHandle((HANDLE) io->olpd.hEvent);
	}
}

int
nni_win_io_sysinit(void)
{
	HANDLE h;
	int    i;
	int    rv;
	int    nthr = nni_plat_ncpu() * 2;

	// Limits on the thread count.  This is fairly arbitrary.
	if (nthr < 4) {
		nthr = 4;
	}
	if (nthr > 64) {
		nthr = 64;
	}
	if ((win_io_thrs = NNI_ALLOC_STRUCTS(win_io_thrs, nthr)) == NULL) {
		return (NNG_ENOMEM);
	}
	win_io_nthr = nthr;

	h = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, nthr);
	if (h == NULL) {
		return (nni_win_error(GetLastError()));
	}
	win_io_h = h;

	for (i = 0; i < win_io_nthr; i++) {
		rv = nni_thr_init(&win_io_thrs[i], win_io_handler, NULL);
		if (rv != 0) {
			goto fail;
		}
	}
	for (i = 0; i < win_io_nthr; i++) {
		nni_thr_run(&win_io_thrs[i]);
	}
	return (0);

fail:
	nni_win_io_sysfini();
	return (rv);
}

void
nni_win_io_sysfini(void)
{
	int    i;
	HANDLE h;

	if ((h = win_io_h) != NULL) {
		CloseHandle(h);
		win_io_h = NULL;
	}
	for (i = 0; i < win_io_nthr; i++) {
		nni_thr_fini(&win_io_thrs[i]);
	}

        NNI_FREE_STRUCTS(win_io_thrs, win_io_nthr);
}

#endif // NNG_PLATFORM_WINDOWS
