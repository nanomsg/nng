//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

// POSIX threads.

#include "core/nng_impl.h"

#ifdef PLATFORM_WINDOWS

void *
nni_alloc(size_t sz)
{
	void *v;

	v = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sz);
	return (v);
}


void
nni_free(void *b, size_t z)
{
	NNI_ARG_UNUSED(z);
	HeapFree(GetProcessHeap(), 0, b);
}


int
nni_plat_mtx_init(nni_plat_mtx *mtx)
{
	InitializeCriticalSection(&mtx->cs);
	mtx->init = 1;
	return (0);
}


void
nni_plat_mtx_fini(nni_plat_mtx *mtx)
{
	if (mtx->init) {
		DeleteCriticalSection(&mtx->cs);
		mtx->init = 0;
	}
}


void
nni_plat_mtx_lock(nni_plat_mtx *mtx)
{
	EnterCriticalSection(&mtx->cs);
}


void
nni_plat_mtx_unlock(nni_plat_mtx *mtx)
{
	LeaveCriticalSection(&mtx->cs);
}


int
nni_plat_cv_init(nni_plat_cv *cv, nni_plat_mtx *mtx)
{
	InitializeConditionVariable(&cv->cv);
	cv->cs = &mtx->cs;
	return (0);
}


void
nni_plat_cv_wake(nni_plat_cv *cv)
{
	WakeAllConditionVariable(&cv->cv);
}


void
nni_plat_cv_wait(nni_plat_cv *cv)
{
	(void) SleepConditionVariableCS(&cv->cv, cv->cs, INFINITE);
}


int
nni_plat_cv_until(nni_plat_cv *cv, nni_time until)
{
	nni_time now;
	DWORD msec;
	BOOL ok;

	now = nni_plat_clock();
	if (now > until) {
		msec = 0;
	} else {
		// times are in usec, but win32 wants millis
		msec = (DWORD) (((until - now) + 999)/1000);
	}

	ok = SleepConditionVariableCS(&cv->cv, cv->cs, msec);
	return (ok ? 0 : NNG_ETIMEDOUT);
}


void
nni_plat_cv_fini(nni_plat_cv *cv)
{
}


static unsigned int __stdcall
nni_plat_thr_main(void *arg)
{
	nni_plat_thr *thr = arg;

	thr->func(thr->arg);
	return (0);
}


int
nni_plat_thr_init(nni_plat_thr *thr, void (*fn)(void *), void *arg)
{
	thr->func = fn;
	thr->arg = arg;

	// We could probably even go down to 8k... but crypto for some
	// protocols might get bigger than this.  1MB is waaay too big.
	thr->handle = (HANDLE) _beginthreadex(NULL, 16384,
		nni_plat_thr_main, thr, STACK_SIZE_PARAM_IS_A_RESERVATION,
		NULL);
	if (thr->handle == NULL) {
		return (NNG_ENOMEM);    // Best guess...
	}
	return (0);
}


void
nni_plat_thr_fini(nni_plat_thr *thr)
{
	if (WaitForSingleObject(thr->handle, INFINITE) == WAIT_FAILED) {
		nni_panic("waiting for thread failed!");
	}
	if (CloseHandle(thr->handle) == 0) {
		nni_panic("close handle for thread failed!");
	}
}


int
nni_plat_init(int (*helper)(void))
{
	LONG old;
	static LONG initing = 0;
	static LONG inited = 0;
	int rv;

	if (inited) {
		return (0);     // fast path
	}

	// This logic gets us to initialize the platform just once.
	// If two threads enter here together, only one will get to run,
	// and the other will be put to sleep briefly so that the first
	// can complete.  This is a poor man's singleton initializer, since
	// we can't statically initialize critical sections.
	while ((old = InterlockedCompareExchange(&initing, 0, 1)) != 0) {
		Sleep(1);
	}
	if (!inited) {
		WSADATA data;
		WORD ver;
		ver = MAKEWORD(2, 2);
		if (WSAStartup(MAKEWORD(2, 2), &data) != 0) {
			if ((LOBYTE(data.wVersion) != 2) ||
			    (HIBYTE(data.wVersion) != 2)) {
				nni_panic("got back wrong winsock ver");
			}
			rv = NNG_EINVAL;
			goto out;
		}
		printf("STARTING...\n");
		if ((rv = nni_win_iocp_sysinit()) != 0) {
			goto out;
		}
		if ((rv = nni_win_resolv_sysinit()) != 0) {
			goto out;
		}
		helper();
		inited = 1;
	}

out:
	InterlockedExchange(&initing, 0);

	return (rv);
}


void
nni_plat_fini(void)
{
	WSACleanup();
	nni_win_resolv_sysfini();
	nni_win_iocp_sysfini();
}


#else

// Suppress empty symbols warnings in ranlib.
int nni_win_thread_not_used = 0;

#endif
