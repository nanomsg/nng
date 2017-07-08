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
	InitializeSRWLock(&mtx->srl);
	mtx->init = 1;
	return (0);
}


void
nni_plat_mtx_fini(nni_plat_mtx *mtx)
{
	mtx->init = 0;
}


void
nni_plat_mtx_lock(nni_plat_mtx *mtx)
{
	AcquireSRWLockExclusive(&mtx->srl);
}


void
nni_plat_mtx_unlock(nni_plat_mtx *mtx)
{
	ReleaseSRWLockExclusive(&mtx->srl);
}


int
nni_plat_cv_init(nni_plat_cv *cv, nni_plat_mtx *mtx)
{
	InitializeConditionVariable(&cv->cv);
	cv->srl = &mtx->srl;
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
	(void) SleepConditionVariableSRW(&cv->cv, cv->srl, INFINITE, 0);
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

	ok = SleepConditionVariableSRW(&cv->cv, cv->srl, msec, 0);
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
	static LONG inited = 0;
	int rv;
	static SRWLOCK lock = SRWLOCK_INIT;

	if (inited) {
		return (0);     // fast path
	}

	AcquireSRWLockExclusive(&lock);

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
	ReleaseSRWLockExclusive(&lock);

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
