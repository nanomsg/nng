//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
// Copyright 2017 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

// POSIX threads.

#include "core/nng_impl.h"

#ifdef NNG_PLATFORM_WINDOWS

#include <stdlib.h>

void *
nni_alloc(size_t sz)
{
	return (calloc(sz, 1));
}

void
nni_free(void *b, size_t z)
{
	NNI_ARG_UNUSED(z);
	free(b);
}

void
nni_plat_mtx_init(nni_plat_mtx *mtx)
{
	InitializeSRWLock(&mtx->srl);
	mtx->init = 1;
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

void
nni_plat_cv_init(nni_plat_cv *cv, nni_plat_mtx *mtx)
{
	InitializeConditionVariable(&cv->cv);
	cv->srl = &mtx->srl;
}

void
nni_plat_cv_wake(nni_plat_cv *cv)
{
	WakeAllConditionVariable(&cv->cv);
}

void
nni_plat_cv_wake1(nni_plat_cv *cv)
{
	WakeConditionVariable(&cv->cv);
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
	DWORD    msec;
	BOOL     ok;

	now = nni_plat_clock();
	if (now > until) {
		msec = 0;
	} else {
		msec = (DWORD)(until - now);
	}

	ok = SleepConditionVariableSRW(&cv->cv, cv->srl, msec, 0);
	return (ok ? 0 : NNG_ETIMEDOUT);
}

void
nni_plat_cv_fini(nni_plat_cv *cv)
{
	NNI_ARG_UNUSED(cv);
}

static unsigned int __stdcall nni_plat_thr_main(void *arg)
{
	nni_plat_thr *thr = arg;

	thr->func(thr->arg);
	return (0);
}

int
nni_plat_thr_init(nni_plat_thr *thr, void (*fn)(void *), void *arg)
{
	thr->func = fn;
	thr->arg  = arg;

	// We could probably even go down to 8k... but crypto for some
	// protocols might get bigger than this.  1MB is waaay too big.
	thr->handle = (HANDLE) _beginthreadex(NULL, 16384, nni_plat_thr_main,
	    thr, STACK_SIZE_PARAM_IS_A_RESERVATION, NULL);
	if (thr->handle == NULL) {
		return (NNG_ENOMEM); // Best guess...
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

static LONG plat_inited = 0;

int
nni_plat_init(int (*helper)(void))
{
	int            rv   = 0;
	static SRWLOCK lock = SRWLOCK_INIT;

	if (plat_inited) {
		return (0); // fast path
	}

	AcquireSRWLockExclusive(&lock);

	if (!plat_inited) {
		if (((rv = nni_win_iocp_sysinit()) != 0) ||
		    ((rv = nni_win_ipc_sysinit()) != 0) ||
		    ((rv = nni_win_tcp_sysinit()) != 0) ||
		    ((rv = nni_win_udp_sysinit()) != 0) ||
		    ((rv = nni_win_resolv_sysinit()) != 0)) {
			goto out;
		}

		helper();
		plat_inited = 1;
	}

out:
	ReleaseSRWLockExclusive(&lock);

	return (rv);
}

void
nni_plat_fini(void)
{
	nni_win_resolv_sysfini();
	nni_win_ipc_sysfini();
	nni_win_udp_sysfini();
	nni_win_tcp_sysfini();
	nni_win_iocp_sysfini();
	WSACleanup();
	plat_inited = 0;
}

#endif
