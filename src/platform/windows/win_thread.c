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

int
nni_plat_mtx_init(nni_plat_mtx *mtx)
{
	InitializeCritialSection(&mtx->cs);
	mtx->owner = 0;
	return (0);
}


void
nni_plat_mtx_fini(nni_plat_mtx *mtx)
{
	if (mtx->owner != 0) {
		nni_panic("cannot delete critical section: mutex owned!")
	}
	DeleteCriticalSection(&mtx->cs);
}


void
nni_plat_mtx_lock(nni_plat_mtx *mtx)
{
	EnterCriticalSection(&mtx->cs);
	if (mtx->owner != 0) {
		nni_panic("recursive mutex entry!");
	}
	mtx->owner = GetCurrentThreadId();
}


void
nni_plat_mtx_unlock(nni_plat_mtx *mtx)
{
	if (mtx->owner != GetCurrentThreadId()) {
		nni_panic("cannot unlock mutex: not owner!");
	}
	self->owner = 0;
	LeaveCriticalSection(&mtx->cs);
}


int
nni_plat_mtx_trylock(nni_plat_mtx *mtx)
{
	BOOL ok;

	ok = TryEnterCriticalSection(&mtx->cs);
	if (!ok) {
		return (NNG_EBUSY);
	}
	if (mtx->owner != 0) {
		nni_panic("recursive trymutex entry?!?")
	}
	mtx->owner = GetCurrentThreadId();
	return (0);
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
	int rv;

	if ((rv = pthread_cond_broadcast(&cv->cv)) != 0) {
		nni_panic("pthread_cond_broadcast: %s", strerror(rv));
	}
}


void
nni_plat_cv_wait(nni_plat_cv *cv)
{
	(void) SleepConditionVariable(&cv->cv, &cv->cs, INFINITE);
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
		msec = (until - now)/1000;
	}

	ok = SleepConditionVariable(&cv->cv, &cv->cs, msec);
	return (ok ? 0 : NNG_ETIMEDOUT);
}


void
nni_plat_cv_fini(nni_plat_cv *cv)
{
}


static unsigned int __stdcall
nni_plat_thread_main(void *arg)
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

	thr->handle = (HANDLE) _beginthreadex(NULL, 0,
		nni_plat_thr_main, thr, 0, NULL);
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
	int rv;
	LONG old;
	static LONG initing = 0;
	static LONG inited = 0;

	if (inited) {
		return (0);     // fast path
	}

	// This logic gets us to initialize the platform just once.
	// If two threads enter here together, only one will get to run,
	// and the other will be put to sleep briefly so that the first
	// can complete.  This is a poor man's singleton initializer, since
	// we can't statically initialize critical sections.
	while ((old = InterlockedTestExchange(&initing, 0, 1)) != 0) {
		Sleep(1);
	}
	if (!inited) {
		helper();
		inited = 1;
	}
	InterlockExchange(&initing, 0);

	return (rv);
}


void
nni_plat_fini(void)
{
}


#endif
