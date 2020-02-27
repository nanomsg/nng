//
// Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

// Windows threads.

#include "core/nng_impl.h"

#ifdef NNG_PLATFORM_WINDOWS

// mingw does not define InterlockedAddNoFence64, use the mingw equivalent
#if defined(__MINGW32__) || defined(__MINGW64__)
#define InterlockedAddNoFence(a, b) \
	__atomic_add_fetch(a, b, __ATOMIC_RELAXED)
#define InterlockedAddNoFence64(a, b) \
	__atomic_add_fetch(a, b, __ATOMIC_RELAXED)
#define InterlockedIncrementAcquire64(a) \
	__atomic_add_fetch(a, 1, __ATOMIC_ACQUIRE)
#define InterlockedDecrementRelease64(a) \
	__atomic_fetch_sub(a, 1, __ATOMIC_RELEASE)
#endif

#include <stdlib.h>

void *
nni_alloc(size_t sz)
{
	return (sz > 0 ? malloc(sz) : NULL);
}

void *
nni_zalloc(size_t sz)
{
	return (sz > 0 ? calloc(1, sz) : NULL);
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

bool
nni_atomic_flag_test_and_set(nni_atomic_flag *f)
{
	return (InterlockedExchange(&f->f, 1) != 0);
}

void
nni_atomic_flag_reset(nni_atomic_flag *f)
{
	InterlockedExchange(&f->f, 0);
}

void
nni_atomic_set_bool(nni_atomic_bool *v, bool b)
{
	InterlockedExchange(&v->v, (LONG) b);
}

bool
nni_atomic_get_bool(nni_atomic_bool *v)
{
	return ((bool) InterlockedAdd(&v->v, 0));
}

bool
nni_atomic_swap_bool(nni_atomic_bool *v, bool b)
{
	return ((bool) InterlockedExchange(&v->v, (LONG) b));
}

void
nni_atomic_init_bool(nni_atomic_bool *v)
{
	InterlockedExchange(&v->v, 0);
}

void
nni_atomic_add64(nni_atomic_u64 *v, uint64_t bump)
{
	InterlockedAddNoFence64(&v->v, (LONGLONG) bump);
}

void
nni_atomic_sub64(nni_atomic_u64 *v, uint64_t bump)
{
	// Windows lacks a sub, so we add the negative.
	InterlockedAddNoFence64(&v->v, (0ll - (LONGLONG) bump));
}

uint64_t
nni_atomic_get64(nni_atomic_u64 *v)
{

	return ((uint64_t)(InterlockedExchangeAdd64(&v->v, 0)));
}

void
nni_atomic_set64(nni_atomic_u64 *v, uint64_t u)
{
	(void) InterlockedExchange64(&v->v, (LONGLONG) u);
}

uint64_t
nni_atomic_swap64(nni_atomic_u64 *v, uint64_t u)
{
	return ((uint64_t)(InterlockedExchange64(&v->v, (LONGLONG) u)));
}

void
nni_atomic_init64(nni_atomic_u64 *v)
{
	InterlockedExchange64(&v->v, 0);
}

void
nni_atomic_inc64(nni_atomic_u64 *v)
{
#ifdef _WIN64
	(void) InterlockedIncrementAcquire64(&v->v);
#else
	(void) InterlockedIncrement64(&v->v);
#endif
}

uint64_t
nni_atomic_dec64_nv(nni_atomic_u64 *v)
{
#ifdef _WIN64
	return ((uint64_t)(InterlockedDecrementRelease64(&v->v)));
#else
	return ((uint64_t)(InterlockedDecrement64(&v->v)));
#endif
}

bool
nni_atomic_cas64(nni_atomic_u64 *v, uint64_t comp, uint64_t new)
{
	uint64_t old;
	old = InterlockedCompareExchange64(&v->v, (LONG64)new, (LONG64)comp);
	return (old == comp);
}


void
nni_atomic_add(nni_atomic_int *v, int bump)
{
	InterlockedAddNoFence(&v->v, (LONG) bump);
}

void
nni_atomic_sub(nni_atomic_int *v, int bump)
{
	// Windows lacks a sub, so we add the negative.
	InterlockedAddNoFence(&v->v, (LONG) -bump);
}

int
nni_atomic_get(nni_atomic_int *v)
{

	return (InterlockedExchangeAdd(&v->v, 0));
}

void
nni_atomic_set(nni_atomic_int *v, int i)
{
	(void) InterlockedExchange(&v->v, (LONG) i);
}

int
nni_atomic_swap(nni_atomic_int *v, int i)
{
	return (InterlockedExchange(&v->v, (LONG) i));
}

void
nni_atomic_init(nni_atomic_int *v)
{
	InterlockedExchange(&v->v, 0);
}

void
nni_atomic_inc(nni_atomic_int *v)
{
	(void) InterlockedIncrementAcquire(&v->v);
}

int
nni_atomic_dec_nv(nni_atomic_int *v)
{
	return (InterlockedDecrementRelease(&v->v));
}

bool
nni_atomic_cas(nni_atomic_int *v, int comp, int new)
{
	int old;
	old = InterlockedCompareExchange(&v->v, (LONG)new, (LONG)comp);
	return (old == comp);
}


static unsigned int __stdcall nni_plat_thr_main(void *arg)
{
	nni_plat_thr *thr = arg;

	thr->id = GetCurrentThreadId();
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

bool
nni_plat_thr_is_self(nni_plat_thr *thr)
{
	return (GetCurrentThreadId() == thr->id);
}

static LONG plat_inited = 0;

int
nni_plat_ncpu(void)
{
	SYSTEM_INFO info;

	GetSystemInfo(&info);
	return ((int) (info.dwNumberOfProcessors));
}

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
		if (((rv = nni_win_io_sysinit()) != 0) ||
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
	nni_win_io_sysfini();
	WSACleanup();
	plat_inited = 0;
}

#endif
