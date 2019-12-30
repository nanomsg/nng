//
// Copyright 2019 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

// POSIX atomics.

#include "core/nng_impl.h"

#ifdef NNG_PLATFORM_POSIX

#ifdef NNG_HAVE_STDATOMIC

#include <stdatomic.h>
bool
nni_atomic_flag_test_and_set(nni_atomic_flag *f)
{
	return (atomic_flag_test_and_set(&f->f));
}

void
nni_atomic_flag_reset(nni_atomic_flag *f)
{
	atomic_flag_clear(&f->f);
}

void
nni_atomic_set_bool(nni_atomic_bool *v, bool b)
{
	atomic_store(&v->v, b);
}

bool
nni_atomic_get_bool(nni_atomic_bool *v)
{
	return (atomic_load(&v->v));
}

bool
nni_atomic_swap_bool(nni_atomic_bool *v, bool b)
{
	return (atomic_exchange(&v->v, b));

}

void
nni_atomic_init_bool(nni_atomic_bool *v)
{
	atomic_init(&v->v, false);
}

void
nni_atomic_add64(nni_atomic_u64 *v, uint64_t bump)
{
	(void) atomic_fetch_add_explicit(
	    &v->v, (uint_fast64_t) bump, memory_order_relaxed);
}

void
nni_atomic_sub64(nni_atomic_u64 *v, uint64_t bump)
{
	(void) atomic_fetch_sub_explicit(
	    &v->v, (uint_fast64_t) bump, memory_order_relaxed);
}

uint64_t
nni_atomic_get64(nni_atomic_u64 *v)
{
	return ((uint64_t) atomic_load(&v->v));
}

void
nni_atomic_set64(nni_atomic_u64 *v, uint64_t u)
{
	atomic_store(&v->v, (uint_fast64_t) u);
}

uint64_t
nni_atomic_swap64(nni_atomic_u64 *v, uint64_t u)
{
	return ((uint64_t) atomic_exchange(&v->v, (uint_fast64_t) u));
}

void
nni_atomic_init64(nni_atomic_u64 *v)
{
	atomic_init(&v->v, 0);
}

void
nni_atomic_inc64(nni_atomic_u64 *v)
{
	atomic_fetch_add(&v->v, 1);
}

uint64_t
nni_atomic_dec64_nv(nni_atomic_u64 *v)
{
	uint64_t ov;

	// C11 atomics give the old rather than new value.
	ov = (uint64_t) atomic_fetch_sub(&v->v, 1);
	return (ov - 1);
}

#else

#include <pthread.h>

static pthread_mutex_t plat_atomic_lock = PTHREAD_MUTEX_INITIALIZER;

bool
nni_atomic_flag_test_and_set(nni_atomic_flag *f)
{
	bool v;
	pthread_mutex_lock(&plat_atomic_lock);
	v    = f->f;
	f->f = true;
	pthread_mutex_unlock(&plat_atomic_lock);
	return (v);
}

void
nni_atomic_flag_reset(nni_atomic_flag *f)
{
	pthread_mutex_lock(&plat_atomic_lock);
	f->f = false;
	pthread_mutex_unlock(&plat_atomic_lock);
}

void
nni_atomic_set_bool(nni_atomic_bool *b)
{
	pthread_mutex_lock(&plat_atomic_lock);
	b->b = false;
	pthread_mutex_unlock(&plat_atomic_lock);
}

void
nni_atomic_get_bool(nni_atomic_bool *b)
{
	bool v;
	pthread_mutex_lock(&plat_atomic_lock);
	v = b->b;
	pthread_mutex_unlock(&plat_atomic_lock);
	return (v);
}

void
nni_atomic_swap_bool(nni_atomic_bool *b, bool n)
{
	bool v;
	pthread_mutex_lock(&plat_atomic_lock);
	v = b->b;
	b->b = n;
	pthread_mutex_unlock(&plat_atomic_lock);
	return (v);
}

void
nni_atomic_initbool(nni_atomic_bool *b)
{
	b->b = false;
}

void
nni_atomic_add64(nni_atomic_u64 *v, uint64_t bump)
{
	pthread_mutex_lock(&plat_atomic_lock);
	v->v += bump;
	pthread_mutex_unlock(&plat_atomic_lock);
}

void
nni_atomic_sub64(nni_atomic_u64 *v, uint64_t bump)
{
	pthread_mutex_lock(&plat_atomic_lock);
	v->v -= bump;
	pthread_mutex_unlock(&plat_atomic_lock);
}

uint64_t
nni_atomic_get64(nni_atomic_u64 *v)
{
	uint64_t rv;
	pthread_mutex_lock(&plat_atomic_lock);
	rv = v->v;
	pthread_mutex_unlock(&plat_atomic_lock);
	return (rv);
}

void
nni_atomic_set64(nni_atomic_u64 *v, uint64_t u)
{
	pthread_mutex_lock(&plat_atomic_lock);
	v->v = u;
	pthread_mutex_unlock(&plat_atomic_lock);
}

uint64_t
nni_atomic_swap64(nni_atomic_u64 *v, uint64_t u)
{
	uint64_t rv;
	pthread_mutex_lock(&plat_atomic_lock);
	rv   = v->v;
	v->v = u;
	pthread_mutex_unlock(&plat_atomic_lock);
	return (rv);
}

void
nni_atomic_init64(nni_atomic_u64 *v)
{
	v->v = 0;
}

void
nni_atomic_inc64(nni_atomic_u64 *v)
{
	pthread_mutex_lock(&plat_atomic_lock);
	v->v++;
	pthread_mutex_unlock(&plat_atomic_lock);
}

uint64_t
nni_atomic_dec64_nv(nni_atomic_u64 *v)
{
	uint64_t nv;
	pthread_mutex_lock(&plat_atomic_lock);
	v->v--;
	nv = v->v;
	pthread_mutex_unlock(&plat_atomic_lock);
	return (nv);
}

#endif

#endif // NNG_PLATFORM_POSIX
