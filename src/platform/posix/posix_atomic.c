//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
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
#endif

#endif // NNG_PLATFORM_POSIX
