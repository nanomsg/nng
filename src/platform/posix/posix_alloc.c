//
// Copyright 2016 Garrett D'Amore <garrett@damore.org>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/nng_impl.h"

#ifdef NNG_PLATFORM_POSIX

#include <stdlib.h>

// POSIX memory allocation.  This is pretty much standard C.
void *
nni_alloc(size_t sz)
{
	return (sz > 0 ? nni_malloc_fn(sz) : NULL);
}

void *
nni_zalloc(size_t sz)
{
	return (sz > 0 ? nni_calloc_fn(1, sz) : NULL);
}

void
nni_free(void *ptr, size_t size)
{
	NNI_ARG_UNUSED(size);
	nni_free_fn(ptr);
}

#endif // NNG_PLATFORM_POSIX
