#include "alloc.h"
#include "defs.h"
#include <stdlib.h>

void *(*nni_malloc_fn)(size_t) = malloc;

void *(*nni_calloc_fn)(size_t, size_t) = calloc;

static void
nni_std_free(void *ptr, size_t z)
{
	NNI_ARG_UNUSED(z);
	free(ptr);
}

void (*nni_free_fn)(void *, size_t) = nni_std_free;

int
nni_alloc_set(void *(*malloc_fn)(size_t), void *(*calloc_fn)(size_t, size_t),
    void (*free_fn)(void *, size_t))
{
	if (malloc_fn && calloc_fn && free_fn) {
		nni_malloc_fn = malloc_fn;
		nni_calloc_fn = calloc_fn;
		nni_free_fn   = free_fn;
		return 0;
	}

	return NNG_EINVAL;
}