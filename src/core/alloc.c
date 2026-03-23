#include "alloc.h"
#include "defs.h"
#include <stdlib.h>

void* (*nni_malloc_fn)(size_t) = malloc;

void* (*nni_calloc_fn)(size_t, size_t) = calloc;

void (*nni_free_fn)(void*) = free;

int nni_alloc_set(void* malloc_fn(size_t), void* calloc_fn(size_t, size_t), void free_fn(void*))
{
    if (malloc_fn && calloc_fn && free_fn) {
        nni_malloc_fn = malloc_fn;
        nni_calloc_fn = calloc_fn;
        nni_free_fn = free_fn;
        return 0;
    }

    return NNG_EINVAL;
}