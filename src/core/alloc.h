#ifndef CORE_IO_H
#define CORE_IO_H

#include <stddef.h>

int nni_alloc_set(void *(*malloc_fn)(size_t),
    void *(*calloc_fn)(size_t, size_t), void (*free_fn)(void *));

#endif