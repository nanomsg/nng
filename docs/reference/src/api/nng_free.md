# nng_free()

## NAME

nng_free --- free memory

## SYNOPSIS

```c
#include <nng/nng.h>

void nng_free(void *ptr, size_t size);
```

## DESCRIPTION

The `nng_free()` function deallocates a memory region of size _size_,
that was previously allocated by [`nng_alloc()`](nng_alloc.md) or
[`nng_recv()`](nng_recv.md) with the `NNG_FLAG_ALLOC` flag.

> [!IMPORTANT]
> It is very important that _size_ match the allocation size
> used to allocate the memory.

> [!IMPORTANT]
> Do not attempt to use this function to deallocate memory
> obtained by a call to the system `malloc()` or `calloc()` functions,
> or the C++ `new` operator.
> Doing so may result in unpredictable
> behavior, including corruption of application memory.

## SEE ALSO

[nng_alloc()](nng_alloc.md),
[nng_recv()](nng_free.md)
