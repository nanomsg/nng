# nng_alloc()

## NAME

nng_alloc --- allocate memory

## SYNOPSIS

```c
#include <nng/nng.h>

void *nng_alloc(size_t size);
```

## DESCRIPTION

The `nng_alloc()` function allocates a contiguous memory region of
at least _size_ bytes.
The memory will be 64-bit aligned.

The returned memory can be used to hold message buffers, in which
case it can be directly passed to [`nng_send()`](../socket/nng_send.md) using
the flag `NNG_FLAG_ALLOC`. Alternatively, it can be freed when no
longer needed using [`nng_free()`](nng_free.md).

> [!IMPORTANT]
> Do not use the system `free()` function (or the C++ `delete` operator) to release this memory.
> On some configurations this may work, but on others it will lead to a crash or
> other unpredictable behavior.

## RETURN VALUES

This function returns a pointer to the allocated memory on success,
and `NULL` otherwise.

## ERRORS

No errors are returned, but if memory cannot be allocated then `NULL`
is returned.

## SEE ALSO

[nng_free()](nng_free.md),
[nng_send()](../socket/nng_send.md)
