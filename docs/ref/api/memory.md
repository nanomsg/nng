# Memory

Managing {{i:memory}} and {{i:allocations}} is something that every C program has to deal with.
In the case of _NNG_, it can be more complicated because the underlying platform
code can provide different allocators that might not be compatible with the use
system allocator used by `malloc` and `free`.

## Allocate Memory

```c
void *nng_alloc(size_t size);
```

The {{i:`nng_alloc`}} function allocates a contiguous memory region of
at least _size_ bytes, and returns a pointer to it.
The memory will be 64-bit aligned.
Note that the memory may have random data in it, just like with `malloc`.

If memory cannot be allocated for any reason, then `NULL` will be returned.
Applications that experience this should treat this like [`NNG_ENOMEM`].

Memory returned by `nng_alloc` can be used to hold message buffers, in which
case it can be directly passed to [`nng_send`] using the flag `NNG_FLAG_ALLOC`.
Alternatively, it can be freed when no longer needed using [`nng_free`].

> [!IMPORTANT]
> Do not use the system `free` function (or the C++ `delete` operator) to release this memory.
> On some configurations this may work, but on others it will lead to a crash or
> other unpredictable behavior.

## Deallocate Memory

```c
void nng_free(void *ptr, size_t size);
```

The {{i:`nng_free`}} function deallocates memory previously allocated by [`nng_alloc`].

The _size_ argument must exactly match the _size_ argument that was supplied to
[`nng_alloc`] when the memory was allocated.

## Duplicate String

```c
char *nng_strdup(const char *src);
```

The {{i:`nng_strdup`}} duplicates the string _src_ and returns it.

This is logically equivalent to using [`nng_alloc`]
to allocate a region of memory of `strlen(s) + 1` bytes, and then
using `strcpy` to copy the string into the destination before
returning it.

The returned string should be deallocated with
[`nng_strfree`], or may be deallocated using the
[`nng_free`] using the length of the returned string plus
one (for the `NUL` terminating byte).

## Free String

```c
void nng_strfree(char *str);
```

The {{i:`nng_strfree`}} function is a convenience function that
can be used to deallocate strings allocated with [`nng_strdup`].

It is effectively the same as `nng_free(strlen(str) + 1)`.

{{#include ../xref.md}}
