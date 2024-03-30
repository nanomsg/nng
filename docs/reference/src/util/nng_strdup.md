# nng_strdup

## NAME

nng_strdup --- duplicate string

## SYNOPSIS

```c
#include <nng/nng.h>

char *nng_strdup(const char *src);
```

## DESCRIPTION

The `nng_strdup()` duplicates the string _src_ and returns it.

This is logically equivalent to using [`nng_alloc()`][nng_alloc]
to allocate a region of memory of `strlen(s) + 1` bytes, and then
using `strcpy()` to copy the string into the destination before
returning it.

The returned string should be deallocated with
[`nng_strfree()`][nng_strfree], or may be deallocated using the
[`nng_free()`][nng_free] using the length of the returned string plus
one (for the `NUL` terminating byte).

> [!IMPORTANT]
> Do not use the system `free()` or similar functions to deallocate
> the string, since those may use a different memory arena!

## RETURN VALUES

This function returns the new string on success, and `NULL` on failure.

## ERRORS

No errors are returned, but a `NULL` return value should be
treated the same as `NNG_ENOMEM`.

## SEE ALSO

[nng_alloc.md][nng_alloc],
[nng_free.md][nng_free],
[nng_strfree.md][nng_strfree]

{{#include ../refs.md}}
