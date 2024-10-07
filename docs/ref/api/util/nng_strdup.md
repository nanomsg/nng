# nng_strdup

## NAME

nng_strdup --- duplicate string

## SYNOPSIS

```c
#include <nng/nng.h>

char *nng_strdup(const char *src);
void nng_strfree(char *str);
```

## DESCRIPTION

The {{i:`nng_strdup`}} duplicates the string _src_ and returns it.

This is logically equivalent to using [`nng_alloc`][nng_alloc]
to allocate a region of memory of `strlen(s) + 1` bytes, and then
using `strcpy` to copy the string into the destination before
returning it.

The returned string should be deallocated with
{{i:`nng_strfree`}}, or may be deallocated using the
[`nng_free`][nng_free] using the length of the returned string plus
one (for the `NUL` terminating byte).

> [!IMPORTANT]
> Do not use the system `free` or similar functions to deallocate
> the string, since those may use a different memory arena!

> [!IMPORTANT]
> If a string created with
> `nng_strdup` is modified to be shorter, then it is incorrect to free it with `nng_strfree`.
> (The [`nng_free`][nng_free] function can be used instead in that
> case, using the length of the original string plus one to account for the `NUL` byte, for the size.)

## RETURN VALUES

The `nng_strdup` function returns the new string on success, and `NULL` on failure.

## ERRORS

No errors are returned from `nng_strdup`, but a `NULL` return value should be
treated the same as `NNG_ENOMEM`.

## SEE ALSO

[nng_alloc][nng_alloc]

[nng_alloc]: ../util/nng_alloc.md
[nng_free]: ../util/nng_alloc.md
