# nng_strfree

## NAME

nng_strfree --- free memory

## SYNOPSIS

```c
#include <nng/nng.h>

void nng_strfree(char *str);
```

## DESCRIPTION

The `nng_strfree()` function deallocates the string _str_.
This is equivalent to using [`nng_free()`](nng_free.md) with
the length of _str_ plus one (for the `NUL` terminating byte) as
the size.

> [!IMPORTANT]
> This should only be used with strings that were allocated
> by [`nng_strdup()`](nng_strdup.md) or [`nng_alloc()`](nng_alloc.md).
> In all cases, the allocation size of the string must be the same
> as `strlen(__str__) + 1`.

> [!IMPORTANT]
> Consequently, if the a string created with
> [`nng_strdup()`](nng_strfree.md) is modified to be shorter, then
> it is incorrect to call this function.
> (The [`nng_free()`](nng_Free.md) function can be used instead in that
> case, using the length of the original string plus one for the size.)

## SEE ALSO

[nng_alloc](nng_alloc.md),
[nng_free](nng_free.md),
[nng_strdup](nng_strdup.md)
