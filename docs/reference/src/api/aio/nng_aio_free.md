# nng_aio_free

## NAME

nng_aio_free --- free asynchronous I/O handle

## SYNOPSIS

```c
#include <nng/nng.h>

void nng_aio_free(nng_aio *aio);
void nng_aio_reap(nng_aio *aio);
```

## DESCRIPTION

The `nng_aio_free()` function frees an allocated asynchronous I/O handle.
If any operation is in progress, the operation is canceled, and the
caller is blocked until the operation is completely canceled, to ensure
that it is safe to deallocate the handle and any associated resources.
(This is done by implicitly calling [`nng_aio_stop()`](nng_aio_stop.md).)

The `nng_aio_reap()` function is the same as `nng_aio_free()`, but does
its work in a background thread.
This can be useful to discard the _aio_ object from within the callback for the _aio_.

> [!IMPORTANT]
> Once either of these functions are called, the _aio_ object is invalid and must not be used again.

## SEE ALSO

[nng_aio_alloc](nng_aio_alloc.md),
[nng_aio_stop](nng_aio_stop.md)
