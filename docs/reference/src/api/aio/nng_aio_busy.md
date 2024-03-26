# nng_aio_busy

## NAME

nng_aio_busy --- test if asynchronous I/O is busy

## SYNOPSIS

```c
#include <nng/nng.h>

bool nng_aio_busy(nng_aio *aio);
```

## DESCRIPTION

The `nng_aio_busy()` function returns true if the
_aio_ is currently busy performing an asynchronous I/O
operation or is executing a completion callback.

If no operation has been started, or the operation has
been completed or canceled, and any callback has been
executed, then it returns false.

This is the same test used internally by
[`nng_aio_wait()`](nng_aio_wait.md).

> [!IMPORTANT]
> Care should be taken to ensure that the _aio_ object is not
> freed when using this function. The caller is responsible for
> coordinating any use of this with any reuse of the _aio_.

## RETURN VALUES

True if the _aio_ is busy, false otherwise.

## SEE ALSO

[nng_aio_abort](nng_aio_abort.md),
[nng_aio_alloc](nng_aio_alloc.md),
[nng_aio_wait](nng_aio_wait.md)
