# nng_aio_wait()

## NAME

nng_aio_wait --- wait for asynchronous I/O operation

## SYNOPSIS

```c
#include <nng/nng.h>

void nng_aio_wait(nng_aio *aio);
```

## DESCRIPTION

The `nng_aio_wait()` function waits for an asynchronous I/O operation
to complete.
If the operation has not been started, or has already
completed, then it returns immediately.

If a callback was set with _aio_ when it was allocated, then this
function will not be called until the callback has completed.

> [!IMPORTANT]
> This function should never be called from a function that itself
> is a callback of an [`nng_aio`](index.md), either this one or any other.
> Doing so may result in a deadlock.

## SEE ALSO

[nng_aio_abort()](nng_aio_abort.md),
[nng_aio_busy()](nng_aio_busy.md)
