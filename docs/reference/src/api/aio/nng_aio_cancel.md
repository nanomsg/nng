# nng_aio_cancel()

## NAME

nng_aio_cancel --- cancel asynchronous I/O operation

## SYNOPSIS

```c
#include <nng/nng.h>

void nng_aio_cancel(nng_aio *aio);
```

## DESCRIPTION

The `nng_aio_cancel()` function aborts an operation previously started
with the handle _aio_.
If the operation is aborted, then the callback
for the handle will be called, and the function
[`nng_aio_result()`](nng_aio_result.md) will return the error `NNG_ECANCELED`.

This function does not wait for the operation to be fully aborted, but
returns immediately.

If no operation is currently in progress (either because it has already
finished, or no operation has been started yet), then this function
has no effect.

This function is the same as calling
[`nng_aio_abort()`](nng_aio_abort.md) with the error `NNG_ECANCELED`.

## SEE ALSO

[nng_aio_abort()](nng_aio_abort.md),
[nng_aio_alloc()](nng_aio_alloc.md),
[nng_aio_result()](nng_aio_result.md)
