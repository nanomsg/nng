# nng_aio_begin()

## NAME

nng_aio_begin --- begin asynchronous I/O operation

## SYNOPSIS

```c
#include <nng/nng.h>

bool nng_aio_begin(nng_aio *aio);
```

## DESCRIPTION

The `nng_aio_begin()` function is called by the I/O provider to indicate that
it is going to process the operation.

The function may return `false`, indicating that the _aio_ has been closed.
In this case the provider should abandon the operation and do nothing else.

This operation should be called at the start of any I/O operation, and must
be called not more than once for a given I/O operation on a given _aio_.

Once this function is called, if `true` is returned, then the provider MUST
guarantee that [`nng_aio_finish()`](nng_aio_finish.md) is called for the _aio_
exactly once, when the operation is complete or canceled.

> [!TIP]
> This function is only for I/O providers (those actually performing
> the operation such as HTTP handler functions or transport providers); ordinary
> users of the _aio_ should not call this function.

## RETURN VALUES

- `true`: The operation has been started.
- `false`: The operation cannot be started.

## SEE ALSO

[nng_aio_cancel()](../aio/nng_aio_cancel.md),
[nng_aio_defer()](nng_aio_defer.md),
[nng_aio_finish()](nng_aio_finish.md)
