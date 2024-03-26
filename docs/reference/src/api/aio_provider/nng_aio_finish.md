# nng_aio_finish

## NAME

nng_aio_finish --- finish asynchronous I/O operation

## SYNOPSIS

```c
#include <nng/nng.h>

void nng_aio_finish(nng_aio *aio, int err);
```

## DESCRIPTION

The `nng_aio_finish()` function marks operation associated with _aio_ as
complete, with the status _err_.
This will be the result returned by [`nng_aio_result()`](../aio/nng_aio_result.md).

This function causes the callback associated with the _aio_ to called.

> [!IMPORTANT]
> It is mandatory that operation providers call this function
> _exactly once_ when they are finished with the operation.
> After calling this function, the provider _must not_ perform any
> further accesses to the _aio_.

> [!TIP]
> This function is only for I/O providers (those actually performing
> the operation such as HTTP handler functions or transport providers); ordinary
> users of the _aio_ should not have any need for this function.

## SEE ALSO

[nng_aio_begin](nng_aio_begin.md),
[nng_aio_cancel](../aio/nng_aio_cancel.md),
[nng_aio_defer](nng_aio_defer.md),
[nng_aio_result](../aio/nng_aio_result.md)
