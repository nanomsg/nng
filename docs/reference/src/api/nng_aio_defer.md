# nng_aio_defer()

## NAME

nng_aio_defer --- defer asynchronous I/O operation

## SYNOPSIS

```c
#include <nng/nng.h>

typedef void (*nng_aio_cancelfn)(nng_aio *aio, void *arg, int err);

void nng_aio_defer(nng_aio *aio, nng_aio_cancelfn fn, void *arg);
```

## DESCRIPTION

The `nng_aio_defer()` function marks operation associated with _aio_ as
being deferred for asynchronous completion, registering a cancellation
function _fn_ and associated argument _arg_.
This permits the operation to be canceled.

If the _aio_ is canceled, the cancellation routine _fn_ will be called
with the _aio_, the _arg_ specified by `nng_aio_defer()`, and an error
value in _err_, which is the reason that the operation is being canceled.

At any given time, the operation may not be cancelable.
For example it may have already been
completed, or be in a state where it is no longer possible to unschedule it.
In this case, the _cancelfn_ should just return without making any changes.

If the cancellation routine successfully canceled the operation, it should
ensure that [`nng_aio_finish()`](nng_aio_finish.md) is called, with the
error code specified by _err_.

> [!IMPORTANT]
> It is mandatory that I/O providers call [`nng_aio_finish()`](nng_aio_finish.md) _*exactly once*_ when they are finished with the operation.

> [!IMPORTANT]
> Care must be taken to ensure that cancellation and completion of
> the routine are multi-thread safe. This will usually involve the use
> of locks or other synchronization primitives.

> [!TIP]
> For operations that complete synchronously, without any need to be
> deferred, the provider need not call `nng_aio_defer()`.

> [!TIP]
> This function is only for I/O providers (those actually performing
> the operation such as HTTP handler functions or transport providers); ordinary
> users of the _aio_ should not call this function.

## SEE ALSO

[nng_aio_alloc()](nng_aio_alloc.md),
[nng_aio_cancel()](nng_aio_cancel.md),
[nng_aio_finish()](nng_aio_finish.md),
[nng_aio](nng_aio.md)
