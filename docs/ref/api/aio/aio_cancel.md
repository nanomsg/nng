# aio_cancel

## NAME

aio_cancel --- canceling asynchronous I/O

## SYNOPSIS

```c
#include <nng/nng.h>

void nng_aio_abort(nng_aio *aio, int err);
void nng_aio_cancel(nng_aio *aio);
void nng_aio_stop(nng_aio *aio);
```

## DESCRIPTION

These functions are used to stop a previously submitted asynchronous
I/O operation. The operation may be canceled, or may continue to
completion. If no operation is in progress (perhaps because it has
already completed), then these operations have no effect.
If the operation is successfully canceled or aborted, then the callback
will still be called.

The {{i:`nng_aio_abort`}} function aborts the operation associated with _aio_
and returns immediately without waiting. If cancellation was successful,
then [`nng_aio_result`][nng_aio_result] will return _err_.

The {{i:`nng_aio_cancel`}} function acts like `nng_aio_abort`, but uses the error code
{{i:`NNG_ECANCELED`}}.

The {{i:`nng_aio_stop`}} function aborts the _aio_ operation with `NNG_ECANCELED`,
and then waits the operation and any associated callback to complete.
This function also marks _aio_ itself permanently stopped, so that any
new operations scheduled by I/O providers using [`nng_aio_begin`][nng_aio_begin]
return false. Thus this function should be used to teardown operations.

> [!TIP]
> When multiple asynchronous I/O handles are in use and need to be
> deallocated, it is safest to stop all of them using `nng_aio_stop`,
> before deallocating any of them with [`nng_aio_free`][nng_aio_free],
> particularly if the callbacks might attempt to reschedule further operations.

## SEE ALSO

[nng_aio][nng_aio],
[nng_aio_result][nng_aio_result],
[nng_aio_free][nng_aio_free]

[nng_aio]: TODO.md
[nng_aio_begin]: TODO.md
[nng_aio_result]: TODO.md
[nng_aio_free]: TODO.md
