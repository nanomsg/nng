# nng_aio_stop

## NAME

nng_aio_stop - stop asynchronous I/O operation

## SYNOPSIS

```c
#include <nng/nng.h>

void nng_aio_stop(nng_aio *aio);
```

## DESCRIPTION

The `nng_aio_stop()` function stops the asynchronous I/O operation
associated with _aio_ by aborting with `NNG_ECANCELED`, and then waits
for it to complete or to be completely aborted, and for the
callback associated with the _aio_ to have completed executing.

Further calls to
[`nng_aio_begin()`](nng_aio_begin.md) using this _aio_ will return `false`.

It is safe to call this for an _aio_, even when no operation is currently
pending for it.

> [!TIP]
> When multiple asynchronous I/O handles are in use and need to be
> shut down, it is safest to stop all of them, before deallocating any of
> them with [`nng_aio_free()`](nng_aio_free.md), particularly if the callbacks
> might attempt to reschedule additional operations.

## SEE ALSO

[nng_aio_cancel](nng_aio_cancel.md),
[nng_aio_free](nng_aio_free.md),
[nng_aio_begin](nng_aio_begin.md),
[nng_aio_wait](nng_aio-wait.md)
