# nng_aio_abort

## NAME

nng_aio_abort --- abort asynchronous I/O operation

## SYNOPSIS

```c
#include <nng/nng.h>

void nng_aio_abort(nng_aio *aio, int err);
```

## DESCRIPTION

The `nng_aio_abort()` function aborts an operation previously started
with the handle _aio_.
If the operation is aborted, then the callback
for the handle will be called, and the function
[`nng_aio_result()`][nng_aio_result]
will return the error _err_.

This function does not wait for the operation to be fully aborted, but
returns immediately.

If no operation is currently in progress (either because it has already
finished, or no operation has been started yet), then this function
has no effect.

## SEE ALSO

[nng_aio_alloc][nng_aio_alloc],
[nng_aio_cancel][nng_aio_cancel],
[nng_aio_result][nng_aio_result]

{{#include ../refs.md}}
