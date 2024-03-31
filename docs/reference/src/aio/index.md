# Aysnchronous I/O

_NNG_ provides rich support for {{i:asynchronous I/O}}.
This allows applications to achieve high levels of concurrency with a
minimum of fuss, optimized for the platform.

Asynchronous I/O is performed without blocking calling application
threads, so they may continue to perform other work.

## AIO Handles

Applications create an `nng_aio` object with a function to call when
the operation is done (along with a pointer to application private data),
then submit the operation.

These `nng_aio` objects are created using the [`nng_aio_alloc()`][nng_aio_alloc],
and destroyed using [`nng_aio_free()`][nng_aio_free].

The `nng_aio` object itself is declared like this:

```c
#include <nng/nng.h>

typedef struct nng_aio nng_aio;
```

Every asynchronous operation uses its own instance an `nng_aio`, and each
`nng_aio` can only be used with a single operation at a time.

> [!IMPORTANT]
> Attempting to submit an operation using an `nng_aio` that is already
> in use for another operation will crash the application.
> However, it is possible to submit another operation on the `nng_aio` from
> the callback associated with the same `nng_aio`.

When the operation is complete, whether successfully
or otherwise, the callback function is executed.
The callback will be executed exactly once.

## Cancellation

The asynchronous I/O framework also supports cancellation of
operations that are already in progress
(see [`nng_aio_cancel()`][nng_aio_cancel]), as well setting a maximum
timeout for them to complete within
(see [`nng_aio_set_timeout()`][nng_aio_set_timeout]).

## Waiting for Completion

It is also possible to initiate an asynchronous operation, and wait for it to
complete [`nng_aio_wait()`][nng_aio_wait].

> [!IMPORTANT]
> Applications must never call [`nng_aio_wait()`][nng_aio_wait] or
> [`nng_aio_stop()`][nng_aio_stop] from a callback registered to
> an `nng_aio` object. Doing so can lead to a deadlock.

## See Also

[nng_aio_abort][nng_aio_abort],
[nng_aio_alloc][nng_aio_alloc],
[nng_aio_cancel][nng_aio_cancel],
[nng_aio_count][nng_aio_count],
[nng_aio_free][nng_aio_free],
[nng_aio_get_input][nng_aio_get_input],
[nng_aio_get_msg][nng_aio_get_msg],
[nng_aio_get_output][nng_aio_get_output],
[nng_aio_result][nng_aio_result],
[nng_aio_set_input][nng_aio_set_input],
[nng_aio_set_iov][nng_aio_set_iov],
[nng_aio_set_msg][nng_aio_set_msg],
[nng_aio_set_timeout][nng_aio_set_timeout],
[nng_aio_stop][nng_aio_stop],
[nng_aio_wait][nng_aio_wait]

{{#include ../refs.md}}
