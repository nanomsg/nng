# nng_aio

## NAME

nng_aio --- asynchronous I/O handle

```c
#include <nng/nng.h>

typedef struct nng_aio nng_aio;
```

## DESCRIPTION

An `nng_aio`{{hi:aio}} is an opaque structure used in conjunction with
{{i:asynchronous I/O}} operations.
Every asynchronous operation uses one of these structures, each of which
can only be used with a single operation at a time.

Asynchronous operations are performed without blocking calling application
threads.
Instead the application registers a callback function to be executed
when the operation is complete (whether successfully or not).
This callback will be executed exactly once.

The asynchronous I/O framework also supports cancellation of
operations that are already in progress
(see [`nng_aio_cancel()`](nng_aio_cancel.md)), as well setting a maximum
timeout for them to complete within
(see [`nng_aio_set_timeout()`](nng_aio_set_timeout.md)).

It is also possible to initiate an asynchronous operation, and wait for it to
complete [`nng_aio_wait()`](nng_aio_wait.md).

These structures are created using the [`nng_aio_alloc()`](nng_aio_alloc.md),
and destroyed using [`nng_aio_free()`](nng_aio_free.md).

> [!IMPORTANT]
> A given `nng_aio` can only have a single operation in progress
> at any given time. Attempts to reuse an `nng_aio` while another
> operation is in progress will generally cause a crash.

## SEE ALSO

[nng_aio_abort()](nng_aio_abort.md),
[nng_aio_alloc()](nng_aio_alloc.md),
[nng_aio_cancel()](nng_aio_cancel.md),
[nng_aio_count()](nng_aio_count.md),
[nng_aio_free()](nng_aio_free.md),
[nng_aio_get_input()](nng_aio_get_input.md),
[nng_aio_get_msg()](nng_aio_get_msg.md),
[nng_aio_get_output()](nng_aio_get_output.md),
[nng_aio_result()](nng_aio_result.md),
[nng_aio_set_input()](nng_aio_set_input.md),
[nng_aio_set_iov()](nng_aio_set_iov.md),
[nng_aio_set_msg()](nng_aio_set_msg.md),
[nng_aio_set_timeout()](nng_aio_set_timeout.md),
[nng_aio_stop()](nng_aio_stop.md),
[nng_aio_wait()](nng_aio_wait.md),
