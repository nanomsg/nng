# nng_aio

## NAME

nng_aio - asynchronous I/O handle

## SYNOPSIS

```c
#include <nng/nng.h>

typedef struct nng_aio nng_aio;
```

## DESCRIPTION

An {{i:`nng_aio`}}{{hi:aio}} is an opaque structure used in conjunction with
{{i:asynchronous I/O}} operations.
Every asynchronous operation uses one of these structures, each of which
can only be used with a single operation at a time.

Asynchronous operations are performed without blocking calling application threads.
Instead the application registers a callback function to be executed
when the operation is complete (whether successfully or not).
This callback will be executed exactly once.

The asynchronous I/O framework also supports cancellation of
operations that are already in progress
(see [`nng_aio_cancel`][aio_cancel]), as well setting a maximum
timeout for them to complete within
(see [`nng_aio_set_timeout`][nng_aio_set_timeout]).

It is also possible to initiate an asynchronous operation, and wait for it to
complete using [`nng_aio_wait`][nng_aio_wait].

These structures are created using [`nng_aio_alloc`][nng_aio_alloc],
and destroyed using [`nng_aio_free`][nng_aio_free].

## SEE ALSO

[nng_aio_cancel][aio_cancel],
[nng_aio_alloc][nng_aio_alloc],
[nng_aio_free][nng_aio_free],
[nng_aio_set_timeout][nng_aio_set_timeout]

<!--
xref:nng_aio_count.3.adoc[nng_aio_count(3)],
xref:nng_aio_free.3.adoc[nng_aio_free(3)],
xref:nng_aio_get_input.3.adoc[nng_aio_get_input(3)],
xref:nng_aio_get_msg.3.adoc[nng_aio_get_msg(3)],
xref:nng_aio_get_output.3.adoc[nng_aio_get_output(3)],
xref:nng_aio_result.3.adoc[nng_aio_result(3)],
xref:nng_aio_set_input.3.adoc[nng_aio_set_input(3)],
xref:nng_aio_set_iov.3.adoc[nng_aio_set_iov(3)],
xref:nng_aio_set_msg.3.adoc[nng_aio_set_msg(3)],
xref:nng_aio_wait.3.adoc[nng_aio_wait(3)],
xref:nng_strerror.3.adoc[nng_strerror(3)],
xref:nng_aio.5.adoc[nng_aio(5)],
-->

[aio_cancel]: nng_aio_cancel.md
[nng_aio_alloc]: nng_aio_alloc.md
[nng_aio_free]: nng_aio_free.md
[nng_aio_set_timeout]: nng_aio_set_timeout.md
[nng_aio_wait]: TODO.md
