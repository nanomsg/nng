# nng_aio_alloc

## NAME

nng_aio_alloc --- allocate asynchronous I/O handle

## SYNOPSIS

```c
#include <nng/nng.h>

int nng_aio_alloc(nng_aio **aiop, void (*callb)(void *), void *arg);
```

## DESCRIPTION

The `nng_aio_alloc()` function allocates a handle for {{i:asynchronous I/O}}
operations, and stores a pointer to it in the location referenced by _aiop_.
The handle is initialized with a completion {{i:callback}} of _callb_,
which will be executed when an associated asynchronous operation finishes.
It will be called with the argument _arg_.

> [!IMPORTANT]
> The callback _callb_ must not perform any blocking operations, and
> must complete its execution quickly. If _callb_ does block, this can
> lead ultimately to an apparent "hang" or deadlock in the application.
> This also means you should avoid operations such as allocating new objects,
> which also means opening or closing sockets, dialers, and so forth.

> [!TIP]
> If more complex or blocking work needs to be performed by _callb_, a separate
> thread can be used, along with a [condition variable][nng_cv_alloc]
> which can be signaled by the callback.

Asynchronous I/O operations all take an [`nng_aio`](index.md)
handle such as allocated by this function.
Such operations are usually started by a function that returns immediately.
The operation is then run asynchronously, and completes sometime later.
When that operation is complete, the callback supplied here is called,
and that callback is able to determine the result of the operation using
[`nng_aio_result()`][nng_aio_result], [`nng_aio_count()`][nng_aio_count],
and [`nng_aio_get_output()`][nng_aio_get_output].

It is possible to wait synchronously for an otherwise asynchronous operation
by using the function [`nng_aio_wait()`][nng_aio_wait].
In that case, it is permissible for _callb_ and _arg_ to both be `NULL`.
Note that if these are `NULL`, then it will not be possible to determine when the
operation is complete except by calling the aforementioned
[`nng_aio_wait()`][nng_aio_wait].

## RETURN VALUES

This function returns 0 on success, and non-zero otherwise.

## ERRORS

- `NNG_ENOMEM`: Insufficient free memory to perform the operation.

## SEE ALSO

[nng_aio_abort][nng_aio_abort],
[nng_aio_cancel][nng_aio_cancel],
[nng_aio_count][nng_aio_count],
[nng_aio_free][nng_aio_free],
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
