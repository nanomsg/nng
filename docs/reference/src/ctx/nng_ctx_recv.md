# nng_ctx_recv

## NAME

nng_ctx_recv --- receive message using context asynchronously

## SYNOPSIS

```c
#include <nng/nng.h>

void nng_ctx_recv(nng_ctx ctx, nng_aio *aio);
```

## DESCRIPTION

The `nng_ctx_recv()` receives a [message][msg] using the
[context][context] _ctx_ asynchronously.

When a message is successfully received by the context, it is
stored in the [_aio_][aio] by an internal call equivalent to
[`nng_aio_set_msg()`][nng_aio_set_msg], then the completion
callback on the _aio_ is executed.
In this case, [`nng_aio_result()`][nng_aio_result] will
return zero.
The callback function is responsible for retrieving the message
and disposing of it appropriately.

> [!IMPORTANT]
> Failing to accept and dispose of messages in this
> case can lead to memory leaks.

If for some reason the asynchronous receive cannot be completed
successfully (including by being canceled or timing out), then
the callback will still be executed,
but [`nng_aio_result()`][nng_aio_result] will be non-zero.

> [!TIP]
> The semantics of what receiving a message means varies from protocol to
> protocol, so examination of the protocol documentation is encouraged.

## ERRORS

The following errors may be set on the _aio_, if the operation fails.

- `NNG_ECANCELED`: The operation was aborted.
- `NNG_ECLOSED`: The context _ctx_ is not open.
- `NNG_ENOMEM`: Insufficient memory is available.
- `NNG_ENOTSUP`: The protocol for context _ctx_ does not support receiving.
- `NNG_ESTATE`: The context _ctx_ cannot receive data in this state.
- `NNG_ETIMEDOUT`: The receive timeout expired.

## SEE ALSO

[Asynchronous I/O][aio],
[Messages][msg]

{{#include ../refs.md}}
