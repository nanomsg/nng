# nng_ctx_send

## NAME

nng_ctx_send --- send message using context asynchronously

## SYNOPSIS

```c
#include <nng/nng.h>

void nng_ctx_send(nng_ctx ctx, nng_aio *aio);
```

## DESCRIPTION

The `nng_ctx_send()` sends a [message](../msg/index.md) using the
[context][nng_ctx] _ctx_ asynchronously.

The message to send must have previously been set on the _aio_
using the [`nng_aio_set_msg()`](../aio/nng_aio_set_msg.md) function.
The function assumes ownership of the message.

If the message was successfully queued for delivery to the socket,
then the _aio_ will be completed, and [`nng_aio_result()`](../aio/nng_aio_result.md)
will return zero.
In this case the socket will dispose of the message when it is finished with it.

> [!NOTE]
> The operation will be completed, and the callback associated
> with the _aio_ executed, as soon as the socket accepts the message
> for sending.
> This does _not_ indicate that the message was actually delivered, as it
> may still be buffered in the sending socket, buffered in the receiving
> socket, or in flight over physical media.

If the operation fails for any reason (including cancellation or timeout),
then the _aio_ callback will be executed and
[`nng_aio_result()`](../aio/nng_aio_result.md) will return a non-zero error status.
In this case, the callback has a responsibility to retrieve the message from
the _aio_ with [`nng_aio_get_msg()`](../aio/nng_aio_get_msg.md) and dispose of
it appropriately.
(This may include retrying the send operation on the same or a different
socket, or deallocating the message with [`nng_msg_free()`](../msg/nng_msg_free.md).

> [!TIP]
> The semantics of what sending a message means varies from protocol to
> protocol, so examination of the protocol documentation is encouraged.

## ERRORS

- `NNG_ECANCELED`: The operation was aborted.
- `NNG_ECLOSED`: The context _ctx_ is not open.
- `NNG_EMSGSIZE`: The message is too large.
- `NNG_ENOMEM`: Insufficient memory is available.
- `NNG_ENOTSUP`: The protocol for context _ctx_ does not support sending.
- `NNG_ESTATE`: The context _ctx_ cannot send data in this state.
- `NNG_ETIMEDOUT`: The send timeout expired.

## SEE ALSO

[nng_aio_get_msg](../aio/nng_aio_get_msg.md),
[nng_aio_set_msg](../aio/nng_aio_set_msg.md),
[nng_ctx_sendmsg][nng_ctx_sendmsg],
[nng_msg_alloc](../msg/nng_msg_alloc.md),
[nng_msg_free](../msg/nng_msg_free.md),
[Asynchronous I/O][aio],
[Messages][msg]

{{#include ../refs.md}}
