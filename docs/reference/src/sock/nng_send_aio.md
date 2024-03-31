# nng_send_aio

## NAME

nng_send_aio --- send message asynchronously

## SYNOPSIS

```
#include <nng/nng.h>

void nng_send_aio(nng_socket s, nng_aio *aio);
```

## DESCRIPTION

The `nng_send_aio()` sends a [message][msg] using the
[socket][socket] _s_ asynchronously.

The message to send must have previously been set on the _aio_
using the [`nng_aio_set_msg()`][nng_aio_set_msg] function.
The function assumes ownership of the message.

If the message was successfully queued for delivery to the socket,
then the _aio_ will complete[^1], and [`nng_aio_result()`][nng_aio_result]
will return zero. In this case the socket will dispose of the
message when it is finished with it.

[^1]:
    This does _not_ indicate that the message was actually delivered, as it
    may still be buffered in the sending socket, buffered in the receiving
    socket, or in flight over physical media.

If the operation fails for any reason (including cancellation or timeout),
then the _aio_ {{i:callback}} will be executed and
`nng_aio_result()` will return a non-zero error status.

In this case, the callback has a responsibility to retrieve the message from
the _aio_ with
[`nng_aio_get_msg()`][nng_aio_get_msg] and dispose of it appropriately. [^2]
(This may include retrying the send operation on the same or a different
socket, or deallocating the message with [`nng_msg_free()`][nng_msg_free].)

[^2]: Failure to do so will leak the memory associated with the message.

> [!NOTE]
> The semantics of what sending a message means varies from protocol to
> protocol, so examination of the protocol documentation is encouraged.
> Furthermore, some protocols may not support sending,
> or may only permit sending when other conditions are met.

## RETURN VALUES

None. (The operation completes asynchronously.)

## ERRORS

- `NNG_ECANCELED`: The operation was aborted.
- `NNG_ECLOSED`: The socket _s_ is not open.
- `NNG_EMSGSIZE`: The message is too large.
- `NNG_ENOMEM`: Insufficient memory is available.
- `NNG_ENOTSUP`: The protocol for socket _s_ does not support sending.
- `NNG_ESTATE`: The socket _s_ cannot send data in this state.
- `NNG_ETIMEDOUT`: The send timeout expired.

## SEE ALSO

[Asynchronous I/O][aio],
[Messages][msg],
[Sockets][socket],
[nng_aio_get_msg][nng_aio_get_msg],
[nng_aio_set_msg][nng_aio_set_msg],
[nng_msg_alloc][nng_msg_alloc]

{{#include ../refs.md}}
