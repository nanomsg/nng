# nng_recv_aio

## NAME

nng_recv_aio --- receive message asynchronously

## SYNOPSIS

```c
#include <nng/nng.h>

void nng_recv_aio(nng_socket s, nng_aio *aio);
```

## DESCRIPTION

The `nng_recv_aio()` function receives a [message][msg] using the
[socket][socket] _s_ asynchronously.

When a message is successfully received by the socket, it is
stored in the _aio_ by an internal call equivalent to
[`nng_aio_set_msg()`][nng_aio_set_msg], then the completion
callback on the _aio_ is executed.
In this case, [`nng_aio_result()`][nng_aio_result] will
return zero.
The callback function is responsible for retrieving the message
and disposing of it appropriately.

> [!IMPORTANT]
> Failing to dispose of successfully received messages
> will leak the memory associated with it.

If for some reason the asynchronous receive cannot be completed
successfully (including by being canceled or timing out), then
the callback will still be executed,
but `nng_aio_result()` will be non-zero.

> [!NOTE]
> The semantics of what receiving a message means varies from protocol to
> protocol, so examination of the protocol documentation is encouraged.
> For example, with [_PUB_][pub] socket the data is broadcast, so that
> only peers who have a suitable subscription will be able to receive it.
> Furthermore, some protocols may not support receiving (such as
> _PUB_) or may require other conditions.
> (For example, [_REQ_][req] sockets cannot normally receive data
> until they have first sent a request.)

## ERRORS

- `NNG_ECANCELED`: The operation was aborted.
- `NNG_ECLOSED`: The socket _s_ is not open.
- `NNG_ENOMEM`: Insufficient memory is available.
- `NNG_ENOTSUP`: The protocol for socket _s_ does not support receiving.
- `NNG_ESTATE`: The socket _s_ cannot receive data in this state.
- `NNG_ETIMEDOUT`: The receive timeout expired.

## SEE ALSO

[Messages][msg],
[Sockets][socket],
[Asynchronous I/O][aio],
[nng_aio_get_msg][nng_aio_get_msg],
[nng_msg_alloc][nng_msg_alloc]

{{#include ../refs.md}}
