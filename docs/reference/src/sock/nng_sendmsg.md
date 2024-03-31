# nng_sendmsg

## NAME

nng_sendmsg --- send message

## SYNOPSIS

```c
#include <nng/nng.h>

int nng_sendmsg(nng_socket s, nng_msg *msg, int flags);
```

## DESCRIPTION

The `nng_sendmsg()` sends [message][msg] _msg_ using the [socket][socket] _s_.

If the function returns zero, indicating it has accepted the message for
delivery, then the _msg_ is owned by the socket _s_, and the caller
must not make any further use of it.
The socket will free the message when it is finished.

If the function returns non-zero, then it is the caller's responsibility
to dispose of the _msg_, which may include freeing it, sending it to
another socket, or simply trying again later.

> [!TIP]
> Using this function gives access to the message structure, and may
> offer more functionality than the simpler [`nng_send()`][nng_send] function. [^1] [^2]

[^1]: It is also more efficient.
[^2]: An asynchronous form of this function is available as [`nng_send_aio()`][nng_send_aio].

> [!NOTE]
> The semantics of what sending a message means vary from protocol to
> protocol, so examination of the protocol documentation is encouraged.
> Furthermore, some protocols may not support sending messages
> or may require other conditions be met first before sending messages.

The _flags_ may contain the following value:

- {{i:`NNG_FLAG_NONBLOCK`}}:
  The function returns immediately, regardless of whether
  the socket is able to accept the data or not.
  If the socket is unable to accept the data (such as if {{i:back-pressure}} exists
  because the peers are consuming messages too slowly, or no peer is present),
  then the function will return with `NNG_EAGAIN`.
  If this flag is not specified, then the function will block if such a
  condition exists.

> [!NOTE]
> Regardless of the presence or absence of `NNG_FLAG_NONBLOCK`, there may
> be queues between the sender and the receiver.
> Furthermore, there is no guarantee that the message has actually been delivered.
> Finally, with some protocols, the semantic is implicitly `NNG_FLAG_NONBLOCK`,
> such as with [_PUB_][pub] sockets, which are {{i:best-effort}} delivery only.

## RETURN VALUES

This function returns 0 on success, and non-zero otherwise.

## ERRORS

- `NNG_EAGAIN`: The operation would block, but `NNG_FLAG_NONBLOCK` was specified.
- `NNG_ECLOSED`: The socket _s_ is not open.
- `NNG_EINVAL`: An invalid set of _flags_ was specified.
- `NNG_EMSGSIZE`: The value of _size_ is too large.
- `NNG_ENOMEM`: Insufficient memory is available.
- `NNG_ENOTSUP`: The protocol for socket _s_ does not support sending.
- `NNG_ESTATE`: The socket _s_ cannot send data in this state.
- `NNG_ETIMEDOUT`: The operation timed out.

## SEE ALSO

[Messages][msg],
[Sockets][socket],
[nng_msg_alloc][nng_msg_alloc],
[nng_recvmsg][nng_recvmsg],
[nng_send][nng_send]

{{#include ../refs.md}}
