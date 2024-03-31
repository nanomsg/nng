# nng_recvmsg

## NAME

nng_recvmsg --- receive a message

## SYNOPSIS

```c
#include <nng/nng.h>

int nng_recvmsg(nng_socket s, nng_msg **msgp, int flags);
```

## DESCRIPTION

The `nng_recvmsg()` receives a [message][msg] on [socket][socket] _s_, storing the
received message at the location pointed to by _msgp_.

This function gives access to the message structure, and thus may
offer more functionality than the simpler [`nng_recv()`][nng_recv] function.[^1] [^2]

[^1]: It is also more efficient.
[^2]: An asynchronous form of this function is available as [`nng_recv_aio()`][nng_recv_aio].

The _flags_ may contain the following value:

- {{i:`NNG_FLAG_NONBLOCK`}}: \
  The function returns immediately, even if no message is available.
  Without this flag, the function will wait until a message is received
  by the socket _s_, or any configured timer expires.

After successfully receiving a message, the caller is responsible for
disposing of it when it is no longer needed.

> [!IMPORTANT]
> Failing to dispose of the message will leak the memory associated with it.

> [!NOTE]
> The semantics of what receiving a message means vary from protocol to
> protocol, so examination of the protocol documentation is encouraged.
> (For example, with a [_REQ_][req] socket a message may only be received
> after a request has been sent).
> Furthermore, some protocols do not support receiving data at all.

## RETURN VALUES

This function returns 0 on success, and non-zero otherwise.

## ERRORS

- `NNG_EAGAIN`: The operation would block, but `NNG_FLAG_NONBLOCK` was specified.
- `NNG_ECLOSED`: The socket _s_ is not open.
- `NNG_EINVAL`: An invalid set of _flags_ was specified.
- `NNG_ENOMEM`: Insufficient memory is available.
- `NNG_ENOTSUP`: The protocol for socket _s_ does not support receiving.
- `NNG_ESTATE`: The socket _s_ cannot receive data in this state.
- `NNG_ETIMEDOUT`: The operation timed out.

## SEE ALSO

[Messages][msg],
[Sockets][socket],
[nng_msg_free][nng_msg_free],
[nng_recv][nng_recv],
[nng_sendmsg][nng_sendmsg]

{{#include ../refs.md}}
