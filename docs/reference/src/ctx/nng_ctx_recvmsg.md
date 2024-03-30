# nng_ctx_recvmsg

## NAME

nng_ctx_recvmsg --- receive message using socket

## SYNOPSIS

```c
#include <nng/nng.h>

int nng_ctx_recvmsg(nng_ctx ctx, nng_msg **msgp, int flags);
```

## DESCRIPTION

The `nng_ctx_recvmsg()` receives a message on [context][context] _ctx_, storing the
received [message][msg] at the location pointed to by _msgp_.

The _flags_ may contain the following value:

- {{i:`NNG_FLAG_NONBLOCK`}}:\
  The function returns immediately, even if no message is available.
  Without this flag, the function will wait until a message is receivable
  on the context _ctx_, or any configured timer expires.

> [!TIP]
> The semantics of what receiving a message means vary from protocol to
> protocol, so examination of the protocol documentation is encouraged.

## RETURN VALUES

This function returns 0 on success, and non-zero otherwise.

## ERRORS

- `NNG_EAGAIN`: The operation would block, but `NNG_FLAG_NONBLOCK` was specified.
- `NNG_ECLOSED`: The context or socket is not open.
- `NNG_EINVAL`: An invalid set of _flags_ was specified.
- `NNG_ENOMEM`: Insufficient memory is available.
- `NNG_ENOTSUP`: The protocol does not support receiving.
- `NNG_ESTATE`: The context cannot receive data in this state.
- `NNG_ETIMEDOUT`: The operation timed out.

## SEE ALSO

[nng_msg_free][nng_msg_free],
[nng_ctx_open][nng_ctx_open],
[nng_ctx_recv][nng_ctx_recv],
[nng_ctx_sendmsg][nng_ctx_sendmsg],
[Messages][msg]

{{#include ../refs.md}}
