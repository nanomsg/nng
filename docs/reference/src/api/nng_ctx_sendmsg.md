# nng_ctx_sendmsg()

## NAME

nng_ctx_sendmsg --- send message using context

## SYNOPSIS

```c
#include <nng/nng.h>

int nng_ctx_sendmsg(nng_ctx c, nng_msg *msg, int flags);
```

## DESCRIPTION

The `nng_ctx_sendmsg()` sends message _msg_ using the context _ctx_.

If the function returns zero, indicating it has accepted the message for
delivery, then the _msg_ is owned by the socket _s_, and the caller
must not make any further use of it.
The socket will free the message when it is finished.

If the function returns non-zero, then it is the caller's responsibility
to dispose of the _msg_, which may include freeing it, sending it to
another socket, or simply trying again later.

> [!TIP]
> The semantics of what sending a message means vary from protocol to
> protocol, so examination of the protocol documentation is encouraged.

The _flags_ may contain the following value:

- `NNG_FLAG_NONBLOCK`:\
  The function returns immediately, regardless of whether
  the context is able to accept the data or not.
  If the context is unable to accept the data (such as if backpressure exists
  because the peers are consuming messages too slowly, or no peer is present),
  then the function will return with `NNG_EAGAIN`.
  If this flag is not specified, then the function will block if such a
  condition exists.

> [!NOTE]
> Regardless of the presence or absence of `NNG_FLAG_NONBLOCK`, there may
> be queues between the sender and the receiver.
> Furthermore, there is no guarantee that the message has actually been delivered.
> Finally, with some protocols, the semantic is implicitly `NNG_FLAG_NONBLOCK`.

## RETURN VALUES

This function returns 0 on success, and non-zero otherwise.

## ERRORS

- `NNG_EAGAIN`: The operation would block, but `NNG_FLAG_NONBLOCK` was specified.
- `NNG_ECLOSED`: The context or socket is not open.
- `NNG_EINVAL`: An invalid set of _flags_ was specified.
- `NNG_EMSGSIZE`: The value of _size_ is too large.
- `NNG_ENOMEM`: Insufficient memory is available.
- `NNG_ENOTSUP`: The protocol does not support sending.
- `NNG_ESTATE`: The context cannot send data in this state.
- `NNG_ETIMEDOUT`: The operation timed out.

## SEE ALSO

[nng_ctx_send()](nng_ctx_send.md),
[nng_msg_alloc()](nng_msg_alloc.md),
[nng_msg_alloc()](nng_msg_free.md),
[nng_ctx](nng_ctx),
[nng_msg](nng_msg)
