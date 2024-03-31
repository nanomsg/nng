# nng_send

## NAME

nng_send --- send data

## SYNOPSIS

```c
#include <nng/nng.h>

int nng_send(nng_socket s, void *data, size_t size, int flags);
```

## DESCRIPTION

The `nng_send()` function sends a message containing the _data_ of
length _size_ using the [socket][socket] _s_.

> [!NOTE]
> The semantics of what sending a message means vary from protocol to
> protocol, so examination of the protocol documentation is encouraged.
> For example, on [_PUB_][pub] sockets the data is broadcast, so that
> any peers who have a suitable subscription will be able to receive it.
> Furthermore, some protocols may not support sending data
> or may require other conditions.
> For example, [_REP_][rep] sockets cannot normally send data
> until they have first received a request.)

The _flags_ may contain either of (or neither of) the following values:

- {{i:`NNG_FLAG_NONBLOCK`}}: \
   The function returns immediately, regardless of whether
  the socket is able to accept the data or not. If the socket is unable
  to accept the data (such as if backpressure exists because the peers
  are consuming messages too slowly, or no peer is present), then the
  function will return with `NNG_EAGAIN`. If this flag is not specified,
  then the function will block if such a condition exists.

- {{i:`NNG_FLAG_ALLOC`}}: \
   The _data_ was allocated using [`nng_alloc()`][nng_alloc], or was
  obtained from a call to [`nng_recv()`][nng_recv] with
  the `NNG_FLAG_ALLOC` flag.
  If this function returns success, then the _data_ is "owned" by the
  function, and it will assume responsibility for calling
  [`nng_free()`][nng_free] when it is no longer needed.
  In the absence of this flag, the _data_ is copied by the implementation
  before the function returns to the caller.

> [!TIP]
> The `NNG_FLAG_ALLOC` flag can be used to reduce data copies, thereby
> increasing performance. However, the [`nng_sendmsg()`][nng_sendmsg] function is even better in this regard, and should be preferred over this
> function when possible.

> [!NOTE]
> Regardless of the presence or absence of `NNG_FLAG_NONBLOCK`, there may
> be queues between the sender and the receiver.
> Furthermore, there is no guarantee that the message has actually been delivered.
> Finally, with some protocols, the semantic is implicitly `NNG_FLAG_NONBLOCK`,
> such as with _PUB_ sockets, which are best-effort delivery only.

> [!IMPORTANT]
> When using `NNG_FLAG_ALLOC`, it is important that the value of _size_
> match the actual allocated size of the data.
> Using an incorrect size results
> in unspecified behavior, which may include heap corruption, program crashes,
> or teleportation of the program's author to an alternate universe.

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

[Sockets][socket],
[nng_alloc][nng_alloc],
[nng_free][nng_free],
[nng_recv][nng_recv],
[nng_send_aio][nng_send_aio],
[nng_sendmsg][nng_sendmsg]

{{#include ../refs.md}}
