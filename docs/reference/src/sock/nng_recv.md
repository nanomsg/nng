# nng_recv

## NAME

nng_recv --- recv data

## SYNOPSIS

```c
#include <nng/nng.h>

int nng_recv(nng_socket s, void *data, size_t *sizep, int flags);
```

## DESCRIPTION

The `nng_recv()` receives a message from the [socket][socket] _s_,
obtaining its body content.

The _flags_ is a bit mask that may contain any of the following values:

- `NNG_FLAG_NONBLOCK`:\
  The function returns immediately, even if no message is available.
  Without this flag, the function will wait until a message is received
  by the socket _s_, or any configured timer expires.

- `NNG_FLAG_ALLOC`:\
  If this flag is present, then a {{i:zero-copy}} mode is used.
  In this case the caller must set the value of _data_ to the location
  of another pointer (of type `void *`), and the _sizep_ pointer must be set
  to a location to receive the size of the message body.
  The function will then allocate a message buffer
  (as if by [`nng_alloc()`][nng_alloc]), fill it with
  the message body, and store it at the address referenced by _data_, and update
  the size referenced by _sizep_.
  The caller is responsible for disposing of the received buffer either by
  the [`nng_free()`][nng_free] function or passing the message (also
  with the {{i:`NNG_FLAG_ALLOC`}} flag) in a call to [`nng_send()`][nng_send].

If the special flag `NNG_FLAG_ALLOC` (see above) is not specified, then the
caller must set _data_ to a buffer to receive the message body content,
and must store the size of that buffer at the location pointed to by _sizep_.
When the function returns, if it is successful, the size at _sizep_ will be
updated with the actual message body length copied into _data_.

> [!NOTE]
> The semantics of what receiving a message means vary from protocol to
> protocol, so examination of the protocol documentation is encouraged.
> Furthermore, some protocols may not support receiving data at all, or
> may require other conditions be met before they can receive.

> [!TIP]
> The `NNG_FLAG_ALLOC` flag can be used to reduce data copies, thereby
> increasing performance, particularly if the buffer is reused to send
> a response using the same flag. However, the [`nng_recvmsg()`][nng_recvmsg] function is even better in this regard, and should be preferred over this
> function when possible.

## RETURN VALUES

This function returns 0 on success, and non-zero otherwise.

## ERRORS

- `NNG_EAGAIN`: The operation would block, but `NNG_FLAG_NONBLOCK` was specified.
- `NNG_ECLOSED`: The socket _s_ is not open.
- `NNG_EINVAL`: An invalid set of _flags_ was specified.
- `NNG_EMSGSIZE`: The received message did not fit in the size provided.
- `NNG_ENOMEM`: Insufficient memory is available.
- `NNG_ENOTSUP`: The protocol for socket _s_ does not support receiving.
- `NNG_ESTATE`: The socket _s_ cannot receive data in this state.
- `NNG_ETIMEDOUT`: The operation timed out.

## SEE ALSO

[nng_alloc][nng_alloc],
[nng_free][nng_free],
[nng_recvmsg][nng_recvmsg],
[nng_send][nng_send]

{{#include ../refs.md}}
