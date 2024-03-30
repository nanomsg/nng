# nng_msg_get_pipe

## NAME

nng_msg_get_pipe --- get pipe for message

## SYNOPSIS

```c
#include <nng/nng.h>

nng_pipe nng_msg_get_pipe(nng_msg *msg);
```

## DESCRIPTION

The `nng_msg_get_pipe()` returns the [`nng_pipe`][pipe] object
associated with [message][msg] _msg_.
On receive, this is the pipe from which a message was received.
On transmit, this would be the pipe that the message should be delivered
to, if a specific peer is required.

> [!NOTE]
> Not all protocols support overriding the destination pipe.

The most usual use case for this is to obtain information about the peer
from which the message was received.
This can be used to provide different behaviors for different peers, such as
a higher level of authentication for peers located on an untrusted network.
The [`nng_pipe_get()`][nng_pipe_get] function
is useful in this situation.

## RETURN VALUES

This function returns the pipe associated with this message, which will
be a positive value.
If the pipe is non-positive, then that indicates that
no specific pipe is associated with the message.

## SEE ALSO

[nng_msg_alloc][nng_msg_alloc],
[nng_msg_set_pipe][nng_msg_set_pipe],
[nng_pipe_get][nng_pipe_get]

{{#include ../refs.md}}
