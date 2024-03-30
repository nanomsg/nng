# nng_msg_set_pipe

## NAME

nng_msg_set_pipe --- set pipe for message

## SYNOPSIS

```c
#include <nng/nng.h>

void nng_msg_set_pipe(nng_msg *msg, nng_pipe p);
```

## DESCRIPTION

The `nng_msg_set_pipe()` sets the [pipe][pipe] associated with [message][msg] _m_ to _p_.
This is most often useful when used with protocols that support directing
a message to a specific peer.
For example the [_PAIR_][pair] version 1 protocol can do
this when `NNG_OPT_PAIR1_POLY` mode is set.

> [!NOTE]
> Not all protocols support overriding the destination pipe.

## SEE ALSO

[nng_msg_alloc][nng_msg_alloc],
[nng_msg_get_pipe][nng_msg_get_pipe]

{{#include ../refs.md}}
