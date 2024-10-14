# nng_msg_pipe

## NAME

nng_msg_pipe --- set or get pipe for message

## SYNOPSIS

```c
#include <nng/nng.h>

nng_pipe nng_msg_get_pipe(nng_msg *msg);
void nng_msg_get_pipe(nng_msg *msg, nng_pipe p);
```

## DESCRIPTION

The {{i:`nng_msg_set_pipe`}} function sets the [pipe][pipe] associated with [message][msg] _m_ to _p_.
This is most often useful when used with protocols that support directing
a message to a specific peer.
For example the [_PAIR_][pair] version 1 protocol can do
this when `NNG_OPT_PAIR1_POLY` mode is set.

The {{i:`nng_msg_get_pipe`}} function returns the pipe that was previously set on the message _m_,
either directly by the application, or when the message was received by the protocol.

> [!NOTE]
> Not all protocols support overriding the destination pipe.

## RETURN VALUES

The `nng_msg_get_pipe` function returns the pipe for the message _m_.

## SEE ALSO

[nng_msg][msg]

[msg]: ./nng_msg.md
[pair]: TODO.md
[pipe]: TODO.md
