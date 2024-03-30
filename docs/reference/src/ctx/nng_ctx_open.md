# nng_ctx_open

## NAME

nng_ctx_open --- create context

## SYNOPSIS

```c
#include <nng/nng.h>

int nng_ctx_open(nng_ctx *ctxp, nng_socket s);
```

## DESCRIPTION

The `nng_ctx_open()` function creates a separate {{hi:context}}[context][context] to be used with
the [socket][socket] _s_,
and returns it at the location pointed by _ctxp_.

> [!NOTE]
> Not every protocol supports creation of separate contexts.

Contexts allow the independent and concurrent use of stateful operations
using the same socket.
For example, two different contexts created on a
[_REP_][rep]
socket can each receive requests, and send replies to them, without any
regard to or interference with each other.

> [!TIP]
> Using contexts is an excellent way to write simpler concurrent
> applications, while retaining the benefits of the protocol-specific
> advanced processing, avoiding the need to bypass that with
> {{hi:raw mode}}[raw mode][raw] sockets.

> [!NOTE]
> Use of contexts with [raw mode][raw] sockets is
> nonsensical, and not supported.

## RETURN VALUES

This function returns 0 on success, and non-zero otherwise.

## ERRORS

- `NNG_ENOMEM`: Insufficient memory is available.
- `NNG_ENOTSUP`: The protocol does not support separate contexts, or the socket was opened in raw mode.

## SEE ALSO

[nng_ctx_close][nng_ctx_close],
[nng_ctx_get][nng_ctx_get],
[nng_ctx_recv][nng_ctx_recv],
[nng_ctx_send][nng_ctx_send],
[nng_ctx_set][nng_ctx_set],
[Sockets][socket]

{{#include ../refs.md}}
