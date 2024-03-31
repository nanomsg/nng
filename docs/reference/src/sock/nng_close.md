# nng_close

## NAME

nng_close --- close socket

## SYNOPSIS

```c
#include <nng/nng.h>

int nng_close(nng_socket s);
```

## DESCRIPTION

The `nng_close()` function closes the [socket][socket] _s_.
Messages that have been submitted for sending may be flushed or delivered,
depending upon the [transport][transport].

Further attempts to use the socket after this call returns will result
in `NNG_ECLOSED`.
Threads waiting for operations on the socket when this
call is executed may also return with an `NNG_ECLOSED` result.

> [!NOTE]
> Closing the socket while data is in transmission will likely lead to loss
> of that data.
> There is no automatic linger or flush to ensure that the socket send buffers
> have completely transmitted.
> It is recommended to wait a brief period after calling
> [`nng_send()`][nng_send] or similar functions, before calling this
> function.

## RETURN VALUES

This function returns 0 on success, and non-zero otherwise.

## ERRORS

- `NNG_ECLOSED`: The socket _s_ is already closed or was never opened.

{{#include ../refs.md}}
