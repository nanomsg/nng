# nng_ctx_close

## NAME

nng_ctx_close --- close context

## SYNOPSIS

```c
#include <nng/nng.h>

int nng_ctx_close(nng_ctx ctx);
```

## DESCRIPTION

The `nng_ctx_close()` function closes the [context][context] _ctx_.
Messages that have been submitted for sending may be flushed or delivered,
depending upon the transport.

Further attempts to use the context after this call returns will result
in `NNG_ECLOSED`.
Threads waiting for operations on the context when this
call is executed may also return with an `NNG_ECLOSED` result.

> [!NOTE]
> Closing the socket associated with _ctx_
> (using [`nng_close()`][nng_close]) also closes this context.

## RETURN VALUES

This function returns 0 on success, and non-zero otherwise.

## ERRORS

- `NNG_ECLOSED`: The context _ctx_ is already closed or was never opened.

## SEE ALSO

[nng_close][nng_close],
[nng_ctx_open][nng_ctx_open]

{{#include ../refs.md}}
