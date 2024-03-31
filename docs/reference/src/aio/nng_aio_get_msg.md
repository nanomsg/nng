# nng_aio_get_msg

## NAME

nng_aio_get_msg --- get message from asynchronous receive

## SYNOPSIS

```c
#include <nng/nng.h>

nng_msg *nng_aio_get_msg(nng_aio *aio);
```

## DESCRIPTION

The `nng_aio_get_msg()` function gets any message stored in _aio_ as
either a result of a successful receive
(see [`nng_recv_aio()`][nng_recv_aio])
or that was previously stored with
[`nng_aio_set_msg()`][nng_aio_set_msg].

> [!IMPORTANT]
> The _aio_ must not have an operation in progress.

## SEE ALSO

[nng_aio_set_msg][nng_aio_set_msg],
[nng_recv_aio][nng_recv_aio],
[Messages][msg]

{{#include ../refs.md}}
