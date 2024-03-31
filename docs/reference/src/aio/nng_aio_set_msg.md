# nng_aio_set_msg()

## NAME

nng_aio_set_msg --- set message for asynchronous send

## SYNOPSIS

```c
#include <nng/nng.h>

void nng_aio_set_msg(nng_aio *aio, nng_msg *msg);
```

## DESCRIPTION

The `nng_aio_set_msg()` function sets the message that will be used
for an asynchronous send operation (see
[`nng_send_aio()`][nng_send_aio]).

> [!IMPORTANT]
> The _aio_ must not have an operation in progress.

## SEE ALSO

[nng_aio_get_msg][nng_aio_get_msg],
[nng_send_aio][nng_send_aio],
[Messages][msg]

{{#include ../refs.md}}
