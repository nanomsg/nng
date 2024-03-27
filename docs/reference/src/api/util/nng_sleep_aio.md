# nng_sleep_aio

## NAME

nng_sleep_aio - sleep asynchronously

## SYNOPSIS

```c
#include <nng/nng.h>

void nng_sleep_aio(nng_duration msec, nng_aio *aio);
```

## DESCRIPTION

The `nng_sleep_aio()` function provides an asynchronous delay mechanism,
causing the callback for _aio_ to be executed after _msec_ milliseconds.
If the sleep finishes completely, the result will always be zero.

> [!NOTE]
> If a timeout is set on _aio_ using
> [`nng_aio_set_timeout()`](../aio/nng_aio_set_timeout.md), and it is shorter
> than _msec_,
> then the sleep will wake up early, with a result code of `NNG_ETIMEDOUT`.

## SEE ALSO

[nng_clock](nng_clock.md),
[nng_msleep](nng_msleep.md),
[Asynchronous I/O](../aio/index.md)
