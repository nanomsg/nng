# nng_aio_set_timeout()

## NAME

nng_aio_set_timeout --- set asynchronous I/O timeout

## SYNOPSIS

```c
#include <nng/nng.h>

typedef int nng_duration;
void nng_aio_set_timeout(nng_aio *aio, nng_duration timeout);

typedef uint64_t nng_time;
void nng_aio_set_expire(nng_aio *aio, nng_time expiration);
```

## DESCRIPTION

The `nng_aio_set_timeout()` function sets a {{ii:timeout}}
for the asynchronous operation associated with _aio_.
This causes a timer to be started when the operation is actually started.
If the timer expires before the operation is completed, then it is
aborted with an error of `NNG_ETIMEDOUT`.
The _timeout_ is specified as a relative number of milliseconds.

If the timeout is `NNG_DURATION_INFINITE`, then no timeout is used.
If the timeout is `NNG_DURATION_DEFAULT`, then a "default" or socket-specific
timeout is used.
(This is frequently the same as `NNG_DURATION_INFINITE`.)

The `nng_aio_set_expire()` function is similar to `nng_aio_set_timeout()`, but sets
an absolute expiration time based on the system clock. The _expiration_
is expressed as a number of milliseconds since some point in the past.
The [`nng_clock()`](nng_clock.md) function can be used to determine
the current value of the clock.

> [!TIP]
> As most operations involve some context switching, it is usually a good
> idea to allow at least a few tens of milliseconds before timing them out --
> a too small timeout might not allow the operation to properly begin before
> giving up!

The value of _timeout_ set for the _aio_ is persistent, so that if the
handle is reused for future operations, it will have the same relative
or absolute timeout.

## SEE ALSO

[nng_aio_cancel()](nng_aio_cancel.md),
[nng_aio_result()](nng_aio_result.md),
[nng_duration](nng_duration)
