# nng_clock

## NAME

nng_clock - get time

## SYNOPSIS

```c
#include <nng/nng.h>

typedef uint64_t nng_time;

nng_time nng_clock(void);
```

## DESCRIPTION

The `nng_clock` function returns the number of elapsed milliseconds since some
arbitrary time in the past.
The resolution of the clock depends on the underlying timing facilities
of the system.
This function may be used for timing, but applications should not expect
very fine-grained values.

> [!NOTE]
> The reference time will be the same for a given program,
> but different programs may have different references.

This function is intended to help with setting appropriate
timeouts using [`nng_cv_until`][nng_cv_until]
or [`nng_aio_set_expire`][nng_aio_set_timeout].

## RETURN VALUES

Milliseconds since reference time.

## SEE ALSO

[nng_cv_until][nng_cv_until],
[nng_msleep][nng_msleep],
[nng_sleep_aio][nng_sleep_aio]

[nng_cv_until]: ../thr/nng_cv.md
[nng_msleep]: ../util/nng_msleep.md
[nng_sleep_aio]: ../aio/nng_sleep_aio.md
[nng_aio_set_timeout]: ../aio/nng_aio_set_timeout.md
