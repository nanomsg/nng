# nng_msleep

## NAME

nng_msleep --- sleep milliseconds

## SYNOPSIS

```c
#include <nng/nng.h>
#include <nng/supplemental/util/platform.h>

void nng_msleep(nng_duration msec);
```

## DESCRIPTION

The `nng_msleep()` blocks the caller for at least _msec_ milliseconds.

> [!NOTE]
> This function may block for longer than requested.
> The actual wait time is determined by the capabilities of the
> underlying system.

## SEE ALSO

[nng_sleep_aio](nng_sleep_aio.md),
[nng_clock](nng_clock.md)
