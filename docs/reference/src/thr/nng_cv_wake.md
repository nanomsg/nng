# nng_cv_wake

## NAME

nng_cv_wake --- wake all waiters

## SYNOPSIS

```c
#include <nng/nng.h>
#include <nng/supplemental/util/platform.h>

void nng_cv_wake(nng_cv *cv);
```

## DESCRIPTION

The `nng_cv_wake()` wakes any threads waiting for the condition variable _cv_
to be signaled in the [`nng_cv_wait()`][nng_cv_wait] or
[`nng_cv_until()`][nng_cv_until] functions.

The caller must have have ownership of the mutex that was used when
_cv_ was allocated.

The caller should already have set the condition that the waiters
will check, while holding the mutex.

> [!TIP]
> This function wakes all threads, which is generally safer but can
> lead to a performance problem when there are many waiters, as they are all
> woken simultaneously and may contend for resources.
> See [`nng_cv_wake1()`][nng_cv_wake1] for a solution to this problem.

## SEE ALSO

[nng_cv_alloc][nng_cv_alloc],
[nng_cv_until][nng_cv_until],
[nng_cv_wait][nng_cv_wait],
[nng_cv_wake1][nng_cv_wake1],
[nng_mtx_alloc][nng_mtx_alloc],
[nng_mtx_lock][nng_mtx_lock],
[nng_mtx_unlock][nng_mtx_unlock]

{{#include ../refs.md}}
