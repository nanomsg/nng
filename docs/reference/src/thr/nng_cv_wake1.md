# nng_cv_wake1

## NAME

nng_cv_wake1 --- wake one waiter

## SYNOPSIS

```c
#include <nng/nng.h>
#include <nng/supplemental/util/platform.h>

void nng_cv_wake1(nng_cv *cv);
```

## DESCRIPTION

The `nng_cv_wake1()` wakes at most one thread waiting for the condition
variable _cv_
to be signaled in the [`nng_cv_wait()`][nng_cv_wait] or
[`nng_cv_until()`][nng_cv_until] functions.

The caller must have have ownership of the mutex that was used when
_cv_ was allocated.

The caller should already have set the condition that the waiters
will check, while holding the mutex.

> [!NOTE]
> The caller cannot predict which waiter will be woken, and so the design must
> ensure that it is sufficient that _any_ waiter be woken.
> When in doubt, it is safer to use [`nng_cv_wake()`][nng_cv_wake].

## SEE ALSO

[nng_cv_alloc][nng_cv_alloc],
[nng_cv_until][nng_cv_until],
[nng_cv_wait][nng_cv_wait],
[nng_cv_wake][nng_cv_wake],
[nng_mtx_alloc][nng_mtx_alloc],
[nng_mtx_lock][nng_mtx_lock],
[nng_mtx_unlock][nng_mtx_unlock]

{{#include ../refs.md}}
