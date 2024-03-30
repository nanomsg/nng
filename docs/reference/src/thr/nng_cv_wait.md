# nng_cv_wait

## NAME

nng_cv_wait --- wait for condition

## SYNOPSIS

```c
#include <nng/nng.h>
#include <nng/supplemental/util/platform.h>

void nng_cv_wait(nng_cv *cv);
```

## DESCRIPTION

The `nng_cv_wait()` waits for the condition variable _cv_ to be signaled
by another thread calling either [`nng_cv_wake()`][nng_cv_wake] or
[`nng_cv_wake1()`][nng_cv_wake1].

The caller must have have ownership of the mutex that was used when
_cv_ was allocated.
This function will drop the ownership of that mutex, and reacquire it
atomically just before returning to the caller.
(The waiting is done without holding the mutex.)

Spurious wakeups are possible.

> [!TIP]
> Any condition may be used or checked, but the condition must be
> checked, as it is possible for this function to wake up spuriously.
> The best way to do this is inside a loop that repeats until the condition
> tests for true.

## EXAMPLE

The following example demonstrates use of this function:

### Example 1: Waiting for the condition

```c
    nng_mtx_lock(m);  // assume cv was allocated using m
    while (!condition_true) {
        nng_cv_wait(cv);
    }
    // condition_true is true
    nng_mtx_unlock(m);
```

### Example 2: Signaling the condition

```c
    nng_mtx_lock(m);
    condition_true = true;
    nng_cv_wake(cv);
    nng_mtx_unlock(m);
```

## SEE ALSO

[nng_cv_alloc][nng_cv_alloc],
[nng_cv_until][nng_cv_until],
[nng_cv_wake][nng_cv_wake],
[nng_cv_wake1][nng_cv_wake1],
[nng_mtx_alloc][nng_mtx_alloc],
[nng_mtx_lock][nng_mtx_lock],
[nng_mtx_unlock][nng_mtx_unlock]

{{#include ../refs.md}}
