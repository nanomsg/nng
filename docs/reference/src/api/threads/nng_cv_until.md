# nng_cv_until()

## NAME

nng_cv_until --- wait for condition or timeout

## SYNOPSIS

```c
#include <nng/nng.h>
#include <nng/supplemental/util/platform.h>

int nng_cv_until(nng_cv *cv, nng_time when);
```

## DESCRIPTION

The `nng_cv_until()` waits until either the condition variable _cv_ is signaled
by another thread calling either
[`nng_cv_wake()`](nng_cv_wake.md) or
[`nng_cv_wake1()`](nng_cv_wake1.md), or the system clock (as tracked
by [`nng_clock()`](nng_clock.md)) reaches _when_.

The caller must have have ownership of the mutex that was used when
_cv_ was allocated.
This function will drop the ownership of that mutex, and reacquire it
atomically just before returning to the caller.
(The waiting is done without holding the mutex.)

Spurious wakeups can occur.

> [!TIP]
> Any condition may be used or checked, but the condition must be
> checked, as it is possible for this function to wake up spuriously.
> The best way to do this is inside a loop that repeats until the condition
> tests for true.

## EXAMPLE

The following example demonstrates use of this function:

### Example 1: Waiting for the condition

```c
    expire = nng_clock() + 1000; // 1 second in the future
    nng_mtx_lock(m);  // assume cv was allocated using m
    while (!condition_true) {
        if (nng_cv_until(cv, expire) == NNG_ETIMEDOUT) {
            printf("Time out reached!\n");
            break;
        }
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

[nng_clock()](nng_clock.md),
[nng_cv_alloc()](nng_cv_alloc.md),
[nng_cv_wait()](nng_cv_wait.md),
[nng_cv_wake()](nng_cv_wake.md),
[nng_cv_wake1()](nng_cv_wake1.md),
[nng_mtx_alloc()](nng_mtx_alloc.md),
[nng_mtx_lock()](nng_mtx_lock.md),
[nng_mtx_unlock()](nng_mtx_unlock.md)
