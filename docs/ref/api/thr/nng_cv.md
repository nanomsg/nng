# nng_cv

## NAME

nng_cv --- condition variable

## SYNOPSIS

```c
#include <nng/nng.h>

typedef struct nng_cv nng_cv;

int nng_cv_alloc(nng_cv **cvp, nng_mtx *mtx);
void nng_cv_free(nng_cv *cv);
int nng_cv_until(nng_cv *cv, nng_time when);
void nng_cv_wait(nng_cv *cv);
void nng_cv_wake(nng_cv *cv);
void nng_cv_wake1(nng_cv *cv);
```

## DESCRIPTION

The {{i:`nng_cv`}} structure implements a {{i:condition variable}}, associated with the
the [mutex][nng_mtx] _mtx_ which was supplied when it was created.

Condition variables provide for a way to wait on an arbitrary condition, and to be woken
when the condition is signaled.
The mutex is dropped while the caller is asleep, and reacquired atomically when the caller
is woken.

> [!IMPORTANT]
>
> The caller of `nng_cv_until`, `nng_cv_wait`, `nng_cv_wake`, and `nng_cv_wake1` _must_
> have ownership of the mutex _mtx_ when calling these functions.

### Initialization and Teardown

The {{i:`nng_cv_alloc`}} function allocates a condition variable, and associated with the mutex _mtx_,
and returns a pointer to it in _cvp_.
The {{i:`nng_cv_free`}} function deallocates the condition variable _cv_.

### Waiting for the Condition

The {{i:`nng_cv_until`}} and {{i:`nng_cv_wait`}} functions put the caller to sleep until the condition
variable _cv_ is signaled, or (in the case of `nng_cv_until`), the specified time _when_
(as determined by [`nng_clock`][nng_clock] is reached.

While `nng_cv_wait` never fails and so has no return value, the `nng_cv_until` function can
return `NNG_ETIMEDOUT` if the time is reached before condition _cv_ is signaled by
either `nng_cv_wake` or `nng_cv_wake1`.

### Signaling the Condition

The {{i:`nng_cv_wake`}} and {{i:`nng_cv_wake1`}} functions wake threads waiting in
`nng_cv_until` or `nng_cv_wake`. The difference between these functions is that
`nng_cv_wake` will wake _every_ thread, whereas `nng_cv_wake1` will wake up exactly
one thread (which may be chosen randomly).

> [!TIP]
> Use of `nng_cv_wake1` may be used to reduce the "thundering herd" syndrom of waking
> all threads concurrently, but should only be used in circumstances where the application
> does not depend on _which_ thread will be woken. When in doubt, `nng_cv_wake` is safer.

## EXAMPLE

### Example 1: Allocating the condition variable

```c
	nng_mtx *m;
	nng_cv *cv;
	nng_mtx_alloc(&m); // error checks elided
	nng_cv_alloc(&cv, m);
```

### Example 2: Waiting for the condition

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

### Example 3: Signaling the condition

```c
    nng_mtx_lock(m);
    condition_true = true;
    nng_cv_wake(cv);
    nng_mtx_unlock(m);
```

## RETURN VALUES

This function returns 0 on success, and non-zero otherwise.

## ERRORS

- `NNG_ENOMEM`: Insufficient free memory exists.
- `NNG_ETIMEDOUT`: The time specified by _when_ is reached without the condition being signaled.

## SEE ALSO

[nng_clock][nng_clock],
[nng_mtx][nng_mtx]

[nng_clock]: ../util/nng_clock.md
[nng_mtx]: ../thr/nng_mtx.md
