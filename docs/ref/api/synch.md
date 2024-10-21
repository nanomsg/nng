# Synchronization Primitives

In order to allow safely accessing shared state, or to allow coordination between
different [threads][thread], _NNG_ provides {{i:synchronization primitives}} in the
form of mutual exclusion locks and condition variables.

Correct use of these primitives will be needed when accessing shared state from
threads, or from callback functions associated with [asynchronous operations][aio].
(The need to do this in callbacks is because the callback may be executed under
a task thread other than the submitting thread.)

## Mutual Exclusion Lock

```c
typedef struct nng_mtx nng_mtx;
```

Mutual exclusion locks, or {{i:mutex}} locks, represented by the {{i:`nng_mtx`}} structure,
allow only a single thread to lock "own" the lock, acquired by [`nng_mtx_lock`][nng_mtx_lock].
Any other thread trying to acquire the same mutex will wait until the owner has released the mutex
by calling [`nng_mtx_unlock`][nng_mtx_unlock].

### Creating a Mutex

```c
int nng_mutx_alloc(nng_mt **mtxp);
```

A mutex can be created by allocating one with {{i:`nng_mtx_lock`}}.
On success, a pointer to the mutex is returned through _mtxp_.
This function can fail due to insufficient memory or resources, in which
case it will return `NNG_ENOMEM`. Otherwise it will succceed and return zero.

### Destroying a Mutex

```c
void nng_mtx_free(nng_mtx *mtx);
```

When no longer needed, a mutex can be deallocated and its resources returned
to the caller, by calling {{i:`nng_mtx_free`}}. The mutex must not be locked
by any thread when calling this function.

### Acquiring a Mutex

```c
void nng_mtx_lock(nng_mtx *mtx);
```

The {{i:`nng_mtx_lock`}} function acquires ownership of a mutex, waiting for it to
unowned by any other threads if necessary.

> [!IMPORTANT]
> A thread must not attempt to reqacuire the same mutex while it already "owns" the mutex.
> If it does attempt to do so, the result will be a single party deadlock.

### Releasing a Mutex

```c
void nng_mtx_unlock(nng_mtx *mtx);
```

The {{i:`nng_mtx_unlock`}} function releases a mutex that the calling thread has previously
acquired with [`nng_mtx_lock`][nng_mtx_lock].

> [!IMPORTANT]
> A thread must not attempt to release (unlock) a mutex if it was not the thread
> that acquired the mutex to begin with.

## Condition Variable

```c
typedef struct nng_cv nng_cv;
```

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

### Creating a Condition Variable

```c
int nng_cv_alloc(nng_cv **cvp, nng_mtx *mtx);
```

The {{i:`nng_cv_alloc`}} function allocates a condition variable, and associated with the mutex _mtx_,
and returns a pointer to it in _cvp_.

### Destroy a Condition Variable

```c
void nng_cv_free(nng_cv *cv);
```

The {{i:`nng_cv_free`}} function deallocates the condition variable _cv_.

### Waiting for the Condition

```c
int nng_cv_until(nng_cv *cv, nng_time when);
void nng_cv_wait(nng_cv *cv);
```

The {{i:`nng_cv_until`}} and {{i:`nng_cv_wait`}} functions put the caller to sleep until the condition
variable _cv_ is signaled, or (in the case of `nng_cv_until`), the specified time _when_
(as determined by [`nng_clock`][nng_clock] is reached.

While `nng_cv_wait` never fails and so has no return value, the `nng_cv_until` function can
return `NNG_ETIMEDOUT` if the time is reached before condition _cv_ is signaled by
either [`nng_cv_wake`][nng_cv_wake] or [`nng_cv_wake1`][nng_cv_wake].

### Signaling the Condition

```c
void nng_cv_wake(nng_cv *cv);
void nng_cv_wake1(nng_cv *cv);
```

The {{i:`nng_cv_wake`}} and {{i:`nng_cv_wake1`}} functions wake threads waiting in
[`nng_cv_until`][nng_cv_wait] or [`nng_cv_wait`][nng_cv_wait].
The difference between these functions is that
`nng_cv_wake` will wake _every_ thread, whereas `nng_cv_wake1` will wake up exactly
one thread (which may be chosen randomly).

> [!TIP]
> Use of `nng_cv_wake1` may be used to reduce the "thundering herd" syndrom of waking
> all threads concurrently, but should only be used in circumstances where the application
> does not depend on _which_ thread will be woken. When in doubt, `nng_cv_wake` is safer.

[aio]: aio.md
[thread]: thread.md
[nng_mtx]: #mutual-exclusion-lock
[nng_mtx_lock]: #acquiring-a-mutex
[nng_mtx_unlock]: #releasing-a-mutex
[nng_cv]: #condition-variable
[nng_cv_wait]: #waiting-for-the-condition
[nng_cv_wake]: #signaling-the-condition
[nng_clock]: ../util/nng_clock.md

## Examples

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
