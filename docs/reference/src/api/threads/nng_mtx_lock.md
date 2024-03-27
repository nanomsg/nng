# nng_mtx_lock

## NAME

nng_mtx_lock --- lock mutex

## SYNOPSIS

```c
#include <nng/nng.h>
#include <nng/supplemental/util/platform.h>

void nng_mtx_lock(nng_mtx *mtx);
```

## DESCRIPTION

The `nng_mtx_lock()` acquires exclusive ownership of the mutex _mtx_.
If the lock is already owned, this function will wait until the current
owner releases it with [`nng_mtx_unlock()`](nng_mtx_unlock.md).

If multiple threads are waiting for the lock, the order of acquisition
is not specified.

> [!NOTE]
> A mutex can _only_ be unlocked by the thread that locked it.

> [!NOTE]
> Mutex locks are _not_ recursive; attempts to reacquire the
> same mutex may result in deadlock or aborting the current program.
> It is a programming error for the owner of a mutex to attempt to
> reacquire it.

## SEE ALSO

[nng_cv_alloc](nng_cv_alloc.md),
[nng_mtx_alloc](nng_mtx_alloc.md),
[nng_mtx_unlock](nng_mtx_unlock.md)
