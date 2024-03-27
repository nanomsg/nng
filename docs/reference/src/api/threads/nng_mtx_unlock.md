# nng_mtx_unlock(3supp)

## NAME

nng_mtx_unlock --- unlock mutex

## SYNOPSIS

```c
#include <nng/nng.h>
#include <nng/supplemental/util/platform.h>

void nng_mtx_unlock(nng_mtx *mtx);
```

## DESCRIPTION

The `nng_mtx_unlock()` relinquishes ownership of the mutex _mtx_ that
was previously acquired via [`nng_mtx_lock()`](nng_mtx_lock.md).

> [!NOTE]
> A mutex can _only_ be unlocked by the thread that locked it.
> Attempting to unlock a mutex that is not owned by the caller will result
> in undefined behavior.

## SEE ALSO

[nng_mtx_alloc](nng_mtx_alloc),
[nng_mtx_lock](nng_mtx_lock)
