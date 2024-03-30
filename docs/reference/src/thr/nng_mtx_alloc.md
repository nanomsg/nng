# nng_mtx_alloc

## NAME

nng_mtx_alloc --- allocate mutex

## SYNOPSIS

```c
#include <nng/nng.h>
#include <nng/supplemental/util/platform.h>

typedef struct nng_mtx nng_mtx;

int nng_mtx_alloc(nng_mtx **mtxp);
```

## DESCRIPTION

The `nng_mtx_alloc()` function allocates {{i:mutex}} and returns it in _mtxp_.

The mutex objects created by this function are suitable only for
simple lock and unlock operations, and are not recursive.
Every effort has been made to use light-weight underlying primitives when available.

Mutex (mutual exclusion) objects can be thought of as binary semaphores,
where only a single thread of execution is permitted to acquire the semaphore.

Furthermore, a mutex can only be unlocked by the thread that locked it.

## RETURN VALUES

This function returns 0 on success, and non-zero otherwise.

## ERRORS

- `NNG_ENOMEM`: Insufficient free memory exists.

## SEE ALSO

[nng_cv_alloc][nng_cv_alloc],
[nng_mtx_free][nng_mtx_free],
[nng_mtx_lock][nng_mtx_lock],
[nng_mtx_unlock][nng_mtx_unlock]

{{#include ../refs.md}}
