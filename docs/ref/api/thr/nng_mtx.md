# nng_mutex

## NAME

nng_mutex --- mutual exclusion lock

## SYNOPSIS

```c
#include <nng/nng.h>

typedef struct nng_mtx nng_mtx;

int nng_mtx_alloc(nng_mtx **mtxp);
void nng_mtx_free(nng_mtx *mtx);
void nng_mtx_lock(nng_mtx *mtx);
void nng_mtx_unlock(nng_mtx *mtx);
```

## DESCRIPTION

The {{i:`nng_mtx`}}{{hi:mutex}} structure provides a {{i:mutual-exclusion}} {{i:lock}}, such
that only one thread at a time can have the lock (taken using `nng_mtx_lock`).
This is critical for solving certain problems that arise in concurrent programming.

### Initialization and Teardown

The `nng_mtx` structure is created dynamically, by the application using {{i:`nng_mtx_alloc`}}.
This function will store a pointer to the allocate mutex at the location signified by _mtxp_.

When the application has no further need of the mutex, it can deallocate the resources
associated using the {{i:`nng_mtx_free`}} function.

### Locking and Unlocking

The `nng_mtx` lock can be acquired by a calling thread using the {{i:`nng_mtx_lock`}} function.

The caller will block until the lock is acquired.
If multiple threads are contending for ownership of the lock, the order of
acquisition is not specified, and applications must not depend on it.

> [!NOTE]
> Mutex locks are _not_ recursive; attempts to reacquire the
> same mutex may result in deadlock or aborting the current program.
> It is a programming error for the owner of a mutex to attempt to
> reacquire it.

The lock can be released by the thread that has ownership using the {{i:`nng_mtx_unlock`}} function.

> [!NOTE]
> A mutex can _only_ be unlocked by the thread that locked it.
> Attempting to unlock a mutex that is not owned by the caller will result
> in undefined behavior.

## RETURN VALUES

The `nng_mtx_lock` function returns 0 on success, or non-zero on failure.

The other mutex functions always succeed, and have no return values.

## ERRORS

- `NNG_ENOMEM`: Insufficient memory is available, or the table is full.
