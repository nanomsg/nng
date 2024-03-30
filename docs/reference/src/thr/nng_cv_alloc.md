# nng_cv_alloc

## NAME

nng_cv_alloc --- allocate condition variable

## SYNOPSIS

```c
#include <nng/nng.h>
#include <nng/supplemental/util/platform.h>

typedef struct nng_cv nng_cv;

int nng_cv_alloc(nng_cv **cvp, nng_mtx *mtx);
```

## DESCRIPTION

The `nng_cv_alloc()` function allocates a {{i:condition variable}}, using
the mutex _mtx_, and returns it in _cvp_.

Every condition variable is associated with a mutex, which must be
owned when a thread waits for the condition using
[`nng_cv_wait()`][nng_cv_wait] or
[`nng_cv_until()`][nng_cv_until].
The mutex must also be owned when signaling the condition using the
[`nng_cv_wake()`][nng_cv_wake] or
[`nng_cv_wake1()`][nng_cv_wake1] functions.

## RETURN VALUES

This function returns 0 on success, and non-zero otherwise.

## ERRORS

- `NNG_ENOMEM`: Insufficient free memory exists.

## SEE ALSO

[nng_cv_free][nng_cv_free],
[nng_cv_until][nng_cv_until],
[nng_cv_wait][nng_cv_wait],
[nng_cv_wake][nng_cv_wake],
[nng_cv_wake1][nng_cv_wake1],
[nng_mtx_alloc][nng_mtx_alloc]

{{#include ../refs.md}}
