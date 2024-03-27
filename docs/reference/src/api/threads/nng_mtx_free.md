# nng_mtx_free

## NAME

nng_mtx_free --- free mutex

## SYNOPSIS

```c
#include <nng/nng.h>
#include <nng/supplemental/util/platform.h>

void nng_mtx_free(nng_mtx *mtx);
```

## DESCRIPTION

The `nng_mtx_free()` function frees the mutex _mtx_.
The mutex must not be locked when this function is called.

## SEE ALSO

[nng_mtx_alloc](nng_mtx_alloc)
