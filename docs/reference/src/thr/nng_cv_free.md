# nng_cv_free

## NAME

nng_cv_free --- free condition variable

### SYNOPSIS

```c
#include <nng/nng.h>
#include <nng/supplemental/util/platform.h>

void nng_cv_free(nng_cv *cv);
```

## DESCRIPTION

The `nng_cv_free()` function frees the condition variable _cv_.

## SEE ALSO

[nng_cv_alloc][nng_cv_alloc]

{{#include ../refs.md}}
