# nng_aio_result

## NAME

nng_aio_result --- return result of asynchronous operation

## SYNOPSIS

```c
#include <nng/nng.h>

int nng_aio_result(nng_aio *aio);
```

## DESCRIPTION

The `nng_aio_result()` returns the result of the operation associated
with the handle _aio_.
If the operation was successful, then 0 is returned.
Otherwise a non-zero error code is returned.

> [!NOTE]
> The return value from this function is undefined if the operation
> has not completed yet.
> Either call this from the handle's completion
> callback, or after waiting for the operation to complete with
> [`nng_aio_wait()`][nng_aio_wait].

## RETURN VALUES

The result of the operation, either zero on success, or an error
number on failure.

## ERRORS

- `NNG_ETIMEDOUT`: The operation timed out.
- `NNG_ECANCELED`: The operation was canceled.

Various other return values are possible depending on the operation.

## SEE ALSO

[nng_aio_abort][nng_aio_abort],
[nng_aio_alloc][nng_aio_alloc],
[nng_aio_wait][nng_aio_wait],
[nng_strerror](../util/nng_strerror.md)

{{#include ../refs.md}}
