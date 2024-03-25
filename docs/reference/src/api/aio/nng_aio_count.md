# nng_aio_count()

## NAME

nng_aio_count --- return number of bytes transferred

## SYNOPSIS

```c
#include <nng/nng.h>

size_t nng_aio_count(nng_aio *aio);
```

## DESCRIPTION

The `nng_aio_count()` returns the number of bytes transferred by the
asynchronous operation associated with the handle _aio_.

Some asynchronous operations do not provide meaningful data for this
function; for example operations that establish connections do not
transfer user data (they may transfer protocol data though) -- in this case
this function will generally return zero.

This function is most useful when used with operations that make use of
of a scatter/gather vector (set by [`nng_aio_set_iov()`](nng_aio_set_iov.md)).

> [!NOTE]
> The return value from this function is undefined if the operation
> has not completed yet.
> Either call this from the handle's completion callback,
> or after waiting for the operation to complete with
> [`nng_aio_wait()`](nng_aio_wait.md).

## RETURN VALUES

The number of bytes transferred by the operation.

## SEE ALSO

[nng_aio_alloc()](nng_aio_alloc.md),
[nng_aio_result()](nng_aio_result.md),
[nng_aio_set_iov()](nng_aio_set_iov.md),
[nng_aio_wait()](nng_aio_wait.md)
