# nng_aio_get_output

## NAME

nng_aio_get_output --- return output result

## SYNOPSIS

```c
#include <nng/nng.h>

void *nng_aio_get_output(nng_aio *aio, unsigned int index);
```

## DESCRIPTION

The `nng_aio_get_output()` function returns the output result at _index_
resulting from the asynchronous operation associated with _aio_.

The type and semantics of output parameters are determined by specific
operations.

> [!NOTE]
> If the _index_ does not correspond to a defined output for the operation,
> or the operation did not succeed, then the return value will be `NULL`.

> [!IMPORTANT]
> It is an error to call this function while the _aio_ is currently
> in use by an active asynchronous operation, or if no operation has been
> performed using the _aio_ yet.

## RETURN VALUES

The *index*th output from the operation, or `NULL`.

## SEE ALSO

[nng_aio_alloc][nng_aio_alloc],
[nng_aio_set_output](../aio_provider/nng_aio_set_output.md),
[nng_aio_result][nng_aio_result]

{{#include ../refs.md}}
