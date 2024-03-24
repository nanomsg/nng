# nng_aio_set_input()

## NAME

nng_aio_set_input --- set input parameter

## SYNOPSIS

```c
#include <nng/nng.h>

void nng_aio_set_input(nng_aio *aio, unsigned int index, void *param);
```

## DESCRIPTION

The `nng_aio_set_input()` function sets the input parameter at _index_
to _param_ for the asynchronous operation associated with _aio_.

The type and semantics of input parameters are determined by specific
operations; the caller must supply appropriate inputs for the operation
to be performed.

The valid values of _index_ range from zero (0) to three (3), as no operation
currently defined can accept more than four parameters.
(This limit could increase in the future.)

> [!NOTE]
> If the _index_ does not correspond to a defined input for the operation,
> then this function will have no effect.

> [!IMPORTANT]
> It is an error to call this function while the _aio_ is currently
> in use by an active asynchronous operation.

An input parameter set with this function may be retrieved later with
the [`nng_aio_get_input()`](nng_aio_get_input.md) function.

## SEE ALSO

[nng_aio_alloc()](nng_aio_alloc.md),
[nng_aio_get_input()](nng_aio_get_input.md),
[nng_aio](nng_aio.md)
