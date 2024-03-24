# nng_aio_get_input(3)

## NAME

nng_aio_get_input --- return input parameter

## SYNOPSIS

```c
#include <nng/nng.h>

void *nng_aio_get_input(nng_aio *aio, unsigned int index);
```

## DESCRIPTION

The `nng_aio_get_input()` function returns the value of the input parameter
previously set at _index_ on _aio_ with the
[`nng_aio_set_input()`](nng_aio_set_input.md) function.

The valid values of _index_ range from zero (0) to three (3), as no operation
currently defined can accept more than four parameters.
If the index supplied is outside of this range,
or if the input parameter was not previously set, then `NULL` is returned.

## RETURN VALUES

Value previously set, or `NULL`.

## SEE ALSO

[nng_aio_alloc()](nng_aio_alloc.md),
[nng_aio_get_output()](nng_aio_get_output.md),
[nng_aio_set_input()](nng_aio_set_input.md),
[nng_aio](nng_aio.md)
