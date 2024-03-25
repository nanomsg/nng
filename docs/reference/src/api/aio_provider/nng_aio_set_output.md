# nng_aio_set_output()

## NAME

nng_aio_set_output --- set output result

## SYNOPSIS

```c
#include <nng/nng.h>

void nng_aio_set_output(nng_aio *aio, unsigned int index, void *result);
```

## DESCRIPTION

The `nng_aio_set_output()` function sets the output result at _index_
to _result_ for the asynchronous operation associated with _aio_.

The type and semantics of output results are determined by specific
operations; the operation must supply appropriate output results when
the operation completes successfully.

The valid values of _index_ range from zero (0) to three (3), as no operation
currently defined can return more than four results.

> [!NOTE]
> Note that attempts to set results with an _index_ greater than
> three (3) will be ignored.

An output result set with this function may be retrieved later with
the [`nng_aio_get_output()`](nng_aio_get_output.md) function.

## SEE ALSO

[nng_aio_get_output(3)](../aio/nng_aio_get_output.md)
