# nng_ctx_id

## NAME

nng_ctx_id --- return numeric context identifier

## SYNOPSIS

```c
#include <nng/nng.h>

int nng_ctx_id(nng_ctx c);
```

## DESCRIPTION

The `nng_ctx_id()` function returns a positive identifier for the [context][context] _c_,
if it is valid.
Otherwise it returns `-1`.

> [!NOTE]
> A context is considered valid if it was ever opened with
> [`nng_ctx_open()`][nng_ctx_open] function.
> Contexts that are allocated on the stack or statically should be
> initialized with the macro {{i:`NNG_CTX_INITIALIZER`}} to ensure that
> they cannot be confused with a valid context before they are opened.

## RETURN VALUES

This function returns the positive value for the context identifier, or
`-1` if the context is invalid.

{{#include ../refs.md}}
