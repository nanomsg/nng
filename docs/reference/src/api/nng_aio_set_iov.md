# nng_aio_set_iov()

## NAME

nng_aio_set_iov --- set scatter/gather vector

## SYNOPSIS

```c
#include <nng/nng.h>

int nng_aio_set_iov(nng_aio *aio, unsigned int niov, nng_iov *iov);
```

## DESCRIPTION

The `nng_aio_set_iov()` function sets a {{i:scatter/gather}} vector _iov_ on the handle _aio_.

The _iov_ is a pointer to an array of _niov_ [`nng_iov`](nng_iov.md)
structures, which have the following definition:

```c
typedef struct nng_iov {
    void * iov_buf;
    size_t iov_len;
};
```

The _iov_ is copied into storage in the _aio_ itself, so that callers may use stack allocated `nng_iov` structures.
The values pointed to by the `iov_buf` members are _not_ copied by this function though.

A maximum of four (4) `nng_iov` members may be supplied.

## RETURN VALUES

This function returns 0 on success, and non-zero otherwise.

## ERRORS

- `NNG_EINVAL`: Value of specified _niov_ is too large.

## SEE ALSO

[nng_aio](nng_aio),
[nng_iov](nng_iov)
