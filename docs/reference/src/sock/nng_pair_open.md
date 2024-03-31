# nng_pair_open

## NAME

nng_pair_open --- create _PAIR_ socket

## SYNOPSIS

#### Version 0
```c
#include <nng/protocol/pair0/pair.h>

int nng_pair0_open(nng_socket *s);

int nng_pair0_open_raw(nng_socket *s);
```

#### Version 1
```c
#include <nng/protocol/pair1/pair.h>

int nng_pair1_open(nng_socket *s);

int nng_pair1_open_raw(nng_socket *s);

int nng_pair1_open_poly(nng_socktet *s);
```

## DESCRIPTION

The `nng_pair0_open()` and `nng_pair1_open()` functions
create a [_PAIR_][pair] version 0 or version 1
[socket][socket] and return it at the location pointed to by _s_.

The `nng_pair0_open_raw()` and `nng_pair1_open_raw()` functions
create a _PAIR_ version 0 or version 1 socket in
[raw mode][raw] and return it at the location pointed to by _s_.

The `nng_pair1_open_poly()` function opens a pair version 1 socket in
{{i:polyamorous mode}}.

> [!NOTE]
> Polyamorous mode is deprecated and should not be used in new applications.
> The `nng_pair1_open_poly()` function will likely be removed in a future release.

## RETURN VALUES

These functions returns 0 on success, and non-zero otherwise.

## ERRORS

* `NNG_ENOMEM`:: Insufficient memory is available.
* `NNG_ENOTSUP`:: The protocol is not supported.

## SEE ALSO

[Sockets][socket],
[_PAIR_ Protocol][pair]

{{#include ../refs.md}}