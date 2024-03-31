# nng_rep_open

## NAME

nng_rep_open --- create _REP_ socket

## SYNOPSIS

```c
#include <nng/nng.h>
#include <nng/protocol/reqrep0/rep.h>

int nng_rep0_open(nng_socket *s);

int nng_rep0_open_raw(nng_socket *);
```

## DESCRIPTION

The `nng_rep0_open()` function creates a [{{i:*REP*}}][rep] version 0
[socket][socket] and returns it at the location pointed to by _s_.

The `nng_rep0_open_raw()` function creates a _REP_ version 0
socket in [raw mode][raw] and returns it at the location pointed to by _s_.

## RETURN VALUES

These functions return 0 on success, and non-zero otherwise.

## ERRORS

* `NNG_ENOMEM`: Insufficient memory is available.
* `NNG_ENOTSUP`: The protocol is not supported.

## SEE ALSO

[Sockets][socket],
[_REP_ Protocol][rep],
[_REQ_ Protocol][req]

{{#include ../refs.md}}
