# nng_req_open

## NAME

nng_req_open --- create req socket

## SYNOPSIS

```c
#include <nng/nng.h>
#include <nng/protocol/reqrep0/req.h>

int nng_req0_open(nng_socket *s);

int nng_req0_open_raw(nng_socket *s);
```

## DESCRIPTION

The `nng_req0_open()` function creates a [{{i:*REQ*}}][req] version 0
[socket][socket] and returns it at the location pointed to by _s_.

The `nng_req0_open_raw()` function creates a _REQ_ version 0
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
