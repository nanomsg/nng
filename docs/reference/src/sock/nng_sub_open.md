# nng_sub_open

## NAME

nng_sub_open - create _SUB_ socket

## SYNOPSIS

```c
#include <nng/nng.h>
#include <nng/protocol/pubsub0/sub.h>

int nng_sub0_open(nng_socket *s);

int nng_sub0_open_raw(nng_socket *s);
```

## DESCRIPTION

The `nng_sub0_open()` function creates a [_SUB_][sub] version 0
[socket][socket] and returns it at the location pointed to by _s_.

The `nng_sub0_open_raw()` function creates a _SUB_ version 0
socket in
[raw mode][raw] and returns it at the location pointed to by _s_.

## RETURN VALUES

These functions return 0 on success, and non-zero otherwise.

## ERRORS

* `NNG_ENOMEM`: Insufficient memory is available.
* `NNG_ENOTSUP`: The protocol is not supported.

## SEE ALSO

[Sockets][socket],
[_PUB_ Protocol][pub],
[_SUB_ Protocol][sub]

{{#include ../refs.md}}