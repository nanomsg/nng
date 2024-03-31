# nng_push_open

## NAME

nng_push_open --- create push socket

## SYNOPSIS

```c
#include <nng/nng.h>
#include <nng/protocol/pipeline0/push.h>

int nng_push0_open(nng_socket *s);

int nng_push0_open_raw(nng_socket *s);
```

## DESCRIPTION

The `nng_push0_open()` function creates a [_PUSH_][push] version 0
[socket][socket] and returns it at the location pointed to by _s_.

The `nng_push0_open_raw()` function creates a _PUSH_ version 0 socket in
[raw mode][raw] and returns it at the location pointed to by _s_.

## RETURN VALUES

These functions return 0 on success, and non-zero otherwise.

## ERRORS

- `NNG_ENOMEM`: Insufficient memory is available.
- `NNG_ENOTSUP`: The protocol is not supported.

## SEE ALSO

[Sockets][socket],
[_PULL_ Protocol][pull],
[_PUSH_ Protocol][push]

{{#include ../refs.md}}
