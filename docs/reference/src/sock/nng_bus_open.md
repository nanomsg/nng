# nng_bus_open

## NAME

nng_bus_open --- create _BUS_ socket

## SYNOPSIS

```c
#include <nng/nng.h>
#include <nng/protocol/bus0/bus.h>

int nng_bus0_open(nng_socket *s);

int nng_bus0_open_raw(nng_socket *s);
```

## DESCRIPTION

The `nng_bus0_open()` function creates a [_BUS_][bus] version 0
[socket][socket] and returns it at the location pointed to by _s_.

The `nng_bus0_open_raw()` function creates a _BUS_ version 0
socket in [raw mode][raw], and returns it at the location pointed to by _s_.

## RETURN VALUES

These functions return 0 on success, and non-zero otherwise.

## ERRORS

- `NNG_ENOMEM`: Insufficient memory is available.
- `NNG_ENOTSUP`: The protocol is not supported.

## SEE ALSO

[BUS protocol][bus],
[RAW mode][raw]

{{#include ../refs.md}}
