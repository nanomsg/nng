# nng_bus_open()

## NAME

nng_bus_open --- create bus socket

## SYNOPSIS

```c
#include <nng/nng.h>
#include <nng/protocol/bus0/bus.h>

int nng_bus0_open(nng_socket *s);

int nng_bus0_open_raw(nng_socket *s);
```

## DESCRIPTION

The `nng_bus0_open()` function creates a [_BUS_](../protocols/bus.md) version 0
[socket](nng_socket.md) and returns it at the location pointed to by _s_.

The `nng_bus0_open_raw()` function creates a [_BUS_](../protocols/bus.md) version 0
[socket](nng_socket.md) in
[raw](../overview/raw.md) mode, and returns it at the location pointed to by _s_.

## RETURN VALUES

These functions return 0 on success, and non-zero otherwise.

## ERRORS

- `NNG_ENOMEM`: Insufficient memory is available.
- `NNG_ENOTSUP`: The protocol is not supported.

## SEE ALSO

[nng_socket()](nng_socket.md),
[BUS protocol](../protocols/bus.md),
[RAW mode](../overview/raw.md)
