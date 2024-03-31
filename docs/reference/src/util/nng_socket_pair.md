# nng_socket_pair

## NAME

nng_socket_pair --- create a connected pair of BSD sockets

## SYNOPSIS

```c
#include <nng/nng.h>
#include <nng/supplemental/util/platform.h>

int nng_socket_pair(int fds[2]);
```

## DESCRIPTION

The `nng_socket_pair()` function creates a pair of connected BSD sockets.
These sockets, which are returned in the _fds_ array, are suitable for
use with the [BSD Socket][sockfd] transport.

On POSIX platforms, this is a thin wrapper around the standard `socketpair()` function,
using the {{i:`AF_UNIX`}} family and the `SOCK_STREAM` socket type.[^1]

[^1]: At present only POSIX platforms implementing `socketpair()` support this function.

> [!TIP]
> This function may be useful for creating a shared connection between a parent process and
> a child process on UNIX platforms, without requiring the processes use a shared filesystem or TCP connection.

## RETURN VALUES

This function returns 0 on success, and non-zero otherwise.

## ERRORS

- `NNG_ENOMEM`: Insufficient memory exists.
- `NNG_ENOTSUP`: This platform does not support socket pairs.

## SEE ALSO

[BSD Socket Transport][sockfd]

{{#include ../refs.md}}
