# nng_surveyor_open

## NAME

nng_surveyor_open --- create _SURVEYOR_ socket

## SYNOPSIS

```c
#include <nng/nng.h>
#include <nng/protocol/survey0/survey.h>

int nng_surveyor0_open(nng_socket *s);

int nng_surveyor0_open_raw(nng_socket *s);
```

## DESCRIPTION

The `nng_surveyor0_open()` function creates a [_SURVEYOR_][surveyor]
version 0 [socket][socket] and returns it at the location
pointed to by _s_.

The `nng_surveyor0_open_raw()` function creates a _SURVEYOR_
version 0 socket in
[raw mode][raw] and returns it at the location pointed to by _s_.

## RETURN VALUES

These functions return 0 on success, and non-zero otherwise.

## ERRORS

- `NNG_ENOMEM`: Insufficient memory is available.
- `NNG_ENOTSUP`: The protocol is not supported.

## SEE ALSO

[Sockets][socket],
[_RESPONDENT_ Protocol][respondent],
[_SURVEYOR_ Protocol][surveyor]

{{#include ../refs.md}}
