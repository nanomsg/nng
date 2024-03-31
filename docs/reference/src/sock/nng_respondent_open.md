# nng_respondent_open

## NAME

nng_respondent_open --- create _RESPONDENT_ socket

## SYNOPSIS

```c
#include <nng/nng.h>
#include <nng/protocol/survey0/respond.h>

int nng_respondent0_open(nng_socket *s);

int nng_respondent0_open_raw(nng_socket *s);
```

## DESCRIPTION

The `nng_respondent0_open()` function creates a [{{i:*RESPONDENT*}}][respondent]
version 0 [socket][socket] and returns it at the location
pointed to by _s_.

The `nng_respondent0_open_raw()` function creates a _RESPONDENT_
version 0 socket in [raw mode][raw] and returns it at the location pointed to by _s_.

## RETURN VALUES

These functions return 0 on success, and non-zero otherwise.

## ERRORS

* `NNG_ENOMEM`: Insufficient memory is available.
* `NNG_ENOTSUP`: The protocol is not supported.

## SEE ALSO

[Sockets][socket],
[_RESPONDENT_ Protocol][respondent],
[_SURVEYOR_ Protocol][surveyor]

{{#include ../refs.md}}
