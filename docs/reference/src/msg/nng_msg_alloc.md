# nng_msg_alloc

## NAME

nng_msg_alloc --- allocate a message

## SYNOPSIS

```c
#include <nng/nng.h>

int nng_msg_alloc(nng_msg **msgp, size_t size);
```

## DESCRIPTION

The `nng_msg_alloc()` function allocates a new [message][msg] with {{i:body}} length _size_
and stores the result in _msgp_.
Messages allocated with this function contain a body and optionally a header.
They are used with receive and transmit functions.

## RETURN VALUES

This function returns 0 on success, and non-zero otherwise.

## ERRORS

- `NNG_ENOMEM`: Insufficient free memory exists to allocate a message.

## SEE ALSO

[nng_msg_free][nng_msg_free],
[nng_msg_body][nng_msg_body],
[nng_msg_dup][nng_msg_dup],
[nng_msg_header][nng_msg_header],
[nng_msg_header_len][nng_msg_header_len],
[nng_msg_len][nng_msg_len],
[nng_msg_capacity][nng_msg_capacity],
[nng_msg_reserve][nng_msg_reserve],
[nng_msg_realloc][nng_msg_realloc]

{{#include ../refs.md}}
