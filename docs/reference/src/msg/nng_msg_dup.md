# nng_msg_dup

## NAME

nng_msg_dup --- duplicate a message

## SYNOPSIS

```c
#include <nng/nng.h>

int nng_msg_dup(nng_msg **dup, nng_msg_t *orig);
```

## DESCRIPTION

The `nng_msg_dup()` makes a duplicate of the original [message][msg] _orig_, and
saves the result in the location pointed by _dup_.
The actual message body and header content is copied,
but the duplicate may contain a
different amount of unused space than the original message.

## RETURN VALUES

This function returns 0 on success, and non-zero otherwise.

## ERRORS

- `NNG_ENOMEM`: Insufficient free memory exists to duplicate a message.

## SEE ALSO

[nng_msg_alloc][nng_msg_alloc],
[nng_msg_free][nng_msg_free]

{{#include ../refs.md}}
