# nng_msg_reserve

## NAME

nng_msg_reserve --- reserve storage for a message

## SYNOPSIS

```c
#include <nng/nng.h>

int nng_msg_reserve(nng_msg *msg, size_t capacity);
```

## DESCRIPTION

The `nng_msg_reserve()` function ensures a [message][msg] has allocated enough storage
to accommodate a body of the given length.
This message attempts to avoid extra allocations,
and will reuse the existing memory when possible.

> [!TIP]
> Using this message before [`nng_msg_append()`][nng_msg_append]
> will prevent additional memory allocations until the message's length exceeds
> the alotted capacity.

> [!IMPORTANT]
> Pointers to message body and header content obtained prior to this
> function must not be in use, as the underlying memory used for the message
> may have changed, particularly if the message capacity is increasing.

## RETURN VALUES

This function returns 0 on success, and non-zero otherwise.

## ERRORS

- `NNG_ENOMEM`: Insufficient free memory exists to reallocate a message.

## SEE ALSO

[nng_msg_alloc][nng_msg_alloc],
[nng_msg_append][nng_msg_append],
[nng_msg_capacity][nng_msg_capacity],
[nng_msg_insert][nng_msg_insert],
[nng_msg_len][nng_msg_len]

{{#include ../refs.md}}
