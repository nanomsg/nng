# nng_msg_realloc(3)

## NAME

nng_msg_realloc --- reallocate a message

## SYNOPSIS

```c
#include <nng/nng.h>

int nng_msg_realloc(nng_msg *msg, size_t size);
```

## DESCRIPTION

The `nng_msg_realloc()` function re-allocates a [message][] so that it has
a {{i:body}} of length _size_.
This message attempts to avoid extra allocations,
and will reuse the existing memory when possible.

TIP: `nng_msg_realloc` is suitable for creating space for direct writing of data.
When appending many small pieces of data to a message using [`nng_msg_append()`][nng_msg_append],
allocations may be reduced by first using
[`nng_msg_reserve()`][nng_msg_reserve]
to create sufficient space.
In any case, reallocating or appending to a message is guaranteed to succeed if the resulting
body length is less than [`nng_msg_capacity()`][nng_msg_capacity].

> [!NOTE]
> Pointers to message body and header content obtained prior to this
> function must not be in use, as the underlying memory used for the message
> may have changed, particularly if the message size is increasing.

## RETURN VALUES

This function returns 0 on success, and non-zero otherwise.

## ERRORS

- `NNG_ENOMEM`: Insufficient free memory exists to reallocate a message.

## SEE ALSO

[nng_msg_alloc][nng_msg_alloc],
[nng_msg_reserve][nng_msg_reserve],
[nng_msg_append][nng_msg_append],
[nng_msg_body][nng_msg_body],
[nng_msg_chop][nng_msg_chop],
[nng_msg_free][nng_msg_free],
[nng_msg_insert][nng_msg_insert],
[nng_msg_len][nng_msg_len],
[nng_msg_trim][nng_msg_trim]

{{#include ../refs.md}}
