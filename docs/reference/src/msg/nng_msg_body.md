# nng_msg_body

## NAME

nng_msg_body --- return message body

## SYNOPSIS

```c
#include <nng/nng.h>

void *nng_msg_body(nng_msg *msg);
```

## DESCRIPTION

The `nng_msg_body()` function returns a pointer to the start of the {{i:body}}
content of the [message][msg] _msg_.

> [!NOTE]
> The value returned by this is invalidated by a call to any of the
> functions that modify the message itself.
> Such functions are
> [`nng_msg_free()`][nng_msg_free],
> [`nng_msg_realloc()`][nng_msg_realloc],
> any of the [`nng_msg_trim()`][nng_msg_trim],
> [`nng_msg_chop()`][nng_msg_chop],
> [`nng_msg_append()`][nng_msg_append],
> or [`nng_msg_insert()`][nng_msg_insert] variants.

## RETURN VALUES

Pointer to start of message body.

## SEE ALSO

[nng_msg_alloc][nng_msg_alloc],
[nng_msg_append][nng_msg_append],
[nng_msg_capacity][nng_msg_capacity],
[nng_msg_chop][nng_msg_chop],
[nng_msg_clear][nng_msg_clear],
[nng_msg_free][nng_msg_free],
[nng_msg_insert][nng_msg_insert],
[nng_msg_len][nng_msg_len],
[nng_msg_reserve][nng_msg_reserve],
[nng_msg_realloc][nng_msg_realloc],
[nng_msg_trim][nng_msg_trim]

{{#include ../refs.md}}
