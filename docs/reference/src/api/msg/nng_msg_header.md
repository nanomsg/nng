# nng_msg_header

## NAME

nng_msg_header --- return message header

## SYNOPSIS

```c
#include <nng/nng.h>

void *nng_msg_header(nng_msg *msg);
```

## DESCRIPTION

The `nng_msg_header()` function returns a pointer to the start of the header
content of the message _msg_.

> [!NOTE]
> The message header contains protocol-specific header content. Most
> applications should not need to access this content, but it is available
> for [raw](../../overview/raw.md) mode sockets.

> [!NOTE]
> The value returned by this is invalidated by a call to any of the
> functions that modify the message or the header content.

## RETURN VALUES

Pointer to start of message header.

## SEE ALSO

[nng_msg_alloc](nng_msg_alloc.md),
[nng_msg_body](nng_msg_body.md),
[nng_msg_free](nng_msg_free.md),
[nng_msg_header_append](nng_msg_header_append.md),
[nng_msg_header_chop](nng_msg_header_chop.md),
[nng_msg_header_insert](nng_msg_header_insert.md)
[nng_msg_header_len](nng_msg_header_len.md),
[nng_msg_header_trim](nng_msg_header_trim.md)
