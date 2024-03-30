# nng_msg_len

## NAME

nng_msg_len --- return message body length

## SYNOPSIS

```c
#include <nng/nng.h>

size_t nng_msg_len(nng_msg *msg);
```

## DESCRIPTION

The `nng_msg_len()` returns the length of the body of [message][msg] _msg_.

## RETURN VALUES

Length of message body.

## SEE ALSO

[nng_msg_alloc](nng_msg_alloc),
[nng_msg_body](nng_msg_body)

{{#include ../refs.md}}
