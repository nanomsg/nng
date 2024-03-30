# nng_msg_append

## NAME

nng_msg_append --- append to message body

## SYNOPSIS

```c
#include <nng/nng.h>

int nng_msg_append(nng_msg *msg, const void *val, size_t size);
int nng_msg_append_u16(nng_msg *msg, uint16_t val16);
int nng_msg_append_u32(nng_msg *msg, uint32_t val32);
int nng_msg_append_u64(nng_msg *msg, uint64_t val64);
```

## DESCRIPTION

The `nng_msg_append()` family of functions appends data to
the end of the body of [message][msg] _msg_, reallocating it if necessary.
The first function appends _size_ bytes, copying them from _val_.
The remaining functions append the value specified (such as _val32_) in
network-byte order (big-endian).

## RETURN VALUES

These functions return 0 on success, and non-zero otherwise.

## ERRORS

- `NNG_ENOMEM`: Insufficient free memory exists.

## SEE ALSO

[nng_msg_alloc][nng_msg_alloc],
[nng_msg_body][nng_msg_body],
[nng_msg_capacity][nng_msg_capacity],
[nng_msg_chop][nng_msg_chop],
[nng_msg_clear][nng_msg_chop],
[nng_msg_free][nng_msg_free],
[nng_msg_insert][nng_msg_insert],
[nng_msg_len][nng_msg_len.md],
[nng_msg_reserve][nng_msg_reserve],
[nng_msg_realloc][nng_msg_realloc],
[nng_msg_trim][nng_msg_trim]

{{#include ../refs.md}}
