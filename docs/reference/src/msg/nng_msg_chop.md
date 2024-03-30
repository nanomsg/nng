# nng_msg_chop

## NAME

nng_msg_chop --- remove data from end of message body

## SYNOPSIS

```c
#include <nng/nng.h>

int nng_msg_chop(nng_msg *msg, size_t size);
int nng_msg_chop_u16(nng_msg *msg, uint16_t *val16);
int nng_msg_chop_u32(nng_msg *msg, uint32_t *val32);
int nng_msg_chop_u64(nng_msg *msg, uint64_t *val64);
```

## DESCRIPTION

The `nng_msg_chop()` family of functions removes data from
the end of the body of [message][msg] _msg_.
The first function removes _size_ bytes.
The remaining functions remove 2, 4, or 8 bytes, and stores them in the value
(such as _val32_),
after converting them from network-byte order (big-endian) to native byte order.

## RETURN VALUES

These functions return 0 on success, and non-zero otherwise.

## ERRORS

- `NNG_EINVAL`: The message body is too short to remove the requested data.

## SEE ALSO

[nng_msg_alloc][nng_msg_alloc],
[nng_msg_append][nng_msg_alloc],
[nng_msg_body][nng_msg_body],
[nng_msg_capacity][nng_msg_capacity],
[nng_msg_clear][nng_msg_chop],
[nng_msg_free][nng_msg_free],
[nng_msg_insert][nng_msg_insert],
[nng_msg_len][nng_msg_len],
[nng_msg_reserve][nng_msg_reserve],
[nng_msg_realloc][nng_msg_realloc],
[nng_msg_trim][nng_msg_trim]

{{#include ../refs.md}}
