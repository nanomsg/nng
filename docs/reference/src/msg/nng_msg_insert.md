# nng_msg_insert

## NAME

nng_msg_insert --- prepend to message body

## SYNOPSIS

```c
#include <nng/nng.h>

int nng_msg_insert(nng_msg *msg, const void *val, size_t size);
int nng_msg_insert_u16(nng_msg *msg, uint16_t val16);
int nng_msg_insert_u32(nng_msg *msg, uint32_t val32);
int nng_msg_insert_u64(nng_msg *msg, uint64_t val64);
```

## DESCRIPTION

The `nng_msg_insert()` family of functions prepends data to
the front of the body of [message][msg] _msg_, reallocating it if necessary.
The first function prepends _size_ bytes, copying them from _val_.
The remaining functions prepend the specified value (such as _val32_)
in network-byte order (big-endian).

> [!TIP]
> These functions make use of space pre-allocated in front of the
> message body if available, so they can often avoid performing any reallocation.
> Applications should use these instead of reallocating and copying message
> content themselves, in order to benefit from this capability.

## RETURN VALUES

These functions return 0 on success, and non-zero otherwise.

## ERRORS

- `NNG_ENOMEM`: Insufficient free memory exists.

## SEE ALSO

[nng_msg_alloc][nng_msg_alloc],
[nng_msg_append][nng_msg_append],
[nng_msg_body][nng_msg_body],
[nng_msg_capacity][nng_msg_capacity],
[nng_msg_chop][nng_msg_chop],
[nng_msg_clear][nng_msg_chop],
[nng_msg_free][nng_msg_free],
[nng_msg_insert][nng_msg_insert],
[nng_msg_len][nng_msg_len],
[nng_msg_reserve][nng_msg_reserve],
[nng_msg_realloc][nng_msg_realloc],
[nng_msg_trim][nng_msg_trim]

{{#include ../refs.md}}
