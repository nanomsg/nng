# nng_msg_header_insert

## NAME

nng_msg_header_insert --- prepend to message header

## SYNOPSIS

```c
#include <nng/nng.h>

int nng_msg_header_insert(nng_msg *msg, const void *val, size_t size);
int nng_msg_header_insert_u16(nng_msg *msg, uint16_t val16);
int nng_msg_header_insert_u32(nng_msg *msg, uint32_t val32);
int nng_msg_header_insert_u64(nng_msg *msg, uint64_t val64);
```

## DESCRIPTION

The `nng_msg_header_insert()` family of functions
prepends data to the front of the headers of [message][msg] _msg_, reallocating
if necessary.
The first function prepends _size_ bytes, copying them from _val_.
The remaining functions prepend the specified value (such as _val32_) in
network-byte order (big-endian).

## RETURN VALUES

These functions return 0 on success, and non-zero otherwise.

## ERRORS

- `NNG_ENOMEM`: Insufficient free memory exists.

## SEE ALSO

[nng_msg_header][nng_msg_header],
[nng_msg_header_append][nng_msg_header_append]
[nng_msg_header_chop][nng_msg_header_chop],
[nng_msg_header_len][nng_msg_header_len],
[nng_msg_header_trim][nng_msg_header_trim]

{{#include ../refs.md}}
