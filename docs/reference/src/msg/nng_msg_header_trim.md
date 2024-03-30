# nng_msg_header_trim

## NAME

nng_msg_header_trim --- remove data from start of message header

## SYNOPSIS

```c
#include <nng/nng.h>

int nng_msg_header_trim(nng_msg *msg, size_t size);
int nng_msg_header_trim_u16(nng_msg *msg, uint16_t *val16);
int nng_msg_header_trim_u32(nng_msg *msg, uint32_t *val32);
int nng_msg_header_trim_u64(nng_msg *msg, uint64_t *val64);
```

## DESCRIPTION

The `nng_msg_header_trim()` family of functions remove
data from the start of the header of [message][msg] _msg_.
The first function removes _size_ bytes.
The remaining functions removes 2, 4, or 8 bytes, and stores them in the
value (such as _val32_),
after converting them from network-byte order (big-endian) to native
byte order.

## RETURN VALUES

This function returns 0 on success, and non-zero otherwise.

## ERRORS

- `NNG_EINVAL`: The message header is too short to remove the requested data.

## SEE ALSO

[nng_msg_header][nng_msg_body],
[nng_msg_header_append][nng_msg_header_append],
[nng_msg_header_chop][nng_msg_header_chop]
[nng_msg_header_insert][nng_msg_header_insert]
[nng_msg_header_len][nng_msg_header_len],

{{#include ../refs.md}}
