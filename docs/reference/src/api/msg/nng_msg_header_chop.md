# nng_msg_header_chop

## NAME

nng_msg_header_chop --- remove data from end of message header

## SYNOPSIS

```c
#include <nng/nng.h>

int nng_msg_header_chop(nng_msg *msg, size_t size);
int nng_msg_header_chop_u16(nng_msg *msg, uint16_t *val16);
int nng_msg_header_chop_u32(nng_msg *msg, uint32_t *val32);
int nng_msg_header_chop_u64(nng_msg *msg, uint64_t *val64);
```

## DESCRIPTION

The `nng_msg_header_chop()` family of functions removes
data from the end of the header of message _msg_.
The first function removes _size_ bytes.
The remaining functions remove 2, 4, or 8 bytes, and stores them in the value
(such as _val32_),
after converting them from network-byte order (big-endian) to native
byte order.

## RETURN VALUES

These function return 0 on success, and non-zero otherwise.

## ERRORS

- `NNG_EINVAL`: The message header is too short to remove the requested data.

## SEE ALSO

[nng_msg_header](nng_msg_body.md),
[nng_msg_header_append](nng_msg_header_append.md),
[nng_msg_header_insert](nng_msg_header_insert.md)
[nng_msg_header_len](nng_msg_header_len.md),
[nng_msg_header_trim](nng_msg_header_trim.md)
