# nng_msg_header_append

## NAME

nng_msg_header_append --- append to message header

## SYNOPSIS

```c
#include <nng/nng.h>

int nng_msg_header_append(nng_msg *msg, const void *val, size_t size);
int nng_msg_header_append_u16(nng_msg *msg, uint16_t val16);
int nng_msg_header_append_u32(nng_msg *msg, uint32_t val32);
int nng_msg_header_append_u64(nng_msg *msg, uint64_t val64);
```

## DESCRIPTION

The `nng_msg_header_append()` family of functions appends data to
the end of the header of [message][msg] _msg_, reallocating it if necessary.
The first function appends _size_ bytes, copying them from _val_.

The remaining functions append the value (such as _val32_) in
network-byte order (big-endian).

## RETURN VALUES

These functions return 0 on success, and non-zero otherwise.

## ERRORS

- `NNG_ENOMEM`: Insufficient free memory exists.

## SEE ALSO

[nng_msg_header][nng_msg_body],
[nng_msg_header_chop][nng_msg_header_chop],
[nng_msg_header_insert][nng_msg_header_insert]
[nng_msg_header_len][nng_msg_header_len],
[nng_msg_header_trim][nng_msg_header_trim]

{{#include ../refs.md}}
