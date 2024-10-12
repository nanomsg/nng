# nng_msg_header

## NAME

nng_msg_header --- message header

## SYNOPSIS

```c
#include <nng/nng.h>

void *nng_msg_header(nng_msg *msg);
size_t nng_msg_header_len(nng_msg *msg);
void nng_msg_header_clear(nng_msg *msg);
int nng_msg_header_append(nng_msg *msg, const void *val, size_t size);
int nng_msg_header_append_u16(nng_msg *msg, uint16_t val16);
int nng_msg_header_append_u32(nng_msg *msg, uint32_t val32);
int nng_msg_header_append_u64(nng_msg *msg, uint64_t val64);
int nng_msg_header_insert(nng_msg *msg, const void *val, size_t size);
int nng_msg_header_insert_u16(nng_msg *msg, uint16_t val16);
int nng_msg_header_insert_u32(nng_msg *msg, uint32_t val32);
int nng_msg_header_insert_u64(nng_msg *msg, uint64_t val64);
int nng_msg_header_chop(nng_msg *msg, size_t size);
int nng_msg_header_chop_u16(nng_msg *msg, uint16_t *val16);
int nng_msg_header_chop_u32(nng_msg *msg, uint32_t *val32);
int nng_msg_header_chop_u64(nng_msg *msg, uint64_t *val64);
int nng_msg_header_trim(nng_msg *msg, size_t size);
int nng_msg_header_trim_u16(nng_msg *msg, uint16_t *val16);
int nng_msg_header_trim_u32(nng_msg *msg, uint32_t *val32);
int nng_msg_header_trim_u64(nng_msg *msg, uint64_t *val64);
```

## DESCRIPTION

The {{i:header}} of a message contains protocol and transport-specific
header content.
Typically there is only a very limited amount of data stored in the message
headers, in order to allow more room for the message body data. Headers
should be considered overhead in the protocols where they appear.

> [!TIP]
> Most applications should not need to access the message header content
> directly, unless they are working with [raw mode][raw] sockets.

The `nng_msg_header` function returns a pointer to the start of the header
content of the message _msg_.

> [!NOTE]
> The value returned by this is invalidated by a call to any of the
> functions that modify the message or the header content.

### Clearing the Message Header

The message headers can be entirely cleared using {{i:`nng_msg_header_clear`}}.
The underlying buffers are left intact, and the bytes may remain at their original values, so
this function should not be relied upon for zeroizing sensitive data.

### Appending and Inserting Data

Appending data to a message header is done by using the {{i:`nng_msg_header_append`}} functions,
and inserting data in the header is done using the {{i:`nng_msg_header_insert`}} functions.

These functions act just like the [`nng_msg_append`][nng_msg_body] and [`nng_msg_insert`][nng_msg_body]
functions, except that they operate on the message header rather than the message body.

### Consuming Data

The {{i:`nng_msg_header_trim`}} functions remove data from the beginning of the message header,
and the {{i:`nng_msg_header_chop`}} functions remove data from the end of the message header.

These functions act just like the [`nng_msg_trim`][nng_msg_body] and [`nng_msg_chop`][nng_msg_body]
functions, except that they operate the message header rather than the message body.

## RETURN VALUES

The `nng_msg_header` function returns a pointer to the start of the message header.
The `nng_msg_header_len` function returns the length of the message header in bytes.
The `nng_msg_header_clear` function does not return anything.
The remaining functions return zero on success, or a non-zero error value on failure.

## ERRORS

- `NNG_ENOMEM`: Insufficient memory exists to grow the message.
- `NNG_EINVAL`: The message body is too short to remove the requested data.

## SEE ALSO

[nng_msg][nng_msg],
[nng_msg_body][nng_msg_body],
[raw mode][raw]

[nng_msg]: ./nng_msg.md
[nng_msg_body]: ./nng_msg_body.md
[raw]: TODO.md
