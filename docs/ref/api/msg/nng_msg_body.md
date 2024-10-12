# nng_msg_body

## NAME

nng_msg_body --- message body

## SYNOPSIS

```c
#include <nng/nng.h>

void *nng_msg_body(nng_msg *msg);
size_t nng_msg_len(nng_msg *msg);
void nng_msg_clear(nng_msg *msg);
int nng_msg_append(nng_msg *msg, const void *val, size_t size);
int nng_msg_append_u16(nng_msg *msg, uint16_t val16);
int nng_msg_append_u32(nng_msg *msg, uint32_t val32);
int nng_msg_append_u64(nng_msg *msg, uint64_t val64);
int nng_msg_insert(nng_msg *msg, const void *val, size_t size);
int nng_msg_insert_u16(nng_msg *msg, uint16_t val16);
int nng_msg_insert_u32(nng_msg *msg, uint32_t val32);
int nng_msg_insert_u64(nng_msg *msg, uint64_t val64);
int nng_msg_chop(nng_msg *msg, size_t size);
int nng_msg_chop_u16(nng_msg *msg, uint16_t *val16);
int nng_msg_chop_u32(nng_msg *msg, uint32_t *val32);
int nng_msg_chop_u64(nng_msg *msg, uint64_t *val64);
int nng_msg_trim(nng_msg *msg, size_t size);
int nng_msg_trim_u16(nng_msg *msg, uint16_t *val16);
int nng_msg_trim_u32(nng_msg *msg, uint32_t *val32);
int nng_msg_trim_u64(nng_msg *msg, uint64_t *val64);
```

## DESCRIPTION

The {{i:body}} of a message is the part of the message that is used
for the application payload, and does not normally include protocol
or transport-specific data.

The `nng_msg_body` function returns a pointer to the start of the body
content of the message _msg_.

The `nng_msg_len` function returns the length of the message body in bytes.

> [!IMPORTANT]
> The value returned by `nng_msg_body` is invalidated by a call to any of the
> functions that modify the message itself.

The rest of these functions allow modifying the message body.

### Clearing the Message Body

The message body can be entirely cleared using {{i:`nng_msg_clear`}}.
The underlying buffers are left intact, and the bytes may remain at their original values, so
this function should not be relied upon for zeroizing sensitive data.

### Appending and Inserting Data

Appending data to a message body is done by using the {{i:`nng_msg_append`}} functions.
The base `nng_msg_append` function appends _size_ bytes of untyped data to the end of the
message.

> [!TIP]
> Using [`nng_msg_reserve`][nng_msg] to preallocate space before appending or inserting
> can reduce allocations and data copies, for a significant performance benefit.

Use of the typed versions, ending in suffixes `_u16`, `_u32`, and `_u64` allows
for unsigned integers to be appended directly. The integers are encoded in network byte order, with
the most significant byte appearing first. The message body will by two, four, or eight
bytes accordingly.

Data may inserted before the rest of the message body by using the {{i:`nng_msg_insert`}} functions.
This will attempt to use "headroom" in the message to avoid a data copy.

> [!TIP]
> Message headroom is limited, so `nng_msg_insert` is best used sparingly.
> It is much more efficient to build the message content from start to end
> using `nng_msg_append`.

Typed versions and the untyped base function behave similarly to the `nng_msg_append` functions.

### Consuming Data

The {{i:`nng_msg_trim`}} functions remove data from the beginning of the message body.
This is accomplished by incrementing the pointer to start of the message by the appropriate size.

Additionally, functions with typed suffixes (`_u16`, `_u32`, `_u64`) allow the data obtained to be decoded and returned.
The data is assumed to have been in network byte order in the message, but is returned in
the native machine byte order. The appropriate number of bytes is consumed for each of these types,
so two bytes for `_u16`, four bytes for `_u32`, and eight bytes for `_u64`.

The {{i:`nng_msg_chop`}} functions behave in a similar fashion, but consume data from the
end of the message body.

## RETURN VALUES

The `nng_msg_body` function returns a pointer to the start of the message body.
The `nng_msg_len` function returns the length of the message in bytes.
The `nng_msg_clear` function does not return anything.
The remaining functions return zero on success, or a non-zero error value on failure.

## ERRORS

- `NNG_ENOMEM`: Insufficient memory exists to grow the message.
- `NNG_EINVAL`: The message body is too short to remove the requested data.

## SEE ALSO

[nng_msg][nng_msg],
[nng_msg_header][nng_msg_header]

[nng_msg]: ./nng_msg.md
[nng_msg_header]: ./nng_msg_header.md
