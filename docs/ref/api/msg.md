# Messages

Messages {{hi:messages}} in Scalability Protocols are the fundamental unit of
transmission and reception, as these protocols are fundamentally message-oriented.

Messages have a [body][nng_msg_body]{{hi:body}}, containing the application-supplied
payload, and a [header][nng_msg_header]{{hi:header}}, containing protocol specific routing and similar
related information.

> [!TIP]
> Only applications using [raw mode][raw] need to access the message header.
> Very few _NNG_ applications do this.

## Message Structure

```c
typedef struct nng_msg nng_msg;
```

The {{i:`nng_msg`}} structure represents a single message. It carries a body
and a header.

### Create a Message

```c
int nng_msg_alloc(nng_msg **msgp, size_t size);
```

The {{i:`nng_msg_alloc`}} function allocates a new message.
It takes a _size_ argument, and returns a message
with a preallocated body of that size in the _msgp_ parameter.

If it succeeds, it returns zero, otherwise this function may return [`NNG_ENOMEM`],
indicating that insufficient memory is available to allocate a new message.

### Destroy a Message

```c
void nng_msg_free(nng_msg *msg);
```

The {{i:`nng_msg_free`}} function deallocates a message.

### Duplicate a Message

```c
int nng_msg_dup(nng_msg **dup, nng_msg *msg);
```

The {{i:`nng_msg_dup`}} function duplicates the message _msg_, storing a pointer
to the new duplicate in _dup_. This function also returns zero on succes, or [`NNG_ENOMEM`]
if memory is exhausted.

## Message Size and Capacity

```c
size_t nng_msg_capacity(nng_msg *msg);
int nng_msg_realloc(nng_msg *msg, size_t size);
int nng_msg_reserve(nng_msg *msg, size_t capacity);
```

Messages have a certain amount of pre-reserved space, which may exceed the total
size of the message. This allows for content to be added to the message later,
without necessarily performing a reallocation.

The {{i:`nng_msg_capacity`}} function returns the amount of prereserved space.
If a message size change is required, and the new size will fit within the capacity
reported by this function, then change will be done without a reallocation, and
likely without a data copy as well.

> [!TIP]
> The capacity reported by `nng_msg_capacity` may not include reserved headroom, which
> is present to allow a very limited amount of content to be inserted in front of the
> message without requiring the rest of the message to be copied.

The message size may be changed by use of the {{i:`nng_msg_realloc`}} function. This
function will reallocate the underlying memory for the message _msg_,
preserving contents while doing so.
If the new size is smaller than the original message, it will
truncate the message, but not perform any allocations.
If reallocation fails due to insufficient memory, then the original is left intact.

The {{i:`nng_msg_reserve`}} function ensures that the total message capacity
is at least _capacity_ bytes. Use of this function to ensure the total anticipated
capacity is present in the message may help prevent many small allocations.

Both `nng_msg_realloc` and `nng_msg_reserve` return zero on success, or may return
[`NNG_ENOMEM`] if insufficient memory exists to preform allocation.

> [!IMPORTANT]
> Any pointers to message content obtained before a call to `nng_msg_realloc` or
> `nng_msg_reserve` (or any other function that changes the message size) should be
> treated as invalid, as the locations pointed to may be deallocated by these functions.

## Message Body

```c
void *nng_msg_body(nng_msg *msg);
size_t nng_msg_len(nng_msg *msg);
```

The body and body length of _msg_ are returned by {{i:`nng_msg_body`}} and
{{i:`nng_msg_len`}}, respectively.

### Clear the Body

```c
void *nng_msg_clear(nng_msg *msg);
```

The {{i:`nng_msg_clear`}} simply resets the total message body length to zero, but does
not affect the capacity. It does not change the underlying bytes of the message.

### Add to Body

```c
int nng_msg_append(nng_msg *msg, const void *val, size_t size);
int nng_msg_append_u16(nng_msg *msg, uint16_t val16);
int nng_msg_append_u32(nng_msg *msg, uint32_t val32);
int nng_msg_append_u64(nng_msg *msg, uint64_t val64);

int nng_msg_insert(nng_msg *msg, const void *val, size_t size);
int nng_msg_insert_u16(nng_msg *msg, uint16_t val16);
int nng_msg_insert_u32(nng_msg *msg, uint32_t val32);
int nng_msg_insert_u64(nng_msg *msg, uint64_t val64);
```

Appending data to a message body is done by using the {{i:`nng_msg_append`}} functions.
The base `nng_msg_append` function appends _size_ bytes of untyped data to the end of the
message.

Use of the typed versions, ending in suffixes `_u16`, `_u32`, and `_u64` allows
for unsigned integers to be appended directly. The integers are encoded in network byte order, with
the most significant byte appearing first. The message body will by two, four, or eight
bytes accordingly.

Data may inserted before the rest of the message body by using the {{i:`nng_msg_insert`}} functions.
This will attempt to use "headroom" in the message to avoid a data copy.
Otherwise they are like the `nng_msg_append` functions except that the put the data in front
of the messages instead of at the end.

> [!TIP]
> Message headroom is limited, so `nng_msg_insert` is best used sparingly.
> It is much more efficient to build the message content from start to end
> using `nng_msg_append`.

### Consume From Body

```c
int nng_msg_chop(nng_msg *msg, size_t size);
int nng_msg_chop_u16(nng_msg *msg, uint16_t *val16);
int nng_msg_chop_u32(nng_msg *msg, uint32_t *val32);
int nng_msg_chop_u64(nng_msg *msg, uint64_t *val64);

int nng_msg_trim(nng_msg *msg, size_t size);
int nng_msg_trim_u16(nng_msg *msg, uint16_t *val16);
int nng_msg_trim_u32(nng_msg *msg, uint32_t *val32);
int nng_msg_trim_u64(nng_msg *msg, uint64_t *val64);
```

The {{i:`nng_msg_chop`}} functions remove data from the end of the body of message _msg_,
reducing the message length by either _size_, or the appropriate value size.

The {{i:`nng_msg_trim`}} functions remove data from the beginning of the message body of _msg_.
but are otherwise just like the `nng_msg_chop` functions.

If the message is not big enough to remove requisite amount of bytes, these functions
return `NNG_EINVAL`. Otherwise they return zero.

Additionally, functions with typed suffixes (`_u16`, `_u32`, `_u64`) decode the data and return it
through the appropriate _val_ pointer.

The data is assumed to have been in network byte order in the message, but is returned in
the native machine byte order. The appropriate number of bytes is consumed for each of these types,
so two bytes for `_u16`, four bytes for `_u32`, and eight bytes for `_u64`.

## Message Header

```c
void *nng_msg_header(nng_msg *msg);
size_t nng_msg_header_len(nng_msg *msg);
```

The header and header length of _msg_ are returned by {{i:`nng_msg_header`}} and
{{i:`nng_msg_header_len`}}, respectively.

The message headers are generally intended for limited use, to store protocol headers.

> [!IMPORTANT]
> The message headers are for protocol and transport headers, and not for general
> application payloads. Misuse of the header may prevent the application from functioning
> properly.

### Clear the Header

```c
void *nng_msg_header_clear(nng_msg *msg);
```

The {{i:`nng_msg_header_clear`}} simply resets the total message header length to zero.

### Append or Insert Header

Appending data to a message header is done by using the {{i:`nng_msg_header_append`}} functions,
and inserting data in the header is done using the {{i:`nng_msg_header_insert`}} functions.

These functions act just like the [`nng_msg_append`] and [`nng_msg_insert`] functions,
except that they operate on the message header rather than the message body.

### Consume from Header

The {{i:`nng_msg_header_trim`}} functions remove data from the beginning of the message header,
and the {{i:`nng_msg_header_chop`}} functions remove data from the end of the message header.

These functions act just like the [`nng_msg_trim`] and [`nng_msg_chop`] functions,
except that they operate the message header rather than the message body.

## Message Pipe

```c
nng_pipe nng_msg_get_pipe(nng_msg *msg);
void nng_msg_get_pipe(nng_msg *msg, nng_pipe p);
```

The {{i:`nng_msg_set_pipe`}} function sets the [pipe] associated with _msg_ to _p_.
This is most often useful when used with protocols that support directing
a message to a specific peer.
For example the [_PAIR_][pair] version 1 protocol can do
this when `NNG_OPT_PAIR1_POLY` mode is set.

The {{i:`nng_msg_get_pipe`}} function returns the pipe that was previously set on the message _m_,
either directly by the application, or when the message was received by the protocol.

> [!NOTE]
> Not all protocols support overriding the destination pipe.

## Examples

### Example 1: Preparing a message for use

```c
    #include <nng/nng.h>

    nng_msg *m;
    if (nng_msg_alloc(&m, strlen("content") + 1) != 0) {
       // handle error
    }
    strcpy(nng_msg_body(m), "content");
```

### Example 2: Preallocating message content

```c
    if (nng_msg_alloc(&m, 1024) != 0) {
        // handle error
    }
    while ((val64 = next_datum()) != 0) P
        if (nng_msg_append_u64(m, val64) != 0) {
            // handle error
        }
    }
```

{{#include ../xref.md}}
