# Messages

Messages in Scalability Protocols are the fundamental unit of transmission
and reception,
as these protocols are fundamentally message-oriented.

## Message object

An `nng_msg` represents a single {{i:message}} sent between Scalability Protocols peers.

Messages have a {{i:body}}, containing the application supplied
payload, and a {{i:header}}, containing protocol specific routing and similar
related information.

> [!TIP]
> Only applications using [raw mode][raw] need to
> access the message header.

### Creating, Destroying and Using

Messages are allocated using [`nng_msg_alloc()`][nng_msg_alloc],
and are deallocated using [`nng_msg_free()`][nng_msg_free].

In addition there are other functions used to access message contents,
including adding data to either the beginning or end of the message,
automatic data conversion, and removing data from the beginning or end.

### Performance Considerations

While there are convenience wrappers for sending and receiving arrays of
bytes, using message objects directly when possible will give better
performance by reducing data copies and needless allocations.

These functions are designed to try to avoid copying message contents
by making use of scratch areas at the beginning and end of the message.
These scratch areas, the "{{i:headroom}}" and "{{i:tailroom}}", are automatically
included when allocating a message.

### Direct Use Forbidden

The `nng_msg` structure is opaque, and applications should never try to
rely on the size of it, nor access internal members directly.
This insulates the application from changes in subsequent _NNG_ versions
that would affect the binary representation of the `nng_msg` itself.

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

## See Also

[nng_aio_get_msg][nng_aio_get_msg],
[nng_aio_set_msg][nng_aio_set_msg],
[nng_msg_alloc][nng_msg_alloc],
[nng_msg_append][nng_msg_append],
[nng_msg_body][nng_msg_body],
[nng_msg_capacity][nng_msg_capacity],
[nng_msg_dup][nng_msg_dup],
[nng_msg_free][nng_msg_free],
[nng_msg_header][nng_msg_header],
[nng_msg_header_append][nng_msg_header_append],
[nng_msg_header_chop][nng_msg_header_chop],
[nng_msg_header_clear][nng_msg_header_clear],
[nng_msg_header_insert][nng_msg_header_insert],
[nng_msg_header_len][nng_msg_header_len],
[nng_msg_header_trim][nng_msg_header_trim],
[nng_msg_insert][nng_msg_insert],
[nng_msg_len][nng_msg_len],
[nng_msg_reserve][nng_msg_reserve],
[nng_msg_realloc][nng_msg_realloc],
[nng_msg_set_pipe][nng_msg_set_pipe],
[nng_msg_trim][nng_msg_trim],
[nng_recvmsg][nng_recvmsg],
[nng_sendmsg][nng_sendmsg]

{{#include ../refs.md}}
