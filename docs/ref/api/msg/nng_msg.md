# nng_msg

## NAME

nng_msg --- message

## SYNOPSIS

```c
#include <nng/nng.h>

typedef struct nng_msg nng_msg;

int nng_msg_alloc(nng_msg **msgp, size_t size);
void nng_msg_free(nng_msg *msg);
int nng_msg_dup(nng_msg **dup, nng_msg *msg);
int nng_msg_realloc(nng_msg *msg, size_t size);
int nng_msg_reserve(nng_msg *msg, size_t capacity);
size_t nng_msg_capacity(nng_msg *msg);
```

## DESCRIPTION

An {{i:`nng_msg`}} represents a single {{i:message}} sent between Scalability Protocols peers.

Messages in Scalability Protocols are the fundamental unit of transmission and reception,
as these protocols are fundamentally message-oriented.

> [!NOTE]
> The `nng_msg` structure is opaque, and applications should never try to
> rely on the size of it, nor access internal members directly.
> This insulates the application from changes in subsequent _NNG_ versions
> that would affect the binary representation of the `nng_msg` itself.

Messages have a [body][nng_msg_body]{{hi:body}}, containing the application-supplied
payload, and a [header][nng_msg_header]{{hi:header}}, containing protocol specific routing and similar
related information.

> [!TIP]
> Only applications using [raw mode][raw] need to access the message header.

### Creating and Destroying Messages

Messages are allocated using {{i:`nng_msg_alloc`}},
and are deallocated using {{i:`nng_msg_free`}}.

The `nng_msg_alloc` function takes a _size_ argument, and returns a message
with a preallocated body of that size in the _msgp_ parameter.

Messages can be deallocated when no longer needed using `nng_msg_free`.

A message may be duplicated using the {{i:`nng_msg_dup`}} function, which can be useful
when a copy must be saved or modified. The contents of the duplicate message will
be the same, but the actual pointers may be different, and the amount of reserved
space may be different as well.

### Message Size and Capacity

The message size may be changed by use of the {{i:`nng_msg_realloc`}} function. This
function will reallocate the underlying memory for the message _msg_,
preserving contents while doing so.
If the new size is smaller than the original message, it will
truncate the message, but not perform any allocations.
If reallocation fails due to insufficient memory, then the original is left intact.

If message growth is anticipated, the {{i:`nng_msg_reserve`}} function can be used
to ensure that the buffers underlying the message will be sufficient to hold a message
of at least _capacity_ bytes. The actual message {{i:capacity}} can be obtained using the
{{i:`nng_msg_capacity`}}. As long as the new size will not exceeed that capacity,
any functions that change the message will do so without an allocation, and are guaranteed
to succeed.

> [!IMPORTANT]
> Any pointers to message content obtained before a call to `nng_msg_realloc` or
> `nng_msg_reserve` (or any other function that changes the message size) should be
> treated as invalid, as the locations pointed to may be deallocated by these functions.

### Performance Considerations

While there are convenience wrappers for sending and receiving arrays of
bytes, using message objects directly when possible will give better
performance by reducing data copies and needless allocations.

These functions are designed to try to avoid copying message contents
by making use of scratch areas at the beginning and end of the message.
These scratch areas, the "{{i:headroom}}" and "{{i:tailroom}}", are automatically
included when allocating a message.

Using `nng_msg_reserve` to ensure that adequate buffer space is available
in advance can reduce repeated allocations and data copies when modifying messages.

## RETURN VALUES

The `nng_msg_alloc`, `nng_msg_dup`, `nng_msg_realloc`, and `nng_msg_reserve`
functions return zero on success, or an error value on failure, typically `NNG_ENOMEM`.

The `nng_msg_capacity` function returns the total body capacity of the message _msg_.

## ERRORS

- `NNG_ENOMEM`: Insufficient free memory exists to perform the operation.

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

## SEE ALSO

[nng_aio_get_msg][nng_aio_get_msg],
[nng_msg_body][nng_msg_body],
[nng_msg_header][nng_msg_header],
[nng_msg_set_pipe][nng_msg_set_pipe],
[nng_recvmsg][nng_recvmsg],
[nng_sendmsg][nng_sendmsg]

[nng_msg_body]: ./nng_msg_body.md
[nng_msg_header]: ./nng_msg_header.md
[nng_msg_set_pipe]: ./nng_msg_set_pipe.md
[nng_aio_get_msg]: TODO.md
[nng_aio_set_msg]: TODO.md
[nng_recvmsg]: TODO.md
[nng_sendmsg]: TODO.md
[raw]: TODO.md
