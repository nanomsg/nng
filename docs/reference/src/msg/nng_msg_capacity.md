# nng_msg_capacity

## NAME

nng_msg_capacity --- return message body length

## SYNOPSIS

```c
#include <nng/nng.h>

size_t nng_msg_capacity(nng_msg *msg);
```

## DESCRIPTION

The `nng_msg_capacity()` returns the storage allocated for the body of [message][msg] _msg_.
The capacity includes the current contents of the message and free space after it.
The message body may grow to capacity without performing any further allocations.

## RETURN VALUES

Allocated capacity for message body.

## SEE ALSO

[nng_msg_alloc][nng_msg_alloc],
[nng_msg_realloc][nng_msg_realloc],
[nng_msg_reserve][nng_msg_reserve]
[nng_msg_body][nng_msg_body]

{{#include ../refs.md}}
