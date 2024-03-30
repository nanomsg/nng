# nng_msg_clear

## NAME

nng_msg_clear --- clear message body content

## SYNOPSIS

```c
#include <nng/nng.h>

void nng_msg_clear(nng_msg *msg);
```

## DESCRIPTION

The `nng_msg_clear()` function resets the body length of [message][msg] _msg_ to zero.

## SEE ALSO

[nng_msg_alloc][nng_msg_alloc],
[nng_msg_capacity][nng_msg_capacity],
[nng_msg_reserve][nng_msg_reserve]

{{#include ../refs.md}}
