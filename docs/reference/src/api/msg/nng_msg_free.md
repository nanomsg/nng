# nng_msg_free

## NAME

nng_msg_free --- free a message

## SYNOPSIS

```c
#include <nng/nng.h>

void nng_msg_free(nng_msg *msg);
```

## DESCRIPTION

The `nng_msg_free()` function deallocates the message _msg_ entirely.

## SEE ALSO

[nng_msg_alloc](nng_msg_alloc.md),
[nng_msg_realloc](nng_msg_realloc.md)
