# nng_msg_header_clear

## NAME

nng_msg_header_clear --- clear message header

## SYNOPSIS

```c
#include <nng/nng.h>

void nng_msg_header_clear(nng_msg *msg);
```

## DESCRIPTION

The `nng_msg_clear()` function resets the header length of _msg_ to zero.

## SEE ALSO

[nng_msg_header](nng_msg_header.md),
[nng_msg_header_len](nng_msg_header_len.md)
