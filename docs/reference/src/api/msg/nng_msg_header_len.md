# nng_msg_header_len

## NAME

nng_msg_header_len --- return message header length

## SYNOPSIS

```c
#include <nng/nng.h>

size_t nng_msg_header_len(nng_msg *msg);
```

## DESCRIPTION

The `nng_msg_header_len()` returns the length of message header of _msg_.

## RETURN VALUES

Length of message header.

## SEE ALSO

[nng_msg_header](nng_msg_header)
