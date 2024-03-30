# nng_pub_open

## NAME

nng*pub_open --- create \_PUB* socket

## SYNOPSIS

```c
#include <nng/nng.h>
#include <nng/protocol/pubsub0/pub.h>

int nng_pub0_open(nng_socket *s);

int nng_pub0_open_raw(nng_socket *s);
```

== DESCRIPTION

The `nng_pub0_open()` function creates a [_PUB_](../../protocols/pub.md) version 0
[socket](index.md) and returns it at the location pointed to by _s_.

The `nng_pub0_open_raw()` function creates a [_PUB_](../../protocols/pub.md) version 0
[socket](index.md) in
[raw](../../overview/raw.md) mode and returns it at the location pointed to by _s_.

## RETURN VALUES

These functions return 0 on success, and non-zero otherwise.

## ERRORS

- `NNG_ENOMEM`: Insufficient memory is available.
- `NNG_ENOTSUP`: The protocol is not supported.

## SEE ALSO

[PUB Protocol](../../protocols/pub.md),
[SUB Protocol](../../protocols/sub.md)
