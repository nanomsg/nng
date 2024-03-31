# nng_device

## NAME

nng_device - message forwarding device

## SYNOPSIS

```c
#include <nng/nng.h>

int nng_device(nng_socket s1, nng_socket s2);

void nng_device_aio(nng_aio *aio, nng_socket s1, nng_socket s2);
```

### DESCRIPTION

The `nng_device()` and `nng_device_aio()` functions forward messages received from one
[socket][socket] _s1_ to another socket _s2_, and vice versa.

These functions are used to create forwarders, which can be used to create
complex network topologies to provide for improved {{i:horizontal scalability}},
reliability, and isolation.

Only [raw mode][raw] sockets may be used with this
function.
These can be created using `_raw` forms of the various socket constructors,
such as [`nng_req0_open_raw()`][nng_req_open].

The `nng_device()` function does not return until one of the sockets
is closed.
The `nng_device_aio()` function returns immediately, and operates completely in
the background.

### Reflectors

One of the sockets passed may be an unopened socket initialized with
the {{i:`NNG_SOCKET_INITIALIZER`}} special value.
If this is the case, then the other socket must be valid, and must use
a protocol that is bidirectional and can peer with itself
(such as [_PAIR_][pair] or [_BUS_][bus]).
In this case the device acts as a {{i:reflector}} or {{i:loop-back}} device,
where messages received from the valid socket are merely returned
to the sender.

## Forwarders

When both sockets are valid, then the result is a {{i:forwarder}} or proxy.
In this case sockets _s1_ and _s2_ must be compatible with each other,
which is to say that they should represent the opposite halves of a two
protocol pattern, or both be the same protocol for a single protocol
pattern.
For example, if _s1_ is a [_PUB_][pub] socket, then _s2_ must
be a [_SUB_][sub] socket.
Or, if _s1_ is a [_BUS_][bus] socket, then _s2_ must also
be a _BUS_ socket.

### Operation

The `nng_device()` function moves messages between the provided sockets.

When a protocol has a {{i:backtrace}} style header, routing information
is present in the header of received messages, and is copied to the
header of the output bound message.
The underlying raw mode protocols supply the necessary header
adjustments to add or remove routing headers as needed.
This allows replies to be
returned to requesters, and responses to be routed back to surveyors.

The caller of these functions is required to close the sockets when the
device is stopped.

Additionally, some protocols have a maximum {{i:time-to-live}} to protect
against forwarding loops and especially amplification loops.
In these cases, the default limit (usually 8), ensures that messages will
self-terminate when they have passed through too many forwarders,
protecting the network from unlimited message amplification that can arise
through misconfiguration.
This is controlled via the [`NNG_OPT_MAXTTL`][NNG_OPT_MAXTTL] option.

> [!NOTE]
> Not all protocols have support for guarding against forwarding loops,
> and even for those that do, forwarding loops can be extremely detrimental
> to network performance.

> [!NOTE]
> Devices (forwarders and reflectors) act in {{i:best-effort}} delivery
> mode only.
> If a message is received from one socket that cannot be accepted by the
> other (due to {{i:back-pressure}} or other issues), then the message is discarded.

> [!TIP]
> Use the request/reply pattern, which includes automatic retries by
> the requester, if reliable delivery is needed.

## RETURN VALUES

This function continues running, and only returns an appropriate error when
one occurs, or if one of the sockets is closed.

## ERRORS

- `NNG_ECLOSED`: At least one of the sockets is not open.
- `NNG_ENOMEM`: Insufficient memory is available.
- `NNG_EINVAL`: The sockets are not compatible, or are both invalid.

## SEE ALSO

[Sockets][socket],
[Raw mode][raw]

{{#include ../refs.md}}
