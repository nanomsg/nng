# Devices

```c
nng_err nng_device(nng_socket s1, nng_socket s2);
void nng_device_aio(nng_aio *aio, nng_socket s1, nng_socket s2);
```

{{hi:device}}
{{hi:forwarder}}
{{hi:reflector}}
The {{i:`nng_device`}} and {{i:`nng_device_aio`}} functions forward messages
received from one [socket] to another socket.
Devices are useful for creating forwarders, proxies, and other network
topologies that improve scalability, reliability, or isolation.

Only [raw] mode sockets may be used with devices.
These sockets are created using the `_raw` forms of the protocol constructors,
such as [`nng_req0_open_raw`].

## Socket Ownership

When either function starts the device successfully, ownership of the sockets
transfers to the device.
The application must not use those sockets again, including closing them with
[`nng_socket_close`].
Attempts to use sockets that are owned by a device fail with [`NNG_EBUSY`].

The device closes the sockets when it stops.
If the device fails to start, ownership remains with the caller, and the caller
is still responsible for closing the sockets.

## Synchronous Devices

The {{i:`nng_device`}} function starts the device and blocks until the device
stops.
This form is intended for simple applications where the device is the primary
control flow.

Applications that need to stop a device under program control should use
[`nng_device_aio`] instead.

## Asynchronous Devices

The {{i:`nng_device_aio`}} function starts the device in the background and
returns immediately.
To stop the device, cancel the _aio_ with [`nng_aio_cancel`] and then wait for
the operation to complete with [`nng_aio_wait`].
The sockets are closed by the device during teardown.

## Reflectors

One socket may be initialized with [`NNG_SOCKET_INITIALIZER`] instead of being
opened.
In this case the other socket must be valid, bidirectional, raw, and able to
peer with itself, such as [PAIR][pair] or [BUS][bus].
The device acts as a reflector, returning messages received from the valid
socket back to that socket.

## Forwarders

When both sockets are valid, they must be compatible peers.
For example, [PUB][pub] may be paired with [SUB][sub], and [BUS][bus] may be
paired with [BUS][bus].

When a protocol has routing information in the message header, the device uses
the raw protocol processing to preserve and update that information as needed.
This lets replies and responses return through forwarders to the correct
requesters or surveyors.

Devices operate in best-effort delivery mode.
If a received message cannot be accepted by the other socket because of
backpressure or another error, the message is discarded.

## Return Values

The {{i:`nng_device`}} function returns `NNG_OK` if the device stops without an
error, or an error code if the device fails.
The {{i:`nng_device_aio`}} function reports its result through the supplied
_aio_.

## Errors

[`NNG_EBUSY`]
: At least one socket is already owned by a device.

[`NNG_ECLOSED`]
: At least one socket is not open.

[`NNG_EINVAL`]
: The sockets are not compatible, are not raw, or are both invalid.

[`NNG_ENOMEM`]
: Insufficient memory is available.

## See Also

[Asynchronous I/O][aio],
[Sockets][socket],
[Protocols][protocol]

{{#include ../xref.md}}
