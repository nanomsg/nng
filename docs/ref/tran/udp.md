# UDP Transport (Experimental)

## Description

The {{i:*udp* transport}} supports communication between peers using {{i:UDP}}.

UDP is a very light-weight connection-less, unreliable, unordered delivery mechanism.

Both {{i:IPv4}} and {{i:IPv6}} are supported when the underlying platform also supports it.

This transport adds an ordering guarantee, so that messages will always be received in
the correct order. Messages that arrive out of order, or are duplicated, will be
dropped. There may be gaps in the messages received, so applications should not assume
that all messages sent will arrive.

> [!NOTE]
> This transport is _experimental_.

## URL Format

This transport uses URIs using the scheme {{i:`udp://`}}, followed by
an IP address or hostname, followed by a colon and finally a
UDP {{i:port number}}.
For example, to contact port 8001 on the localhost either of the following URIs
could be used: `udp://127.0.0.1:8001` or `udp://localhost:8001`.

A URI may be restricted to IPv6 using the scheme `udp6://`, and may
be restricted to IPv4 using the scheme `udp4://`.

> [!NOTE]
> Specifying `udp6://` may not prevent IPv4 hosts from being used with
> IPv4-in-IPv6 addresses, particularly when using a wildcard hostname with
> listeners.
> The details of this varies across operating systems.

> [!TIP]
> We recommend using either numeric IP addresses, or names that are
> specific to either IPv4 or IPv6 to prevent confusion and surprises.

When specifying IPv6 addresses, the address must be enclosed in
square brackets (`[]`) to avoid confusion with the final colon
separating the port.

For example, the same port 8001 on the IPv6 loopback address (`::1`) would
be specified as `udp://[::1]:8001`.

The special value of 0 ({{i:`INADDR_ANY`}})
can be used for a listener to indicate that it should listen on all
interfaces on the host.
A short-hand for this form is to omit the IP address entirely.
For example, the following two URIs are equivalent,
and could be used to listen to port 9999 on the host:

1. `udp://0.0.0.0:9999`
2. `udp://:9999`

## Socket Address

When using an [`nng_sockaddr`] structure,
the actual structure is either of type
[`nng_sockaddr_in`] (for IPv4) or
[`nng_sockaddr_in6`] (for IPv6).

## Transport Options

The following transport options are supported by this transport,
where supported by the underlying platform.

| Option                                                    | Type     | Description                                                                                                         |
| --------------------------------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------- |
| [`NNG_OPT_RECVMAXSZ`]                                     | `size_t` | Maximum size of incoming messages, will be limited to at most 65000.                                                |
| `NNG_OPT_UDP_COPY_MAX`<a name="NNG_OPT_UDP_COPY_MAX"></a> | `size_t` | Threshold above which received messages are "loaned" up, rather than a new message being allocated and copied into. |
| `NNG_OPT_BOUND_PORT`<a name="NNG_OPT_BOUND_PORT"></a>     | `int`    | The locally bound UDP port number (1-65535), read-only for [listener] objects only.                                 |

## Maximum Message Size

This transport maps each SP message to a single UDP packet.
In order to allow room for network headers, we thus limit the maximum
message size to 65000 bytes, minus the overhead for any SP protocol headers.

However, applications are _strongly_ encouraged to only use this transport for
very much smaller messages, ideally those that will fit within a single network
packet without requiring fragmentation and reassembly.

For Ethernet without jumbo frames, this typically means an {{i:MTU}} of a little
less than 1500 bytes. (Specifically, 1452, which allows 28 bytes for IPv4 and UDP,
and 20 bytes for the this transport. Reduce by an additional 20 bytes for IPv6.)

Other link layers may have different MTUs, however IPv6 requires a minimum MTU of 1280,
which after deducting 48 bytes for IPv6 and UDP headers, and 20 bytes for our transport
header, leaves 1212 bytes for user data. If additional allowances are made for SP protocol
headers with a default TTL of 8 (resulting in 72 additional bytes for route information),
the final user accessible payload will be 1140 bytes. Thus this can be likely be viewed
as a safe maximum to employ for SP payload data across all transports.

The maximum message size is negotiated as part of establishing a peering relationship,
and oversize messages will be dropped by the sender before going to the network.

The maximum message size to receive can be configured with the [`NNG_OPT_RECVMAXSZ`] option.

## Keep Alive

This transports maintains a logical "connection" with each peer, to provide a rough
facsimile of a connection based semantic. This requires some resource on each peer.
In order to ensure that resources are reclaimed when a peer vanishes unexpectedly, a
keep-alive mechanism is implemented.

TODO: Document the tunables for this.

{{#include ../xref.md}}
