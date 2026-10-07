# UDP Transport (Experimental)

## Description

The {{i:*udp* transport}} supports communication between peers using {{i:UDP}}.

UDP is a lightweight, connectionless, unreliable, unordered delivery mechanism.

Both {{i:IPv4}} and {{i:IPv6}} are supported when the underlying platform also supports it.

This transport preserves NNG message boundaries, but does not add retransmission,
ordering, or duplicate suppression. Applications must tolerate messages being lost,
reordered, or duplicated.

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
> The details of this vary across operating systems.

> [!TIP]
> We recommend using either numeric IP addresses, or names that are
> specific to either IPv4 or IPv6 to prevent confusion and surprises.

When specifying IPv6 addresses, the address must be enclosed in
square brackets (`[]`) to avoid confusion with the final colon
separating the port.

For example, the same port 8001 on the IPv6 loopback address (`::1`) would
be specified as `udp://[::1]:8001`.

For a listener, use the IPv4 address `0.0.0.0` or the IPv6 address `::`
to listen on all interfaces of that family. To listen on all IPv4 interfaces
on port 9999, use:

`udp4://0.0.0.0:9999`

To listen on all IPv6 interfaces on the same port, use:

`udp6://[::]:9999`

The abbreviated form `udp://:9999` leaves the address family to the platform
resolver and should be used only when either family is acceptable.

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
| [`NNG_OPT_UDP_CONN_RETRY`]                                 | `nng_duration` | Interval between connection requests while dialing. The default is 200 milliseconds.                                 |
| [`NNG_OPT_UDP_CONN_EXPIRE`]                                | `nng_duration` | Time allowed to establish a connection. The default is 5 seconds.                                                   |
| `NNG_OPT_UDP_MAX_PEERS`<a name="NNG_OPT_UDP_MAX_PEERS"></a> | `size_t` | Maximum number of remote peers admitted by a listener. The default is 1024; set to 0 to disable the limit. |
| `NNG_OPT_BOUND_PORT`<a name="NNG_OPT_BOUND_PORT"></a>     | `int`    | The locally bound UDP port number, read-only. A listener reports its bound port; a dialer reports its ephemeral port after opening its UDP socket. |

## Maximum Message Size

This transport maps each SP message to a single UDP packet.
In order to allow room for network headers, we thus limit the maximum
message size to 65000 bytes, minus the overhead for any SP protocol headers.

However, applications are _strongly_ encouraged to only use this transport for
very much smaller messages, ideally those that will fit within a single network
packet without requiring fragmentation and reassembly.

For Ethernet without jumbo frames, this typically means an {{i:MTU}} of a little
less than 1500 bytes. (Specifically, 1464 bytes before SP protocol headers, which
allows 28 bytes for IPv4 and UDP, and 8 bytes for this transport. Reduce by an
additional 20 bytes for IPv6.)

Other link layers may have different MTUs, however IPv6 requires a minimum MTU of 1280,
which after deducting 48 bytes for IPv6 and UDP headers, and 8 bytes for our transport
header, leaves 1224 bytes for user data. If additional allowances are made for SP protocol
headers with a default TTL of 8 (resulting in 72 additional bytes for route information),
the final user accessible payload will be 1152 bytes. Thus this can likely be viewed
as a safe maximum to employ for SP payload data across all transports.

The maximum message size is negotiated as part of establishing a peering relationship,
and oversize messages will be dropped by the sender before going to the network.

The maximum message size to receive can be configured with the [`NNG_OPT_RECVMAXSZ`] option.

## Peer Admission

Each new source address causes the listener to allocate a logical UDP peer.
To bound the resources consumed by spoofed or otherwise untrusted connection
requests, listeners admit at most 1024 peers by default. Configure
[`NNG_OPT_UDP_MAX_PEERS`] before starting the listener to select another
limit. A value of 0 disables this protection.

## Connection Establishment

UDP dialers retry their connection request every 200 milliseconds by default
and give up after 5 seconds. Configure [`NNG_OPT_UDP_CONN_RETRY`] and
[`NNG_OPT_UDP_CONN_EXPIRE`] before starting a dialer to adjust these durations.
Both options take an [`nng_duration`] and require a positive value.
Values less than or equal to zero are rejected with `NNG_EINVAL`.

## Keep Alive

This transport maintains a logical "connection" with each peer, to provide a rough
facsimile of a connection based semantic. This requires some resource on each peer.
In order to ensure that resources are reclaimed when a peer vanishes unexpectedly, a
keep-alive mechanism is implemented.

{{#include ../xref.md}}
