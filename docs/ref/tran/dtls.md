# DTLS Transport (Experimental)

## DESCRIPTION

The {{i:*dtls* transport}}{{hi:*dtls*}} provides encrypted and authenticated
communication between peers using {{i:DTLS}} over {{i:UDP}}.
Both {{i:IPv4}} and {{i:IPv6}} are supported when the underlying platform
supports them.

DTLS provides TLS-like security for datagram transports. This transport is
message-oriented and preserves NNG message boundaries, but it is still based on
UDP and does not provide TCP-style reliable delivery. Applications should avoid
large messages and should tolerate message loss caused by the network.

TLS configuration objects and certificate APIs are documented in [TLS].
DTLS [dialers][dialer] and [listeners][listener] must be configured with
[`nng_dialer_set_tls`] or [`nng_listener_set_tls`] before they are started.

> [!NOTE]
> This transport is _experimental_.
> It requires TLS support and the `NNG_TRANSPORT_DTLS` build option.
> It supports unicast UDP endpoints only; multicast and broadcast are not
> supported.

### URI Formats

This transport uses URIs using the scheme {{i:`dtls://`}}, followed by an
{{i:IP address}} or {{i:hostname}}, and a UDP port number.
For example, `dtls://127.0.0.1:4433` and `dtls://localhost:4433`
both refer to port 4433 on the local host.

For IPv6 literal addresses, the IPv6 address must be enclosed in square brackets,
then the colon and finally the UDP port.
For example, `dtls://[::1]:4433` refers to port 4433 on the IPv6 loopback
address.

#### Forcing IPv4 or IPv6

To force either IPv4 or IPv6, the scheme may be specified as `dtls4://` or
`dtls6://`.
This should only be needed when a hostname might resolve to either address family.

> [!NOTE]
> Specifying `dtls6://` may not prevent IPv4 hosts from being used with
> IPv4-in-IPv6 addresses, particularly when listening on wildcard addresses.
> The details vary across operating systems.
> The `dtls4://` and `dtls6://` schemes are specific to NNG.

#### Listening to All Addresses

When listening, a zero IP address can be supplied by either eliding the address
altogether, or by specifying `0.0.0.0` (IPv4) or `::` (IPv6) explicitly.
If left empty, IPv6 will be selected if available on the host, otherwise IPv4
will be selected.

For example, the following URIs are equivalent for listening on UDP port 9999:

- `dtls://0.0.0.0:9999`
- `dtls://:9999`

> [!TIP]
> Certificate validation generally works best when clients use host names rather
> than IP addresses.
> Configure the expected server name with [`nng_tls_config_server_name`] when the
> certificate identity differs from the URL host, or when an IP address is used.

### TLS Configuration

DTLS endpoints use [`nng_tls_config`] objects in the same way as the [TLS transport].
Listeners normally use a server-mode configuration with a local certificate and
private key.
Dialers normally use a client-mode configuration with certificate authority
material and the expected server name.
Pre-shared key configurations may also be used when supported by the selected TLS
engine.

The TLS configuration must be set before the dialer or listener is started.
After a DTLS endpoint has started, attempts to change its TLS configuration or
its receive maximum will fail with [`NNG_EBUSY`].

Peer certificates can be obtained from connected pipes with [`nng_pipe_peer_cert`],
subject to the TLS engine's certificate support and the authentication mode.

### Socket Address

When using an [`nng_sockaddr`] structure,
the concrete type is either [`nng_sockaddr_in`] or [`nng_sockaddr_in6`],
depending on whether IPv4 or IPv6 is in use.

### Transport Options

The following transport options are supported by this transport,
where supported by the underlying platform.
Options that change connection behavior must be set before the dialer or
listener is started.

| Option                                                | Type     | Description                                                                                                                     |
| ----------------------------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------- |
| [`NNG_OPT_RECVMAXSZ`]                                 | `size_t` | Maximum size of incoming messages. Values larger than the DTLS transport maximum are clamped to the transport maximum.          |
| [`NNG_OPT_UDP_MAX_PEERS`]                              | `size_t` | Maximum number of unauthenticated inbound DTLS handshakes. The default is 1024; set to 0 to disable the limit.                   |
| `NNG_OPT_BOUND_PORT`<a name="NNG_OPT_BOUND_PORT"></a> | `int`    | The locally bound UDP port number (1-65535), read-only for [listener] objects only.                                             |

The DTLS transport does not support TCP-specific options such as
`NNG_OPT_TCP_NODELAY` or `NNG_OPT_TCP_KEEPALIVE`.

## Peer Admission

DTLS only adds a pipe to the socket after TLS has validated an inbound peer.
Before that point, each source address consumes handshake state. Listeners
therefore admit at most 1024 unauthenticated peers by default. Configure
[`NNG_OPT_UDP_MAX_PEERS`] before starting the listener to select another limit.
A value of 0 disables this protection.

### Maximum Message Size

This transport maps each NNG message to a DTLS record carried over UDP.
The transport maximum is smaller than the 16 KiB DTLS record size to leave room
for DTLS and transport headers.
The receive maximum can be configured with [`NNG_OPT_RECVMAXSZ`], but it cannot
exceed the DTLS transport maximum.

Applications are encouraged to use much smaller messages whenever possible.
Large UDP datagrams are more likely to be fragmented at the IP layer, and a lost
fragment causes the entire message to be lost.

### Keep Alive

DTLS maintains a logical connection for each peer and uses periodic transport
control messages to refresh that state.
Peers that are inactive for too long are closed and their resources are reclaimed.

{{#include ../xref.md}}
