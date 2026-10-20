# DTLS Transport

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
> It requires TLS support and the `NNG_TRANSPORT_DTLS` build option.
> When using wolfSSL, version 5.8.0 or newer is required for correct replay protection
> with DTLS 1.2. Builds with DTLS 1.3 enabled require wolfSSL 5.9.1 or newer.
> wolfSSL must support configurable MTUs (`--enable-dtls-mtu`, or
> `WOLFSSL_OPENSSLALL=yes` with CMake).
> Older wolfSSL versions may still be used for stream TLS with `NNG_TRANSPORT_DTLS=OFF`.
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

Use separate configuration objects for DTLS and stream TLS.
A configuration is bound to its transport type on first use; reusing it for the other type fails with [`NNG_EINVAL`].

DTLS 1.2 is supported by all three TLS engines.
DTLS 1.3 is supported with wolfSSL built with DTLS 1.3 enabled, and with
OpenSSL 4.1 or newer built with DTLS 1.3 enabled.
Mbed TLS and earlier OpenSSL releases support DTLS 1.2 only.

[`nng_tls_config_version`] uses `NNG_TLS_1_2` and `NNG_TLS_1_3` to select the
corresponding DTLS versions. The default range permits both; the highest
mutually supported version is negotiated.
To require DTLS 1.3, set both limits to `NNG_TLS_1_3` before starting the endpoint.
If the engine cannot support any DTLS version in the configured range,
starting the endpoint fails with [`NNG_ENOTSUP`].

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
| [`NNG_OPT_UDP_CONN_RETRY`]                             | `nng_duration` | Interval between connection requests while dialing. The default is 200 milliseconds. Only positive values are accepted; `<= 0` returns `NNG_EINVAL`. |
| [`NNG_OPT_UDP_CONN_EXPIRE`]                            | `nng_duration` | Time allowed to establish a connection, including inbound listener handshakes. The default is 5 seconds. Only positive values are accepted; `<= 0` returns `NNG_EINVAL`. |
| [`NNG_OPT_UDP_MAX_PEERS`]                              | `size_t` | Maximum number of pending inbound connections, including connections awaiting cleanup. The default is 1024; set to 0 to disable the limit. |
| [`NNG_OPT_DTLS_CONN_RATE`]                             | `size_t` | New inbound handshake allocations per second, with a burst of the same size. The default is 128; set to 0 to disable the rate limit. |
| [`NNG_OPT_BOUND_PORT`] | `int`    | The locally bound UDP port number (1-65535), read-only for [listener] objects only.                                             |

The DTLS transport does not support TCP-specific options such as
`NNG_OPT_TCP_NODELAY` or `NNG_OPT_TCP_KEEPALIVE`.

### Peer Admission

A listener screens traffic from unknown source addresses before allocating TLS
state. Only an initial ClientHello fragment with a plausible DTLS record and
handshake header is admitted. The declared ClientHello length must not exceed
16 KiB. The screen permits fragmented ClientHello messages when the first
fragment arrives first; other fragments from unknown sources are discarded until
the client retransmits the first fragment. wolfSSL and older Mbed TLS versions
require an unfragmented initial ClientHello before cookie validation.

Each admitted source consumes handshake state even before its address or
identity has been verified. Cookie exchanges validate the source address before
the server sends its certificate flight, but admission is not stateless.
The listener applies two independent limits:

- [`NNG_OPT_UDP_MAX_PEERS`] limits pending inbound connections to 1024 by default.
  A connection holds a slot through TLS and NNG protocol negotiation. A failed
  connection continues to hold its slot until its resources have been released.
  Established connections do not count toward this limit.
- [`NNG_OPT_DTLS_CONN_RATE`] limits allocations for new inbound handshakes to
  128 per second by default. The listener starts with credit for 128 allocations;
  credit replenishes continuously at the configured rate, up to the same burst
  limit. Failed handshakes also consume credit. This option accepts values from
  0 through `UINT32_MAX`.

Set these options on the listener before starting it. Setting either option to
0 disables that limit independently. Attempts to change them after starting the
listener fail with [`NNG_EBUSY`].

[`NNG_OPT_UDP_CONN_EXPIRE`] sets the deadline for both inbound and outbound
connection establishment, including TLS and NNG protocol negotiation. The
listener default is 5 seconds from admission; packets discarded before admission
do not start a deadline or extend another connection's deadline.

Traffic from existing peers bypasses the admission limits. When a limit is
reached, new sources are silently discarded and may retry after capacity becomes
available. Sustained traffic containing plausible ClientHello messages can
therefore delay legitimate new connections. Applications expecting many new
connections at once should adjust these limits and the connection deadline for
their workload.

When statistics are enabled, each listener exposes `peer_pending` for the number
of pending connections, `peer_alloc` for the number of inbound handshake
allocations, `peer_invalid` for datagrams rejected by the initial screen,
`peer_rate` for admissions rejected by the rate limit, and `peer_reject` for
admissions rejected by the pending connection limit.

### Maximum Message Size

This transport maps each NNG message to a DTLS record carried over UDP.
The transport maximum is smaller than the 16 KiB DTLS record size to leave room
for DTLS and transport headers.
The receive maximum can be configured with [`NNG_OPT_RECVMAXSZ`], but it cannot
exceed the DTLS transport maximum.
NNG protocol headers count toward this maximum, so the largest application
payload depends on the messaging protocol.
Operating systems may impose a lower limit on UDP datagram size.

Applications are encouraged to use much smaller messages whenever possible.
Large UDP datagrams are more likely to be fragmented at the IP layer, and a lost
fragment causes the entire message to be lost.

### Keep Alive

DTLS maintains a logical connection for each peer and uses periodic transport
control messages to refresh that state.
Peers that are inactive for too long are closed and their resources are reclaimed.

{{#include ../xref.md}}
