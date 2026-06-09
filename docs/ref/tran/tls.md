# TLS Transport

## DESCRIPTION

The {{i:*tls* transport}}{{hi:*tls*}} provides communication between
peers across a TCP/IP network using {{i:TLS}} over TCP.
Both {{i:IPv4}} and {{i:IPv6}} are supported when the underlying platform supports them.

The protocol details are documented in the
[TLS Mapping for Scalability Protocols](http://nanomsg.org/rfcs/sp-tls-v1.html).
TLS configuration objects and certificate APIs are documented in [TLS].

### URI Formats

This transport uses URIs using the scheme {{i:`tls+tcp://`}}, followed by an
{{i:IP address}} or {{i:hostname}}, and a TCP port number.
For example, `tls+tcp://127.0.0.1:4433` and `tls+tcp://localhost:4433`
both refer to port 4433 on the local host.

For IPv6 literal addresses, the IPv6 address must be enclosed in square brackets,
then the colon and finally the TCP port.
For example, `tls+tcp://[::1]:4433` refers to port 4433 on the IPv6 loopback address.

#### Forcing IPv4 or IPv6

To force either IPv4 or IPv6, the scheme may be specified as `tls+tcp4://` or
`tls+tcp6://`.
This should only be needed when a hostname might resolve to either address family.

> [!NOTE]
> Specifying `tls+tcp6://` may not prevent IPv4 hosts from being used with
> IPv4-in-IPv6 addresses, particularly when listening on wildcard addresses.
> The details vary across operating systems.
> The `tls+tcp4://` and `tls+tcp6://` schemes are specific to NNG.

#### Listening to All Addresses

When listening, a zero IP address can be supplied by either eliding the address altogether,
or by specifying `0.0.0.0` (IPv4) or `::` (IPv6) explicitly.
If left empty, IPv6 will be selected if available on the host, otherwise IPv4 will be selected.

For example, the following URIs are equivalent for listening on port 9999:

- `tls+tcp://0.0.0.0:9999`
- `tls+tcp://:9999`

> [!TIP]
> Certificate validation generally works best when clients use host names rather than IP addresses.
> The name in the URL is used when validating the certificate supplied by the server.

### Socket Address

When using an [`nng_sockaddr`] structure,
the concrete type is either [`nng_sockaddr_in`] or [`nng_sockaddr_in6`],
depending on whether IPv4 or IPv6 is in use.

### Transport Options

The following transport options are supported by this transport,
where supported by the underlying platform.
Options that change connection behavior must be set before the dialer or listener is started.

| Option                                                                 | Type     | Description                                                                                                                     |
| ---------------------------------------------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------- |
| `NNG_OPT_TCP_NODELAY`                                                  | `bool`   | Disable or enable use of {{i:Nagle's algorithm}} for TCP connections. Normally should be set to `true`.                         |
| `NNG_OPT_TCP_KEEPALIVE`                                                | `bool`   | Enable or disable use of TCP keep-alive. Set to `false` by default.                                                             |
| `NNG_OPT_TLS_VERIFIED`<a name="NNG_OPT_TLS_VERIFIED"></a>              | `bool`   | Read-only option indicating whether the remote peer was verified using TLS authentication.                                      |
| `NNG_OPT_TLS_PEER_CN`<a name="NNG_OPT_TLS_PEER_CN"></a>                | `string` | Read-only option returning the common name from the peer certificate, when available.                                           |
| `NNG_OPT_BOUND_PORT`<a name="NNG_OPT_BOUND_PORT"></a>                  | `int`    | The locally bound TCP port number (1-65535), read-only for [listener] objects only.                                             |

> [!NOTE]
> `NNG_OPT_TLS_VERIFIED` and `NNG_OPT_TLS_PEER_CN` may not be meaningful if peer authentication is disabled.
> For richer peer certificate information, use [`nng_pipe_peer_cert`] or another peer certificate API.

{{#include ../xref.md}}
