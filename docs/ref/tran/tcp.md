# TCP Transport

## DESCRIPTION

The {{i:*tcp* transport}}{{hi:*tcp*}} provides communication support between
sockets within different processes using the TCP stream protocol over
IP or IPv6.

### URI Formats

This transport uses URIs using the scheme {{i:`tcp://`}}, followed by an
{{i:IP address}} or {{i:hostname}}, and port number, formatted as follows.

For host names and IPv4 literal addresses, the hostname or IP address is followed by
a colon, and then a TCP port number. For example, `tcp://myservice.net:123` would
refer to a server available at `myservice.net` on TCP port 123.

For IPv6 literal addresses, the IPv6 address must be enclosed in square brackets,
then the colon and finally the TCP port. For example, `tcp://[::1]:7890` would
refer to a service running on the IPv6 loopback (`::1`) on TCP port 7890.

#### Forcing IPv4 or IPv6

To force the selection of either IPv4 or IPv6, the scheme may be specified as either
`tcp4://` or `tcp6://` instead of just `tcp://`. This should only be needed when
a hostname that might resolve either way is supplied instead of an explicit IP address.

#### Listening to All Addresses

When listening, a zero IP address can be supplied by either eliding the address altogether,
or by specifying `0.0.0.0` (IPv4) or `::` (IPv6) explicitly. If left empty, IPv6 will
be selected if available on the host, otherwise IPv4 will be selected.

> [!TIP]
> IP addresses may be more reliable than host names. Certainly when using the URL
> for a [listener], it is better to use an IP address that is known to exist on the
> local system, or the zero address to listen to all interfaces.

### Socket Address

When using an [`nng_sockaddr`],
the concrete type is either [`nng_sockaddr_in`] or [`nng_sockaddr_in6`], depending on whether
IPv4 or IPv6 is in use.

### Transport Options

The following transport options are supported by this transport,
where supported by the underlying platform.

| Option                                                | Type   | Description                                                                                                                                         |
| ----------------------------------------------------- | ------ | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| `NNG_OPT_TCP_NODELAY`                                 | `bool` | Disable or enable use of {{i:Nagle's algorithm}} for TCP connections. Normally should be set to `true`.                                             |
| `NNG_OPT_TCP_KEEPALIVE`                               | `bool` | Enable or disable use of TCP keep-alive. Set to `false` by default.                                                                                 |
| `NNG_OPT_PEER_GID`                                    | `int`  | Read-only option, returns the group ID of the process at the other end of the socket, if platform supports it and the peer is on the same system.   |
| `NNG_OPT_PEER_PID`                                    | `int`  | Read-only option, returns the process ID of the process at the other end of the socket, if platform supports it and the peer is on the same system. |
| `NNG_OPT_PEER_UID`                                    | `int`  | Read-only option, returns the user ID of the process at the other end of the socket, if platform supports it and the peer is on the same system.    |
| `NNG_OPT_PEER_ZONEID`                                 | `int`  | Read-only option, returns the zone ID of the process at the other end of the socket, if platform supports it and the peer is on the same system.    |
| [`NNG_OPT_LISTEN_FD`]                                 | `int`  | Write-only for listeners before they start, use the named socket for accepting (for use with socket activation).                                    |
| `NNG_OPT_BOUND_PORT`<a name="NNG_OPT_BOUND_PORT"></a> | `int`  | The locally bound TCP port number (1-65535), read-only for [listener] objects only.                                                                 |

{{#include ../xref.md}}
