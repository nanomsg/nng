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
To contact port 80 on the local host, either `tcp://127.0.0.1:80` or
`tcp://localhost:80` can be used.

For IPv6 literal addresses, the IPv6 address must be enclosed in square brackets,
then the colon and finally the TCP port. For example, `tcp://[::1]:7890` would
refer to a service running on the IPv6 loopback (`::1`) on TCP port 7890.

#### Forcing IPv4 or IPv6

To force the selection of either IPv4 or IPv6, the scheme may be specified as either
`tcp4://` or `tcp6://` instead of just `tcp://`. This should only be needed when
a hostname that might resolve either way is supplied instead of an explicit IP address.

> [!NOTE]
> `tcp4://` and `tcp6://` are specific to NNG and may not be understood by
> other Scalability Protocol implementations.
>
> Additionally, `tcp6://` may still permit IPv4 peers via IPv4-mapped IPv6
> addresses on some platforms, especially when listening on wildcard
> addresses.

#### Listening to All Addresses

When listening, a zero IP address can be supplied by either eliding the address altogether,
or by specifying `0.0.0.0` (IPv4) or `::` (IPv6) explicitly. If left empty, IPv6 will
be selected if available on the host, otherwise IPv4 will be selected.

For example, the following URIs are equivalent ways to listen on TCP port
9999 on all IPv4 interfaces:

1. `tcp://0.0.0.0:9999`
2. `tcp://:9999`

> [!TIP]
> IP addresses may be more reliable than host names. Certainly when using the URL
> for a [listener], it is better to use an IP address that is known to exist on the
> local system, or the zero address to listen to all interfaces.

> [!TIP]
> Prefer numeric IP addresses or hostnames known to resolve only to the
> intended address family. This avoids surprises when a name can resolve to
> both IPv4 and IPv6.

### Socket Address

When using an [`nng_sockaddr`],
the concrete type is either [`nng_sockaddr_in`] or [`nng_sockaddr_in6`], depending on whether
IPv4 or IPv6 is in use.

### Other TCP-Relevant Options

TCP dialers and listeners may also expose inherited options such as the local
address and configured URL, depending on the object and context. See the common
option documentation in the broader API reference for those shared semantics.

### Transport Options

The following transport options are supported by this transport,
where supported by the underlying platform.
Options that change connection behavior should be set before the [dialer] or
[listener] is started.

| Option                                                | Type   | Description                                                                                                                                         |
| ----------------------------------------------------- | ------ | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| `NNG_OPT_TCP_NODELAY`                                 | `bool` | Disable or enable use of {{i:Nagle's algorithm}} for TCP connections. When `true` (the default), data is sent promptly rather than waiting to coalesce into larger writes. On low-bandwidth links, enabling Nagle's algorithm by setting this to `false` can reduce overhead at the cost of latency. |
| `NNG_OPT_TCP_KEEPALIVE`                               | `bool` | Enable or disable TCP keep-alive. This is `false` by default. When enabled, the system periodically probes otherwise idle connections to detect dead peers and keep stateful middleboxes from expiring the connection. |
| `NNG_OPT_PEER_GID`                                    | `int`  | Read-only option, returns the group ID of the process at the other end of the socket, if platform supports it and the peer is on the same system.   |
| `NNG_OPT_PEER_PID`                                    | `int`  | Read-only option, returns the process ID of the process at the other end of the socket, if platform supports it and the peer is on the same system. |
| `NNG_OPT_PEER_UID`                                    | `int`  | Read-only option, returns the user ID of the process at the other end of the socket, if platform supports it and the peer is on the same system.    |
| `NNG_OPT_PEER_ZONEID`                                 | `int`  | Read-only option, returns the zone ID of the process at the other end of the socket, if platform supports it and the peer is on the same system.    |
| [`NNG_OPT_LISTEN_FD`]                                 | `int`  | Write-only for listeners before they start. Supplies an already-created listening file descriptor or `SOCKET`, which is useful for socket activation and similar supervisor-managed startup flows. |
| `NNG_OPT_BOUND_PORT`<a name="NNG_OPT_BOUND_PORT"></a> | `int`  | The locally bound TCP port number (1-65535), read-only for [listener] objects only. This is especially useful after binding to port zero to discover the ephemeral port actually selected by the system. |

> [!NOTE]
> For `NNG_OPT_TCP_NODELAY` and `NNG_OPT_TCP_KEEPALIVE`, setting the option on
> a dialer or listener affects connections created afterwards. It does not
> retroactively reconfigure existing live connections.

{{#include ../xref.md}}
