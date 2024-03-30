# TCP transport

The {{i:*tcp* transport}}{{hi:*tcp*}} provides communication support between
sockets across a {{i:TCP/IP}} network.

Both IPv4 and IPv6 are supported when the underlying platform also supports it.

## URI Format

This transport uses URIs using the scheme {{i:`tcp://`}}, followed by
an IP address or hostname, followed by a colon and finally a
TCP {{i:port number}}.
For example, to contact port 80 on the localhost either of the following URIs
could be used: `tcp://127.0.0.1:80` or `tcp://localhost:80`.

A URI may be restricted to IPv6 using the scheme `tcp6://`, and may
be restricted to IPv4 using the scheme `tcp4://`.

> [!NOTE]
> Specifying `tcp6://` may not prevent IPv4 hosts from being used with
> IPv4-in-IPv6 addresses, particularly when using a wildcard hostname with
> listeners.
> The details of this varies across operating systems.

> [!NOTE]
> Both `tcp6://` and `tcp4://` are specific to _NNG_, and might not
> be understood by other implementations.

> [!TIP]
> We recommend using either numeric IP addresses, or names that are
> specific to either IPv4 or IPv6 to prevent confusion and surprises.

When specifying IPv6 addresses, the address must be enclosed in
square brackets (`[]`) to avoid confusion with the final colon
separating the port.

For example, the same port 80 on the IPv6 loopback address (`::1`) would
be specified as `tcp://[::1]:80`.

The special value of 0 ({{i:`INADDR_ANY`}})
can be used for a listener to indicate that it should listen on all
interfaces on the host.
A short-hand for this form is to either omit the address, or specify
the asterisk (`*`) character.
For example, the following three URIs are all equivalent,
and could be used to listen to port 9999 on the host:

1. `tcp://0.0.0.0:9999`
2. `tcp://*:9999`
3. `tcp://:9999`

The entire URI must be less than `NNG_MAXADDRLEN` bytes long.

## Socket Address

When using an [`nng_sockaddr`](../api/nng_sockaddr.md) structure,
the actual structure is either of type
[`nng_sockaddr_in`](../api/nng_sockaddr_in.md) (for IPv4) or
[`nng_sockaddr_in6`](../api/nng_sockaddr_in6.md) (for IPv6).

## Transport Options

The following transport options are supported by this transport,
where supported by the underlying platform.

- [`NNG_OPT_LOCADDR`](../api/nng_options.md#NNG_OPT_LOCADDR)
- [`NNG_OPT_REMADDR`](../api/nng_options.md#NNG_OPT_REMADDR)
- [`NNG_OPT_TCP_KEEPALIVE`](../api/nng_tcp_options.md#NNG_OPT_TCP_KEEPALIVE)
- [`NNG_OPT_TCP_NODELAY`](../api/nng_tcp_options.md#NNG_OPT_TCP_NODELAY)
- [`NNG_OPT_URL`](../api/nng_options.md#NNG_OPT_URL)
