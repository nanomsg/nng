# WebSocket Transport

## DESCRIPTION

The {{i:*WebSocket* transport}}{{hi:*WebSocket*}} provides communication
between peers across a TCP/IP network using
[WebSockets](https://www.rfc-editor.org/rfc/rfc6455).
It supports the Scalability Protocols over WebSocket, and also supports
raw WebSocket connections through the [streams] API.

Both IPv4 and IPv6 are supported when the underlying platform supports them.
The protocol details for Scalability Protocol sockets are documented in the
[WebSocket Mapping for Scalability Protocols](http://nanomsg.org/rfcs/sp-websocket-v1.html).

The secure WebSocket schemes use TLS over TCP.
TLS configuration objects and certificate APIs are documented in [TLS], and
the underlying TCP behavior is similar to the [TCP] and [TLS transport] transports.
WebSocket handshakes use NNG's [HTTP Support](../api/http.md).

### URI Formats

This transport uses URIs using the scheme {{i:`ws://`}}, followed by an
{{i:IP address}} or {{i:hostname}}, an optional TCP port number, and an
optional path.
If no port is specified, port 80 is used.
If no path is specified, `/` is used.

For example, `ws://localhost/app/pubsub` connects to port 80 on `localhost`,
using the path `/app/pubsub`.
The path is significant: different listeners can share the same host and port
when they use different WebSocket paths.

Secure WebSocket endpoints use the {{i:`wss://`}} scheme and default to TCP port 443.
The URI format is otherwise the same as `ws://`.

#### Forcing IPv4 or IPv6

To force either IPv4 or IPv6, the scheme may be specified as `ws4://` or
`ws6://` instead of `ws://`.
The secure forms are `wss4://` and `wss6://`.
These should only be needed when a hostname might resolve to either address family.

> [!NOTE]
> Specifying `ws6://` or `wss6://` may not prevent IPv4 hosts from being used with
> IPv4-in-IPv6 addresses, particularly when listening on wildcard addresses.
> The details vary across operating systems.
> The `ws4://`, `ws6://`, `wss4://`, and `wss6://` schemes are specific to NNG.

#### IPv6 Addresses

For IPv6 literal addresses, the IPv6 address must be enclosed in square brackets.
For example, `ws://[::1]:8080/app/pubsub` refers to port 8080 on the IPv6
loopback address with the path `/app/pubsub`.

#### Listening to All Addresses

When listening, a zero IP address can be supplied by either eliding the address
altogether, or by specifying `0.0.0.0` (IPv4) or `::` (IPv6) explicitly.
If left empty, IPv6 will be selected if available on the host, otherwise IPv4
will be selected.

For example, the following URIs are equivalent for listening on port 9999:

- `ws://0.0.0.0:9999/pipe`
- `ws://:9999/pipe`

> [!TIP]
> IP addresses may be more reliable than host names for listeners.
> Certificate validation for `wss://` endpoints generally works best when
> clients use host names rather than IP addresses.

> [!NOTE]
> The URL host name, when present, is also used in the HTTP `Host` header
> during the WebSocket handshake.

### Socket Address

When using an [`nng_sockaddr`],
the concrete type is either [`nng_sockaddr_in`] or [`nng_sockaddr_in6`],
depending on whether IPv4 or IPv6 is in use.

### Shared HTTP Server Instances

WebSocket listeners use shared HTTP server instances.
This allows multiple sockets, stream listeners, or other HTTP services in the
same process to share a hostname and port.
For example, one process can listen on `ws://:8080/one` and `ws://:8080/two`
with different NNG sockets.

When a listener is created, it is registered with an existing HTTP server
instance when one can be found.
The matching algorithm uses the configured hostname or IP address string and
port, so listeners are easiest to reason about when they use numeric IP
addresses or an empty host name.

Because a shared server instance has one TLS configuration, changing the TLS
configuration may not be possible after another listener has already started
that server.
The shared server instance can also be used by other NNG HTTP services in the
same process, such as static content handlers.

### Scalability Protocol Use

When the WebSocket transport is used with NNG sockets, it carries binary
Scalability Protocol messages over WebSocket binary frames.
The transport sets the WebSocket subprotocol during the handshake.
For example, a REQ socket advertises the peer protocol name expected by the
matching REP peer.

Applications can configure WebSocket headers, frame sizes, TCP options, and
TLS options on the usual [dialer] and [listener] objects before they are
started.
After a connection is established, HTTP handshake headers and the request URI
can be inspected from the [pipe].

### Stream Use

The same `ws://` and `wss://` URLs can be used with [`nng_stream_dialer_alloc`]
and [`nng_stream_listener_alloc`].
This mode gives applications direct access to a WebSocket connection as an
[`nng_stream`], using [`nng_stream_send`] and [`nng_stream_recv`].

Raw WebSocket streams use binary frames by default.
They can be configured to send or receive text frames with
[`NNG_OPT_WS_SEND_TEXT`] and [`NNG_OPT_WS_RECV_TEXT`], which is useful when
communicating with third-party WebSocket peers.
These text-frame options should not be used with Scalability Protocol sockets,
which require binary protocol data.

> [!NOTE]
> NNG does not validate that text frames contain valid UTF-8.
> Applications that need strict RFC 6455 conformance must validate text data
> themselves and close the connection when invalid data is received.

### TLS Configuration

The `wss://`, `wss4://`, and `wss6://` schemes use TLS.
TLS support must be enabled in the NNG build.

For Scalability Protocol sockets, configure TLS with [`nng_dialer_set_tls`] or
[`nng_listener_set_tls`] before starting the dialer or listener.
For raw streams, configure TLS with [`nng_stream_dialer_set_tls`] or
[`nng_stream_listener_set_tls`] before dialing or listening.

The set functions take their own hold on the [`nng_tls_config`] object, so the
caller may release its reference after a successful call.
The corresponding get functions do not add a new hold; callers that retain the
returned configuration independently should call [`nng_tls_config_hold`].

Once the underlying HTTP server, dialer, or listener has started using a TLS
configuration, that configuration cannot be changed.
This is especially important when multiple `wss://` listeners share the same
HTTP server instance.

Peer certificate information can be obtained with [`nng_pipe_peer_cert`] for
Scalability Protocol pipes or [`nng_stream_peer_cert`] for streams.

### Transport and Stream Options

The following options are supported by this transport, where supported by the
underlying platform.
Options that change connection behavior must be set before the dialer,
listener, stream dialer, or stream listener is started.

| Option                                                                       | Type     | Description                                                                                                                                                                                                                                                                         |
| ---------------------------------------------------------------------------- | -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `NNG_OPT_TCP_NODELAY`                                                        | `bool`   | Disable or enable use of {{i:Nagle's algorithm}} for TCP connections. Normally should be set to `true`.                                                                                                                                                                             |
| `NNG_OPT_TCP_KEEPALIVE`                                                      | `bool`   | Enable or disable use of TCP keep-alive. Set to `false` by default.                                                                                                                                                                                                                 |
| `NNG_OPT_BOUND_PORT`<a name="NNG_OPT_BOUND_PORT"></a>                        | `int`    | The locally bound TCP port number (1-65535), read-only for listener objects only.                                                                                                                                                                                                    |
| `NNG_OPT_WS_HEADER`<a name="NNG_OPT_WS_HEADER"></a>                          | `string` | Option prefix for HTTP headers. Append the header name to set a handshake header on a dialer or listener, or to retrieve a received header from a connected pipe or stream. For example, `NNG_OPT_WS_HEADER "X-Trace-ID"` refers to the `X-Trace-ID` header.                         |
| `NNG_OPT_WS_PROTOCOL`<a name="NNG_OPT_WS_PROTOCOL"></a>                      | `string` | WebSocket subprotocol, corresponding to the `Sec-WebSocket-Protocol` header. Scalability Protocol sockets configure this automatically.                                                                                                                                              |
| `NNG_OPT_WS_REQUEST_URI`<a name="NNG_OPT_WS_REQUEST_URI"></a>                | `string` | Read-only request URI sent by the client, available from connected pipes and streams. This is useful for listeners that handle a subtree.                                                                                                                                            |
| `NNG_OPT_WS_SENDMAXFRAME`<a name="NNG_OPT_WS_SENDMAXFRAME"></a>              | `size`   | Maximum WebSocket frame size to send before fragmenting. The default is 64 KiB. Larger values can improve throughput but may increase latency and peer buffering requirements. There is no WebSocket negotiation for this value.                                                     |
| `NNG_OPT_WS_RECVMAXFRAME`<a name="NNG_OPT_WS_RECVMAXFRAME"></a>              | `size`   | Maximum WebSocket frame size accepted from the peer. Frames larger than this are rejected. This should not normally be larger than [`NNG_OPT_RECVMAXSZ`].                                                                                                                           |
| `NNG_OPT_WS_HEADER_RESET`<a name="NNG_OPT_WS_HEADER_RESET"></a>              | `bool`   | Read-only option for connected pipes and streams. Reading it resets HTTP header iteration to the beginning.                                                                                                                                                                         |
| `NNG_OPT_WS_HEADER_NEXT`<a name="NNG_OPT_WS_HEADER_NEXT"></a>                | `bool`   | Read-only option for connected pipes and streams. Reading it advances HTTP header iteration. It returns `true` when another header is available, and `false` when iteration is complete.                                                                                            |
| `NNG_OPT_WS_HEADER_KEY`<a name="NNG_OPT_WS_HEADER_KEY"></a>                  | `string` | Read-only option for connected pipes and streams. Returns the current HTTP header name after [`NNG_OPT_WS_HEADER_NEXT`] has returned `true`.                                                                                                                                         |
| `NNG_OPT_WS_HEADER_VALUE`<a name="NNG_OPT_WS_HEADER_VALUE"></a>              | `string` | Read-only option for connected pipes and streams. Returns the current HTTP header value after [`NNG_OPT_WS_HEADER_NEXT`] has returned `true`.                                                                                                                                        |
| `NNG_OPT_WS_SEND_TEXT`<a name="NNG_OPT_WS_SEND_TEXT"></a>                    | `bool`   | Raw streams only. Send WebSocket text frames instead of binary frames. NNG does not validate UTF-8.                                                                                                                                                                                  |
| `NNG_OPT_WS_RECV_TEXT`<a name="NNG_OPT_WS_RECV_TEXT"></a>                    | `bool`   | Raw streams only. Accept inbound WebSocket text frames as well as binary frames. NNG does not validate UTF-8.                                                                                                                                                                        |
| `NNG_OPT_TLS_VERIFIED`<a name="NNG_OPT_TLS_VERIFIED"></a>                    | `bool`   | `wss://` only. Read-only option indicating whether the remote peer was verified using TLS authentication.                                                                                                                                                                           |
| `NNG_OPT_TLS_PEER_CN`<a name="NNG_OPT_TLS_PEER_CN"></a>                      | `string` | `wss://` only. Read-only option returning the common name from the peer certificate, when available.                                                                                                                                                                                |

> [!NOTE]
> `NNG_OPT_TLS_VERIFIED` and `NNG_OPT_TLS_PEER_CN` may not be meaningful if
> peer authentication is disabled.
> For richer peer certificate information, use [`nng_pipe_peer_cert`] or
> [`nng_stream_peer_cert`].

{{#include ../xref.md}}
