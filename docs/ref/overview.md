# Overview

NNG provides a common messaging framework for solving communication problems
in distributed applications. It is built around two core ideas:
[protocols](proto/index.md), which define messaging semantics, and
[transports](tran/index.md), which define how peers communicate over an
underlying mechanism such as TCP, IPC, TLS, WebSocket, or in-process channels.

Protocols implement communication patterns such as request/reply,
publish/subscribe, pipelines, surveys, and buses. Transports provide the
underlying connection or message delivery mechanism. New transports can be
added without changing applications that use the socket API, and custom
protocols can be added for specialized applications.

NNG is wire-compatible with the SP protocols described by the
[nanomsg](https://github.com/nanomsg/nanomsg) project, so applications can
interoperate with other conforming implementations such as
[mangos](https://github.com/go-mangos/mangos). Applications that need this
interoperability must use protocols and transports supported by both peers.

NNG also provides compatibility interfaces for some legacy nanomsg code, but
new applications should use the native NNG APIs described in this reference.
The library itself is implemented in C; bindings for other languages are
provided by other projects.

## Conceptual Model

NNG presents a [socket](api/sock.md) view of networking. Sockets are created
with protocol-specific constructors, and each socket implements exactly one
protocol. A socket may send messages, receive messages, or both, depending on
the protocol. It also enforces protocol-specific behavior, such as subscription
filtering for subscriber sockets or request/reply matching for request sockets.

NNG sockets are message-oriented. A message is delivered whole or not at all;
partial message delivery is not exposed to the application. NNG does not make
general ordering or delivery guarantees beyond those supplied by a specific
protocol. Some protocols add stronger behavior through their own retry,
matching, or validation mechanisms.

Sockets communicate through [dialers and listeners](api/endpoint.md), also
called endpoints. Dialers initiate outbound connections to a URL, while
listeners accept inbound connections at a URL. A socket may use dialers,
listeners, both, or neither.

Endpoints do not themselves carry application data. They create
[pipes](api/pipe.md), which are message-oriented connections between peers.
For stream-oriented transports such as TCP and IPC, a pipe usually corresponds
to a single connected operating-system socket. Listeners create pipes when new
peer connections arrive; dialers create pipes by connecting to their configured
remote address and typically reconnect after a disconnection.

Most applications do not need to manage endpoints or pipes directly. The socket
abstraction is usually sufficient unless the application needs connection
metadata, endpoint options, pipe notifications, or a proxy-style topology.

## Raw Mode

Most applications use sockets in normal, or cooked, mode. Cooked sockets provide
the full protocol semantics automatically. Applications that need to bypass
those semantics, such as proxies and devices, can use
[raw mode sockets](api/sock.md#raw-mode-sockets) instead.

Raw mode gives the application direct responsibility for protocol headers and
protocol-specific processing. It is usually unnecessary unless an application is
forwarding messages or implementing protocol behavior itself.

## URLs

NNG identifies service addresses with [URLs](api/url.md). URL schemes select
the transport, and the rest of the URL supplies transport-specific addressing
information. NNG follows RFC 3986 URL syntax, with additional schemes for SP
transports and additional canonicalization rules described in the URL API
reference.
