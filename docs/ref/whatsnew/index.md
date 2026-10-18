# What's New in NNG 2.0

NNG 2.0 expands the ways applications can communicate, adds more choices for
securing connections, and reduces overhead in common I/O paths. This chapter
highlights these improvements for readers familiar with NNG 1.x.
Some capabilities described here also appeared in later 1.x releases, so the
differences will depend on which 1.x release an application uses.

NNG 2.0 also makes changes to the application programming interface.
The [Migrating from NNG 1.x](../migrate/nng1.md) guide describes the changes
needed to update existing applications.

## New Transports and Local Connections

### UDP Messaging

The [UDP transport](../tran/udp.md) carries Scalability Protocols messages
over UDP, with support for both IPv4 and IPv6. It preserves message boundaries
and maintains logical peer connections, including keep-alive and peer expiry.
Applications use `udp://` URLs, or `udp4://` and `udp6://` to select an address
family explicitly.

UDP is useful for applications that prefer to discard lost or stale data
rather than wait for retransmission. It does not provide reliable delivery,
ordering, or duplicate suppression, so applications must tolerate those
conditions. Each message must fit in a single UDP datagram; small messages
that avoid IP fragmentation are recommended.

Connection retry and expiry intervals are configurable, and listeners can
limit the number of peers they admit. The transport can also loan larger
received buffers to the messaging layer to avoid an extra allocation and copy.

### DTLS Messaging

The new [DTLS transport](../tran/dtls.md) adds encryption and authentication
to datagram messaging using `dtls://`, `dtls4://`, and `dtls6://` URLs.
It uses the same [`nng_tls_config`] objects as stream TLS, making certificate
or pre-shared-key configuration familiar to applications already using TLS.
Available authentication methods depend on the selected TLS engine.

DTLS retains UDP's delivery characteristics; encryption does not add reliable
delivery or ordering. It is intended for small messages over unicast UDP.

> [!NOTE]
> DTLS is experimental and requires TLS support and the `NNG_TRANSPORT_DTLS`
> build option. The supported version is DTLS 1.2. Stream TLS 1.3 support does
> not imply DTLS 1.3 support. See the transport reference for engine requirements
> and message size limits.

### UNIX Domain Sockets on Windows

The [IPC transport](../tran/ipc.md) now supports Windows AF_UNIX sockets.
Applications can use `ipc://` or its `unix://` alias for UNIX domain socket
communication on Windows systems that provide this facility, as well as on
POSIX systems. Windows paths use the Win32 pathname format.

Windows named pipes remain available through the explicit `winpipe://`
scheme. This matters when interoperating with older Windows NNG applications:
NNG 1.x used `ipc://` for named pipes, while NNG 2.0 uses it for AF_UNIX sockets.
Use `winpipe://` in the NNG 2.0 application to communicate with a legacy
named-pipe peer.

### Existing File Descriptors and Socket Pairs

The [Socket transport](../tran/socket.md), sometimes called the file descriptor
or FD transport, lets an application attach an already-connected BSD socket
to an NNG socket. A `socket://` listener accepts connected descriptors through
the `NNG_OPT_SOCKET_FD` option, and each supplied descriptor becomes an NNG pipe.
The application can therefore arrange connection establishment separately
from NNG's messaging protocols.

The [`nng_socket_pair`] function creates a pair of connected descriptors for
this purpose. For example, a parent and child process can communicate without
creating a named filesystem socket or opening a TCP port. Both this function
and the Socket transport are supported on POSIX platforms only.

### Socket Activation

Applications can use an externally created listening socket with supported
listeners through [`NNG_OPT_LISTEN_FD`]. This enables integration with service
managers such as systemd, which can create a listening socket before starting
the application and pass it to the service.

Socket activation is available for TCP on POSIX and Windows, and for UNIX
domain sockets on POSIX. It is also exposed through the stream API.
See the [socket activation example](../api/stream.md#socket-activation) for
details. Unlike the Socket transport, this supplies a _listening_ socket,
from which NNG accepts connections.

## Expanded TLS Support

### More TLS Engines

NNG supports [Mbed TLS, wolfSSL, and OpenSSL](../api/tls.md), allowing
applications to select the TLS implementation that fits their deployment.
OpenSSL support is new in NNG 2.0 and requires OpenSSL 3.5 or newer; wolfSSL
is also supported alongside Mbed TLS.

Enable TLS with `NNG_ENABLE_TLS=ON` and select the engine with
`NNG_TLS_ENGINE=mbed`, `NNG_TLS_ENGINE=wolf`, or `NNG_TLS_ENGINE=openssl` when
configuring the build. The chosen engine supplies TLS for the TLS transport,
secure WebSockets, HTTPS, and, when enabled, DTLS. Individual features depend
on the engine and its build configuration.

### TLS 1.3

Applications can use TLS 1.3 when supported by the selected engine.
The default version range allows TLS 1.2 and TLS 1.3, and
[`nng_tls_config_version`] can restrict the range, including requiring
TLS 1.3. Support for the obsolete TLS 1.0 and TLS 1.1 versions has been removed.

See [TLS Versions](../api/tls.md#tls-versions) for the supported capabilities.
TLS 1.3 session resumption and zero round trip time (0-RTT) are not supported.

### Pre-Shared Keys

[TLS pre-shared keys](../api/tls.md#pre-shared-keys) provide an alternative
to certificate-based authentication. With [`nng_tls_config_psk`], applications
configure an identity and a shared secret. A server configuration can hold
keys for multiple client identities. This can simplify deployments where
peers already share secrets and a certificate infrastructure is unnecessary.
PSK support depends on the TLS engine and its configuration.

### Richer Certificate Inspection

The new [`nng_tls_cert`] API provides access to peer certificates from NNG
pipes, streams, and HTTP connections. Applications can inspect the subject,
issuer, serial number, subject alternative names, and validity dates, or
export the certificate in DER format for use with another library.
Certificates can also be parsed from PEM or DER data.

This replaces the limited certificate-name properties from NNG 1.x with a
common certificate object. See [Peer Certificates](../api/tls.md#peer-certificates)
for ownership rules and engine-dependent availability.

## Lower I/O Overhead

### Synchronous Completion with Skippable Callbacks

The new [`nng_aio_skip_callback`] function lets an application opt in to
synchronous completion of an asynchronous operation. If the operation can
finish immediately, NNG sets a caller-supplied flag and makes the result
available in the AIO without dispatching its callback. Otherwise, the operation
completes through the normal asynchronous path.

This avoids unnecessary callback scheduling and context switches when data
or buffer space is already available. Applications must opt in before each
operation and handle both completion paths. The synchronous [`nng_sendmsg`]
and [`nng_recvmsg`] families use this mechanism internally.
See [Skipping Callbacks](../api/aio.md#skipping-callbacks) for an example.

### Faster WebSocket Masking

WebSocket masking and unmasking now process data in larger chunks, with
SIMD implementations using NEON on AArch64 and SSE2 on x86-64 where supported
by the compiler. Portable implementations remain available for other builds.
This reduces the CPU cost of processing masked WebSocket payloads without
requiring application changes or changing the wire format.

### Fewer Allocations and Less Locking

Internal transport and I/O structures have been reorganized to combine
allocations and embed frequently used objects. Poller and reference-counting
paths have also been revised to reduce locking overhead. The HTTP implementation
reuses buffers and avoids allocations for common metadata.
These changes reduce bookkeeping in frequently executed paths; the benefit
depends on the platform and workload.

## HTTP and WebSocket Improvements

### HTTP over UNIX Domain Sockets

HTTP clients and servers can now communicate over UNIX domain sockets using
`http+unix://` URLs. For example, a service at `/var/run/service.sock` can use:

```text
http+unix://%2Fvar%2Frun%2Fservice.sock
```

The socket path is percent-encoded in the URL authority, leaving the URL path
available for the HTTP request target. This allows local HTTP services without
allocating TCP ports and works on POSIX and Windows where the UNIX stream
driver is available. See [HTTP over Unix-domain sockets](../api/http.md#http-over-unix-domain-sockets)
for URL construction and request details.

### Simpler HTTP APIs and More Flexible Routing

The HTTP API has been refactored around a connection object, simplifying
request and response handling. Header iteration is available through
[`nng_http_next_header`], and [`nng_http_hijack_stream`] allows an HTTP upgrade
handler to take over a connection as an [`nng_stream`], preserving data already
read by the HTTP parser.

WebSocket listeners can now accept a subtree of URL paths using
`NNG_OPT_WS_TREE`, with the actual request URI available through
`NNG_OPT_WS_REQUEST_URI`. This lets one listener handle related routes.
See the [WebSocket transport options](../tran/websocket.md#transport-and-stream-options).

## More Application Control

- **Runtime initialization and thread tuning.** Explicit [`nng_init`] and
  [`nng_fini`] calls give applications control over the library's lifetime.
  Initialization parameters can tune task, expiration, I/O poller, and DNS
  resolver thread counts, subject to platform support. Initialization is
  reference counted so multiple library consumers in a process can share NNG.
- **Custom memory allocation.** The `nng_init_params` structure accepts
  `malloc_fn`, `calloc_fn`, and `free_fn` hooks, allowing applications to
  supply their own memory allocator when initializing NNG. Supply all three
  hooks together on the first call to `nng_init`.
- **IPC socket ownership.** POSIX IPC listeners can request a socket's owner
  and group with `NNG_OPT_IPC_OWNER` and `NNG_OPT_IPC_GROUP`, in addition to
  configuring filesystem permissions. See the [IPC transport](../tran/ipc.md)
  for platform and privilege requirements.
- **More direct, typed APIs.** Dedicated functions for addresses, subscriptions,
  TLS configuration, and protocol information replace many generic options.
  Most declarations are consolidated in `<nng/nng.h>`, reducing the number of
  headers applications need. The [migration guide](../migrate/nng1.md) maps the
  old interfaces to their replacements.
- **More TLS options in nngcat.** The command-line tool can use pre-shared keys
  and encrypted private keys, making it easier to test secured services.
  See [nngcat TLS options](../tools/nngcat.md#tls).

{{#include ../xref.md}}
