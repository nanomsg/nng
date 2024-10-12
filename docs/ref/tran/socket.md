# BSD Socket Transport (Experimental)

## Description

The {{i:_socket_ transport}} supports communication between
peers across arbitrary BSD sockets, such as those that are
created with [`nng_socket_pair`][nng_socket_pair].

This transport only supports [listeners][listener],
using [`nng_listener_create`][nng_listener_create].

> [!NOTE]
> Attempts to create [dialers][dialer] using this transport will result in `NNG_ENOTSUP`.

The socket file descriptor is passed to the listener using
the {{i:`NNG_OPT_SOCKET_FD`}} option (as an integer).
Setting this option will cause the listener to create a [pipe][pipe]
backed by the file descriptor.

The protocol between peers using this transport is compatible with the protocol used
for the [_tcp_][tcp] transport, but this is an implementation detail and subject to change without notice.
{{footnote: Specifically it is not compatible with the [_ipc_][ipc] transport.}}

> [!NOTE]
> This transport is _experimental_, and at present is only supported on POSIX platforms.
> {{footnote: Windows lacks a suitable `socketpair()` equivalent function we could use.}}

## Registration

No special action is necessary to register this transport.

## URI Format

This transport uses the URL {{i:`socket://`}}, without further qualification.

## Socket Address

The socket address will be of family {{i:`NNG_AF_UNSPEC`}}.
There are no further socket details available.

## Transport Options

The following transport option is available:

- {{i:`NNG_OPT_SOCKET_FD`}}: \
  (int) \
  \
  This is a write-only option, that may be set multiple times on a listener.
  Each time this is set, the listener will create a [pipe][pipe] backed by the given file
  descriptor passed as an argument.

Additionally, the following options may be supported on pipes when the platform supports them:

- [`NNG_OPT_PEER_GID`][NNG_OPT_PEER_GID]
- [`NNG_OPT_PEER_PID`][NNG_OPT_PEER_PID]
- [`NNG_OPT_PEER_UID`][NNG_OPT_PEER_UID]
- [`NNG_OPT_PEER_ZONEID`][NNG_OPT_PEER_ZONEID]

[ipc]: [ipc.md]
[tcp]: [tcp.md]
[pipe]: [TODO.md]
[listener]: [TODO.md]
[dialer]: [TODO.md]
[nng_sockaddr]: [TODO.md]
[nng_listener_create]: [TODO.md]
[nng_socket_pair]: ../../api/util/nng_socket_pair.md
[NNG_OPT_LOCADDR]: [TODO.md]
[NNG_OPT_REMADDR]: [TODO.md]
[NNG_OPT_URL]: [TODO.md]
[NNG_OPT_PEER_GID]: [TODO.md]
[NNG_OPT_PEER_PID]: [TODO.md]
[NNG_OPT_PEER_UID]: [TODO.md]
[NNG_OPT_PEER_ZONEID]: [TODO.md]
