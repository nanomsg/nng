# Socket Transport (Experimental)

## Description

The {{i:*socket* transport}} supports communication between
peers across arbitrary BSD sockets, such as those that are
created with [`nng_socket_pair`].

This transport only supports [listeners][listener], using [`nng_listener_create`].

> [!NOTE]
> Attempts to create [dialers][dialer] using this transport will result in `NNG_ENOTSUP`.

The socket file descriptor is passed to the listener using
the {{i:`NNG_OPT_SOCKET_FD`}} option (as an integer).
Setting this option will cause the listener to create a [pipe]
backed by the file descriptor.

The protocol between peers using this transport is compatible with the protocol used
for the _[tcp]_ transport, but this is an implementation detail and subject to change without notice.
{{footnote: Specifically it is not compatible with the _[ipc]_ transport.}}

> [!NOTE]
> This transport is _experimental_, and at present is only supported on POSIX platforms.
> {{footnote: Windows lacks a suitable `socketpair` equivalent function we could use.}}

## URL Format

This transport uses the URL {{i:`socket://`}}, without further qualification.

## Socket Address

The socket address will be of family {{i:`NNG_AF_UNSPEC`}}.
There are no further socket details available.

## Transport Options

The following transport options are supported by this transport.

| Option                | Type  | Description                                                                                                                                                                          |
| --------------------- | ----- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `NNG_OPT_SOCKET_FD`   | `int` | Write-only option, that may be set multiple times on a listener. Each time this is set, the listener will create a [pipe] backed by the given file descriptor passed as an argument. |
| `NNG_OPT_PEER_GID`    | `int` | Read only option, returns the group ID of the process at the other end of the socket, if platform supports it.                                                                       |
| `NNG_OPT_PEER_PID`    | `int` | Read only option, returns the processed ID of the process at the other end of the socket, if platform supports it.                                                                   |
| `NNG_OPT_PEER_UID`    | `int` | Read only option, returns the user ID of the process at the other end of the socket, if platform supports it.                                                                        |
| `NNG_OPT_PEER_ZONEID` | `int` | Read only option, returns the zone ID of the process at the other end of the socket, if platform supports it.                                                                        |

> [!NOTE]
> The `NNG_OPT_PEER_GID`, `NNG_OPT_PEER_PID`, `NNG_OPT_PEER_UID`, and `NNG_OPT_PEER_ZONEID` options depend on platform support.
> These behave in exactly the same fashion as for the _[ipc]_ transport.

{{#include ../xref.md}}
