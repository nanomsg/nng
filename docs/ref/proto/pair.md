# PAIR protocol

The {{i:*PAIR* protocol}}{{hi:*PAIR*}} implements a peer-to-peer pattern, where
relationships between peers are one-to-one.

### Socket Operations

The [`nng_pair_open`][nng_pair_open] functions create a _PAIR_ socket.

Normally, this pattern will block when attempting to send a message if
no peer is able to receive the message.

> [!NOTE]
> Even though this mode may appear to be reliable, because back-pressure
> prevents discarding messages most of the time, there are topologies involving
> where messages may be discarded.
> Applications that require reliable delivery semantics should consider using
> [_REQ_][req] sockets, or implement their own acknowledgment layer on top of _PAIR_ sockets.

### Protocol Versions

Version 0 is the legacy version of this protocol.
It lacks any header
information, and is suitable when building simple one-to-one topologies.

> [!TIP]
> Use version 0 if you need to communicate with other implementations,
> including the legacy [libnanomsg][nanomsg] library or
> [mangos][mangos].

Version 1 of the protocol offers improved protection against loops when
used with [devices][device].

### Polyamorous Mode

> [!NOTE]
> Polyamorous mode is deprecated, and support for it will likely
> be removed in a future release, when a suitable mesh protocol is
> available.
> In the meantime, applications are encouraged to look to other patterns.

Normally pair sockets are for one-to-one communication, and a given peer
will reject new connections if it already has an active connection to another
peer.

_Polyamorous_{{hi:polyamorous mode}} changes this, to allow a socket to communicate with
multiple directly-connected peers.
This mode is enabled by opening a socket using [`nng_pair1_open_poly`][nng_pair_open].

> [!TIP]
> Polyamorous mode is only available when using pair version 1.

In polyamorous mode a socket can support many one-to-one connections.
In this mode, the application must
choose the remote peer to receive an outgoing message by setting the
[`nng_pipe`][pipe] to use for the outgoing message using
[`nng_msg_set_pipe`][nng_msg_pipe].

If no remote peer is specified by the sender, then the protocol will select
any available connected peer.

Most often the value of the outgoing pipe will be obtained from an incoming
message using [`nng_msg_get_pipe`][nng_msg_pipe],
such as when replying to an incoming message.

> [!NOTE]
> Directed send _only_ works with directly connected peers.
> It will not function across [device][device] proxies.

In order to prevent head-of-line blocking, if the peer on the given pipe
is not able to receive (or the pipe is no longer available, such as if the
peer has disconnected), then the message will be discarded with no notification
to the sender.

### Protocol Options

The following protocol-specific options are available.

- [`NNG_OPT_MAXTTL`][NNG_OPT_MAXTTL]:
  (`int`, version 1 only). Maximum time-to-live.

- `NNG_OPT_PAIR1_POLY`:
  (`bool`, version 1 only) This option is no longer supported.
  Formerly it was used to configure _polyamorous_ mode, but that mode
  is now established by using the `nng_pair1_open_poly` function.

### Protocol Headers

Version 0 of the pair protocol has no protocol-specific headers.

Version 1 of the pair protocol uses a single 32-bit unsigned value. The
low-order (big-endian) byte of this value contains a "hop" count, and is
used in conjunction with the
[`NNG_OPT_MAXTTL`][NNG_OPT_MAXTTL] option to guard against
device forwarding loops.
This value is initialized to 1, and incremented each time the message is
received by a new node.

[nng_pair_open]: TODO.md
[NNG_OPT_MAXTTL]: TODO.md
[device]: TODO.md
[nanomsg]: TODO.md
[mangos]: TODO.md
[pipe]: TODO.md
[nng_msg_pipe]: ../api/msg/nng_msg_pipe.md
[req]: ./req.md
