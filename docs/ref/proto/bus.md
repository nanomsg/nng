# BUS Protocol

The {{i:*BUS* protocol}}{{hi:*BUS*}} provides for building mesh networks where
every peer is connected to every other peer.
In this protocol, each message sent by a node is sent to every one of
its directly connected peers.

> [!TIP]
> Messages are only sent to directly connected peers.
> This means that in the event that a peer is connected indirectly, it will not
> receive messages.
> When using this protocol to build mesh networks, it
> is therefore important that a _fully-connected_ mesh network be constructed.

All message delivery in this pattern is {{i:best-effort}}, which means that
peers may not receive messages.
Furthermore, delivery may occur to some,
all, or none of the directly connected peers.
(Messages are not delivered when peer nodes are unable to receive.)
Hence, send operations will never block; instead if the
message cannot be delivered for any reason it is discarded.

> [!TIP]
> In order to minimize the likelihood of message loss, this protocol
> should not be used for high throughput communications.
> Furthermore, the more traffic _in aggregate_ that occurs across the topology,
> the more likely that message loss is to occur.

## Socket Operations

The [`nng_bus0_open`][nng_bus_open] functions create a bus socket.
This socket may be used to send and receive messages.
Sending messages will attempt to deliver to each directly connected peer.

## Protocol Versions

Only version 0 of this protocol is supported.
(At the time of writing, no other versions of this protocol have been defined.)

## Protocol Options

The _BUS_ protocol has no protocol-specific options.

## Protocol Headers

When using a _BUS_ socket in [raw mode][raw], received messages will
contain the incoming [pipe][pipe] ID as the sole element in the header.
If a message containing such a header is sent using a raw _BUS_ socket, then,
the message will be delivered to all connected pipes _except_ the one
identified in the header.
This behavior is intended for use with [device][device]
configurations consisting of just a single socket.
Such configurations are useful in the creation of rebroadcasters, and this
capability prevents a message from being routed back to its source.
If no header is present, then a message is sent to all connected pipes.

When using normal (cooked mode) _BUS_ sockets, no message headers are present.

[nng_bus_open]: TODO.md
[device]: TODO.md
[pipe]: TODO.md
[raw]: TODO.md
