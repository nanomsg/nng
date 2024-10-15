# PULL protocol

The {{i:*PULL* protocol}}{{hi:*PULL*}} is one half of a
{{i:pipeline pattern}}.
The other half is the [_PUSH_][push] protocol.

In the pipeline pattern, pushers distribute messages to pullers.
Each message sent
by a pusher will be sent to one of its peer pullers,
chosen in a round-robin fashion
from the set of connected peers available for receiving.
This property makes this pattern useful in {{i:load-balancing}} scenarios.

### Socket Operations

The [`nng_pull0_open`][nng_pull_open] functions create a
_PULL_ socket.
This socket may be used to receive messages, but is unable to send them.
Attempts to send messages will result in `NNG_ENOTSUP`.

When receiving messages, the _PULL_ protocol accepts messages as
they arrive from peers.
If two peers both have a message ready, the
order in which messages are handled is undefined.

### Protocol Versions

Only version 0 of this protocol is supported.
(At the time of writing, no other versions of this protocol have been defined.)

### Protocol Options

The _PULL_ protocol has no protocol-specific options.

### Protocol Headers

The _PULL_ protocol has no protocol-specific headers.

[nng_pull_open]: TODO.md
[push]: ./push.md
