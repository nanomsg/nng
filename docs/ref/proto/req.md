# REQ protocol

The {{i:*REQ* protocol}}{{hi:*REQ*}} is one half of a {{i:request/reply pattern}}.
In this pattern, a requester sends a message to one replier, who
is expected to reply.
The request is resent if no reply arrives,
until a reply is received or the request times out.

> [!TIP]
> This protocol is useful in setting up RPC-like services.
> It is also "reliable", in that a the requester will keep retrying until
> a reply is received.

> [!NOTE]
> Because requests are resent, it is important that they be {{i:idempotent}}
> to ensure predictable and repeatable behavior even in the face of duplicated
> requests, which can occur (for example if a reply message is lost for
> some reason.)

{{hi: load-balancing}}
The requester generally only has one outstanding request at a time unless
in [raw mode][raw],
and it will generally attempt to spread work requests to different peer repliers.

> [!TIP]
> This property, when combined with a [device][device]
> can help provide a degree of load-balancing.

The _REQ_ protocol is the requester side, and the [_REP_][rep] protocol
is the replier side.

### Socket Operations

The [`nng_req0_open`][nng_req_open] functions create a _REQ_ socket.
This socket may be used to send messages (requests), and then to receive replies.

Generally a reply can only be received after sending a request.
(Attempts to receive a message will result in `NNG_ESTATE` if there is no
outstanding request.)

Furthermore, only a single receive operation may be pending at a time.
Attempts to post more receive operations concurrently will result in
`NNG_ESTATE`.

Requests may be canceled by sending a different request.
This will cause the requester to discard any reply from the earlier request,
but it will not stop a replier
from processing a request it has already received or terminate a request
that has already been placed on the wire.

[Raw mode][raw] sockets ignore all these restrictions.

### Context Operations

This protocol supports the creation of [contexts][context] for concurrent
use cases using [`nng_ctx_open`][nng_ctx_open].

The `NNG_OPT_REQ_RESENDTIME` value may be configured differently
on contexts created this way.

Each context may have at most one outstanding request, and operates
independently from the others.

The restrictions for order of operations with sockets apply equally
well for contexts, except that each context will be treated as if it were
a separate socket.

### Protocol Versions

Only version 0 of this protocol is supported.
(At the time of writing, no other versions of this protocol have been defined.)

### Protocol Options

The following protocol-specific option is available.

- {{i:`NNG_OPT_REQ_RESENDTIME`}}: \
  ([`nng_duration`][duration]) \
  When a new request is started, a timer of this duration is also started.
  If no reply is received before this timer expires, then the request will
  be resent. \
  \
  Requests are also automatically resent if the peer to whom
  the original request was sent disconnects. \
  \
  Resending may be deferred up to the value of the `NNG_OPT_RESENDTICK` parameter. \
  \
  If the value is set to [`NNG_DURATION_INFINITE`][duration], then resends are disabled
  altogether. This should be used when the request is not idemptoent.

- {{i:`NNG_OPT_REQ_RESENDTICK`}}: \
  ([`nng_duration`][duration]) \
  This is the granularity of the clock that is used to check for resending.
  The default is a second. Setting this to a higher rate will allow for
  more timely resending to occur, but may incur significant additional
  overhead when the socket has many outstanding requests (contexts). \
  \
  When there are no requests outstanding that have a resend set, then
  the clock does not tick at all. \
  \
  This option is shared for all contexts on a socket, and is only available for the socket itself.

### Protocol Headers

This protocol uses a {{ii:backtrace}} in the header.
This form uses a stack of 32-bit big-endian identifiers.
There _must_ be at least one identifier, the **request ID**, which will be the
last element in the array, and _must_ have the most significant bit set.

There may be additional **peer ID**s preceding the request ID.
These will be distinguishable from the request ID by having their most
significant bit clear.

When a request message is received by a forwarding node (such as a [device][device]),
the forwarding node prepends a
32-bit peer ID (which _must_ have the most significant bit clear),
which is the forwarder's way of identifying the directly connected
peer from which it received the message.
(This peer ID, except for the
most significant bit, has meaning only to the forwarding node itself.)

It may help to think of prepending a peer ID as pushing a peer ID onto the
front of the stack of headers for the message.
(It will use the peer ID
it popped from the front to determine the next intermediate destination
for the reply.)

When a reply message is created, it is created using the same headers
that the request contained.

A forwarding node can pop the peer ID it originally pushed on the
message, stripping it from the front of the message as it does so.

When the reply finally arrives back at the initiating requester, it
should have only a single element in the message, which will be the
request ID it originally used for the request.

[nng_req_open]: TODO.md
[nng_ctx_open]: TODO.md
[raw]: TODO.md
[device]: TODO.md
[context]: TODO.md
[rep]: ./rep.md
[duration]: ../api/util/nng_duration.md
