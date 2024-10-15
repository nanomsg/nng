# REP Protocol

The {{i:*REP* protocol}}{{hi:*REP*}} is one half of a {{i:request/reply pattern}}.
In this pattern, a requester sends a message to one replier, who
is expected to reply.
The request is resent if no reply arrives,
until a reply is received or the request times out.

> [!TIP]
> This protocol is useful in setting up RPC-like services.
> It is also reliable, in that a requester will keep retrying until
> a reply is received.

The _REP_ protocol is the replier side, and the
[_REP_][req] protocol is the requester side.

## Socket Operations

The [`nng_rep0_open`][nng_rep_open] functions create a replier socket.
This socket may be used to receive messages (requests), and then to send
replies.

Generally a reply can only be sent after receiving a request.

Send operations will result in `NNG_ESTATE` if no corresponding request
was previously received.

Likewise, only one receive operation may be pending at a time.
Any additional concurrent receive operations will result in `NNG_ESTATE`.

[Raw mode][raw] sockets ignore all these restrictions.

## Context Operations

This protocol supports the creation of [contexts][context] for concurrent
use cases using [`nng_ctx_open`][nng_ctx_open].

Each context may have at most one outstanding request, and operates
independently of the others.
The restrictions for order of operations with sockets apply equally
well for contexts, except that each context will be treated as if it were
a separate socket.

## Protocol Versions

Only version 0 of this protocol is supported.
(At the time of writing, no other versions of this protocol have been defined.)

## Protocol Options

The _REP_ protocol has no protocol-specific options.

## Protocol Headers

The _REP_ protocol uses a {{ii:backtrace}} in the header.
This is more fully documented in the [_REQ_][req] chapter.

[nng_rep_open]: TODO.md
[nng_ctx_open]: TODO.md
[raw]: TODO.md
[context]: TODO.md
[req]: ./req.md
