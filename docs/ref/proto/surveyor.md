# SURVEYOR protocol

The {{i:*SURVEYOR* protocol}}{{hi:*SURVEYOR*}} is one half of a {{i:survey pattern}}.
In this pattern, a surveyor sends a survey, which is broadcast to all
peer respondents.
The respondents then have a chance, but are not obliged, to reply.
The survey itself is a timed event, so that responses
received after the survey has finished are discarded.

> [!TIP]
> This protocol is useful in solving {{i:voting}} problems, such as
> {{i:leader election}} in cluster configurations,
> as well as certain kinds of {{i:service discovery}} problems.

The _SURVEYOR_ protocol is the surveyor side, and the
[_RESPONDENT_][respondent] protocol is the respondent side.

### Socket Operations

The [`nng_surveyor0_open`][nng_surveyor_open]
functions create a surveyor socket.
This socket may be used to send messages (surveys), and then to receive replies.
A reply can only be received after sending a survey.
A surveyor can normally expect to receive at most one reply from each responder.
(Messages can be duplicated in some topologies,
so there is no guarantee of this.)

Attempts to receive on a socket with no outstanding survey will result
in `NNG_ESTATE`.
If the survey times out while the surveyor is waiting
for replies, then the result will be `NNG_ETIMEDOUT`.

Only one survey can be outstanding at a time; sending another survey will
cancel the prior one, and any responses from respondents from the prior
survey that arrive after this will be discarded.

[Raw mode][raw] sockets ignore all these restrictions.

### Context Operations

This protocol supports the creation of [contexts][context] for concurrent
use cases using [`nng_ctx_open`][nng_ctx_open].

Each context can initiate its own surveys, and it will receive only
responses to its own outstanding surveys.
Other contexts on the same socket may have overlapping surveys
operating at the same time.

Each of these may have their own timeouts established with
`NNG_OPT_SURVEYOR_SURVEYTIME`.

Additionally, sending a survey on a context will only cancel an outstanding
survey on the same context.

> [!NOTE]
> Due to the best-effort nature of this protocol, if too may contexts
> are attempting to perform surveys simultaneously, it is possible for either
> individual outgoing surveys or incoming responses to be lost.

### Protocol Versions

Only version 0 of this protocol is supported.
At the time of writing, no other versions of this protocol have been defined.
{{footnote: An earlier and incompatible version of the protocol was used in older
pre-releases of [nanomsg][nanomsg], but was not released in any production version.}}

### Protocol Options

The following protocol-specific option is available.

- {{i:`NNG_OPT_SURVEYOR_SURVEYTIME`}}: \
   ([`nng_duration`][duration]) \
   \
   When a new survey is started, a timer of this duration is started.
  Any responses arriving this time will be discarded.
  Attempts to receive
  after the timer expires with no other surveys started will result in
  `NNG_ESTATE`.\
  \
  If a receive is pending when this timer expires, it will result in
  `NNG_ETIMEDOUT`.

### Protocol Headers

{{hi:backtrace}}
This form uses a stack of 32-bit big-endian identifiers.
There _must_ be at least one identifier, the **survey ID**, which will be the
last element in the array, and _must_ have the most significant bit set.

There may be additional **peer ID**s preceding the survey ID.
These will be distinguishable from the survey ID by having their most
significant bit clear.

When a survey message is received by a forwarding node (such as a
[device][device]),
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
for the response.)

When a response message is created, it is created using the same headers
that the survey contained.

A forwarding node can pop the peer ID it originally pushed on the
message, stripping it from the front of the message as it does so.

When the response finally arrives back at the initiating surveyor, it
should have only a single element in the message, which will be the
survey ID it originally used for the request.

More detail can be found in the [sp-surveyor-01 RFC][survey_rfc] document.

[nng_surveyor_open]: TODO.md
[nng_ctx_open]: TODO.md
[context]: TODO.md
[nanomsg]: TODO.md
[raw]: TODO.md
[survey_rfc]: TODO.md
[device]: TODO.md
[duration]: ../api/util/nng_duration.md
[respondent]: ./respondent.md
