# RESPONDENT protocol

The {{i:*RESPONDENT* protocol}}{{hi:*RESPONDENT*}} is one half of a {{i:survey pattern}}.
In this pattern, a surveyor sends a survey, which is broadcast to all
peer respondents.
The respondents then have a chance to reply (but are not obliged to reply).
The survey itself is a timed event, so that responses
received after the survey has finished are discarded.

> [!TIP]
> This protocol is useful in solving voting problems, such as leader
> election in cluster configurations, as well as certain kinds of service
> discovery problems.

The _RESPONDENT_ protocol is the respondent side, and the
[_SURVEYOR_][surveyor] protocol is the surveyor side.

### Socket Operations

The [`nng_respondent0_open`][nng_respondent_open] functions create a
respondent socket.
This socket may be used to receive messages, and then to send replies.
A reply can only be sent after receiving a survey, and generally the
reply will be sent to surveyor from whom the last survey was received.

Respondents may discard a survey by simply not replying to it.

[Raw mode][raw] sockets ignore all these restrictions.

### Context Operations

This protocol supports the creation of [contexts][context] for concurrent
use cases using [`nng_ctx_open`][nng_ctx_open].

Incoming surveys will be routed to and received by only one context.
Additional surveys may be received by other contexts in parallel.
Replies made using a context will be returned to the the surveyor that
issued the survey most recently received by that context.
The restrictions for order of operations with sockets apply equally
well for contexts, except that each context will be treated as if it were
a separate socket.

### Protocol Versions

Only version 0 of this protocol is supported.
At the time of writing, no other versions of this protocol have been defined.
{{footnote: An earlier and incompatible version of the protocol was used in older
pre-releases of [nanomsg][nanomsg], but was not released in any production version.}}

### Protocol Options

The _respondent_ protocol has no protocol-specific options.

### Protocol Headers

The _RESPONDENT_ protocol uses a {{ii:backtrace}} in the header.
This is more fully documented in the [_SURVEYOR_][surveyor] manual.

[nng_respondent_open]: TODO.md
[nng_ctx_open]: TODO.md
[nanomsg]: TODO.md
[context]: TODO.md
[raw]: TODO.md
[surveyor]: ./surveyor.md
