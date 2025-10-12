# SUB protocol

The {{i:*SUB* protocol}}{{hi:*SUB*}} is one half of a publisher/{{i:subscriber}} pattern.
In this pattern, a publisher sends data, which is broadcast to all subscribers.
The subscribing applications only see the data to which they have subscribed.

The _SUB_ protocol is the subscriber side, and the
[_PUB_][pub] protocol is the publisher side.

> [!NOTE]
> The publisher delivers all messages to all subscribers.
> The subscribers maintain their own subscriptions, and filter them locally.
> Thus, this pattern should not be used in an attempt to
> reduce bandwidth consumption.

The topics that subscribers subscribe to is compared to the leading bytes of
the message body.
Applications should construct their messages accordingly.

### Socket Operations

```c
int nng_sub0_open(nng_socket *);
int nng_sub0_open_raw(nng_socket *);
int nng_sub0_socket_subscribe(nng_socket id, const void *buf, size_t sz);
int nng_sub0_socket_unsubscribe(nng_socket id, const void *buf, size_t sz);
```

The {{i:`nng_sub0_open`}} and {{i:`nng_sub0_open_raw`}} functions create a _SUB_ socket in
either [cooked] or [raw] mode.

The {{i:`nng_sub0_socket_subscribe`}} function is used to add a subscription topic to the socket.
Messages that do not match any subscription topic will be filtered out, and unavailable
for receiving.

A message is deemed to match a subscription if it has at least _sz_ bytes, and the first
_sz_ bytes are the same as _buf_.

The {{i:`nng_sub0_socket_unsubscribe`}} function removes a subscription from the socket.

> [!NOTE]
> A socket with no subscriptions cannot receive messages.

> [!TIP]
> To receive all messages, simply subscribe to a zero length topic.

### Context Operations

The _SUB_ protocol supports [contexts][context].

```c
int nng_sub0_ctx_subscribe(nng_ctx id, const void *buf, size_t sz);
int nng_sub0_ctx_unsubscribe(nng_ctx id, const void *buf, size_t sz);
```

The {{i:`nng_sub0_ctx_subscribe`}} and {{i:`nng_sub0_ctx_unsubscribe`}} functions
perform manage subscriptions for the context in precisely the same way that
[`nng_sub0_socket_subscribe`] and [`nng_sub0_socket_unsubscribe`] do.

Each context maintains its own set of subscriptions, and these are also independent
of socket level subscriptions.

### Protocol Options

| Option                       | Type   | Description                                                                                                                                                                                                           |
| ---------------------------- | ------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| {{i:`NNG_OPT_SUB_PREF_NEW`}} | `bool` | If `true` (default), when the receive queue is full, then older unreceived messages will be discarded to make room for newer messages. If `false`, the older message is preserved and the newer message is discarded. |

### Protocol Versions

Only version 0 of this protocol is supported.
(At the time of writing, no other versions of this protocol have been defined.)

### Protocol Headers

The _SUB_ protocol has no protocol-specific headers.

{{#include ../xref.md}}
