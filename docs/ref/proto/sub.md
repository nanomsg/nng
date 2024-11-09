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

The [`nng_sub0_open`][nng_sub_open] functions create a _SUB_ socket.
This socket may be used to receive messages, but is unable to send them.
Attempts to send messages will result in `NNG_ENOTSUP`.

### Protocol Versions

Only version 0 of this protocol is supported.
(At the time of writing, no other versions of this protocol have been defined.)

### Protocol Options

The following protocol-specific option is available.

- {{i:`NNG_OPT_SUB_PREFNEW`}}: \
  (`bool`) \
  \
  This read/write option specifies the behavior of the subscriber when the queue is full.
  When `true` (the default), the subscriber will make room in the queue by removing the oldest message.
  When `false`, the subscriber will reject messages if the message queue does not have room.

### Protocol Headers

The _SUB_ protocol has no protocol-specific headers.

[nng_sub_open]: TODO.md
[nng_socket_set]: TODO.md
[pub]: ./pub.md
