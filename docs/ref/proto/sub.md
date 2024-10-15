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

The following protocol-specific options are available.

- {{i:`NNG_OPT_SUB_SUBSCRIBE`}}{{hi:subscribe}}: \
   \
   This option registers a topic that the subscriber is interested in.
  The option is write-only, and takes an array of bytes, of arbitrary size.
  Each incoming message is checked against the list of subscribed topics.
  If the body begins with the entire set of bytes in the topic, then the
  message is accepted. If no topic matches, then the message is
  discarded. \
   \
  This option is a byte array. Thus if you use
  [`nng_socket_set_string`][nng_socket_set] the `NUL` terminator byte will
  be included in the topic.
  If that isn't desired, consider using
  [`nng_socket_set`][nng_socket_set] and using `strlen` of the topic
  as the topic size. \
  \
  To receive all messages, an empty topic (zero length) can be used.

- {{i:`NNG_OPT_SUB_UNSUBSCRIBE`}}: \
   \
   This option, also read-only, removes a topic from the subscription list.
  Note that if the topic was not previously subscribed to with
  `NNG_OPT_SUB_SUBSCRIBE` then an `NNG_ENOENT` error will result.

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
