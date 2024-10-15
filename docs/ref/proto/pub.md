# PUB Protocol

The {{i:*PUB* protocol}}{{hi:*PUB*}} is one half of a {{i:publisher}}/subscriber pattern.
In this pattern, a publisher sends data, which is broadcast to all
subscribers.
The subscribing applications only see the data to which
they have subscribed.

The _PUB_ protocol is the publisher side, and the
[_SUB_](sub.md) protocol is the subscriber side.

> [!NOTE]
> In this implementation, the publisher delivers all messages to all
> subscribers.
> The subscribers maintain their own subscriptions, and filter them locally.
> Thus, this pattern should not be used in an attempt to reduce bandwidth
> consumption.

The topics that subscribers subscribe to is just the first part of
the message body.
Applications should construct their messages accordingly.

## Socket Operations

The [`nng_pub0_open`][nng_pub_open] functions create a publisher socket.
This socket may be used to send messages, but is unable to receive them.
Attempts to receive messages will result in `NNG_ENOTSUP`.

## Protocol Versions

Only version 0 of this protocol is supported.
(At the time of writing, no other versions of this protocol have been defined.)

## Protocol Options

The _PUB_ protocol has no protocol-specific options.

## Protocol Headers

The _PUB_ protocol has no protocol-specific headers.

[nng_pub_open]: TODO.md
