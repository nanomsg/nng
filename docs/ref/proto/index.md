# Protocols

{{hi:protocol}}
The Scalability Protocols are a principally a collection of common networking
patterns found in applications.

The following patterns are included:

## Request - Reply

The {{i:request/reply pattern}} is made up of the [_REQ_][req] and [_REP_][rep] protocols.
This most often used when implementing RPC-like services, where
a given request is matched by a single reply.

## Pipeline

The {{i:pipeline pattern}} is made up of the [_PUSH_][push] and [_PULL_][pull]
protocols.

In this pattern communication is {{i:half-duplex}}, in that one side sends
data and another side receives.

This pattern is also characterized by its ability to solve distribution
problems, and the fact that it has {{i:back-pressure}}, providing a measure
of {{i:flow control}} to data production and consumption.

## Publish - Subscribe

## Bus

## Pair

[bus]: bus.md
[pair]: pair.md
[push]: push.md
[pull]: pull.md
[req]: req.md
[rep]: rep.md
[sub]: sub.md
[pub]: pub.md
[respondent]: respondent.md
[surveyor]: surveyor.md
