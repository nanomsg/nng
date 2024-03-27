# INPROC Transport

{{hi:transport, _inproc_}}
{{hi:intra-process}}
The {{i:_inproc_ transport}} provides communication support between
sockets within the same process.
This may be used as an alternative
to slower transports when data must be moved within the same process.

This transport tries hard to avoid copying data, and thus is very
light-weight.

## URI Format

{{hi:URI, `inproc://`}}
This transport uses URIs using the scheme `inproc://`, followed by
an arbitrary string of text, terminated by a `NUL` byte.

Multiple URIs can be used within the
same application, and they will not interfere with one another.

Two applications may also use the same URI without interfering with each
other, and they will be unable to communicate with each other using
that URI.

## Socket Address

When using an [`nng_sockaddr`](../api/nng_sockaddr.md) structure,
the actual structure is of type
[`nng_sockaddr_inproc`](../api/nng_sockaddr_inproc.md).

## Transport Options

The _inproc_ transport has no special options.

> [!NOTE]
> While _inproc_ accepts the option [`NNG_OPT_RECVMAXSZ`] for
> compatibility, the value of the option is ignored with no enforcement.
> As _inproc_ peers are in the same address space, they are implicitly
> trusted, so the protection afforded by `NNG_OPT_RECVMAXSZ` is unnecessary.

## Mixing Implementations

When mixing the _NNG_ library with other implementations of these
protocols in the same process (such as the _mangos_
or _libnanomsg_ implementations), it will not be possible to utilize
the _inproc_ transport to communicate across this boundary.

This limitation also extends to using different instances of the _NNG_
library within the same process.
