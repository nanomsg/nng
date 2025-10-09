# INPROC Transport

The {{i:*inproc* transport}}{{hi:*inproc*}}{{i:intra-process}} provides communication support between
sockets within the same process.
This may be used as an alternative
to slower transports when data must be moved within the same process.

This transport tries hard to avoid copying data, and thus is very
light-weight.

## URL Format

This transport uses URLs using the scheme {{i:`inproc://`}}, followed by
an arbitrary string of text, terminated by a `NUL` byte.

Multiple URLs can be used within the
same application, and they will not interfere with one another.

Two applications may also use the same URL without interfering with each other.
They will however be unable to communicate with each other using that URL.

## Socket Address

When using an [`nng_sockaddr`] structure, the actual structure is of type [`nng_sockaddr_inproc`].

## Transport Options

The _inproc_ transport has no special options.

> [!NOTE]
> While _inproc_ accepts the option [`NNG_OPT_RECVMAXSZ`] for
> compatibility, the value of the option is ignored with no enforcement.
> As _inproc_ peers are in the same address space, they are implicitly
> trusted, so the protection afforded by `NNG_OPT_RECVMAXSZ` is unnecessary.

## Mixing Implementations

When mixing the _NNG_ library with other implementations of these
protocols in the same process (such as the [mangos]
or [libnanomsg] implementations), it will not be possible to utilize
the _inproc_ transport to communicate across this boundary.

This limitation also extends to using different instances of the _NNG_
library within the same process.

{{#include ../xref.md}}
