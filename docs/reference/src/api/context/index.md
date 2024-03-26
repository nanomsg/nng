# nng_ctx

## NAME

nng_ctx --- protocol context

## SYNOPSIS

```c
#include <nng/nng.h>

typedef struct nng_ctx_s nng_ctx
```

## DESCRIPTION

An `nng_ctx`{{hi:context}} is a handle to an underlying context object,
which keeps the protocol state for some stateful protocols.
The purpose of a separate context object is to permit applications to
share a single [socket](../socket/index.md), with its various underlying
[dialers](nng_dialer.md),
[listeners](nng_listener.md),
[pipes](nng_pipe.md),
while still benefiting from separate state tracking.

For example, a [_REQ_](../protocols/req.md) context will contain the request ID
of any sent request, a timer to retry the request on failure, and so forth.
A separate context on the same socket can have similar data, but corresponding
to a completely different request.

> [!NOTE]
> The `nng_ctx` structure is always passed by value (both
> for input parameters and return values), and should be treated opaquely.
> Passing structures this way gives the compiler a chance to perform
> accurate type checks in functions passing values of this type.

All contexts share the same socket, and so some options, as well as the
underlying transport details, will be common to all contexts on that socket.

Protocols that make use of contexts will also have a default context
that is used when the socket global operations are used.
Operations using the global context will generally not interfere with
any other contexts, except that certain socket options may affect socket
global behavior.

{{hi:concurrent}}{{hi:raw mode}}
Historically, applications wanting to use a stateful protocol concurrently
would have to resort to [raw mode](../overview/raw.md) sockets, which bypasses
much of the various protocol handling, leaving it to up to the application
to do so.
Contexts make it possible to still benefit from advanced protocol handling,
including timeouts, retries, and matching requests to responses, while doing so
concurrently.

> [!TIP]
> Contexts are an excellent mechanism to use when building concurrent
> applications, and should be used in lieu of
> [raw mode](../overview/raw.md) sockets when possible.

## Caveats

Not every protocol supports separate contexts.
See the protocol-specific documentation for further details about whether
contexts are supported, and details about what options are supported for
contexts.

Use of file descriptor polling (with descriptors obtained using the
[`NNG_OPT_RECVFD`](nng_options.md#NNG_OPT_RECVFD) or
[`NNG_OPT_SENDFD`](nng_options.md#NNG_OPT_SENDFD) options) while contexts
are in use on the same socket is not supported, and may lead to unpredictable
behavior. These asynchronous methods should not be mixed on the same socket.

[Raw mode](../overview/raw.md) sockets do not support contexts, since
there is generally no state tracked for them, and thus contexts make no sense.

## Initialization

A context may be initialized using the macro `NNG_CTX_INITIALIZER`
before it is opened, to prevent confusion with valid open contexts.

## Example

The following program fragment demonstrates the use of contexts to implement
a concurrent [_REP_](../protocols/rep.md) service that simply echos messages back
to the sender.

```c
struct echo_context {
    nng_ctx ctx;
    nng_aio *aio;
    enum { INIT, RECV, SEND } state;
};

void
echo(void *arg)
{
    struct echo_context *ec = arg;

    switch (ec->state) {
    case INIT:
        ec->state = RECV;
        nng_ctx_recv(ec->ctx, ec->aio);
        return;
    case RECV:
        if (nng_aio_result(ec->aio) != 0) {
            // ... handle error
        }
        // We reuse the message on the ec->aio
        ec->state = SEND;
        nng_ctx_send(ec->ctx, ec->aio);
        return;
    case SEND:
        if (nng_aio_result(ec->aio) != 0) {
            // ... handle error
        }
        ec->state = RECV;
        nng_ctx_recv(ec->ctx, ec->aio);
        return;
    }
}
```

Given the above fragment, the following example shows setting up the
service. It assumes that the [socket](nng_socket.md) has already been
created and any transports set up as well with functions such as
[`nng_dial()`](nng_dial.md) or [`nng_listen()`](nng_listen.md).

```c
#define CONCURRENCY 1024

echo_context ecs[CONCURRENCY];

void
start_echo_service(nng_socket rep_socket)
{
    for (int i = 0; i < CONCURRENCY; i++) {
        // error checks elided for clarity
        nng_ctx_open(ec[i].ctx, rep_socket)
        nng_aio_alloc(ec[i].aio, echo, &e[i]);
        ec[i].state = INIT;
        echo(&ec[i]); // start it running
    }
}
```

## SEE ALSO

[nng_ctx_close](nng_ctx_close.md),
[nng_ctx_open](nng_ctx_open.md),
[nng_ctx_get](nng_ctx_get.md),
[nng_ctx_id](nng_ctx_id.md)
[nng_ctx_recv](nng_ctx_recv.md),
[nng_ctx_recvmsg](nng_ctx_recvmsg.md),
[nng_ctx_send](nng_ctx_send.md),
[nng_ctx_sendmsg](nng_ctx_sendmsg.md),
[nng_ctx_set](nng_ctx_set.md),
[nng_dialer](nng_dialer.md),
[nng_listener](nng_listener.md),
[nng_socket](../socket/index.md),
[nng_options](nng_options.md)
