# Contexts

Contexts {{hi:context}} in Scalability Protocols provide for isolation of protocol-specific
state machines and associated data, allowing multiple {{i:concurrent}} {{i:state machines}} (or transactions)
to coexist on a single [socket].

For example, a [REP][rep] server may wish to allow many requests to be serviced concurrently,
even though some jobs may take significant time to process. Contexts provide for this ability.

Not all protocols have contexts, because many protocols simply have no state to manage.
The following protocols support contexts:

- [REP][rep]
- [REQ][req]
- [RESPONDENT][respondent]
- [SURVEYOR][surveyor]
- [SUB][sub]

For these protocols, the socket will also have a single, default, context that is used when
performing send or receive operations on the socket directly.

Other protocols are stateless, at least with respect to message processing, and have no use for
contexts. For the same reason, [raw] mode sockets do not support contexts.

> [!TIP]
> Developers with experience with [libnanomsg] may be used to using [raw] sockets for concurrency.
> Contexts provide a superior solution, as they are much easier to use, less error prone, and allow
> for easy control of the amount of concurrency used on any given socket.

One drawback of contexts is that they cannot be used with file descriptor polling using
[`nng_socket_get_recv_poll_fd`] or [`nng_socket_get_send_poll_fd`].

## Context Structure

```c
#define NNG_CTX_INITIALIZER // opaque value

typedef struct nng_ctx_s nng_ctx;
```

The {{i:`nng_ctx`}} structure represents context. This is a handle, and
the members of it are opaque. However, unlike a pointer, it is passed by value.

A context may be initialized statically with the {{i:`NNG_CTX_INITIALIZER`}} macro,
to ensure that it cannot be confused with a valid open context.

## Creating a Context

```c
int nng_ctx_open(nng_ctx *ctxp, nng_socket s);
```

The {{i:`nng_ctx_open`}} function creates a separate context to be used with the [socket] _s_,
and returns it at the location pointed by _ctxp_.

## Context Identity

```c
int nng_ctx_id(nng_ctx c);
```

The {{i:`nng_ctx_id`}} function returns a positive identifier for the context _c_ if it is valid.
Otherwise it returns `-1`.

A context is considered valid if it was ever opened with [`nng_ctx_open`] function.
Contexts that are allocated on the stack or statically should be initialized with the macro [`NNG_CTX_INITIALIZER`]
to ensure that they cannot be confused with a valid context before they are opened.

## Closing a Context

```c
int nng_ctx_close(nng_ctx ctx);
```

The {{i:`nng_ctx_close`}} function closes the context _ctx_.
Messages that have been submitted for sending may be flushed or delivered,
depending upon the transport.

Further attempts to use the context after this call returns will result in `NNG_ECLOSED`.
Threads waiting for operations on the context when this
call is executed may also return with an `NNG_ECLOSED` result.

> [!NOTE]
> Closing the socket associated with _ctx_ using [`nng_socket_close`] also closes this context.

## Sending Messages

```c
int nng_ctx_sendmsg(nng_ctx ctx, nng_msg *msg, int flags);
void nng_ctx_send(nng_ctx ctx, nng_aio *aio);
```

These functions ({{i:`nng_ctx_sendmsg`}} and {{i:`nng_ctx_send`}}) send
messages over the socket _s_. The differences in their behaviors are as follows.

> [!NOTE]
> The semantics of what sending a message means varies from protocol to
> protocol, so examination of the protocol documentation is encouraged.
> Additionally, some protocols may not support sending at all or may require other pre-conditions first.
> (For example, [REP][rep] sockets cannot normally send data until they have first received a request,
> while [SUB][sub] sockets can only receive data and never send it.)

### nng_ctx_sendmsg

The `nng_ctx_sendmsg` function sends the _msg_ over the context _ctx_.

If this function returns zero, then the socket will dispose of _msg_ when the transmission is complete.
If the function returns a non-zero status, then the call retains the responsibility for disposing of _msg_.

The _flags_ can contain the value [`NNG_FLAG_NONBLOCK`], indicating that the function should not wait if the socket
cannot accept more data for sending. In such a case, it will return [`NNG_EAGAIN`].

### nng_ctx_send

The `nng_ctx_send` function sends a message asynchronously, using the [`nng_aio`] _aio_, over the context _ctx_.
The message to send must have been set on _aio_ using the [`nng_aio_set_msg`] function.

If the operation completes successfully, then the context will have disposed of the message.
However, if it fails, then callback of _aio_ should arrange for a final disposition of the message.
(The message can be retrieved from _aio_ with [`nng_aio_get_msg`].)

Note that callback associated with _aio_ may be called _before_ the message is finally delivered to the recipient.
For example, the message may be sitting in queue, or located in TCP buffers, or even in flight.

> [!TIP]
> This is the preferred function to use for sending data on a context. While it does require a few extra
> steps on the part of the application, the lowest latencies and highest performance will be achieved by using
> this function instead of [`nng_ctx_sendmsg`].

## Receiving Messages

```c
int nng_ctx_recvmsg(nng_ctx ctx, nng_msg **msgp, int flags);
void nng_ctx_recv(nng_ctx ctx, nng_aio *aio);
```

These functions (, {{i:`nng_ctx_recvmsg`}} and {{i:`nng_ctx_recv`}}) receive
messages over the context _ctx_. The differences in their behaviors are as follows.

> [!NOTE]
> The semantics of what receiving a message means varies from protocol to
> protocol, so examination of the protocol documentation is encouraged.
> Additionally, some protocols may not support receiving at all or may require other pre-conditions first.
> (For example, [REQ][req] sockets cannot normally receive data until they have first sent a request.)

### nng_recvmsg

The `nng_ctx_recvmsg` function receives a message and stores a pointer to the [`nng_msg`] for that message in _msgp_.

The _flags_ can contain the value [`NNG_FLAG_NONBLOCK`], indicating that the function should not wait if the socket
has no messages available to receive. In such a case, it will return [`NNG_EAGAIN`].

### nng_socket_recv

The `nng_ctx_send` function receives a message asynchronously, using the [`nng_aio`] _aio_, over the context _ctx_.
On success, the received message can be retrieved from the _aio_ using the [`nng_aio_get_msg`] function.

> [!NOTE]
> It is important that the application retrieves the message, and disposes of it accordingly.
> Failure to do so will leak the memory.

> [!TIP]
> This is the preferred function to use for receiving data on a context. While it does require a few extra
> steps on the part of the application, the lowest latencies and highest performance will be achieved by using
> this function instead of [`nng_ctx_recvmsg`].

## Context Options

```c
int nng_ctx_get_bool(nng_ctx ctx, const char *opt, bool *valp);
int nng_ctx_get_int(nng_ctx ctx, const char *opt, int *valp);
int nng_ctx_get_ms(nng_ctx ctx, const char *opt, nng_duration *valp);
int nng_ctx_get_size(nng_ctx ctx, const char *opt, size_t *valp);

int nng_ctx_set_bool(nng_ctx ctx, const char *opt, int val);
int nng_ctx_set_int(nng_ctx ctx, const char *opt, int val);
int nng_ctx_set_ms(nng_ctx ctx, const char *opt, nng_duration val);
int nng_ctx_set_size(nng_ctx ctx, const char *opt, size_t val);
```

Some protocols support certain options that affect the behavior of a specific context.
For example, most protocols will let you set the defaults timeouts associated with
send or receive separately for different contexts.

These functions are used to retrieve or change the value of an option named _opt_ from the context _ctx_.
The `nng_ctx_get_` functions retrieve the value from _ctx_, and store it in the location _valp_ references.
The `nng_ctx_set_` functions change the value for the _ctx_, taking it from _val_.

These functions access an option as a specific type. The protocol documentation will have details about which options
are available for contexts, whether they can be read or written, and the appropriate type to use.

## Examples

These examples show building blocks for a concurrent service based on contexts.

### Example 1: Context Echo Server

The following program fragment demonstrates the use of contexts to implement
a concurrent [REP][rep] service that simply echos messages back
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

### Example 2: Starting the Echo Service

Given the above fragment, the following example shows setting up the service.
It assumes that the [socket] has already been
created and any transports set up as well with functions such as [`nng_dial`] or [`nng_listen`].

```c

#define CONCURRENCY 1024

static struct echo_context ecs[CONCURRENCY];

void
start_echo_service(nng_socket rep_socket)
{
    for (int i = 0; i < CONCURRENCY; i++) {
        // error checks elided for clarity
        nng_ctx_open(&ecs[i].ctx, rep_socket);
        nng_aio_alloc(&ecs[i].aio, echo, ecs+i);
        ecs[i].state = INIT;
        echo(ecs+i); // start it running
    }
}
```

{{#include ../xref.md}}
