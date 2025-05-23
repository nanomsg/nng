# Sockets

Sockets {{hi:socket}} in Scalability Protocols provide the handle for communication
between peers. Sockets also encapsulate protocol specific semantics, such as
filtering subscriptions, or automatically retrying requests.

## Socket Structure

```c
#define NNG_SOCKET_INITIALIZER // opaque value

typedef struct nng_socket_s nng_socket;
```

The {{i:`nng_socket`}} structure represents socket. This is a handle, and
the members of it are opaque. However, unlike a pointer, it is usually
passed by value.

A socket may be initialized statically with the `NNG_SOCKET_INITIALIZER` macro,
to ensure that it cannot be confused with a valid open socket.

## Socket Identity

```c
int nng_socket_id(nng_socket s);
int nng_socket_raw(nng_socket s, bool *raw);
int nng_socket_proto_id(nng_socket s, uint16_t *proto);
int nng_socket_peer_id(nng_socket s, uint16_t *proto);
int nng_socket_proto_name(nng_socket s, const char **name);
int nng_socket_peer_name(nng_socket s, const char **name);
```

These functions are used to provide fundamental information about the socket _s_.
Most applications will not need to use these functions.

The {{i:`nng_socket_id`}} function returns the numeric id, which will be a non-negative
value, associated with the socket. If the socket is uninitialized (has never been opened),
then the return value may be `-1`.

The {{i:`nng_socket_proto_id`}} and {{i:`nng_socket_peer_id`}} functions provide the 16-bit
protocol identifier for the socket's protocol, and of the protocol peers will use when
communicating with the socket.

The {{i:`nng_socket_proto_name`}} and {{i:`nng_socket_peer_name`}} functions provide the ASCII
names of the socket's protocol, and of the protocol peers of the socket use.
The value stored in _name_ is a fixed string located in program text, and must not be freed
or altered. It is guaranteed to remain valid while this library is present.

The {{i:`nng_socket_raw`}} function determines whether the socket is in
[raw mode][raw] or not, storing `true` in _raw_ if it is, or `false` if it is not.

## Opening a Socket

```c
int nng_bus0_open(nng_socket *s);
int nng_pub0_open(nng_socket *s);
int nng_pull0_open(nng_socket *s);
int nng_push0_open(nng_socket *s);
int nng_rep0_open(nng_socket *s);
int nng_req0_open(nng_socket *s);
int nng_respondent0_open(nng_socket *s);
int nng_sub0_open(nng_socket *s);
int nng_surveyor0_open(nng_socket *s);
```

These functions open a socket, returning it in _s_.
The constructors for sockets are protocol specific so please refer to protocol documentation
for more specific information.

The following functions open a socket in normal mode:

- {{i:`nng_bus0_open`}} - [BUS][bus] version 0
- {{i:`nng_pair0_open`}} - [PAIR][pair] version 0
- {{i:`nng_pair1_open`}} - [PAIR][pair] version 1
- {{i:`nng_pair1_open_poly`}} - [PAIR][pair] version 1, [polyamorous] mode
- {{i:`nng_pub0_open`}} - [PUB][pub] version 0
- {{i:`nng_pull0_open`}} - [PULL][pull] version 0
- {{i:`nng_push0_open`}} - [PUSH][push] version 0
- {{i:`nng_rep0_open`}} - [REP][rep] version 0
- {{i:`nng_req0_open`}} - [REQ][req] version 0
- {{i:`nng_respondent0_open`}} - [RESPONDENT][respondent] version 0
- {{i:`nng_sub0_open`}} - [SUB][sub] version 0
- {{i:`nng_surveyor0_open`}} - [SURVEYOR][surveyor] version 0

## Raw Mode Sockets

```c
int nng_bus0_open_raw(nng_socket *s);
int nng_pub0_open_raw(nng_socket *s);
int nng_pull0_open_raw(nng_socket *s);
int nng_push0_open_raw(nng_socket *s);
int nng_rep0_open_raw(nng_socket *s);
int nng_req0_open_raw(nng_socket *s);
int nng_respondent0_open_raw(nng_socket *s);
int nng_sub0_open_raw(nng_socket *s);
int nng_surveyor0_open_raw(nng_socket *s);
```

{{hi:raw mode}}
Raw mode sockets are used in circumstances when the application needs direct access
to the message headers to control the protocol details.

Such sockets require greater sophistication on the part of the application to use,
as the application must process the protocol headers specifically.
The details of the protocol headers, and requirements, are described in the protocol
documentation for each protocol.

Raw mode sockets do not have any kind of state machine associated with them, as all of
the protocol specific processing must be performed by the application.

> [!TIP]
> Most applications do not need to use raw sockets.
> The notable exception is when using [`nng_device`], which requires raw sockets.
> To obtain asynchronous behavior, consider using [contexts][context] instead.

The following functions open a socket in [raw] mode:

- {{i:`nng_bus0_open_raw`}} - [BUS][bus] version 0, raw mode
- {{i:`nng_pair0_open_raw`}} - [PAIR][pair] version 0, raw mode
- {{i:`nng_pair1_open_raw`}} - [PAIR][pair] version 1, raw mode
- {{i:`nng_pub0_open_raw`}} - [PUB][pub] version 0, raw mode
- {{i:`nng_pull0_open_raw`}} - [PULL][pull] version 0, raw mode
- {{i:`nng_push0_open_raw`}} - [PUSH][push] version 0, raw mode
- {{i:`nng_rep0_open_raw`}} - [REP][rep] version 0, raw mode
- {{i:`nng_req0_open_raw`}} - [REP][req] version 0, raw mode
- {{i:`nng_respondent0_open_raw`}} - [RESPONDENT][respondent] version 0, raw mode
- {{i:`nng_sub0_open_raw`}} - [SUB][sub] version 0, raw mode
- {{i:`nng_surveyor0_open_raw`}} - [SURVEYOR][surveyor] version 0, raw mode

## Closing a Socket

```c
int nng_socket_close(nng_socket s);
```

The {{i:`nng_socket_close`}} function closes a socket, releasing all resources
associated with it. Any operations that are in progress will be terminated with
a result of [`NNG_ECLOSED`].

> [!NOTE]
> Closing a socket also invalidates any [dialers][dialer], [listeners][listener],
> [pipes][pipe], or [contexts][context] associated with it.

> [!NOTE]
> This function will wait for any outstanding operations to be aborted, or to complete,
> before returning. Consequently it is not safe to call this from contexts that cannot
> block.

> [!NOTE]
> Closing the socket may be disruptive to transfers that are still in progress.

## Sending Messages

```c
int nng_send(nng_socket s, void *data, size_t size, int flags);
int nng_sendmsg(nng_socket s, nng_msg *msg, int flags);
void nng_socket_send(nng_socket s, nng_aio *aio);
```

These functions ({{i:`nng_send`}}, {{i:`nng_sendmsg`}}, and {{i:`nng_socket_send`}}) send
messages over the socket _s_. The differences in their behaviors are as follows.

> [!NOTE]
> The semantics of what sending a message means varies from protocol to
> protocol, so examination of the protocol documentation is encouraged.
> Additionally, some protocols may not support sending at all or may require other pre-conditions first.
> (For example, [REP][rep] sockets cannot normally send data until they have first received a request,
> while [SUB][sub] sockets can only receive data and never send it.)

### nng_send

The `nng_send` function is the simplest to use, but is the least efficient.
It sends the content in _data_, as a message of _size_ bytes. The _flags_ is a bit mask
made up of zero or more of the following values:

- {{i:`NNG_FLAG_NONBLOCK`}}: <a name="NNG_FLAG_NONBLOCK"></a>
  If the socket cannot accept more data at this time, it does not block, but returns immediately
  with a status of [`NNG_EAGAIN`]. If this flag is absent, the function will wait until data can be sent.

> [!NOTE]
> Regardless of the presence or absence of `NNG_FLAG_NONBLOCK`, there may
> be queues between the sender and the receiver.
> Furthermore, there is no guarantee that the message has actually been delivered.
> Finally, with some protocols, the semantic is implicitly `NNG_FLAG_NONBLOCK`,
> such as with [PUB][pub] sockets, which are best-effort delivery only.

### nng_sendmsg

The `nng_sendmsg` function sends the _msg_ over the socket _s_.

If this function returns zero, then the socket will dispose of _msg_ when the transmission is complete.
If the function returns a non-zero status, then the call retains the responsibility for disposing of _msg_.

The _flags_ can contain the value [`NNG_FLAG_NONBLOCK`], indicating that the function should not wait if the socket
cannot accept more data for sending. In such a case, it will return [`NNG_EAGAIN`].

> [!TIP]
> This function is preferred over [`nng_send`], as it gives access to the message structure and eliminates both
> a data copy and allocation.

### nng_socket_send

The `nng_socket_send` function sends a message asynchronously, using the [`nng_aio`] _aio_, over the socket _s_.
The message to send must have been set on _aio_ using the [`nng_aio_set_msg`] function.

If the operation completes successfully, then the socket will have disposed of the message.
However, if it fails, then callback of _aio_ should arrange for a final disposition of the message.
(The message can be retrieved from _aio_ with [`nng_aio_get_msg`].)

Note that callback associated with _aio_ may be called _before_ the message is finally delivered to the recipient.
For example, the message may be sitting in queue, or located in TCP buffers, or even in flight.

> [!TIP]
> This is the preferred function to use for sending data on a socket. While it does require a few extra
> steps on the part of the application, the lowest latencies and highest performance will be achieved by using
> this function instead of [`nng_send`] or [`nng_sendmsg`].

## Receiving Messages

```c
int nng_recv(nng_socket s, void *data, size_t *sizep, int flags);
int nng_recvmsg(nng_socket s, nng_msg **msgp, int flags);
void nng_socket_recv(nng_socket s, nng_aio *aio);
```

These functions ({{i:`nng_recv`}}, {{i:`nng_recvmsg`}}, and {{i:`nng_socket_recv`}}) receive
messages over the socket _s_. The differences in their behaviors are as follows.

> [!NOTE]
> The semantics of what receiving a message means varies from protocol to
> protocol, so examination of the protocol documentation is encouraged.
> Additionally, some protocols may not support receiving at all or may require other pre-conditions first.
> (For example, [REQ][req] sockets cannot normally receive data until they have first sent a request,
> while [PUB][pub] sockets can only send data and never receive it.)

### nng_recv

The `nng_recv` function is the simplest to use, but is the least efficient.
It receives the content in _data_, as a message size (in bytes) of up to the value stored in _sizep_.

Upon success, the size of the message received will be stored in _sizep_.

The _flags_ is a bit mask made up of zero or more of the following values:

- {{i:`NNG_FLAG_NONBLOCK`}}:
  If the socket has no messages pending for reception at this time, it does not block, but returns immediately
  with a status of [`NNG_EAGAIN`]. If this flag is absent, the function will wait until data can be received.

### nng_recvmsg

The `nng_recvmsg` function receives a message and stores a pointer to the [`nng_msg`] for that message in _msgp_.

The _flags_ can contain the value [`NNG_FLAG_NONBLOCK`], indicating that the function should not wait if the socket
has no messages available to receive. In such a case, it will return [`NNG_EAGAIN`].

> [!TIP]
> This function is preferred over [`nng_recv`], as it gives access to the message structure and eliminates both
> a data copy and allocation.

### nng_socket_recv

The `nng_socket_send` function receives a message asynchronously, using the [`nng_aio`] _aio_, over the socket _s_.
On success, the received message can be retrieved from the _aio_ using the [`nng_aio_get_msg`] function.

> [!NOTE]
> It is important that the application retrieves the message, and disposes of it accordingly.
> Failure to do so will leak the memory.

> [!TIP]
> This is the preferred function to use for receiving data on a socket. While it does require a few extra
> steps on the part of the application, the lowest latencies and highest performance will be achieved by using
> this function instead of [`nng_recv`] or [`nng_recvmsg`].

## Socket Options

```c
int nng_socket_get_bool(nng_socket s, const char *opt, bool *valp);
int nng_socket_get_int(nng_socket s, const char *opt, int *valp);
int nng_socket_get_ms(nng_socket s, const char *opt, nng_duration *valp);
int nng_socket_get_size(nng_socket s, const char *opt, size_t *valp);

int nng_socket_set_bool(nng_socket s, const char *opt, int val);
int nng_socket_set_int(nng_socket s, const char *opt, int val);
int nng_socket_set_ms(nng_socket s, const char *opt, nng_duration val);
int nng_socket_set_size(nng_socket s, const char *opt, size_t val);
```

Protocols usually have protocol specific behaviors that can be adjusted via options.

These functions are used to retrieve or change the value of an option named _opt_ from the context _ctx_.
The `nng_socket_get_` functions retrieve the value from the socket _s_, and store it in the location _valp_ references.
The `nng_socket_set_` functions change the value for the socket _s_, taking it from _val_.

These functions access an option as a specific type. The protocol documentation will have details about which options
are available, whether they can be read or written, and the appropriate type to use.

> [!NOTE]
> Socket options are are used to tune the behavior of the higher level protocol. To change the options
> for an underlying transport, the option should be set on the [dialer] or [listener] instead of the [socket].

### Common Options

The following options are available for many protocols, and always use the same types and semantics described below.

| Option                                                | Type           | Description                                                                                                                                                                       |
| ----------------------------------------------------- | -------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `NNG_OPT_MAXTTL`<a name="NNG_OPT_MAXTTL"></a>         | `int`          | Maximum number of traversals across an [`nng_device`] device, to prevent forwarding loops. May be 1-255, inclusive. Normally defaults to 8.                                       |
| `NNG_OPT_RECONNMAXT`<a name="NNG_OPT_RECONNMAXT"></a> | `nng_duration` | Maximum time [dialers][dialer] will delay before trying after failing to connect.                                                                                                 |
| `NNG_OPT_RECONNMINT`<a name="NNG_OPT_RECONNMINT"></a> | `nng_duration` | Minimum time [dialers][dialer] will delay before trying after failing to connect.                                                                                                 |
| `NNG_OPT_RECVBUF`<a name="NNG_OPT_RECVBUF"></a>       | `int`          | Maximum number of messages (0-8192) to buffer locally when receiving.                                                                                                             |
| `NNG_OPT_RECVMAXSZ`<a name="NNG_OPT_RECVMAXSZ"></a>   | `size_t`       | Maximum message size acceptable for receiving. Zero means unlimited. Intended to prevent remote abuse. Can be tuned independently on [dialers][dialer] and [listeners][listener]. |
| `NNG_OPT_RECVTIMEO`<a name="NNG_OPT_RECVTIMEO"></a>   | `nng_duration` | Default timeout (ms) for receiving messages.                                                                                                                                      |
| `NNG_OPT_SENDBUF`<a name="NNG_OPT_SENDBUF"></a>       | `int`          | Maximum number of messages (0-8192) to buffer when sending messages.                                                                                                              |
| `NNG_OPT_SENDTIMEO`<a name="NNG_OPT_SENDTIMEO"></a>   | `nng_duration` | Default timeout (ms) for sending messages.                                                                                                                                        |

&nbsp;

> [!NOTE]
> The `NNG_OPT_RECONNMAXT`, `NNG_OPT_RECONNMINT`, and `NNG_OPT_RECVMAXSZ` options are just the initial defaults that [dialers][dialer]
> (and for `NNG_OPT_RECVMAXSZ` also [listeners][listener])
> will use. After the dialer or listener is created, changes to the socket's value will have no affect on that dialer or listener.

## Polling Socket Events

```c
int nng_socket_get_recv_poll_fd(nng_socket s, int *fdp);
int nng_socket_get_send_poll_fd(nng_socket s, int *fdp);
```

Sometimes it is necessary to integrate a socket into a `poll` or `select` driven
{{i:event loop}}. (Or, on Linux, `epoll`, or on BSD derived systems like macOS `kqueue`).

For these occasions, a suitable file descriptor for polling is provided
by these two functions.

The {{i:`nng_socket_get_recv_poll_fd`}} function obtains a file descriptor
that will poll as readable when a message is ready for receiving for the socket.

The {{i:`nng_socket_get_send_poll_fd`}} function obtains a file descriptor
that will poll as readable when the socket can accept a message for sending.

These file descriptors should only be polled for readability, and no
other operation performed on them. The socket will read from, or write to,
these file descriptors to provide a level-signaled behavior automatically.

Additionally the socket will close these file descriptors when the socket itself is closed.

These functions replace the `NNG_OPT_SENDFD` and `NNG_OPT_RECVFD` socket options that
were available in previous versions of NNG.

> [!NOTE]
> These functions are not compatible with [contexts][context].

> [!NOTE]
> The file descriptors supplied by these functions is not used for transporting message data.
> The only valid use of these file descriptors is for polling for the ability to send or receive
> messages on the socket.

> [!TIP]
> Using these functions will force the socket to perform extra system calls, and thus
> have a negative impact on performance and latency. It is preferable to use [asynchronous I/O][aio]
> when possible.

## Examples

### Example 1: Initializing a Socket

```c
nng_socket s = NNG_SOCKET_INITIALIZER;
```

### Example 2: Publishing a Timestamp

This example demonstrates the use of [`nng_aio`], [`nng_socket_send`], and [`nng_sleep_aio`] to
build a service that publishes a timestamp at one second intervals. Error handling is elided for the
sake of clarity.

```c
#include <stdlib.h>
#include <stdio.h>
#include <nng/nng.h>
#include <nng/protocol/pubsub0/pub.h>

struct state {
    nng_socket s;
    bool sleeping;
    nng_aio *aio;
};

static struct state state;

void callback(void *arg) {
    nng_msg *msg;
    nng_time now;
    struct state *state = arg;
    if (nng_aio_result(state->aio) != 0) {
        fprintf(stderr, "Error %s occurred", nng_strerror(nng_aio_result(state->aio)));
        return; // terminate the callback loop
    }
    if (state->sleeping) {
        state->sleeping = false;
        nng_msg_alloc(&msg, sizeof (nng_time));
        now = nng_clock();
        nng_msg_append(msg, &now, sizeof (now)); // note: native endian
        nng_aio_set_msg(state->aio, msg);
        nng_socket_send(state->s, state->aio);
    } else {
        state->sleeping = true;
        nng_sleep_aio(1000, state->aio); // 1000 ms == 1 second
    }
}

int main(int argc, char **argv) {
    const char *url = argv[1]; // should check this

    nng_aio_alloc(&state.aio, NULL, NULL);
    nng_pub0_open(&state.s);
    nng_listen(state.s, url, NULL, 0);
    state.sleeping = 0;
    nng_sleep_aio(1, state.aio); // kick it off right away
    for(;;) {
        nng_msleep(0x7FFFFFFF); // infinite, could use pause or sigsuspend
    }
}
```

### Example 3: Watching a Periodic Timestamp

This example demonstrates the use of [`nng_aio`], [`nng_socket_recv`], to build a client to
watch for messages received from the service created in Example 2.
Error handling is elided for the sake of clarity.

```c
#include <stdlib.h>
#include <stdio.h>
#include <string.h>>
#include <nng/nng.h>
#include <nng/protocol/pubsub0/sub.h>

struct state {
    nng_socket s;
    nng_aio *aio;
};

static struct state state;

void callback(void *arg) {
    nng_msg *msg;
    nng_time now;
    struct state *state = arg;
    if (nng_aio_result(state->aio) != 0) {
        fprintf(stderr, "Error %s occurred", nng_strerror(nng_aio_result(state->aio)));
        return; // terminate the callback loop
    }
    msg = nng_aio_get_msg(state->aio);
    memcpy(&now, nng_msg_body(msg), sizeof (now)); // should check the length!
    printf("Timestamp is %lu\n", (unsigned long)now);
    nng_msg_free(msg);
    nng_aio_set_msg(state->aio, NULL);
    nng_socket_recv(state->s, state->aio);
}

int main(int argc, char **argv) {
    const char *url = argv[1]; // should check this

    nng_aio_alloc(&state.aio, NULL, NULL);
    nng_sub0_open(&state.s);
    nng_sub0_socket_subscribe(state.s, NULL, 0); // subscribe to everything
    nng_dial(state.s, url, NULL, 0);
    nng_socket_recv(state.s, state.aio); // kick it off right away
    for(;;) {
        nng_msleep(0x7FFFFFFF); // infinite, could use pause or sigsuspend
    }
}
```

{{#include ../xref.md}}
