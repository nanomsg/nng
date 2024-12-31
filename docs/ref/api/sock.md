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

{{#include ../xref.md}}
