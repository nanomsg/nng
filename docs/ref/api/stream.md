# Streams

NNG provides a common {{i:streams}} API for working with byte-oriented streams. In NNG, streams are bidirectional
connections for exchanging a stream of bytes.

Some common examples of streams are TCP connections, UNIX domain sockets, Windows named pipes, and WebSockets.

The API documented here is to facilitate applications that wish to work with these at a lower-level than
Scalability Protocols, in a way that is both portable and agnostic about the specific underlying transport mechanism.

> [!TIP]
> When working with Scalability Protocols directly, it is unlikely that there will be any need for
> using these Streams APIs.

## Stream Type

```c
typedef struct nng_stream nng_stream
```

The base {{i:`nng_stream`}} type represents a bidirectional, byte-oriented, reliable connection.

> [!NOTE]
> The `nng_stream` object is used for raw byte stream connections, and
> should not be confused with a [pipe] object created on a [socket] using
> the [`nng_listen`], [`nng_dial`] or related functions.

## Sending and Receiving Data

```c
void nng_stream_send(nng_stream *s, nng_aio *aio);
void nng_stream_recv(nng_stream *s, nng_aio *aio);
```

The {{i:`nng_stream_send`}} function starts sending data asynchronously over the stream _s_.
The data is sent from the scatter/gather vector located in the [`nng_aio`] _aio_,
which must have been previously set using [`nng_aio_set_iov`].

The {{i:`nng_stream_recv`}} function starts receiving data asynchronously over the stream _s_
into the scatter/gather vector located in the [`nng_aio`] _aio_,
which must have been previously set using [`nng_aio_set_iov`].

These functions return immediately, with no return value.
Completion of the operation is signaled via the _aio_, and the final
result may be obtained via [`nng_aio_result`].

The I/O operation may complete as soon as at least one byte has been
transferred, or an error has occurred.
Therefore, the number of bytes transferred may be less than requested.
The actual number of bytes transferred can be determined with [`nng_aio_count`].

## Closing a Stream

```c
void nng_stream_close(nng_stream *s);
void nng_stream_stop(nng_stream *s);
void nng_stream_free(nng_stream *s);
```

The {{i:`nng_stream_close`}} function closes a stream, but does not destroy it.
This function returns immediately. Operations that are pending against the stream, such
as [`nng_stream_send`] or [`nng_stream_recv`] operations will be canceled asynchronously, if possible.
Those operations will result in [`NNG_ECLOSED`].

The {{i:`nng_stream_stop`}} function not only closes the stream, but waits for any operations
pending against it to complete, and for any underlying asynchronous registered I/O to be fully deregistered.
As some systems use separate threads for asynchronous I/O, stopping the stream is necessary before those
resources can be freed. Until the stream is stopped, there could still be I/O operations in flight,
making it unsafe to deallocate memory.

The {{i:`nng_stream_free`}} function stops the stream like `nng_stream_stop`, but also deallocates the
stream itself.

> [!NOTE]
> Because `nng_stream_stop` and `nng_stream_free` both may block waiting for outstanding I/O to complete
> or be aborted, these functions are unsafe to call from functions that may not block, such as the
> completion function registered with an [`nng_aio`] when it is created.

## Stream Addresses

```c
const nng_sockaddr *nng_stream_peer_addr(nng_stream *s);
const nng_sockaddr *nng_stream_self_addr(nng_stream *s);
```

{{hi:`nng_stream_peer_addr`}}
{{hi:`nng_stream_self_addr`}}
These functions are used to obtain value of the local (self) or remote (peer) addresses
for the given stream _s_.

## Getting Stream Options

```c
nng_err nng_stream_get_bool(nng_stream *s, const char *opt, bool *valp);
nng_err nng_stream_get_int(nng_stream *s, const char *opt, int *valp);
nng_err nng_stream_get_ms(nng_stream *s, const char *opt, nng_duration *valp);
nng_err nng_stream_get_size(nng_stream *s, const char *opt, size_t *valp);
nng_err nng_stream_get_addr(nng_stream *s, const char *opt, nng_sockaddr *valp);
nng_err nng_stream_get_string(nng_stream *s, const char *opt, const char **valp);
```

{{hi:`nng_stream_get_bool`}}
{{hi:`nng_stream_get_int`}}
{{hi:`nng_stream_get_ms`}}
{{hi:`nng_stream_get_size`}}
{{hi:`nng_stream_get_string`}}
These functions are used to obtain value of an option named _opt_ from the stream _s_, and store it in the location
referenced by _valp_.

These functions access an option as a specific type. The transport layer will have details about which options
are available, and which type they may be accessed using.

In the case of `nng_stream_get_string`, the string pointer is only guaranteed to be valid while the
stream exists. Callers should make a copy of the data if required before closing the stream.

## Stream Factories

```c
typedef struct nng_stream_dialer nng_stream_dialer;
typedef struct nng_stream_listener nng_stream_listener;
```

{{hi:stream factory}}
The {{i:`nng_stream_listener`}} object and {{i:`nng_stream_listener`}} objects can be thought of as factories that
create [`nng_stream`] streams.

The `nng_stream_listener` object a handle to a listener, which creates streams by accepting incoming connection requests.
In a BSD socket implementation, this is the entity responsible for doing {{i:`bind`}}, {{i:`listen`}} and {{i:`accept`}}.
Normally a listener may be used to accept multiple, possibly many, concurrent connections.

The `nng_stream_dialer` object is a handle to a dialer, which creates streams by making outgoing
connection requests. While there isn't a specific BSD socket analogue, this can be thought of as a factory for TCP sockets
created by opening them with {{i:`socket`}} and then calling {{i:`connect`}} on them.

## Creating a Stream Factory

```c
nng_err nng_stream_dialer_alloc(nng_stream_dialer **dialerp, const char *url);
nng_err nng_stream_dialer_alloc_url(nng_stream_dialer **dialerp, const nng_url *url);
nng_err nng_stream_listener_alloc(nng_stream_listener **lstenerp, const char *url);
nng_err nng_stream_listener_alloc_url(nng_stream_listener **listenerp, const nng_url *url);
```

The {{i:`nng_stream_dialer_alloc`}} and {{i:`nng_stream_dialer_alloc_url`}} functions create a stream dialer, associated the
{{i:URL}} specified by _url_ represented as a string, or as an [`nng_url`] object, respectively. The dialer is returned in the location
_dialerp_ references.

The {{i:`nng_stream_listener_alloc`}} and {{i:`nng_stream_listener_alloc_url`}} functions create a stream listener, associated the
URL specified by _url_ represented as a string, or as an [`nng_url`] object, respectively. The listener is returned in the location
_listenerp_ references.

### Example 1: Creating a TCP Listener

This shows creating a TCP listener that listens on `INADDR_ANY`, port 444.

```c
nng_listener listener;
int rv = nng_stream_listener_alloc(&listener, "tcp://:444");
```

## Closing a Stream Factory

```c
void nng_stream_dialer_close(nng_stream_listener *dialer);
void nng_stream_dialer_stop(nng_stream_listener *dialer);
void nng_stream_dialer_free(nng_stream_listener *dialer);
void nng_stream_listener_close(nng_stream_listener *listener);
void nng_stream_listener_stop(nng_stream_listener *listener);
void nng_stream_listener_free(nng_stream_listener *listener);
```

The {{i:`nng_stream_dialer_close`}} and {{i:`nng_stream_listener_close`}} functions close the stream _dialer_ or _listener_,
preventing it from creating new connections.
This will generally include closing any underlying file used for creating such connections.
However, some requests may still be pending when this function returns, as it does not wait for the shutdown to complete.

The {{i:`nng_stream_dialer_stop`}} and {{i:`nng_stream_listener_stop`}} functions performs the same action,
but also wait until all outstanding requests are serviced, and the _dialer_ or _listener_ is completely stopped.
Because they blocks, these functions must not be called in contexts where blocking is not allowed.

The {{i:`nng_stream_dialer_free`}} and {{i:`nng_stream_listener_free`}} function performs the same action as
`nng_stream_dialer_stop` or `nng_stream_listener_stop`, but also deallocates the _dialer_ or _listener_, and any associated resources.

> [!TIP]
> A best practice for shutting down an application safely is to stop everything _before_ deallocating. This ensures that no
> callbacks are running that could reference an object after it is deallocated.

## Making Outgoing Connections

```c
void nng_stream_dialer_dial(nng_stream_dialer *dialer, nng_aio *aio);
```

The {{i:`nng_stream_dialer_dial`}} initiates an outgoing connection asynchronously, using the [`nng_aio`] _aio_.
If it successfully establishes a connection, it creates an [`nng_stream`], which can be obtained as the first
output result on _aio_ using the [`nng_aio_get_output`] function with index zero.

> [!TIP]
> An [`nng_stream_dialer`] can be used multiple times to make multiple concurrent connection requests, but
> they all must reference the same URL.

### Example 3: Connecting to Google

This demonstrates making an outbound connection to "google.com" on TCP port 80.
Error handling is elided for clarity.

```c
nng_aio *aio;
nng_stream_dialer *dialer;
nng_stream *stream;

nng_stream_dialer_alloc(&dialer, "tcp://google.com:80");

nng_aio_alloc(&aio, NULL, NULL);

// make a single outbound connection
nng_stream_dialer_dial(dialer, aio);
nng_aio_wait(aio); // wait for the asynch operation to complete
if (nng_aio_result(aio) != 0) {
    // ... handle the error
}
stream = nng_aio_get_output(aio, 0);
```

## Accepting Incoming Connections

```c
nng_err nng_stream_listener_listen(nng_stream_listener *listener);
void nng_stream_listener_accept(nng_stream_listener *listener, nng_aio *aio);
```

Accepting incoming connections is performed in two steps. The first step, {{i:`nng_stream_listener_listen`}} is to setup for
listening. For a TCP implementation of this, for example, this would perform the `bind` and the `listen` steps. This will bind
to the address represented by the URL that was specific when the listener was created with [`nng_stream_listener_alloc`].

In the second step, {{i:`nng_stream_listener_accept`}} accepts an incoming connection on _listener_ asynchronously, using the [`nng_aio`] _aio_.
If an incoming connection is accepted, it will be represented as an [`nng_stream`], which can be obtained from the _aio_ as the first
output result using the [`nng_aio_get_output`] function with index zero.

### Example 3: Accepting an Inbound Stream

For clarity this example uses a synchronous approach using [`nng_aio_wait`], but a typical server application
would most likely use a callback to accept the incoming stream, and start another instance of `nng_stream_listener_accept`.

```c
nng_aio *aio;
nng_listener *listener;
nng_stream *stream;

nng_stream_listener_alloc(&listener, "tcp://:8181");
nng_aio_alloc(&aio, NULL, NULL); // normally would use a callback

// listen (binding to the URL in the process)
if (nng_stream_listener_listen(listener)) {
    // ... handle the error
}

// now accept a single incoming connection as a stream object
nng_stream_listener_accept(l, aio);
nng_aio_wait(aio); // wait for the asynch operation to complete
if (nng_aio_result(aio) != 0) {
    // ... handle the error
}
stream = nng_aio_get_output(aio, 0);
```

## Stream Factory Options

```c
nng_err nng_stream_dialer_get_bool(nng_stream_dialer *dialer, const char *opt, bool *valp);
nng_err nng_stream_dialer_get_int(nng_stream_dialer *dialer, const char *opt, int *valp);
nng_err nng_stream_dialer_get_ms(nng_stream_dialer *dialer, const char *opt, nng_duration *valp);
nng_err nng_stream_dialer_get_size(nng_stream_dialer *dialer, const char *opt, size_t *valp);
nng_err nng_stream_dialer_get_string(nng_stream_dialer *dialer, const char *opt, const char **valp);

nng_err nng_stream_listener_get_bool(nng_stream_listener *listener, const char *opt, bool *valp);
nng_err nng_stream_listener_get_int(nng_stream_listener *listener, const char *opt, int *valp);
nng_err nng_stream_listener_get_ms(nng_stream_listener *listener, const char *opt, nng_duration *valp);
nng_err nng_stream_listener_get_size(nng_stream_listener *listener, const char *opt, size_t *valp);
nng_err nng_stream_listener_get_string(nng_stream_listener *listener, const char *opt, const char **valp);

nng_err nng_stream_dialer_set_addr(nng_stream_dialer *dialer, const char *opt, const nng_sockaddr *val);
nng_err nng_stream_dialer_set_bool(nng_stream_dialer *dialer, const char *opt, bool val);
nng_err nng_stream_dialer_set_int(nng_stream_dialer *dialer, const char *opt, int val);
nng_err nng_stream_dialer_set_ms(nng_stream_dialer *dialer, const char *opt, nng_duration val);
nng_err nng_stream_dialer_set_size(nng_stream_dialer *dialer, const char *opt, size_t val);
nng_err nng_stream_dialer_set_string(nng_stream_dialer *dialer, const char *opt, const char *val);

nng_err nng_stream_listener_set_bool(nng_stream_listener *listener, const char *opt, bool val);
nng_err nng_stream_listener_set_int(nng_stream_listener *listener, const char *opt, int val);
nng_err nng_stream_listener_set_ms(nng_stream_listener *listener, const char *opt, nng_duration val);
nng_err nng_stream_listener_set_size(nng_stream_listener *listener, const char *opt, size_t val);
nng_err nng_stream_listener_set_string(nng_stream_listener *listener, const char *opt, const char *val);
```

{{hi:`nng_stream_dialer_get_bool`}}
{{hi:`nng_stream_dialer_get_int`}}
{{hi:`nng_stream_dialer_get_ms`}}
{{hi:`nng_stream_dialer_get_size`}}
{{hi:`nng_stream_dialer_get_string`}}
{{hi:`nng_stream_dialer_set_bool`}}
{{hi:`nng_stream_dialer_set_int`}}
{{hi:`nng_stream_dialer_set_ms`}}
{{hi:`nng_stream_dialer_set_size`}}
{{hi:`nng_stream_dialer_set_addr`}}
{{hi:`nng_stream_dialer_set_string`}}
{{hi:`nng_stream_listener_get_bool`}}
{{hi:`nng_stream_listener_get_int`}}
{{hi:`nng_stream_listener_get_ms`}}
{{hi:`nng_stream_listener_get_size`}}
{{hi:`nng_stream_listener_get_addr`}}
{{hi:`nng_stream_listener_get_string`}}
{{hi:`nng_stream_listener_set_bool`}}
{{hi:`nng_stream_listener_set_int`}}
{{hi:`nng_stream_listener_set_ms`}}
{{hi:`nng_stream_listener_set_size`}}
{{hi:`nng_stream_listener_set_addr`}}
{{hi:`nng_stream_listener_set_string`}}
These functions are used to retrieve or change the value of an option named _opt_ from the stream _dialer_ or _listener_.
The `nng_stream_dialer_get_` and `nng_stream_listener_get_` function families retrieve the value, and store it in the location _valp_ references.
The `nng_stream_dialer_set_` and `nng_stream_listener_set_` function families change the value for the _dialer_ or _listener_, taking it from _val_.

These functions access an option as a specific type. The transport layer will have details about which options
are available, and which type they may be accessed using.

In the case of `nng_stream_dialer_get_string` and `nng_stream_listener_get_string`, the memory holding
the string is only valid as long as the associated object remains open.

In the case of `nng_stream_dialer_set_string` and `nng_stream_listener_set_string`, the string contents are copied if necessary, so that the caller
need not retain the value referenced once the function returns.

In the case of `nng_stream_dialer_set_addr`, the contents of _addr_ are copied if necessary, so that the caller
need not retain the value referenced once the function returns.

### Example 4: Socket Activation<a name="socket-activation"></a>

Some [`nng_stream_listener`] objects, depending on the underlying transport and platform, can support a technique known as "{{i:socket activation}}",
where the file descriptor used for listening and accepting is supplied externally, such as by a system service manager.
In this case, the application supplies the file descriptor or `SOCKET` object using the {{i:`NNG_OPT_LISTEN_FD`}} option,
instead of calling [`nng_stream_listener_listen`].

> [!TIP]
> Scalability Protocols transports based upon stream implementations that support socket activation can also benefit from this approach.

```c
nng_stream_listener *listener;
int fd;

// This is a systemd API, not part of NNG.
// See systemd documentation for an explanation.
// fd at this point has already had bind() and listen() called.
fd = SD_LISTEN_FDS_START + 0;

nng_stream_listener_alloc(&listener, "tcp://");
nng_stream_listener_set_int(listener, NNG_OPT_LISTEN_FD, fd);

// can now start doing nng_stream_listener_accept...
```

## TLS Configuration

```c
nng_err nng_stream_dialer_get_tls(nng_stream_listener *dialer, nng_tls_config **tlsp);
nng_err nng_stream_dialer_set_tls(nng_stream_listener *dialer, nng_tls_config *tls);
nng_err nng_stream_listener_get_tls(nng_stream_listener *listener, nng_tls_config **tlsp);
nng_err nng_stream_listener_set_tls(nng_stream_listener *listener, nng_tls_config *tls);
```

Both [`nng_stream_dialer`] and [`nng_stream_listener`] objects may support configuration of {{i:TLS}} parameters.
The {{i:`nng_stream_dialer_set_tls`}} and {{i:`nng_stream_listener_set_tls`}} functions support setting the
configuration of a [`nng_tls_config`] object supplied by _tls_ on _dialer_ or _listener_.
This must be performed before the _listener_ starts listening with [`nng_stream_listener_listen`], or the dialer starts an outgoing connection
as a result of [`nng_stream_dialer_dial`].

The configuration object that was previously established (which may be a default if one was not explicitly
configured) can be obtained with the {{i:`nng_stream_dialer_get_tls`}} and {{i:`nng_stream_listener_get_tls`}}.
They will return a pointer to the [`nng_tls_config`] object in question at the location referenced by _tlsp_.

> [!NOTE]
> TLS configuration cannot be changed once it has started being used by a listener or dialer. This applies to
> both configuring a different TLS configuration object, as well as mutating the existing [`nng_tls_config`] object.

{{#include ../xref.md}}
