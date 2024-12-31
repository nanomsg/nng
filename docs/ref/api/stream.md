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

The {{i:`nng_stream_recv`}} function starts receiving data [asynchronously over the stream _s_
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

## Getting Stream Options

```c
int nng_stream_get_bool(nng_stream *s, const char *opt, bool *valp);
int nng_stream_get_int(nng_stream *s, const char *opt, int *valp);
int nng_stream_get_ms(nng_stream *s, const char *opt, nng_duration *valp);
int nng_stream_get_size(nng_stream *s, const char *opt, size_t *valp);
int nng_stream_get_addr(nng_stream *s, const char *opt, nng_sockaddr *valp);
int nng_stream_get_string(nng_stream *s, const char *opt, char **valp);
int nng_stream_get_uint64(nng_stream *s, const char *opt, uint64_t *valp);
```

{{hi:`nng_stream_get_bool`}}
{{hi:`nng_stream_get_int`}}
{{hi:`nng_stream_get_ms`}}
{{hi:`nng_stream_get_size`}}
{{hi:`nng_stream_get_addr`}}
{{hi:`nng_stream_get_string`}}
{{hi:`nng_stream_get_uint64`}}
These functions are used to obtain value of an option named _opt_ from the stream _s_, and store it in the location
referenced by _valp_.

These functions access an option as a specific type. The transport layer will have details about which options
are available, and which type they may be accessed using.

In the case of `nng_stream_get_string`, the string is created as if by [`nng_strdup`], and must be freed by
the caller using [`nng_strfree`] when no longer needed.

{{#include ../xref.md}}
