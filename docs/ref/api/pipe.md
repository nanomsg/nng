# Pipes

```c
typedef struct nng_pipe_s nng_pipe;
```

An {{i:`nng_pipe`}} is a handle to a {{i:pipe}} object, which can be thought of as a single {{i:connection}}.
(In most cases this is actually the case -- the pipe is an abstraction for a single TCP or IPC connection.)
Pipes are associated with either the listener or dialer that created them,
and therefore are also automatically associated with a single socket.

> [!NOTE]
> The `nng_pipe` structure is always passed by value (both
> for input parameters and return values), and should be treated opaquely.
> Passing structures this way gives the compiler a chance to perform
> accurate type checks in functions passing values of this type.

> [!TIP]
> Most applications should never concern themselves with individual pipes.
> However it is possible to access a pipe when more information about the
> source of a message is needed, or when more control is required over message delivery.

Pipe objects are created by [dialers][dialer] and and [listeners][listener].

## Initialization

A pipe may be initialized using the macro {{i:`NNG_PIPE_INITIALIZER`}}
before it is opened, to prevent confusion with valid open pipes.

For example:

```c
nng_pipe p = NNG_PIPE_INITIALIZER;
```

## Pipe Identity

```c
int nng_pipe_id(nng_pipe p);
```

The {{i:`nng_pipe_id`}} function returns a positive identifier for the pipe _p_, if it is valid.
Otherwise it returns `-1`.

> [!NOTE]
> A pipe is considered valid if it was ever created by the socket.
> Pipes that are allocated on the stack or statically should be initialized with the macro
> [`NNG_PIPE_INITIALIZER`] to ensure that they cannot be confused with a valid pipe.

## Closing a Pipe

```c
nng_err nng_pipe_close(nng_pipe p);
```

The {{i:`nng_pipe_close`}} function closes the supplied pipe, _p_.
Messages that have been submitted for sending may be flushed or delivered,
depending upon the transport.

Further attempts to use the pipe after this call returns will result in [`NNG_ECLOSED`].

> [!TIP]
> Pipes are automatically closed when their creator closes, or when the
> remote peer closes the underlying connection.

## Pipe Creator

```c
nng_dialer nng_pipe_dialer(nng_pipe p);
nng_listener nng_pipe_listener(nng_pipe p);
nng_socket nng_pipe_socket(nng_pipe p);
```

{{hi:`nng_pipe_dialer`}}
{{hi:`nng_pipe_listener`}}
{{hi:`nng_pipe_socket`}}
These functions return the [socket], [dialer], or [listener] that created or owns the pipe.

If the pipe was does not have an associated dialer or listener, then the associated will
return [`NNG_DIALER_INITIALIZER`] or [`NNG_LISTENER_INITIALIZER`], as appropriate, and
either [`nng_dialer_id`] or [`nng_listener_id`] for the returned object will return -1.

> [!NOTE]
> The socket, or the endpoint, returned by these functions may be in the process of closing,
> and might not be further usable as a result. (Other functions will result in [`NNG_ECLOSED`].)

## Pipe Socket Addresses

```c
nng_err nng_pipe_peer_addr(nng_pipe p, nng_sockaddr *sap);
nng_err nng_pipe_self_addr(nng_pipe p, nng_sockaddr *sap);
```

The [`nng_sockaddr`] for the local (self) or remote (peer) of the pipe is available using these
functions. The associated address will be stored in the location pointed to by _sap_.

## Pipe Options

```c
nng_err nng_pipe_get_bool(nng_pipe p, const char *opt, bool *valp);
nng_err nng_pipe_get_int(nng_pipe p, const char *opt, int *valp);
nng_err nng_pipe_get_ms(nng_pipe p, const char *opt, nng_duration *valp);
nng_err nng_pipe_get_size(nng_pipe p, const char *opt, size_t *valp);
nng_err nng_pipe_get_string(nng_pipe p, const char *opt, const char **valp);
nng_err nng_pipe_get_strcpy(nng_pipe p, const char *opt, char *val, size_t len);
nng_err nng_pipe_get_strdup(nng_pipe p, const char *opt, char **valp);
nng_err nng_pipe_get_strlen(nng_pipe p, const char *opt, size_t *lenp);
```

{{hi:`nng_pipe_get_bool`}}
{{hi:`nng_pipe_get_int`}}
{{hi:`nng_pipe_get_ms`}}
{{hi:`nng_pipe_get_size`}}
{{hi:`nng_pipe_get_string`}}
{{hi:`nng_pipe_get_strcpy`}}
{{hi:`nng_pipe_get_strdup`}}
These functions are used to obtain value of an option named _opt_ from the pipe _p_, and store it in the location
referenced by _valp_.

These functions access an option as a specific type. The transport layer will have details about which options
are available, and which type they may be accessed using.

In the case of `nng_pipe_get_string`, the underlying string may only be valid for as long as the pipe is valid.
Thus, this function can only be safely called in a pipe event callback set up with [`nng_pipe_notify`].

The `nng_pipe_get_strdup` function is like `nng_pipe_get_string`, but makes a copy into a newly allocated buffer, so that the string must be freed by the caller using [`nng_strfree`].

The `nng_pipe_get_strcpy` function is also like `nng_pipe_get_string`, but it makes a copy into a buffer
supplied by the caller. The buffer is passed in _val_, and the size of the buffer is passed in _len_.
The value of _len_ must be large enough to hold the string and the terminating zero byte.

The `nng_pipe_get_strlen` function is used to obtain the length of the string. This can be useful
to find the size of the buffer needed by the `nng_pipe_get_strcpy` function for a property.
Note that like `strlen`, this size does not account for the zero byte to terminate the string.

## Pipe Notifications

```c
typedef enum {
        NNG_PIPE_EV_ADD_PRE,
        NNG_PIPE_EV_ADD_POST,
        NNG_PIPE_EV_REM_POST,
} nng_pipe_ev;

typedef void (*nng_pipe_cb)(nng_pipe, nng_pipe_ev, void *);

nng_err nng_pipe_notify(nng_socket s, nng_pipe_ev ev, nng_pipe_cb cb, void *arg);
```

The {{i:`nng_pipe_notify`}} function registers the callback function _cb_
to be called whenever the pipe event specified by
_ev_ occurs on the socket _s_.
The callback _cb_ will be passed _arg_ as its final argument.

A different callback may be supplied for each event.
Each event may have at most one callback registered.
Registering a callback implicitly unregisters any previously registered.

The following pipe events are supported:

| Event                                                           | Description                                                                                                                                                                                                                                                              |
| --------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| {{i:`NNG_PIPE_EV_ADD_PRE`}}<a name="NNG_PIPE_EV_ADD_PRE"></a>   | This event occurs after a connection and negotiation has completed, but before the pipe is added to the socket. If the pipe is closed (using [`nng_pipe_close`]) at this point, the socket will never see the pipe, and no further events will occur for the given pipe. |
| {{i:`NNG_PIPE_EV_ADD_POST`}}<a name="NNG_PIPE_EV_ADD_POST"></a> | This event occurs after the pipe is fully added to the socket. Prior to this time, it is not possible to communicate over the pipe with the socket.                                                                                                                      |
| {{i:`NNG_PIPE_EV_REM_POST`}}<a name="NNG_PIPE_EV_REM_POST"></a> | This event occurs after the pipe has been removed from the socket. The underlying transport may be closed at this point, and it is not possible communicate using this pipe.                                                                                             |

> [!WARNING]
> The callback _cb_ function must _not_ attempt to perform any
> accesses to the socket, as it is called with a lock on the socket held!
> Doing so would thus result in a deadlock.

> [!TIP]
> The callback _cb_ may close a pipe for any reason by simply closing it using [`nng_pipe_close`].
> For example, this might be done to prevent an unauthorized peer from connecting to the socket,
> if an authorization check made during `NNG_PIPE_EV_ADD_PRE` fails.

> [!NOTE]
> This function ignores invalid values for _ev_.

{{#include ../xref.md}}
