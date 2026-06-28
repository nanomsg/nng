# Dialers and Listeners

```c
#define NNG_DIALER_INITIALIZER   // opaque value
#define NNG_LISTENER_INITIALIZER // opaque value

typedef struct nng_dialer_s nng_dialer;
typedef struct nng_listener_s nng_listener;
```

{{hi:dialer}}
{{hi:listener}}
Dialers and listeners connect a [socket] to a transport address.
A {{i:`nng_dialer`}} initiates outgoing connections to a remote listener.
An {{i:`nng_listener`}} accepts incoming connections from remote dialers.

When a connection is established, NNG creates an [`nng_pipe`] and attaches it to the socket.
A dialer creates at most one pipe at a time.
A listener can create many pipes, which may be open concurrently.

NNG sometimes refers to dialers and listeners collectively as {{i:endpoints}}.
That term is useful when discussing shared behavior, but the public API names are dialer and listener.

> [!NOTE]
> The client/server relationship implied by dialer and listener is independent of protocol roles.
> For example, a [REP][rep] socket can use a dialer to connect to a listener on a [REQ][req] socket.
> A socket can also have multiple dialers, multiple listeners, or both.

## Initialization

```c
nng_dialer d = NNG_DIALER_INITIALIZER;
nng_listener l = NNG_LISTENER_INITIALIZER;
```

The `nng_dialer` and `nng_listener` structures are opaque handles passed by value.
They should be initialized with [`NNG_DIALER_INITIALIZER`] or [`NNG_LISTENER_INITIALIZER`] before they are opened,
so that they cannot be confused with valid open handles.

## Creating and Starting

```c
int nng_dial(nng_socket s, const char *url, nng_dialer *dialerp, int flags);
int nng_dial_url(nng_socket s, const nng_url *url, nng_dialer *dialerp, int flags);

int nng_listen(nng_socket s, const char *url, nng_listener *listenerp, int flags);
int nng_listen_url(nng_socket s, const nng_url *url, nng_listener *listenerp, int flags);
```

The {{i:`nng_dial`}} and {{i:`nng_dial_url`}} functions create a dialer associated with socket _s_,
configure it to connect to _url_, and start it.
If _dialerp_ is not `NULL`, the newly created dialer is stored there.

The {{i:`nng_listen`}} and {{i:`nng_listen_url`}} functions create a listener associated with socket _s_,
configure it to listen at _url_, and start it.
If _listenerp_ is not `NULL`, the newly created listener is stored there.

The forms that take `const char *url` parse the URL from a string.
The `_url` forms use an existing [`nng_url`] object.

Because these functions start the dialer or listener immediately, applications usually cannot apply additional
transport options first.
Use [`nng_dialer_create`] or [`nng_listener_create`] when configuration must be applied before starting.

### Dialer Connection Behavior

Normally, the first dial attempt is made synchronously, including any required name resolution.
If the connection is refused or otherwise fails, the error is returned immediately and no retry is scheduled.

If [`NNG_FLAG_NONBLOCK`] is supplied in _flags_, the first connection attempt is made asynchronously.
In that mode, connection failures are retried in the background.

Once a dialer has connected successfully, it waits for the pipe to close.
If the pipe closes, the dialer attempts to reconnect asynchronously, even if the original connection was made synchronously.

> [!TIP]
> `NNG_FLAG_NONBLOCK` can make startup more resilient, but it can also make initial connection failures harder to diagnose.
> Use [`nng_dialer_start_aio`] when the application needs asynchronous startup and the result of the first dial attempt.

### Listener Behavior

The _flags_ argument to `nng_listen` and `nng_listen_url` is ignored and reserved for future use.

A listener continues to accept new connections, associating their pipes with the socket, until either the listener
or the socket is closed.

### Errors

The create-and-start functions can return:

- [`NNG_EADDRINUSE`]: The listener address is already in use.
- [`NNG_EADDRINVAL`]: The URL is invalid.
- [`NNG_ECLOSED`]: The socket is closed.
- [`NNG_ECONNREFUSED`]: The remote peer refused the initial dial connection.
- [`NNG_ECONNRESET`]: The remote peer reset the initial dial connection.
- [`NNG_EINVAL`]: The URL or flags are invalid.
- [`NNG_ENOMEM`]: Insufficient memory is available.
- [`NNG_EPEERAUTH`]: Authentication or authorization failed.
- [`NNG_EPROTO`]: A protocol error occurred.
- [`NNG_EUNREACHABLE`]: The remote address is not reachable.

## Creating Before Starting

```c
int nng_dialer_create(nng_dialer *dialerp, nng_socket s, const char *url);
int nng_dialer_create_url(nng_dialer *dialerp, nng_socket s, const nng_url *url);

int nng_listener_create(nng_listener *listenerp, nng_socket s, const char *url);
int nng_listener_create_url(nng_listener *listenerp, nng_socket s, const nng_url *url);
```

The {{i:`nng_dialer_create`}} and {{i:`nng_dialer_create_url`}} functions create a dialer associated with socket _s_,
configure it to connect to _url_, and store it in _dialerp_.
The dialer is not started.

The {{i:`nng_listener_create`}} and {{i:`nng_listener_create_url`}} functions create a listener associated with socket _s_,
configure it to listen at _url_, and store it in _listenerp_.
The listener is not started.

Use these functions when the dialer or listener needs additional configuration before it starts, such as transport options,
TLS configuration, or a listener socket activation file descriptor.

### Errors

These functions can return:

- [`NNG_EADDRINVAL`]: The URL is invalid.
- [`NNG_ECLOSED`]: The socket is closed.
- [`NNG_ENOMEM`]: Insufficient memory is available.

## Starting

```c
int nng_dialer_start(nng_dialer dialer, int flags);
void nng_dialer_start_aio(nng_dialer dialer, int flags, nng_aio *aio);
int nng_listener_start(nng_listener listener, int flags);
```

The {{i:`nng_dialer_start`}} function starts _dialer_.
It follows the same synchronous and `NNG_FLAG_NONBLOCK` behavior described for [`nng_dial`].

The {{i:`nng_dialer_start_aio`}} function starts _dialer_ asynchronously using _aio_.
It must be called with `NNG_FLAG_NONBLOCK` in _flags_.
When the first dial attempt completes, the operation result is reported through _aio_.
Only the first dialing result is reported this way.

The {{i:`nng_listener_start`}} function starts _listener_, causing it to bind to its address and accept connections.
The _flags_ argument is ignored and reserved for future use.

Once a dialer or listener has started, it is generally not possible to change its configuration.

### Errors

`nng_dialer_start` can return, and `nng_dialer_start_aio` can report through its AIO, these errors:

- [`NNG_EADDRINVAL`]: The URL is invalid.
- [`NNG_ECLOSED`]: The socket is closed.
- [`NNG_ECONNREFUSED`]: The remote peer refused the initial connection.
- [`NNG_ECONNRESET`]: The remote peer reset the initial connection.
- [`NNG_EINVAL`]: The flags are invalid.
- [`NNG_ENOENT`]: The dialer handle is invalid.
- [`NNG_ENOMEM`]: Insufficient memory is available.
- [`NNG_EPEERAUTH`]: Authentication or authorization failed.
- [`NNG_EPROTO`]: A protocol error occurred.
- [`NNG_ESTATE`]: The dialer is already started.
- [`NNG_EUNREACHABLE`]: The remote address is not reachable.

`nng_listener_start` can fail with:

- [`NNG_EADDRINUSE`]: The listener address is already in use.
- [`NNG_ECLOSED`]: The listener is closed.
- [`NNG_EPERM`]: Permission was denied when binding to the address.
- [`NNG_ESTATE`]: The listener is already started.

## Closing

```c
int nng_dialer_close(nng_dialer dialer);
int nng_listener_close(nng_listener listener);
```

The {{i:`nng_dialer_close`}} function closes _dialer_.
The {{i:`nng_listener_close`}} function closes _listener_.

Closing a dialer or listener also closes any pipes it created.
Once this function returns, the dialer or listener and its resources are deallocated.
Further attempts to use the handle will fail with [`NNG_ECLOSED`].

Dialers and listeners are also closed when their associated socket is closed.

### Errors

These functions can return:

- [`NNG_ECLOSED`]: The handle does not refer to an open dialer or listener.

## Identity

```c
int nng_dialer_id(nng_dialer dialer);
int nng_listener_id(nng_listener listener);
```

The {{i:`nng_dialer_id`}} and {{i:`nng_listener_id`}} functions return a positive identifier if the supplied handle is valid.
Otherwise they return `-1`.

A dialer or listener is considered valid if it was ever created by one of the create or create-and-start functions.
Handles allocated on the stack or statically should be initialized with [`NNG_DIALER_INITIALIZER`] or
[`NNG_LISTENER_INITIALIZER`] before use.

## Associated URLs

```c
int nng_dialer_get_url(nng_dialer dialer, const nng_url **urlp);
int nng_listener_get_url(nng_listener listener, const nng_url **urlp);
```

The {{i:`nng_dialer_get_url`}} and {{i:`nng_listener_get_url`}} functions return the URL associated with _dialer_ or _listener_.
The URL pointer is stored in _urlp_.

The returned URL belongs to the dialer or listener.
It must not be modified or freed by the caller, and it is invalid after the dialer or listener is closed.

> [!NOTE]
> Older NNG documentation referred to an `NNG_OPT_URL` option for endpoints.
> That option has been removed.
> Use `nng_dialer_get_url` and `nng_listener_get_url` instead, which return a
> typed [`nng_url`] object rather than a string.

### Errors

These functions can return:

- [`NNG_ECLOSED`]: The handle does not refer to an open dialer or listener.

## Options

```c
int nng_dialer_get_bool(nng_dialer dialer, const char *opt, bool *valp);
int nng_dialer_get_int(nng_dialer dialer, const char *opt, int *valp);
int nng_dialer_get_ms(nng_dialer dialer, const char *opt, nng_duration *valp);
int nng_dialer_get_size(nng_dialer dialer, const char *opt, size_t *valp);
int nng_dialer_get_addr(nng_dialer dialer, const char *opt, nng_sockaddr *valp);
int nng_dialer_get_string(nng_dialer dialer, const char *opt, const char **valp);
int nng_dialer_get_uint64(nng_dialer dialer, const char *opt, uint64_t *valp);

int nng_listener_get_bool(nng_listener listener, const char *opt, bool *valp);
int nng_listener_get_int(nng_listener listener, const char *opt, int *valp);
int nng_listener_get_ms(nng_listener listener, const char *opt, nng_duration *valp);
int nng_listener_get_size(nng_listener listener, const char *opt, size_t *valp);
int nng_listener_get_string(nng_listener listener, const char *opt, const char **valp);
int nng_listener_get_uint64(nng_listener listener, const char *opt, uint64_t *valp);

int nng_dialer_set_bool(nng_dialer dialer, const char *opt, bool val);
int nng_dialer_set_int(nng_dialer dialer, const char *opt, int val);
int nng_dialer_set_ms(nng_dialer dialer, const char *opt, nng_duration val);
int nng_dialer_set_size(nng_dialer dialer, const char *opt, size_t val);
int nng_dialer_set_addr(nng_dialer dialer, const char *opt, const nng_sockaddr *val);
int nng_dialer_set_string(nng_dialer dialer, const char *opt, const char *val);
int nng_dialer_set_uint64(nng_dialer dialer, const char *opt, uint64_t val);

int nng_listener_set_bool(nng_listener listener, const char *opt, bool val);
int nng_listener_set_int(nng_listener listener, const char *opt, int val);
int nng_listener_set_ms(nng_listener listener, const char *opt, nng_duration val);
int nng_listener_set_size(nng_listener listener, const char *opt, size_t val);
int nng_listener_set_string(nng_listener listener, const char *opt, const char *val);
int nng_listener_set_uint64(nng_listener listener, const char *opt, uint64_t val);
```

The {{i:`nng_dialer_get`}} and {{i:`nng_listener_get`}} function families retrieve option values from a dialer or listener.
The {{i:`nng_dialer_set`}} and {{i:`nng_listener_set`}} function families configure option values on a dialer or listener.

The function suffix identifies the type used for the option:

| Suffix    | Type           | Use                                                                                |
| --------- | -------------- | ---------------------------------------------------------------------------------- |
| `_bool`   | `bool`         | Boolean options.                                                                   |
| `_int`    | `int`          | Integer options.                                                                   |
| `_ms`     | `nng_duration` | Time durations, stored as milliseconds.                                            |
| `_size`   | `size_t`       | Buffer sizes, maximum message sizes, and similar values.                           |
| `_addr`   | `nng_sockaddr` | Socket addresses. This form is available for dialer options only.                  |
| `_string` | `const char *` | `NUL`-terminated UTF-8 or ASCII strings.                                           |
| `_uint64` | `uint64_t`     | 64-bit unsigned values, typically identifiers, network numbers, and similar values. |

Available options vary by transport and by option.
Many common options are listed in [Socket Options][socket-options] and transport-specific options are documented
with each transport.

### Endpoint-Specific Options

The following endpoint-specific option is defined by the core API:

| Option                                        | Type           | Description |
| --------------------------------------------- | -------------- | ----------- |
| `NNG_OPT_LOCADDR`<a name="NNG_OPT_LOCADDR"></a> | `nng_sockaddr` | Dialers only. Configures the local address to bind before initiating outgoing connections, when supported by the transport. |

`NNG_OPT_LOCADDR` is most useful for transports such as TCP or UDP where the
application needs to choose the local interface or source address for outgoing
connections.
When used on a TCP dialer, the IP address portion is used as the source
address, but the port is ignored and an ephemeral port is chosen by the
system.

> [!NOTE]
> Support for `NNG_OPT_LOCADDR` depends on the transport.
> Some transports support it on dialers, some do not, and listeners may expose
> related local-address information differently or not at all.

> [!NOTE]
> Socket option values for `NNG_OPT_RECONNMAXT`, `NNG_OPT_RECONNMINT`, and `NNG_OPT_RECVMAXSZ` provide initial defaults
> for dialers and listeners created afterward.
> Changing those socket options does not affect existing dialers or listeners.

> [!NOTE]
> Once a dialer or listener has started, it is generally not possible to change its configuration.

### Errors

The option functions can return:

- [`NNG_EBADTYPE`]: The typed accessor does not match the option type.
- [`NNG_ECLOSED`]: The handle does not refer to an open dialer or listener.
- [`NNG_EINVAL`]: The value is invalid, or the destination is too small.
- [`NNG_ENOMEM`]: Insufficient memory is available.
- [`NNG_ENOTSUP`]: The option is not supported.
- [`NNG_EREADONLY`]: The option is read-only.
- [`NNG_ESTATE`]: The dialer or listener is already started.
- [`NNG_EWRITEONLY`]: The option is write-only.

## TLS Configuration

```c
int nng_dialer_get_tls(nng_dialer dialer, nng_tls_config **cfgp);
int nng_dialer_set_tls(nng_dialer dialer, nng_tls_config *cfg);
int nng_listener_get_tls(nng_listener listener, nng_tls_config **cfgp);
int nng_listener_set_tls(nng_listener listener, nng_tls_config *cfg);
```

These functions configure or retrieve TLS configuration objects for dialers and listeners whose transports support TLS.
They are documented in [Using Configuration Objects][tls-config-objects].

## Windows Security Descriptors

```c
int nng_listener_set_security_descriptor(nng_listener listener, void *desc);
```

The {{i:`nng_listener_set_security_descriptor`}} function configures the Windows security descriptor for _listener_.
This is used by transports that expose Windows named objects, such as the [IPC transport][ipc].
It must be called before the listener is started.

### Errors

This function can return:

- [`NNG_ECLOSED`]: The listener is closed.
- [`NNG_EINVAL`]: The descriptor is invalid.
- [`NNG_ENOTSUP`]: The transport or platform does not support security descriptors.
- [`NNG_ESTATE`]: The listener is already started.

## Examples

### Connecting With Convenience Functions

```c
nng_socket s;
nng_dialer d = NNG_DIALER_INITIALIZER;

nng_req0_open(&s);
nng_dial(s, "tcp://127.0.0.1:8080", &d, 0);
```

### Configuring Before Starting

```c
nng_socket s;
nng_listener l = NNG_LISTENER_INITIALIZER;

nng_rep0_open(&s);
nng_listener_create(&l, s, "tcp://127.0.0.1:8080");
nng_listener_set_size(l, NNG_OPT_RECVMAXSZ, 1024 * 1024);
nng_listener_start(l, 0);
```

{{#include ../xref.md}}
