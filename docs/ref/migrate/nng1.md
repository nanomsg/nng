# Migrating from NNG 1.x

There are some incompatibities from NNG 1.x.
This guide should help in migrating applications to use NNG 2.0.

## Nanomsg Compatibility

Applications using the legacy `libnanomsg` API will have to be updated to native _NNG_ interfaces.
See the [Migrating From libnanomsg](nanomsg.md) chapter for details.

## Library Initialization

It is now required for applications to initialize the library explicitly before using it.
This is done using the [`nng_init`] function.

## Transport Specific Functions

Transports have not needed to be registered for a long time now,
and the functions for doing so have been removed. These functions
can be simply removed from your application:

- `nng_inproc_register`
- `nng_ipc_register`
- `nng_tls_register`
- `nng_tcp_register`
- `nng_ws_register`
- `nng_wss_register`
- `nng_zt_register`

Additionally, the header files containing these functions have been removed, such as
`nng/transport/ipc/ipc.h`. Simply remove `#include` references to those files.

(Special exception: The options for ZeroTier are still located in the
`nng/transport/zerotier/zerotier.h`.)

The `NNG_OPT_WSS_REQUEST_HEADERS` and `NNG_OPT_WSS_RESPONSE_HEADERS` aliases for
`NNG_OPT_WS_OPT_WS_REQUEST_HEADERS` and `NNG_OPT_WS_RESPONSE_HEADERS` have been removed.
Just convert any use of them to `NNG_OPT_WS_REQUEST_HEADERS` or
`NNG_OPT_WS_RESPONSE_HEADERS` as appropriate.

## Asynchronous I/O Returns

When closing an [`nng_aio`] object with [`nng_aio_stop`], the result
of operation will be aborted with a result error of [`NNG_ECLOSED`], instead of [`NNG_ECANCELED`].
The `NNG_ECLOSED` error is a permanent failure, and operations should not be tried when
encountering it, whereas `NNG_ECANCELED` might just apply to a single operation that was
canceled by the submitter.

This situation can also occur when an underlying object such as a socket is closed.
In all cases, `NNG_ECLOSED` should be treated as a permanent failure.

## TLS Configuration

The support for configuring TLS via `NNG_OPT_TLS_CONFIG`, `NNG_TLS_AUTH_MODE`, `NNG_OPT_TLS_CA_FILE`,
`NNG_OPT_TLS_SERVER_NAME`, and similar has been removed.

Instead configuration must be performed by allocating
a `nng_tls_config` object, and then setting fields on it using the appropriate functions,
after which it may be configured on a listener or dialer using the [`nng_listener_set_tls`]
or [`nng_dialer_set_tls`] functions.

Likewise, when using the streams API, use the [`nng_stream_listener_set_tls`] or
[`nng_stream_dialer_set_tls`] functions.

Note that the declarations needed for TLS configuration are now available in `<nng/nng.h>`,
rather than the supplemental header.

## Old TLS Versions Removed

Support for very old TLS versions 1.0 and 1.1 is removed.
Further, the `NNG_TLS_1_0` and `NNG_TLS_1_1` constants are also removed.
Applications should use `NNG_TLS_1_2` or even `NNG_TLS_1_3` instead.

## Only One TLS Key/Cert Per Configuration

The ability to configure multiple keys and certificates for a given TLS configuration object is removed.
(The [`nng_tls_config_own_cert`] will return [`NNG_EBUSY`] if it has already been called for the configuration.)
The intended purpose was to support alternative cryptographic algorithms, but this is not necessary, was never
used, and was error prone.

## Support for Local Addresses in Dial URLs Removed

NNG 1.x had an undocumented ability to specify the local address to bind
to when dialing, by using the local address in front of the destination
address separated by a semicolon. This was provided for legacy libnanomsg
compatilibility, and is no longer offered. The correct way to specify a
local address is by setting `NNG_OPT_LOCADDR` on the dialer.

## Option Functions

The previously deprecated `nng_pipe_getopt_xxx` family of functions is removed.
Applications should use `nng_pipe_get` and related functions instead.

The socket option function families for `nng_getopt` and `nng_setopt` have been removed as well.
In this case, use the `nng_socket_get` and `nng_socket_set` functions as appropriate.

The `_getopt` and `_setopt` functions for contexts, listeners, and dialers are no longer
present. Simply changing `_getopt` to `_get` or `_setopt` to `_set` in the function name
should be sufficient in most cases.

The following functions served no useful purpose (after other changes described in this document),
and are thus removed:

- `nng_ctx_get_string`
- `nng_ctx_set_string`
- `nng_dialer_get_ptr`
- `nng_dialer_set_ptr`
- `nng_listener_get_ptr`
- `nng_listener_set_ptr`
- `nng_socket_get_ptr`
- `nng_socket_set_ptr`
- `nng_socket_get_string`
- `nng_socket_set_string`
- `nng_stream_get_ptr`
- `nng_stream_set_ptr`
- `nng_stream_dialer_get_ptr`
- `nng_stream_dialer_set_ptr`
- `nng_stream_listener_get_ptr`
- `nng_stream_listener_set_ptr`
- `nng_ctx_get_ptr` (not documented)
- `nng_ctx_set_ptr` (not documented)

## Untyped Option Functions Removed

The following functions are removed. To access options, use a proper typed access function,
such as one ending in a suffix like `_bool` (to access a `bool` typed option).

- `nng_ctx_get`
- `nng_ctx_set`
- `nng_dialer_get`
- `nng_dialer_set`
- `nng_listener_get`
- `nng_listener_set`
- `nng_pipe_get`
- `nng_socket_get`
- `nng_socket_set`
- `nng_stream_get`
- `nng_stream_set`
- `nng_stream_dialer_get`
- `nng_stream_dialer_set`
- `nng_stream_listener_get`
- `nng_stream_listener_set`

## Stream Options

The ability to set options on streams after they have been created is no longer present.
(It turns out that this was not very useful.) All functions `nng_stream_set_xxx` are removed.
For tuning the `NNG_OPT_TCP_NODELAY` or similar properties, set the option on the listener
or dialer that creates the stream instead.

## Transport Options

A number of transport options can no longer be set on the socket. Instead these
options must be set on the endpoint (dialer or listener) using the appropriate
`nng_dialer_set` or `nng_listener_set` option. This likely means that it is necessary
to allocate and configure the endpoint before attaching it to the socket. This will
also afford a much more fine-grained level of control over transport options.

The following options are copied from the socket when creating a dialer or listener,
but afterwards will not be changed on the dialer or listener if the socket
changes. It is recommended to set them properly on the socket before
creating dialers or listeners, or set them explicitly on the dialer or listener
directly:

- `NNG_OPT_RECONNMINT`
- `NNG_OPT_RECONNMAXT`
- `NNG_OPT_RECVMAXSZ`

The latter option is a hint for transports and intended to facilitate early
detection (and possibly avoidance of extra allocations) of oversize messages,
before bringing them into the socket itself.

## Socket Options

The `NNG_OPT_PROTO`, `NNG_OPT_PROTONAME`, `NNG_OPT_PEER`, and `NNG_OPT_PEERNAME` options
have been replaced by functions instead of options.
Use [`nng_socket_proto_id`], [`nng_socket_peer_id`], [`nng_socket_proto_name`], and [`nng_socket_peer_name`] instead.
Note that the new functions provide a reference to a static string, and thus do not require
allocation, and the returned strings should not be freed. Also the IDs are provided as `uint16_t`,
matching the actual wire protocol values, instead of `int`.

The `NNG_OPT_RAW` option has aso been replaced by a function, [`nng_socket_raw`].

The `NNG_OPT_SENDFD` and `NNG_OPT_RECVFD` options have been replaced by
[`nng_socket_get_send_poll_fd`] and [`nng_socket_get_recv_poll_fd`] respectively.

The `NNG_OPT_SOCKNAME` function is removed. This was provided for application use, and never used internally by NNG.
Applications should keep track of this information separately.

## Subscriptions

The `NNG_OPT_SUB_SUBSCRIBE` and `NNG_OPT_SUB_UNSUBCRIBE` options have been replaced by
the following functions: [`nng_sub0_socket_subscribe`], [`nng_sub0_socket_unsubscribe`],
[`nng_sub0_ctx_subscribe`] and [`nng_sub0_ctx_unsubscribe`]. These functions, like the options
they replace, are only applicable to SUB sockets.

## Statistics Use Constified Pointers

A number of the [statistics][statistic] functions take, or return, `const nng_stat *` instead
of plain `nng_stat *`. The ABI has not changed, but it may be necessary to declare
certain methods variables `const` to avoid warnings about misuse of `const`.

## Wildcards Not Valid in URLs

The use of `*` to act as a wild card meaning all local interface addresses
is removed. The empty string already performs this function, and unlike
`*` is RFC compliant.

## URL Option Removed

The `NNG_OPT_URL` option has been removed.
It is replaced by the type safe [`nng_dialer_get_url`] and
[`nng_listener_get_url`] functions, which return an [`nng_url`]
structure instead of a string.

## URL Structure Changes

The details of [`nng_url`] have changed significantly, and direct
access of the structure is no longer permitted. Intead new
accessors functions are provided:

- `u_scheme` is replaced by [`nng_url_scheme`].
- `u_port` is replaced by [`nng_url_port`], but this returns a `uint16_t`.
- `u_hostname` is replaced by [`nng_url_hostname`].
- `u_path` is replaced by [`nng_url_path`].
- `u_query` is replaced by [`nng_url_query`].
- `u_fragment` is replaced by [`nng_url_fragment`].
- `u_userinfo` is replaced by [`nng_url_userinfo`].
- `u_requri` is removed - it can be easily formulated from the other fields.
- `u_host` is removed - use [`nng_url_hostname`] and [`nng_url_port`] to construct if needed
- `u_rawurl` is removed - a "cooked" URL can be obtained from the new [`nng_url_sprintf`] function.

## Security Descriptors (Windows Only)

The `NNG_OPT_IPC_SECURITY_DESCRIPTOR` option is removed, and replaced
with the functions [`nng_listener_get_security_descriptor`] and
[`nng_stream_listener_get_security_descriptor`].

Security descriptor support is only relevant to Windows,
and is presently only supported for IPC when Named Pipes are used.
Planned future changes to switch to UNIX domain sockets may eliminate
support for security descriptors altogether in NNG.

{{#include ../xref.md}}
