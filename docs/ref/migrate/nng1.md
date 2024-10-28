# Migrating from NNG 1.x

There are some incompatibities from NNG 1.x.
This guide should help in migrating applications to use NNG 2.0.

## Nanomsg Compatibility

Applications using the legacy `libnanomsg` API will have to be updated to native _NNG_ interfaces.
See the [Migrating From libnanomsg](nanomsg.md) chapter for details.

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

## TLS Options

The support for configuring TLS via `NNG_TLS_AUTH_MODE`, `NNG_OPT_TLS_CA_FILE`, `NNG_OPT_TLS_SERVER_NAME`,
and similar has been removed. Instead configuration must be performed by allocating
a `nng_tls_config` object, and then setting fields on it using the appropriate functions,
after which it may be configured on a listener or dialer using the `NNG_OPT_TLS_CONFIG` option.

Note that TLS configuration is now available in `<nng/nng.h>`, rather than the supplemental header.

## Option Functions

The previously deprecated `nng_pipe_getopt_xxx` family of functions is removed.
Applications should use `nng_pipe_get` and related functions instead.

The socket option function families for `nng_getopt` and `nng_setopt` have been removed as well.
In this case, use the `nng_socket_get` and `nng_socket_set` functions as appropriate.

The `_getopt` and `_setopt` functions for contexts, listeners, and dialers are no longer
present. Simply changing `_getopt` to `_get` or `_setopt` to `_set` in the function name
should be sufficient in most cases.

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

## Statistics Use Constified Pointers

A number of the statistics functions take, or return, `const nng_stat *` instead
of plain `nng_stat *`. The ABI has not changed, but it may be necessary to declare
certain methods variables `const` to avoid warnings about misuse of `const`.
