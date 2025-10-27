# Migrating from NNG 1.x

There are some incompatibities from NNG 1.x, and applications must make certain changes for NNG 2.0.
This guide should help with this migration. While we have made reasonable efforts to highlight all
of the things that applications could run into, this list is not necessarily exhaustive, and undocumented
interfaces may have changed without notice here.

## Detecting NNG v2

For applications that need to detect NNG v2 versus older code, the `NNG_MAJOR_VERSION` macro
can be used. This will have numeric value 2 for version 2, and 1 for earlier versions.

> [!NOTE]
> NNG version 2.0 is not stabilized yet, and while it is in development there is no compatibility guarantee
> between releases or builds of NNG 2.

## Nanomsg Compatibility

Applications using the legacy `libnanomsg` API will have to be updated to native NNG interfaces.
See the [Migrating From libnanomsg](nanomsg.md) chapter for details.

## Library Initialization

It is now required for applications to initialize the library explicitly before using it.
This is done using the [`nng_init`] function.

## Removed Headers

The following header files are removed, and the declarations they provided are now provided by including `<nng/nng.h>`.
Simply remove any references to them.

- `nng/protocol/bus0/bus.h`
- `nng/protocol/pair0/pair.h`
- `nng/protocol/pair1/pair.h`
- `nng/protocol/pipeline0/pull.h`
- `nng/protocol/pipeline0/push.h`
- `nng/protocol/pubsub0/pub.h`
- `nng/protocol/pubsub0/sub.h`
- `nng/protocol/reqrep0/rep.h`
- `nng/protocol/reqrep0/req.h`
- `nng/protocol/survey0/respond.h`
- `nng/protocol/survey0/survey.h`
- `nng/supplemental/tls/tls.h`
- `nng/supplemental/util/idhash.h`
- `nng/supplemental/util/platform.h`
- `nng/transport/inproc/inproc.h`
- `nng/transport/ipc/ipc.h`
- `nng/transport/tcp/tcp.h`
- `nng/transport/tls/tls.h`
- `nng/transport/ws/websocket.h`
- `nng/transport/zerotier/zerotier.h`

## Renamed Functions

The following functions have been renamed as described by the following table.
The old names are available by defining the macro `NNG1_TRANSITION` in your compilation environment.

| Old Name       | New Name             |
| -------------- | -------------------- |
| `nng_close`    | [`nng_socket_close`] |
| `nng_recv_aio` | [`nng_socket_recv`]  |
| `nng_send_aio` | [`nng_socket_send`]  |

## Removed Protocol Aliases

The following macro aliases are removed, unless `NNG1_TRANSITION` is defined in your compilation environment.

- `nng_bus_open`
- `nng_pair_open`
- `nng_pub_open`
- `nng_pull_open`
- `nng_push_open`
- `nng_rep_open`
- `nng_req_open`
- `nng_respondent_open`
- `nng_sub_open`
- `nng_surveyor_open`

Just add either `0` or `1` (in the case of PAIRv1) to get the protocol desired. (Forcing the version number to
be supplied should avoid surprises later as new versions of protocols are added.)

## NNG_FLAG_ALLOC Removed

The `NNG_FLAG_ALLOC` flag that allowed a zero copy semantic with [`nng_send`] and [`nng_recv`] is removed.
This was implemented mostly to aid legacy nanomsg applications, and it was both error prone and still a bit
suboptimal in terms of performance.

Modern code should use one of [`nng_sendmsg`], [`nng_recvmsg`], [`nng_socket_send`], or [`nng_socket_recv`] to get the maximum performance benefit.
Working directly with [`nng_msg`] structures gives more control, reduces copies, and reduces allocation activity.

## Error Code Changes

When an operation fails with [`NNG_ESTOPPED`], it means that the associated [`nni_aio`] object has
been permanently stopped and must not be reused. Applications must watch for this error code, and
not resubmit an operation that returns it. This is particularly important for callbacks that automatically
resubmit operations. Failure to observe this rule will lead to an infinite loop
as any further operations on the object will fail immediately with `NNG_ESTOPPED`.

The error codes `NNG_EAMBIGUOUS` and `NNG_ENOARG` have been removed.

## AIO Provider API changes

The API used for providers for asynchronous I/O operations has changed slightly.

- The `nng_aio_begin` function is removed. However a new [`nng_aio_reset`] function should be called
  instead, before performing any other operations on an _aio_ object. (This simply clears certain fields.)
- The `nng_aio_defer` function is replaced, with a very [`nng_aio_start`] function. However, this function
  has slightly different semantics. It will automatically call the callback if the operation cannot be
  scheduled.
- Be aware of the new `NNG_ESTOPPED` error code, for operations on a handle that is being torn down by
  the consumer.

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

## TLS Peer Certificate APIs Replaced

The `NNG_OPT_TLS_PEER_CN` and `NNG_OPT_TLS_PEER_ALT_NAMES` properties have been removed.
They are replaced with functions like [`nng_pipe_peer_cert`], [`nng_stream_peer_cert`],
and [`nng_http_peer_cert`] which return a new `nng_tls_cert` object.

This object supports methods to get additional information about the certificate, as well
as to obtain the raw DER content so that it can be imported for use in other APIs.

## Support for Local Addresses in Dial URLs Removed

NNG 1.x had an undocumented ability to specify the local address to bind
to when dialing, by using the local address in front of the destination
address separated by a semicolon. This was provided for legacy libnanomsg
compatibility, and is no longer offered. The correct way to specify a
local address is by setting `NNG_OPT_LOCADDR` on the dialer.

## Support for Address Options Removed

The `NNG_OPT_REMADDR` and `NNG_OPT_LOCADDR` options are removed. For streams and pipes, there are
[`nng_stream_peer_addr`] and [`nng_pipe_peer_addr`] functions. For dialers
and stream dialers, the application should track the relevant information
used to configure the listener. Functions formerly used to configure these are
removed as well.

## IPC Option Type Changes

The types of [`NNG_OPT_PEER_GID`], [`NNG_OPT_PEER_PID`], [`NNG_OPT_PEER_UID`], and [`NNG_OPT_PEER_ZONEID`]
have changed from `uint64_t` to `int`. The underlying platforms all use 32-bit quantities for these.

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
- `nng_ctx_get_uint64`
- `nng_dialer_get_ptr`
- `nng_dialer_set_ptr`
- `nng_dialer_get_uint64`
- `nng_dialer_set_uint64`
- `nng_listener_get_ptr`
- `nng_listener_set_ptr`
- `nng_listener_get_uint64`
- `nng_listener_set_uint64`
- `nng_socket_get_ptr`
- `nng_socket_set_ptr`
- `nng_socket_get_string`
- `nng_socket_set_string`
- `nng_socket_get_uint64`
- `nng_socket_set_uint64`
- `nng_stream_get_ptr`
- `nng_stream_set_ptr`
- `nng_stream_get_uint64`
- `nng_stream_dialer_get_ptr`
- `nng_stream_dialer_set_ptr`
- `nng_stream_dialer_get_uint64`
- `nng_stream_dialer_set_uint64`
- `nng_stream_listener_get_ptr`
- `nng_stream_listener_set_ptr`
- `nng_stream_listener_get_uint64`
- `nng_stream_listener_set_uint64`
- `nng_stream_listener_get_addr`
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

The `nng_stream_get_addr` function is removed.
Use the new [`nng_stream_peer_addr`] or [`nng_stream_peer_self_addr`] instead.

The ability to set options on streams after they have been created is no longer present.
(It turns out that this was not very useful.) All functions `nng_stream_set_xxx` are removed.
For tuning the `NNG_OPT_TCP_NODELAY` or similar properties, set the option on the listener
or dialer that creates the stream instead.

## Transport Options

A number of transport options can no longer be set on the socket. Instead these
options must be set on the endpoint (dialer or listener) using the appropriate
[`nng_dialer_set`] or [`nng_listener_set`] option. This likely means that it is necessary
to allocate and configure the endpoint before attaching it to the socket. This will
also afford a much more fine-grained level of control over transport options.

The following options are copied from the socket when creating a dialer or listener,
but afterwards will not be changed on the dialer or listener if the socket
changes. It is recommended to set them properly on the socket before
creating dialers or listeners, or set them explicitly on the dialer or listener
directly:

- [`NNG_OPT_RECONNMINT`]
- [`NNG_OPT_RECONNMAXT`]
- [`NNG_OPT_RECVMAXSZ`]

The latter option is a hint for transports and intended to facilitate early
detection (and possibly avoidance of extra allocations) of oversize messages,
before bringing them into the socket itself.

The `NNG_OPT_TCP_BOUND_PORT` port is renamed to just [`NNG_OPT_BOUND_PORT`],
and is available for listeners using transports based on either TCP or UDP.

The `nng_pipe_get_addr` function has been removed, and replaced with the new
[`nng_pipe_peer_addr`] and [`nng_pipe_self_addr`] functions. These should be
easier to use.

## Socket Options

The `NNG_OPT_PROTO`, `NNG_OPT_PROTONAME`, `NNG_OPT_PEER`, and `NNG_OPT_PEERNAME` options
have been replaced by functions instead of options.
Use [`nng_socket_proto_id`], [`nng_socket_peer_id`], [`nng_socket_proto_name`], and [`nng_socket_peer_name`] instead.
Note that the new functions provide a reference to a static string, and thus do not require
allocation, and the returned strings should not be freed. Also the IDs are provided as `uint16_t`,
matching the actual wire protocol values, instead of `int`.

The `NNG_OPT_RAW` option has also been replaced by a function, [`nng_socket_raw`].

The `NNG_OPT_SENDFD` and `NNG_OPT_RECVFD` options have been replaced by
[`nng_socket_get_send_poll_fd`] and [`nng_socket_get_recv_poll_fd`] respectively.

The `NNG_OPT_SOCKNAME` function is removed. This was provided for application use, and never used internally by NNG.
Applications should keep track of this information separately.

## Subscriptions

The `NNG_OPT_SUB_SUBSCRIBE` and `NNG_OPT_SUB_UNSUBSCRIBE` options have been replaced by
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
access of the structure is no longer permitted. Instead new
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

## HTTP API

The entire HTTP API has been refactored and should be much simpler to use and more efficient.
Applications directly using the HTTP API will need to be fully modified.

A few limits on string lengths of certain values are now applied, which allows us to preallocate values
and eliminate certain unreasonable error paths. If values longer than these are supplied in certain APIs
they may be silently truncated to the limit:

- Hostnames are limited per RFC 1035 to 253 characters (not including terminating "." or zero byte.)
- HTTP Method names are limited to 32 bytes (the longest IANA registered method is currently 18 bytes, used for WebDAV.)
- The fixed part of URI pathnames used with HTTP handlers is limited to 1024 bytes. (Longer URIs may be accepted
  by using [`nng_http_handler_set_tree`] and matching a parent of the directory component.)

The following API calls have changed so that they are `void` returns, and cannot fail.
They may silently truncate data.

- [`nng_http_req_set_method`]
- [`nng_http_res_set_status`]
- [`nng_http_handler_collect_body`]
- [`nng_http_handler_set_data`]
- [`nng_http_handler_set_host`]
- [`nng_http_handler_set_method`]
- [`nng_http_handler_set_tree`]

The HTTP handler objects may not be modified once in use. Previously this would fail with `NNG_EBUSY`.
These checks are removed now, but debug builds will assert if an application tries to do so.

The `nng_http_server_get_addr` function is removed. Instead there is now
[`nng_http_server_get_port`] which can be used to obtain the port actually bound if the server
was configured with port 0.

## WebSocket API

The `NNG_OPT_WSS_REQUEST_HEADERS`, `NNG_OPT_WSS_RESPONSE_HEADERS` and
`NNG_OPT_WS_OPT_WS_REQUEST_HEADERS`, `NNG_OPT_WS_RESPONSE_HEADERS` have been removed.

The `NNG_OPT_WS_REQUEST_HEADER` and `NNG_OPT_WS_RESPONSE_HEADER` option prefixes have been
collapsed into just `NNG_OPT_WS_HEADER`, with slightly different semantics. It still is
a prefix (append the name of the header of interest), but setting it can only affect
outbound headers (request header for dialers, response header for listeners), and when
reading it on a pipe, the value returned is the header sent by the remote peer.

The undocumented hook function signature has changed to reflect changes in the HTTP API.

## Security Descriptors (Windows Only)

The `NNG_OPT_IPC_SECURITY_DESCRIPTOR` option is removed, and replaced
with the functions [`nng_listener_get_security_descriptor`] and
[`nng_stream_listener_get_security_descriptor`].

Security descriptor support is only relevant to Windows,
and is presently only supported for IPC when Named Pipes are used.
Planned future changes to switch to UNIX domain sockets may eliminate
support for security descriptors altogether in NNG.

## Command Line Argument Parser Changes

The supplemental function `nng_opts_parse` and supporting definitions have moved.
This functionality is now supplied by a header only library, available in `nng/args.h`.
See [`nng_args_parse`] for more information.

## ZeroTier Support Removed

The Layer 2 special ZeroTier transport has been removed.
It is possible to use NNG with ZeroTier using TCP/IP, and a future update
is planned to provided coexistence between ZeroTier & the native stack's TCP/IP using lwIP.

## Abstract Autobinding No Longer Supported

As we have removed `NNG_OPT_LOCADDR`, it is no longer possible to meaningfully
use autobinding with abstract sockets on Linux. This is trivially worked around by using a
large (say 128-bit) random integer as the name.

This can be done via using of [`nng_random`] combined with `sprintf`, as the following example demonstrates:

```c
char url[256];
snprintf(url, sizeof (url), `abstract://my-app-%08x-%08x-%08x-%08x",
    nni_random(), nni_random(), nni_random(), nni_random());
```

{{#include ../xref.md}}
