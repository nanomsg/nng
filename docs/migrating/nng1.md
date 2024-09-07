# Migrating from NNG 1.x

There are some incompatibities from NNG 1.x.
This guide should help in migrating applications to use NNG 2.0.

## Nanomsg Compatibility

Applications using the legacy `libnanomsg` API will have to be updated to native NNG interfaces.
See the [Migration Guide for libnanomsg](nanomsg.md) for details.

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
Just convert any use of them to `NNG_OPT_WS_REQUST_HEADERS` or
`NNG_OPT_WS_RESPOSNE_HEADERS` as appropriate.
