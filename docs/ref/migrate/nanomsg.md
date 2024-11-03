# Migrating from libnanomsg

Previous version of NNG offered direct API compatibility with _libnanomsg_,
but that support is no longer offered in this version.

If your application is still using legacy _libnanomsg_ APIs, you will need to
update it for this version of NNG.

## Header Files

Most applications can replace all `#include <nn/*.h>` statements with `#include <nng/nng.h>`.

## Link Libraries

Replace `-lnanomsg` with `-lnng`.
It may be necessary to include additional system libraries, such as `-lpthread`, depending on your system.

## Types

Sockets, dialers, and listeners in _libnanomsg_ are simple integers.
In NNG, these are `struct` types.

Messages are quite different in NNG, with the absence of the POSIX message control
headers.

The `struct nn_msghdr` structure has no equivalent. See `nng_msg` for the
NNG approach to messages. Likewise there is no `struct nn_cmsghdr` equivalent.

## API Conversions

| Nanomsg API         | NNG Equivalent                                                     | Notes                                                                                                 |
| ------------------- | ------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------- |
| `nn_strerror`       | `nng_strerror`                                                     |
| `nn_errno`          | No equivalent. Errors are redirectly rather than through `errno`.  |
| `nn_socket`         | Use the appropriate protocol constructor, such as `nng_req0_open`. |
| `nn_close`          | `nng_close`                                                        |
| `nn_bind`           | `nng_listen`, `nng_listener_create`                                | Allocating a listener with `nng_lister_create` and configuring it offers more capabilities.           |
| `nn_connect`        | `nng_dial`, `nng_dialer_create`                                    | Allocating a dialer with `nng_dialer_create` and configuring it offers more capabilities.             |
| `nn_shutdown`       | `nng_lister_close`, `nng_dialer_close`                             |
| `nn_allocmsg`       | `nng_msg_alloc`                                                    | There are significant semantic differences.                                                           |
| `nn_freemsg`        | `nng_msg_free`                                                     |
| `nn_reallocmsg`     | `nng_msg_realloc`                                                  |
| `nn_send`           | `nng_send`                                                         |
| `nn_recv`           | `nng_recv`                                                         |
| `nn_sendmsg`        | `nng_sendmsg`                                                      |
| `nn_getsockopt`     | `nng_socket_get`                                                   | NNG has typed accessors for options, and also separate functions for dialers and listeners.           |
| `nn_setsockopt`     | `nng_socket_set`                                                   |
| `nn_device`         | `nng_device`                                                       |
| `nn_poll`           | None                                                               | Can be constructed using `nng_aio`. Few if any applications ever used this API.                       |
| `nn_term`           | None                                                               | The `nng_fini` API can do this, but is not recommended except when debugging memory leaks.            |
| `nn_get_statistic`  | `nng_stats_get`                                                    | The statistics in NNG are completely different, with different semantics and no stability guarantees. |
| `NN_POLLIN`         | None                                                               | Used only with `nn_poll`.                                                                             |
| `NN_POLLOUT`        | None                                                               | Used only with `nn_poll`.                                                                             |
| `NN_MSG`            | `NNG_FLAG_ALLOC`                                                   | See `nng_send` and `nng_recv` for details.                                                            |
| `NN_CMSG_ALIGN`     | None                                                               |
| `NN_CMSG_FIRSTHDR`  | None                                                               |
| `NN_CMSG_NXTHDR`    | None                                                               |
| `NN_CMSG_DATA`      | None                                                               |
| `NN_CMSG_LEN`       | None                                                               |
| `NN_CMSG_SPACE`     | None                                                               |
| `struct nn_iovec`   | `nng_iov`                                                          |
| `struct nn_msghdr`  | `nng_msg`                                                          |
| `struct nn_cmsghdr` | `nng_msg` and `nng_msg_header`                                     |

## Options

The following options are changed.

| Nanomsg Option         | NNG Eqvaivalent               | Notes                                                   |
| ---------------------- | ----------------------------- | ------------------------------------------------------- |
| `NN_LINGER`            | None                          | NNG does not support tuning this.                       |
| `NN_SNDBUF`            | `NNG_OPT_SENDBUF`             | NNG value is given in messages, not bytes.              |
| `NN_RCVBUF`            | `NNG_OPT_RECVBUF`             | NNG value is given in messages, not bytes.              |
| `NN_SNDTIMEO`          | `NNG_OPT_SENDTIMEO`           |
| `NN_RCVTIMEO`          | `NNG_OPT_RECVTIMEO`           |
| `NN_RECONNECT_IVL`     | `NNG_OPT_RECONNMINT`          |
| `NN_RECONNECT_IVL_MAX` | `NNG_OPT_RECONNMAXT`          |
| `NN_SNDPRIO`           | None                          | Not supported in NNG yet.                               |
| `NN_RCVPRIO`           | None                          | Not supported in NNG yet.                               |
| `NN_RCVFD`             | `nng_socket_get_recv_poll_fd` | No longer an option, use a function call.               |
| `NN_SNDFD`             | `nng_socket_get_send_poll_fd` | No longer an option, use a function call.               |
| `NN_DOMAIN`            | None                          | NNG options are not divided by domain or protocol.      |
| `NN_PROTOCOL`          | `nng_socket_proto_id`         | No longer an option. See also `nng_socket_proto_name`.  |
| `NN_IPV4ONLY`          | None                          | Use URL such as `tcp4://` to obtain this functionality. |
| `NN_SOCKET_NAME`       | `NNG_OPT_SOCKNAME`            |
| `NN_MAXTTL`            | `NNG_OPT_MAXTTL`              |

## Error Codes

Most of the error codes have similar names in NNG, just prefixed with `NNG_`.
There are some exceptions. Be aware that the numeric values are _not_ the same.

| Nanomsg Error  | NNG Error                                                                      | Notes                                                                              |
| -------------- | ------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------- |
| `EINTR`        | `NNG_EINTR`                                                                    |                                                                                    |
| `ENOMEM`       | `NNG_ENOMEM`                                                                   |                                                                                    |
| `EINVAL`       | `NNG_EINVAL`, `NNG_EADDRINVAL`, `NNG_EBADTYPE`, `NNG_EAMBIGUOUS`               | NNG discrimates between different types of errors.                                 |
| `EBUSY`        | `NNG_EBUSY`                                                                    |                                                                                    |
| `ETIMEDOUT`    | `NNG_ETIMEDOUT`                                                                |                                                                                    |
| `ECONNREFUSED` | `NNG_ECONNREFUSED`                                                             |                                                                                    |
| `EBADF`        | `NNG_ECLOSED`, `NNG_ECANCELED`                                                 | Canceling an operation returns differently than using an invalid or closed object. |
| `EAGAIN`       | `NNG_EAGAIN`                                                                   |
| `ENOTSUP`      | `NNG_ENOTSUP`                                                                  |
| `EADDRINUSE`   | `NNG_EADDRINUSE`                                                               |
| `EFSM`         | `NNG_ESTATE`                                                                   | Not a legal POSIX _errno_ value.                                                   |
| `ENOENT`       | `NNG_ENOENT`                                                                   |
| `EPROTO`       | `NNG_EPROTO`                                                                   |
| `EHOSTUNREACH` | `NNG_EUNREACHABLE`                                                             |
| `EACCCES`      | `NNG_EPERM`, `NNG_EWRITEONLY`, `NNG_EREADONLY`, `NNG_ECRYPTO`, `NNG_EPEERAUTH` | NNG has more fine grained reasons for access failures.                             |
| `EMSGSIZE`     | `NNG_EMSGSIZE`                                                                 |
| `ECONNABORTED` | `NNG_ECONNABORTED`                                                             |
| `ECONNRESET`   | `NNG_ECONNRESET`                                                               |
| `EEXIST`       | `NNG_EEXIST`                                                                   |
| `EMFILE`       | `NNG_ENOFILES`                                                                 |
| `ENOSPC`       | `NNG_ENOSPC`                                                                   |
