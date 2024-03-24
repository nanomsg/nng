# Legacy Compatibility Functions

{{hi:compatibility layer}}
_NNG_ provides source-level compatibility for most _libnanomsg_ 1.0 applications.

This is intended to facilitate converting {{i:legacy applications}} to use _NNG_.
New applications should use the newer _NNG_ APIs instead.

Applications making use of this must take care
to link with _libnng_ instead of _libnn_.

> [!TIP]
> While not recommended for long term use, the value returned by
> [`nng_socket_id()`](nng_socket_id.md) can be used with these functions
> just like a value returned by [`nn_socket()`](nn_socket.md).
> This can be way to facilitate incremental transition to the new API.

Some capabilities, protocols, and transports, will not be accessible
using this API, as the compatible API has no provision for expression
of certain concepts introduced in the new API.

While reasonable efforts have been made to provide for compatibility,
some things may behave differently, and some less common parts of the
_libnanomsg_ 1.0 API are not supported at this time, including certain
options and the statistics API.
See the [Caveats](#caveats) section below.

### Availability

The availability of this legacy API depends on whether the library was
configured to include it.

> [!NOTE]
> Future versions of _NNG_ may not include this compatibility layer
> by default, or even at all. Modernizing applications to use the new
> API is strongly recommended.

### Compiling

When compiling legacy _nanomsg_ applications, it will generally be
necessary to change the include search path to add the `compat` subdirectory
of the directory where headers were installed.
For example, if _NNG_ is installed in `$prefix`, then header files will
normally be located in `$prefix/include/nng`.
In this case, to build legacy _nanomsg_ apps against _NNG_ you would
add `$prefix/include/nng/compat` to your compiler's search path.

Alternatively, you can change your source code so that `#include` statements
referring to `<nanomsg>` instead refer to `<nng/compat/nanomsg>`.
For example, instead of:

```c
#include <nanomsg/nn.h>
#include <nanomsg/reqrep.h>
```

you would have this:

```c
#include <nng/compat/nanomsg/nn.h>
#include <nng/compat/nanomsg/reqrep.h>
```

Legacy applications built using these methods should be linked against _libnng_
instead of _libnn_, just like any other _NNG_ application.

### Caveats

The following caveats apply when using the legacy API with _NNG_.

- Socket numbers can be quite large.
  The legacy _libnanomsg_ attempted to reuse socket numbers, like
  file descriptors in UNIX systems.
  _NNG_ avoids this to prevent accidental reuse or
  collision after a descriptor is closed.
  Consequently, socket numbers can become quite large, and should
  probably not be used for array indices.

- The following options (`nn_getsockopt`) are unsupported:
  `NN_SNDPRIO`, `NN_RCVPRIO`, `NN_IPV4ONLY`.

- Access to statistics using this legacy API
  [`nn_get_statistic()`](nn_get_statistic.md) is unsupported.

- Some transports can support longer URLs than legacy _libnanomsg_ can.
  It is a good idea to use short pathnames in URLs if interoperability
  is a concern.

- Only absolute paths are supported in `ipc://` URLs.
  For example, `ipc:///tmp/mysocket` is acceptable, but `ipc://mysocket` is not.

- The WebSocket transport in this implementation (`ws://` URLs)
  only supports `BINARY` frames.

- Some newer transports are unusable from this mode.
  In particular, this legacy API offers no way to configure
  TLS or ZeroTier parameters that may be required for use.

- ABI versioning of the compatibility layer is not supported,
  and the `NN_VERSION_` macros are not present.

- Runtime symbol information is not implemented.
  Specifically, there is no `nn_symbol()` function.

- The TCP transport (`tcp://` URLs) does not support specifying the local
  address or interface when binding. (This could be fixed in the future,
  but most likely this will be available only using the new API.)

- The values of `NN_RCVMAXSIZE` are constrained.
  Specifically, values set larger than 2GB using the new API will be reported
  as unlimited (`-1`) in the new API, and the value `0` will disable any
  enforcement, just like `-1`.
  (There is no practical reason to ever want to limit the receive size to
  zero.)

- This implementation counts buffers in terms of messages rather than bytes.
  As a result, the buffer sizes accessed with `NN_SNDBUF` and `NN_RCVBUF` are
  rounded up to a whole number of kilobytes, then divided by 1024, in order
  to approximate buffering assuming 1 KB messages.
  Few applications should need to adjust the default values.
