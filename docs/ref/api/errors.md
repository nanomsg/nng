# Errors

Many _NNG_ functions can fail for a variety of reasons.
These functions tend to return either zero on success,
or a non-zero error code to indicate failure.
{{footnote: This convention goes back to UNIX system calls,
which behave the same way, but _NNG_ does not use a separate
_errno_ variable.}}

All these error codes are `int`.

Not every possible error code is defined here, as sometimes
an underlying system or library error code is "wrapped".

## Human Readable Error Message

```c
const char *nng_strerror(int err);
```

The {{i:`nng_strerror`}} returns the human-readable description of the
given error in `err`.

The error message returned is a fixed `NUL`-terminated string and may be located in
read-only memory.

The returned {{i:error message}} is provided in US English, but in the
future locale-specific strings may be presented instead.

> [!NOTE]
> The specific strings associated with specific error messages are
> subject to change.
> Therefore applications must not depend on the message,
> but may use them verbatim when supplying information to end-users, such
> as in diagnostic messages or log entries.

## List of Errors

| Error                                             | Value                   | Description                                                                                                                                       |
| ------------------------------------------------- | ----------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| `NNG_EINTR`<a name="NNG_EINTR"></a>               | 1                       | Operation interrupted.                                                                                                                            |
| `NNG_ENOMEM`<a name="NNG_ENOMEM"></a>             | 2                       | Out of memory, or other resource exahusted.                                                                                                       |
| `NNG_EINVAL`<a name="NNG_EINVAL"></a>             | 3                       | Invalid argument. The arguments are invalid or malformed somehow.                                                                                 |
| `NNG_EBUSY`<a name="NNG_EBUSY"></a>               | 4                       | Resource busy.                                                                                                                                    |
| `NNG_ETIMEDOUT`<a name="NNG_ETIMEDOUT"></a>       | 5                       | Timed out. The operation took longer than the allotted time.                                                                                      |
| `NNG_ECONNREFUSED`<a name="NNG_ECONNREFUSED"></a> | 6                       | Connection refused. Usually indicates the wrong address or a server is running.                                                                   |
| `NNG_ECLOSED`<a name="NNG_ECLOSED"></a>           | 7                       | Object closed. Typically the [socket] is closed.                                                                                                  |
| `NNG_EAGAIN`<a name="NNG_EAGAIN"></a>             | 8                       | Try again. Typcally for a non-blocking operation that might succeed later.                                                                        |
| `NNG_ENOTSUP`<a name="NNG_ENOTSUP"></a>           | 9                       | Not supported. Perhaps the protocol or transport is not supported, or the operation is not not supported with the transport or protocol.          |
| `NNG_EADDRINUSE`<a name="NNG_EADDRINUSE"></a>     | 10                      | Address in use. The network address is already used by another process. Most often this is seen for [listeners][listener].                        |
| `NNG_ESTATE`<a name="NNG_ESTATE"></a>             | 11                      | Incorrect state. The operation cannot be performed in the current state, such as trying to send a response when no request has yet been received. |
| `NNG_ENOENT`<a name="NNG_ENOENT"></a>             | 12                      | Entry not found (no such object.) Can also indicate that a file does not exist.                                                                   |
| `NNG_EPROTO`<a name="NNG_EPROTO"></a>             | 13                      | Protocol error. Typically this indicates incorrect messages over a network.                                                                       |
| `NNG_EUNREACHABLE`<a name="NNG_EUNREACHABLE"></a> | 14                      | Destination unreachable.                                                                                                                          |
| `NNG_EADDRINVAL`<a name="NNG_EADDRINVAL"></a>     | 15                      | Address invalid. Like [`NNG_EINVAL`], but only for network addresses.                                                                             |
| `NNG_EPERM`<a name="NNG_EPERM"></a>               | 16                      | Permission denied.                                                                                                                                |
| `NNG_EMSGSIZE`<a name="NNG_EMSGSIZE"></a>         | 17                      | Message too large.                                                                                                                                |
| `NNG_ECONNABORTED`<a name="NNG_ECONNABORTED"></a> | 18                      | Connection aborted. A connection attempt was aborted locally.                                                                                     |
| `NNG_ECONNRESET`<a name="NNG_ECONNRESET"></a>     | 19                      | Connection reset. The remote peer reset the connection unexpectedly.                                                                              |
| `NNG_ECANCELED`<a name="NNG_ECANCELED"></a>       | 20                      | Operation canceled. Typically as a result of [`nng_aio_cancel`] or similar.                                                                       |
| `NNG_ENOFILES`<a name="NNG_ENOFILES"></a>         | 21                      | Out of files. Either the destination file system cannot store files, or all available file handles are used.                                      |
| `NNG_ENOSPC`<a name="NNG_ENOSPC"></a>             | 22                      | Out of space. Destination table or filesystem is full.                                                                                            |
| `NNG_EEXIST`<a name="NNG_EEXIST"></a>             | 23                      | Resource already exists.                                                                                                                          |
| `NNG_EREADONLY`<a name="NNG_EREADONLY"></a>       | 24                      | Read only resource. An attempt to modify a read-only file or other object.                                                                        |
| `NNG_EWRITEONLY`<a name="NNG_EWRITEONLY"></a>     | 25                      | Write only resource. A read operation failed because the object only supports writes.                                                             |
| `NNG_ECRYPTO`<a name="NNG_ECRYPTO"></a>           | 26                      | Cryptographic error. Usually indicates an invalid key was used for TLS.                                                                           |
| `NNG_EPEERAUTH`<a name="NNG_EPEERAUTH"></a>       | 27                      | Peer could not be authenticated.                                                                                                                  |
| `NNG_ENOARG`<a name="NNG_ENOARG"></a>             | 28                      | Option requires argument. A command-line option was supplied without an argument. Only used with [`nng_opts_parse`].                              |
| `NNG_EAMBIGUOUS`<a name="NNG_EAMBIGUOUS"></a>     | 29                      | Ambiguous option. The command line option could not be unambiguously resolved. Only used with [`nng_opts_parse`].                                 |
| `NNG_EBADTYPE`<a name="NNG_EBADTYPE"></a>         | 30                      | Incorrect type. A type-specific function was used for an object of the wrong type.                                                                |
| `NNG_ECONNSHUT`<a name="NNG_ECONNSHUT"></a>       | 31                      | Connection shutdown. The connection was shut down and cannot be used.                                                                             |
| `NNG_EINTERNAL`<a name="NNG_EINTERNAL"></a>       | 1000                    | An unidentifier internal error occurred.                                                                                                          |
| `NNG_ESYSERR`<a name="NNG_ESYSERR"></a>           | 0x10000000 - 0x1FFFFFFF | An unidentified system error occurred. These are errors reported by the operating system.                                                         |
| `NNG_ETRANERR`<a name="NNG_ETRANERR"></a>         | 0x20000000 - 0x2FFFFFFF | An unidentified transport error occurred.                                                                                                         |

{{#include ../xref.md}}
