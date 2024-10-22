# Miscellaneous

This chapter discusses some interfaces that don't really
fit anywhere else.

## Get Random Number

```c
uint32_t nng_random(void);
```

The {{i:`nng_random`}} returns a {{i:random number}}.
The value returned is suitable for use with cryptographic functions such as
key generation, and is obtained using platform-specific cryptographically strong random
number facilities when available.

## Create Socket Pair

```c
int nng_socket_pair(int fds[2]);
```

The `nng_socket_pair` function creates a pair of connected file descriptors.
These file descriptors, which are returned in the _fds_ array, are suitable for
use with the [Socket transport][socket].

On POSIX platforms, this is a thin wrapper around the standard `socketpair` function,
using the {{i:`AF_UNIX`}} family and the `SOCK_STREAM` socket type.
{{footnote: At present only POSIX platforms implementing `socketpair` support this function.}}

This will return zero on success, or an error number. On platforms that lack this
capability, such as Windows, it will return `NNG_ENOTSUP`.

> [!TIP]
> This function may be useful for creating a shared connection between a parent process and
> a child process on UNIX platforms, without requiring the processes use a shared filesystem or TCP connection.

## Report Library Version

```c
const char * nng_version(void);
```

The {{i:`nng_version`}} function returns a human readable {{i:version number}}
for _NNG_, formatted as a `NUL`-terminated string.

Additionally, compile time version information is available
via some predefined macros:

- {{i:`NNG_MAJOR_VERSION`}}: Major version number.
- {{i:`NNG_MINOR_VERSION`}}: Minor version number.
- {{i:`NNG_PATCH_VERSION`}}: Patch version number.

_NNG_ is developed and released using
[Semantic Versioning 2.0](http://www.semver.org), and
the version numbers reported refer to both the API and the library itself.
(The {{i:ABI}} -- {{i:application binary interface}} -- between the
library and the application is controlled in a similar, but different
manner depending upon the link options and how the library is built.)

[socket]: ../tran/socket.md
