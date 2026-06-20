# Socket Addresses

```c
typedef union nng_sockaddr {
    uint16_t              s_family;
    nng_sockaddr_ipc      s_ipc;
    nng_sockaddr_inproc   s_inproc;
    nng_sockaddr_in6      s_in6;
    nng_sockaddr_in       s_in;
    nng_sockaddr_abstract s_abstract;
    nng_sockaddr_storage  s_storage;
} nng_sockaddr;

enum nng_sockaddr_family {
    NNG_AF_UNSPEC   = 0,
    NNG_AF_INPROC   = 1,
    NNG_AF_IPC      = 2,
    NNG_AF_INET     = 3,
    NNG_AF_INET6    = 4,
    NNG_AF_ABSTRACT = 5
};
```

An {{i:`nng_sockaddr`}} is used to represent the addresses used by
underlying transports, such as TCP/IP addresses, IPC paths, and in-process
names.

> [!NOTE]
> The name `sockaddr` reflects its similarity to POSIX `struct sockaddr`.
> In _NNG_, these addresses are more closely associated with [`nng_pipe`]
> and transport endpoints than with [sockets][socket].

The structure is a union with different members for different address types.
Every member structure has a `uint16_t` address family as its first field.
This overlaps the `s_family` member of the union and indicates which member
is valid.

The `s_storage` member reserves enough space to store any supported socket
address family. Applications should use the family-specific members instead
when inspecting an address.

| Family            | Member       | Description                                                                 |
| ----------------- | ------------ | --------------------------------------------------------------------------- |
| `NNG_AF_UNSPEC`   | none         | Invalid or unspecified address.                                             |
| `NNG_AF_INPROC`   | `s_inproc`   | In-process address for the [inproc transport][inproc].                      |
| `NNG_AF_IPC`      | `s_ipc`      | Inter-process address for the [IPC transport][ipc].                         |
| `NNG_AF_INET`     | `s_in`       | IPv4 address used by TCP, TLS, UDP, and similar IP transports.              |
| `NNG_AF_INET6`    | `s_in6`      | IPv6 address used by TCP, TLS, UDP, and similar IP transports.              |
| `NNG_AF_ABSTRACT` | `s_abstract` | Abstract socket address for the [IPC transport][ipc] on Linux systems.      |

## In-Process Addresses

```c
typedef struct nng_sockaddr_inproc {
    uint16_t sa_family;
    char     sa_name[NNG_MAXADDRLEN];
} nng_sockaddr_inproc;
```

An {{i:`nng_sockaddr_inproc`}} is the flavor of [`nng_sockaddr`] used for
addresses associated with the [inproc transport][inproc].

The `sa_family` field is always `NNG_AF_INPROC`.

The `sa_name` field holds an arbitrary `NUL`-terminated C string identifying
the in-process address. No other restrictions are placed on the name.

> [!TIP]
> Applications should use the `sizeof` operator instead of hard coding the
> size of the `sa_name` member. The size is guaranteed to be at least 128.

## IPC Addresses

```c
typedef struct nng_sockaddr_path nng_sockaddr_ipc;

struct nng_sockaddr_path {
    uint16_t sa_family;
    char     sa_path[NNG_MAXADDRLEN];
};
```

An {{i:`nng_sockaddr_ipc`}} is the flavor of [`nng_sockaddr`] used for
traditional path-based addresses associated with the [IPC transport][ipc].

The `sa_family` field is always `NNG_AF_IPC`.

The `sa_path` field holds a `NUL`-terminated C string corresponding to the
path where the IPC socket is located. On systems using UNIX domain sockets,
this is a path in the file system. On Windows systems, this is the named pipe
path without the leading `\\.\pipe\` portion, which _NNG_ adds automatically.

> [!TIP]
> Applications should use the `sizeof` operator instead of hard coding the
> size of the `sa_path` member. The size is guaranteed to be at least 128,
> but paths of this length may not be supported on every system.

> [!TIP]
> Portable applications should restrict themselves to path names of not more
> than 90 bytes. Many systems have limits around 100 bytes, and some systems
> have smaller limits.

> [!NOTE]
> If compatibility with legacy _nanomsg_ applications is required, path names
> must not be longer than 122 bytes, including the final `NUL` byte.
> Legacy versions of _nanomsg_ cannot express URLs longer than 128 bytes,
> including the `ipc://` prefix.

## Abstract Addresses

```c
typedef struct nng_sockaddr_abstract {
    uint16_t sa_family;
    uint16_t sa_len;
    uint8_t  sa_name[107];
} nng_sockaddr_abstract;
```

An {{i:`nng_sockaddr_abstract`}} is the flavor of [`nng_sockaddr`] used to
represent abstract socket addresses for the [IPC transport][ipc].

Abstract sockets are only supported on Linux at present. These sockets have
a name that is an array of bytes, with no special meaning. Abstract sockets
have no presence in the file system, do not honor file permissions, and are
automatically cleaned up by the operating system when no longer in use.

The `sa_family` field is always `NNG_AF_ABSTRACT`.

The `sa_len` field gives the number of bytes stored in `sa_name`.

The `sa_name` field holds the name of the abstract socket. The bytes of the
name can have any value, including zero.

> [!NOTE]
> The name does not include the leading `NUL` byte used on Linux to
> distinguish abstract socket addresses from path-based socket addresses.

> [!NOTE]
> Abstract sockets are Linux-specific. They are not recommended for portable
> applications.

## IPv4 Addresses

```c
typedef struct nng_sockaddr_in {
    uint16_t sa_family;
    uint16_t sa_port;
    uint32_t sa_addr;
} nng_sockaddr_in;
```

An {{i:`nng_sockaddr_in`}} is the flavor of [`nng_sockaddr`] used for IPv4
addresses, including the IP address and TCP or UDP port number. IPv6 addresses
use [`nng_sockaddr_in6`] instead.

The `sa_family` field is always `NNG_AF_INET`.

The `sa_port` field holds the TCP or UDP port number in network byte order.
A zero value indicates that no specific port number is specified.

The `sa_addr` field holds the IPv4 address in network byte order.

> [!TIP]
> The `sa_port` and `sa_addr` fields are in network byte order to facilitate
> their use with system APIs such as `inet_ntop`.

> [!IMPORTANT]
> Although this structure appears similar to BSD `sockaddr_in`, it is not
> the same type, and the two may not be used interchangeably.

## IPv6 Addresses

```c
typedef struct nng_sockaddr_in6 {
    uint16_t sa_family;
    uint16_t sa_port;
    uint32_t sa_scope;
    uint8_t  sa_addr[16];
} nng_sockaddr_in6;
```

An {{i:`nng_sockaddr_in6`}} is the flavor of [`nng_sockaddr`] used for IPv6
addresses, including the IP address and TCP or UDP port number. IPv4 addresses
use [`nng_sockaddr_in`] instead.

The `sa_family` field is always `NNG_AF_INET6`.

The `sa_port` field holds the TCP or UDP port number in network byte order.
A zero value indicates that no specific port number is specified.

The `sa_scope` field is the IPv6 scope identifier. It is typically used with
link-local addresses to identify a specific interface. The details of this
value are platform-specific.

The `sa_addr` field holds the IPv6 address in network byte order.

> [!TIP]
> The `sa_port` and `sa_addr` fields are in network byte order to facilitate
> their use with system APIs such as `inet_ntop`.

> [!IMPORTANT]
> Although this structure appears similar to BSD `sockaddr_in6`, it is not
> the same type, and the two may not be used interchangeably.

## Format an Address

```c
#define NNG_MAXADDRSTRLEN (NNG_MAXADDRLEN + 16)

const char *nng_str_sockaddr(const nng_sockaddr *sa, char *buf, size_t bufsz);
```

The {{i:`nng_str_sockaddr`}} function provides a displayable representation
of the socket address _sa_ in the buffer _buf_, which has room for _bufsz_
bytes including the terminating `NUL` byte. The function returns _buf_.

If the buffer is too small, the result will be truncated. A buffer of
`NNG_MAXADDRSTRLEN` bytes is sufficient to avoid typical truncations, although
very long IPC paths can still be truncated.

As long as _bufsz_ is greater than zero, the result will be `NUL`-terminated.

> [!IMPORTANT]
> The string produced by `nng_str_sockaddr` is intended for display in logs
> and diagnostics. It is not intended to be parsed, and the display format
> may change without notice.

## Address Port

```c
uint32_t nng_sockaddr_port(const nng_sockaddr *sa);
```

The {{i:`nng_sockaddr_port`}} function returns the port number associated with
_sa_ in native byte order.

For `NNG_AF_INET` and `NNG_AF_INET6` addresses, this is the TCP or UDP port.
For address families that do not have a port number, zero is returned.

## Compare Addresses

```c
bool nng_sockaddr_equal(const nng_sockaddr *sa1, const nng_sockaddr *sa2);
```

The {{i:`nng_sockaddr_equal`}} function returns `true` if _sa1_ and _sa2_
represent the same address, or `false` otherwise.

## Hash an Address

```c
uint64_t nng_sockaddr_hash(const nng_sockaddr *sa);
```

The {{i:`nng_sockaddr_hash`}} function returns a non-zero 64-bit hash value
for _sa_.

This value is intended for building indexes, such as with the [ID map][id map].
Collisions are possible. The hash value is not portable between systems and
may not be portable between versions of _NNG_.

{{#include ../xref.md}}
