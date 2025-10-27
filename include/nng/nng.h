//
// Copyright 2025 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef NNG_NNG_H
#define NNG_NNG_H

// NNG (nanomsg-next-gen) is an improved implementation of the SP protocols.
// The APIs have changed, and there is no attempt to provide API compatibility
// with legacy libnanomsg. This file defines the library consumer-facing
// Public API. Use of definitions or declarations not found in this header
// file is specifically unsupported and strongly discouraged.

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

// NNG_DECL is used on declarations to deal with scope.
// For building Windows DLLs, it should be the appropriate __declspec().
// For shared libraries with platforms that support hidden visibility,
// it should evaluate to __attribute__((visibility("default"))).
#ifndef NNG_DECL
#if defined(_WIN32) && !defined(NNG_STATIC_LIB)
#if defined(NNG_SHARED_LIB)
#define NNG_DECL __declspec(dllexport)
#else
#define NNG_DECL __declspec(dllimport)
#endif // NNG_SHARED_LIB
#else
#if defined(NNG_SHARED_LIB) && defined(NNG_HIDDEN_VISIBILITY)
#define NNG_DECL __attribute__((visibility("default")))
#else
#define NNG_DECL extern
#endif
#endif // _WIN32 && !NNG_STATIC_LIB
#endif // NNG_DECL

#ifndef NNG_DEPRECATED
#if defined(__GNUC__) || defined(__clang__)
#define NNG_DEPRECATED __attribute__((deprecated))
#else
#define NNG_DEPRECATED
#endif
#endif

// NNG Library & API version.
// We use SemVer, and these versions are about the API, and
// may not necessarily match the ABI versions.
#define NNG_MAJOR_VERSION 2
#define NNG_MINOR_VERSION 0
#define NNG_PATCH_VERSION 0

// if non-empty (i.e. "pre"), this is a pre-release
#define NNG_RELEASE_SUFFIX "dev"

// Maximum length of a socket address. This includes the terminating NUL.
// This limit is built into other implementations, so do not change it.
// Note that some transports are quite happy to let you use addresses
// in excess of this, but if you do you may not be able to communicate
// with other implementations.
#define NNG_MAXADDRLEN (128)

// NNG_PROTOCOL_NUMBER is used by protocol headers to calculate their
// protocol number from a major and minor number.  Applications should
// probably not need to use this.
#define NNG_PROTOCOL_NUMBER(maj, min) (((x) * 16) + (y))

// Types common to nng.

// Identifiers are wrapped in a structure to improve compiler validation
// of incorrect passing.  This gives us strong type checking.  Modern
// compilers compile passing these by value to identical code as passing
// the integer type (at least with optimization applied).  Please do not
// access the ID member directly.

typedef struct nng_ctx_s {
	uint32_t id;
} nng_ctx;

typedef struct nng_dialer_s {
	uint32_t id;
} nng_dialer;

typedef struct nng_listener_s {
	uint32_t id;
} nng_listener;

typedef struct nng_pipe_s {
	uint32_t id;
} nng_pipe;

typedef struct nng_socket_s {
	uint32_t id;
} nng_socket;

typedef int32_t nng_duration; // in milliseconds

// nng_time represents an absolute time since some arbitrary point in the
// past, measured in milliseconds.  The values are always positive.
typedef uint64_t nng_time;

// Error codes.  These generally have different values from UNIX errnos,
// so take care about converting them.  The one exception is that 0 is
// unambiguously "success".
//
// NNG_SYSERR is a special code, which allows us to wrap errors from the
// underlying operating system.  We generally prefer to map errors to one
// of the above, but if we cannot, then we just encode an error this way.
// The bit is large enough to accommodate all known UNIX and Win32 error
// codes.  We try hard to match things semantically to one of our standard
// errors.  For example, a connection reset or aborted we treat as a
// closed connection, because that's basically what it means.  (The remote
// peer closed the connection.)  For certain kinds of resource exhaustion
// we treat it the same as memory.  But for files, etc. that's OS-specific,
// and we use the generic below.  Some of the above error codes we use
// internally, and the application should never see (e.g. NNG_EINTR).
//
// NNG_ETRANERR is like ESYSERR, but is used to wrap transport specific
// errors, from different transports.  It should only be used when none
// of the other options are available.
typedef enum {
	NNG_OK           = 0, // not an error!
	NNG_EINTR        = 1,
	NNG_ENOMEM       = 2,
	NNG_EINVAL       = 3,
	NNG_EBUSY        = 4,
	NNG_ETIMEDOUT    = 5,
	NNG_ECONNREFUSED = 6,
	NNG_ECLOSED      = 7,
	NNG_EAGAIN       = 8,
	NNG_ENOTSUP      = 9,
	NNG_EADDRINUSE   = 10,
	NNG_ESTATE       = 11,
	NNG_ENOENT       = 12,
	NNG_EPROTO       = 13,
	NNG_EUNREACHABLE = 14,
	NNG_EADDRINVAL   = 15,
	NNG_EPERM        = 16,
	NNG_EMSGSIZE     = 17,
	NNG_ECONNABORTED = 18,
	NNG_ECONNRESET   = 19,
	NNG_ECANCELED    = 20,
	NNG_ENOFILES     = 21,
	NNG_ENOSPC       = 22,
	NNG_EEXIST       = 23,
	NNG_EREADONLY    = 24,
	NNG_EWRITEONLY   = 25,
	NNG_ECRYPTO      = 26,
	NNG_EPEERAUTH    = 27,
	NNG_EBADTYPE     = 30,
	NNG_ECONNSHUT    = 31,
	NNG_ESTOPPED     = 999,
	NNG_EINTERNAL    = 1000,
	NNG_ESYSERR      = 0x10000000,
	NNG_ETRANERR     = 0x20000000
} nng_err;

typedef struct nng_msg  nng_msg;
typedef struct nng_stat nng_stat;
typedef struct nng_aio  nng_aio;

// URL structure.
typedef struct nng_url nng_url;

// For some transports, we need TLS configuration, including certificates
// and so forth.  A TLS configuration cannot be changed once it is in use.
typedef struct nng_tls_config nng_tls_config;

// This is a representation of X.509 certificate as used in TLS transports.
// Internal details are opaque.
typedef struct nng_tls_cert_s nng_tls_cert;

// Initializers.
// clang-format off
#define NNG_PIPE_INITIALIZER { 0 }
#define NNG_SOCKET_INITIALIZER { 0 }
#define NNG_DIALER_INITIALIZER { 0 }
#define NNG_LISTENER_INITIALIZER { 0 }
#define NNG_CTX_INITIALIZER { 0 }
// clang-format on

// Some address details. This is in some ways like a traditional sockets
// sockaddr, but we have our own to cope with our unique families, etc.
// The details of this structure are directly exposed to applications.
// These structures can be obtained via property lookups, etc.
struct nng_sockaddr_inproc {
	uint16_t sa_family;
	char     sa_name[NNG_MAXADDRLEN];
};

struct nng_sockaddr_path {
	uint16_t sa_family;
	char     sa_path[NNG_MAXADDRLEN];
};

struct nng_sockaddr_in6 {
	uint16_t sa_family;
	uint16_t sa_port;
	uint32_t sa_scope; // scope moved here to make sa_addr 64-bit aligned
	uint8_t  sa_addr[16];
};

struct nng_sockaddr_in {
	uint16_t sa_family;
	uint16_t sa_port;
	uint32_t sa_addr;
};

struct nng_sockaddr_abstract {
	uint16_t sa_family;
	uint16_t sa_len;       // will be 0 - 107 max.
	uint8_t  sa_name[107]; // 108 linux/windows, without leading NUL
};

// nng_sockaddr_storage is the size required to store any nng_sockaddr.
// This size must not change, and no individual nng_sockaddr type may grow
// larger than this without breaking binary compatibility.
struct nng_sockaddr_storage {
	uint16_t sa_family;
	uint64_t sa_pad[16];
};

typedef struct nng_sockaddr_inproc   nng_sockaddr_inproc;
typedef struct nng_sockaddr_path     nng_sockaddr_path;
typedef struct nng_sockaddr_path     nng_sockaddr_ipc;
typedef struct nng_sockaddr_in       nng_sockaddr_in;
typedef struct nng_sockaddr_in6      nng_sockaddr_in6;
typedef struct nng_sockaddr_abstract nng_sockaddr_abstract;
typedef struct nng_sockaddr_storage  nng_sockaddr_storage;

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

// Scatter/gather I/O.
typedef struct nng_iov {
	void  *iov_buf;
	size_t iov_len;
} nng_iov;

// Some definitions for durations used with timeouts.
#define NNG_DURATION_INFINITE (-1)
#define NNG_DURATION_DEFAULT (-2)
#define NNG_DURATION_ZERO (0)

// nng_socket_close closes the socket, terminating all activity and
// closing any underlying connections and releasing any associated
// resources.
NNG_DECL int nng_socket_close(nng_socket);

// nng_socket_id returns the positive socket id for the socket, or -1
// if the socket is not valid.
NNG_DECL int nng_socket_id(nng_socket);

NNG_DECL int nng_socket_set_bool(nng_socket, const char *, bool);
NNG_DECL int nng_socket_set_int(nng_socket, const char *, int);
NNG_DECL int nng_socket_set_size(nng_socket, const char *, size_t);
NNG_DECL int nng_socket_set_ms(nng_socket, const char *, nng_duration);

NNG_DECL int nng_socket_get_bool(nng_socket, const char *, bool *);
NNG_DECL int nng_socket_get_int(nng_socket, const char *, int *);
NNG_DECL int nng_socket_get_size(nng_socket, const char *, size_t *);
NNG_DECL int nng_socket_get_ms(nng_socket, const char *, nng_duration *);

// These functions are used to obtain a file descriptor that will poll
// as readable if the socket can receive or send. Applications must never
// read or write to the file descriptor directly, but simply check it
// with poll, epoll, kqueue, or similar functions.  This is intended to
// aid in integration NNG with external event loops based on polling I/O.
// Note that using these functions will force NNG to make extra system calls,
// and thus impact performance.  The file descriptor pollability is
// level-triggered.  These file descriptors will be closed when the socket
// is closed.
NNG_DECL int nng_socket_get_recv_poll_fd(nng_socket id, int *fdp);
NNG_DECL int nng_socket_get_send_poll_fd(nng_socket id, int *fdp);

// These functions are used on a socket to get information about it's
// identity, and the identity of the peer.  Few applications need these.
NNG_DECL int nng_socket_proto_id(nng_socket id, uint16_t *idp);
NNG_DECL int nng_socket_peer_id(nng_socket id, uint16_t *idp);
NNG_DECL int nng_socket_proto_name(nng_socket id, const char **namep);
NNG_DECL int nng_socket_peer_name(nng_socket id, const char **namep);
NNG_DECL int nng_socket_raw(nng_socket id, bool *rawp);

// Utility function for getting a printable form of the socket address
// for display in logs, etc.  It is not intended to be parsed, and the
// display format may change without notice.  Generally you should allow
// at least NNG_MAXADDRSTRLEN if you want to avoid typical truncations.
// It is still possible for very long IPC paths to be truncated, but that
// is an edge case and applications that pass such long paths should
// expect some truncation (but they may pass larger values).
#define NNG_MAXADDRSTRLEN (NNG_MAXADDRLEN + 16) // extra bytes for scheme
NNG_DECL const char *nng_str_sockaddr(
    const nng_sockaddr *sa, char *buf, size_t bufsz);

// Obtain a port number (for NNG_AF_INET and NNG_AF_INET6this will be 16 bits
// maximum, but other address families may have larger port numbers.)  For
// address that don't have the concept of port numbers, zero will be returned.
NNG_DECL uint32_t nng_sockaddr_port(const nng_sockaddr *sa);

// Compare two socket addresses. Returns true if they are equal, false
// otherwise.
NNG_DECL bool nng_sockaddr_equal(
    const nng_sockaddr *sa1, const nng_sockaddr *sa2);

// Generate a quick non-zero 64-bit value for the sockaddr.
// This should usually be unique, but collisions are possible.
// The resulting hash is not portable between systems, and may not
// be portable from one version of NNG to the next.
//
// The intended use is to allow creation of an index for use with id maps.
NNG_DECL uint64_t nng_sockaddr_hash(const nng_sockaddr *sa);

// Arguably the pipe callback functions could be handled as an option,
// but with the need to specify an argument, we find it best to unify
// this as a separate function to pass in the argument and the callback.
// Only one callback can be set on a given socket, and there is no way
// to retrieve the old value.
typedef enum {
	NNG_PIPE_EV_NONE,     // Used internally, must be first, never posted
	NNG_PIPE_EV_ADD_PRE,  // Called just before pipe added to socket
	NNG_PIPE_EV_ADD_POST, // Called just after pipe added to socket
	NNG_PIPE_EV_REM_POST, // Called just after pipe removed from socket
	NNG_PIPE_EV_NUM,      // Used internally, must be last.
} nng_pipe_ev;

typedef void (*nng_pipe_cb)(nng_pipe, nng_pipe_ev, void *);

// nng_pipe_notify registers a callback to be executed when the
// given event is triggered.  To watch for different events, register
// multiple times.  Each event can have at most one callback registered.
NNG_DECL nng_err nng_pipe_notify(nng_socket, nng_pipe_ev, nng_pipe_cb, void *);

// nng_listen creates a listening endpoint with no special options,
// and starts it listening.  It is functionally equivalent to the legacy
// nn_bind(). The underlying endpoint is returned back to the caller in the
// endpoint pointer, if it is not NULL.  The flags are ignored at present.
NNG_DECL int nng_listen(nng_socket, const char *, nng_listener *, int);
NNG_DECL int nng_listen_url(nng_socket, const nng_url *, nng_listener *, int);

// nng_dial creates a dialing endpoint, with no special options, and
// starts it dialing.  Dialers have at most one active connection at a time
// This is similar to the legacy nn_connect().  The underlying endpoint
// is returned back to the caller in the endpoint pointer, if it is not NULL.
// The flags may be NNG_FLAG_NONBLOCK to indicate that the first attempt to
// dial will be made in the background, returning control to the caller
// immediately.  In this case, if the connection fails, the function will
// keep retrying in the background.  (If the connection is dropped in either
// case, it will still be reconnected in the background -- only the initial
// connection attempt is normally synchronous.)
NNG_DECL int nng_dial(nng_socket, const char *, nng_dialer *, int);
NNG_DECL int nng_dial_url(nng_socket, const nng_url *url, nng_dialer *, int);

// nng_dialer_create creates a new dialer, that is not yet started.
NNG_DECL int nng_dialer_create(nng_dialer *, nng_socket, const char *);
NNG_DECL int nng_dialer_create_url(nng_dialer *, nng_socket, const nng_url *);

// nng_listener_create creates a new listener, that is not yet started.
NNG_DECL int nng_listener_create(nng_listener *, nng_socket, const char *);
NNG_DECL int nng_listener_create_url(
    nng_listener *, nng_socket, const nng_url *);

// nng_dialer_start starts the endpoint dialing.  This is only possible if
// the dialer is not already dialing.
NNG_DECL int nng_dialer_start(nng_dialer, int);

// nng_dialer_start_aio starts the endpoint dialing asynchronously.  This is
// only possible if the dialer is not already dialing.  Unlike
// nng_dialer_start, this accepts an AIO such that the caller can learn when
// the dialing eventually succeeds or fails.  The supplied AIO must have been
// initialized, and is only triggered with the result of the first dial
// attempt.
NNG_DECL void nng_dialer_start_aio(nng_dialer, int, nng_aio *);

// nng_listener_start starts the endpoint listening.  This is only possible if
// the listener is not already listening.
NNG_DECL int nng_listener_start(nng_listener, int);

// nng_dialer_close closes the dialer, shutting down all underlying
// connections and releasing all associated resources.
NNG_DECL int nng_dialer_close(nng_dialer);

// nng_listener_close closes the listener, shutting down all underlying
// connections and releasing all associated resources.
NNG_DECL int nng_listener_close(nng_listener);

// nng_dialer_id returns the positive dialer ID, or -1 if the dialer is
// invalid.
NNG_DECL int nng_dialer_id(nng_dialer);

// nng_listener_id returns the positive listener ID, or -1 if the listener is
// invalid.
NNG_DECL int nng_listener_id(nng_listener);

NNG_DECL int nng_dialer_set_bool(nng_dialer, const char *, bool);
NNG_DECL int nng_dialer_set_int(nng_dialer, const char *, int);
NNG_DECL int nng_dialer_set_size(nng_dialer, const char *, size_t);
NNG_DECL int nng_dialer_set_uint64(nng_dialer, const char *, uint64_t);
NNG_DECL int nng_dialer_set_string(nng_dialer, const char *, const char *);
NNG_DECL int nng_dialer_set_ms(nng_dialer, const char *, nng_duration);
NNG_DECL int nng_dialer_set_addr(
    nng_dialer, const char *, const nng_sockaddr *);
NNG_DECL int nng_dialer_set_tls(nng_dialer, nng_tls_config *);

NNG_DECL int nng_dialer_get_bool(nng_dialer, const char *, bool *);
NNG_DECL int nng_dialer_get_int(nng_dialer, const char *, int *);
NNG_DECL int nng_dialer_get_size(nng_dialer, const char *, size_t *);
NNG_DECL int nng_dialer_get_uint64(nng_dialer, const char *, uint64_t *);
NNG_DECL int nng_dialer_get_string(nng_dialer, const char *, const char **);
NNG_DECL int nng_dialer_get_ms(nng_dialer, const char *, nng_duration *);
NNG_DECL int nng_dialer_get_addr(nng_dialer, const char *, nng_sockaddr *);
NNG_DECL int nng_dialer_get_tls(nng_dialer, nng_tls_config **);
NNG_DECL int nng_dialer_get_url(nng_dialer id, const nng_url **urlp);

NNG_DECL int nng_listener_set_bool(nng_listener, const char *, bool);
NNG_DECL int nng_listener_set_int(nng_listener, const char *, int);
NNG_DECL int nng_listener_set_size(nng_listener, const char *, size_t);
NNG_DECL int nng_listener_set_uint64(nng_listener, const char *, uint64_t);
NNG_DECL int nng_listener_set_string(nng_listener, const char *, const char *);
NNG_DECL int nng_listener_set_ms(nng_listener, const char *, nng_duration);
NNG_DECL int nng_listener_set_tls(nng_listener, nng_tls_config *);
NNG_DECL int nng_listener_set_security_descriptor(nng_listener, void *);
NNG_DECL int nng_listener_get_url(nng_listener id, const nng_url **urlp);

NNG_DECL int nng_listener_get_bool(nng_listener, const char *, bool *);
NNG_DECL int nng_listener_get_int(nng_listener, const char *, int *);
NNG_DECL int nng_listener_get_size(nng_listener, const char *, size_t *);
NNG_DECL int nng_listener_get_uint64(nng_listener, const char *, uint64_t *);
NNG_DECL int nng_listener_get_string(
    nng_listener, const char *, const char **);
NNG_DECL int nng_listener_get_ms(nng_listener, const char *, nng_duration *);
NNG_DECL int nng_listener_get_tls(nng_listener, nng_tls_config **);

// nng_strerror returns a human-readable string associated with the error
// code supplied.
NNG_DECL const char *nng_strerror(nng_err);

// nng_send sends (or arranges to send) the data on the socket.  Note that
// this function may (will!) return before any receiver has actually
// received the data.  The return value will be zero to indicate that the
// socket has accepted the entire data for send, or an errno to indicate
// failure.  The flags may include NNG_FLAG_NONBLOCK.
NNG_DECL int nng_send(nng_socket, const void *, size_t, int);

// nng_recv receives message data into the socket, up to the supplied size.
// The actual size of the message data will be written to the value pointed
// to by size.  The flags may include NNG_FLAG_NONBLOCK.
NNG_DECL int nng_recv(nng_socket, void *, size_t *, int);

// nng_sendmsg is like nng_send, but offers up a message structure, which
// gives the ability to provide more control over the message, including
// providing backtrace information.  It also can take a message that was
// obtained via nn_recvmsg, allowing for zero copy forwarding.
NNG_DECL int nng_sendmsg(nng_socket, nng_msg *, int);

// nng_recvmsg is like nng_recv, but is used to obtain a message structure
// as well as the data buffer.  This can be used to obtain more information
// about where the message came from, access raw headers, etc.  It also
// can be passed off directly to nng_sendmsg.
NNG_DECL int nng_recvmsg(nng_socket, nng_msg **, int);

// nng_socket_send sends data on the socket asynchronously.  As with nng_send,
// the completion may be executed before the data has actually been delivered,
// but only when it is accepted for delivery.  The supplied AIO must have
// been initialized, and have an associated message.  The message will be
// "owned" by the socket if the operation completes successfully.  Otherwise,
// the caller is responsible for freeing it.
NNG_DECL void nng_socket_send(nng_socket, nng_aio *);

// nng_socket_recv receives data on the socket asynchronously.  On a successful
// result, the AIO will have an associated message, that can be obtained
// with nng_aio_get_msg().  The caller takes ownership of the message at
// this point.
NNG_DECL void nng_socket_recv(nng_socket, nng_aio *);

// Context support.  User contexts are not supported by all protocols,
// but for those that do, they give a way to create multiple contexts
// on a single socket, each of which runs the protocol's state machinery
// independently, offering a way to achieve concurrent protocol support
// without resorting to raw mode sockets.  See the protocol specific
// documentation for further details.  (Note that at this time, only
// asynchronous send/recv are supported for contexts, but its easy enough
// to make synchronous versions with nng_aio_wait().)  Note that
// nng_socket_close of the parent socket will *block* as long as any contexts
// are open.

// nng_ctx_open creates a context.  This returns NNG_ENOTSUP if the
// protocol implementation does not support separate contexts.
NNG_DECL int nng_ctx_open(nng_ctx *, nng_socket);

// nng_ctx_close closes the context.
NNG_DECL int nng_ctx_close(nng_ctx);

// nng_ctx_id returns the numeric id for the context; this will be
// a positive value for a valid context, or < 0 for an invalid context.
// A valid context is not necessarily an *open* context.
NNG_DECL int nng_ctx_id(nng_ctx);

// nng_ctx_recv receives asynchronously.  It works like nng_socket_recv, but
// uses a local context instead of the socket global context.
NNG_DECL void nng_ctx_recv(nng_ctx, nng_aio *);

// nng_ctx_recvmsg allows for receiving a message synchronously using
// a context.  It has the same semantics as nng_recvmsg, but operates
// on a context instead of a socket.
NNG_DECL int nng_ctx_recvmsg(nng_ctx, nng_msg **, int);

// nng_ctx_send sends asynchronously. It works like nng_socket_send, but
// uses a local context instead of the socket global context.
NNG_DECL void nng_ctx_send(nng_ctx, nng_aio *);

// nng_ctx_sendmsg is allows for sending a message synchronously using
// a context.  It has the same semantics as nng_sendmsg, but operates
// on a context instead of a socket.
NNG_DECL int nng_ctx_sendmsg(nng_ctx, nng_msg *, int);

NNG_DECL int nng_ctx_get_bool(nng_ctx, const char *, bool *);
NNG_DECL int nng_ctx_get_int(nng_ctx, const char *, int *);
NNG_DECL int nng_ctx_get_size(nng_ctx, const char *, size_t *);
NNG_DECL int nng_ctx_get_ms(nng_ctx, const char *, nng_duration *);

NNG_DECL int nng_ctx_set(nng_ctx, const char *, const void *, size_t);
NNG_DECL int nng_ctx_set_bool(nng_ctx, const char *, bool);
NNG_DECL int nng_ctx_set_int(nng_ctx, const char *, int);
NNG_DECL int nng_ctx_set_size(nng_ctx, const char *, size_t);
NNG_DECL int nng_ctx_set_ms(nng_ctx, const char *, nng_duration);

// nng_alloc is used to allocate memory.  It's intended purpose is for
// allocating memory suitable for message buffers with nng_send().
// Applications that need memory for other purposes should use their platform
// specific API.
NNG_DECL void *nng_alloc(size_t);

// nng_free is used to free memory allocated with nng_alloc.  As the
// application is required to keep track of the size of memory, this is
// probably less convenient for general uses than the C library malloc and
// calloc.
NNG_DECL void nng_free(void *, size_t);

// nng_strdup duplicates the source string, using nng_alloc. The result
// should be freed with nng_strfree (or nng_free(strlen(s)+1)).
NNG_DECL char *nng_strdup(const char *);

// nng_strfree is equivalent to nng_free(strlen(s)+1).
NNG_DECL void nng_strfree(char *);

// Async IO API.  AIO structures can be thought of as "handles" to
// support asynchronous operations.  They contain the completion callback, and
// a pointer to consumer data.  This is similar to how overlapped I/O
// works in Windows, when used with a completion callback.
//
// AIO structures can carry up to 4 distinct input values, and up to
// 4 distinct output values, and up to 4 distinct "private state" values.
// The meaning of the inputs and the outputs are determined by the
// I/O functions being called.

// nng_aio_alloc allocates a new AIO, and associated the completion
// callback and its opaque argument.  If NULL is supplied for the
// callback, then the caller must use nng_aio_wait() to wait for the
// operation to complete.  If the completion callback is not NULL, then
// when a submitted operation completes (or is canceled or fails) the
// callback will be executed, generally in a different thread, with no
// locks held.
NNG_DECL nng_err nng_aio_alloc(nng_aio **, void (*)(void *), void *);

// nng_aio_free frees the AIO and any associated resources.
// It *must not* be in use at the time it is freed.
NNG_DECL void nng_aio_free(nng_aio *);

// nng_aio_reap is like nng_aio_free, but calls it from a background
// reaper thread.  This can be useful to free aio objects from aio
// callbacks (e.g. when the result of the callback is to discard
// the object in question.)  The aio object must be in further use
// when this is called.
NNG_DECL void nng_aio_reap(nng_aio *);

// nng_aio_stop stops any outstanding operation, and waits for the
// AIO to be free, including for the callback to have completed
// execution.  Therefore, the caller must NOT hold any locks that
// are acquired in the callback, or deadlock will occur.
// No further operations may be scheduled on the aio, stop is
// a permanent operation.
NNG_DECL void nng_aio_stop(nng_aio *);

// nng_aio_result returns the status/result of the operation. This
// will be zero on successful completion, or an nng error code on
// failure.
NNG_DECL nng_err nng_aio_result(nng_aio *);

// nng_aio_count returns the number of bytes transferred for certain
// I/O operations.  This is meaningless for other operations (e.g.
// DNS lookups or TCP connection setup).
NNG_DECL size_t nng_aio_count(nng_aio *);

// nng_aio_cancel attempts to cancel any in-progress I/O operation.
// The AIO callback will still be executed, but if the cancellation is
// successful then the status will be NNG_ECANCELED.
// An AIO can only be canceled if it was submitted already.
NNG_DECL void nng_aio_cancel(nng_aio *);

// nng_aio_abort is like nng_aio_cancel, but allows for a different
// error result to be returned.
NNG_DECL void nng_aio_abort(nng_aio *, nng_err);

// nng_aio_wait waits synchronously for any pending operation to complete.
// It also waits for the callback to have completed execution.  Therefore,
// the caller of this function must not hold any locks acquired by the
// callback or deadlock may occur.
NNG_DECL void nng_aio_wait(nng_aio *);

// nng_aio_busy returns true if the aio is still busy processing the
// operation, or executing associated completion functions.  Note that
// if the completion function schedules a new operation using the aio,
// then this function will continue to return true.
NNG_DECL bool nng_aio_busy(nng_aio *);

// nng_aio_set_msg sets the message structure to use for asynchronous
// message send operations.
NNG_DECL void nng_aio_set_msg(nng_aio *, nng_msg *);

// nng_aio_get_msg returns the message structure associated with a completed
// receive operation.
NNG_DECL nng_msg *nng_aio_get_msg(nng_aio *);

// nng_aio_set_input sets an input parameter at the given index.
NNG_DECL int nng_aio_set_input(nng_aio *, unsigned, void *);

// nng_aio_get_input retrieves the input parameter at the given index.
NNG_DECL void *nng_aio_get_input(nng_aio *, unsigned);

// nng_aio_set_output sets an output result at the given index.
NNG_DECL int nng_aio_set_output(nng_aio *, unsigned, void *);

// nng_aio_get_output retrieves the output result at the given index.
NNG_DECL void *nng_aio_get_output(nng_aio *, unsigned);

// nng_aio_set_timeout sets a timeout on the AIO.  This should be called for
// operations that should time out after a period.  The timeout should be
// either a positive number of milliseconds, or NNG_DURATION_INFINITE to
// indicate that the operation has no timeout.  A poll may be done by
// specifying NNG_DURATION_ZERO.  The value NNG_DURATION_DEFAULT indicates
// that any socket specific timeout should be used.
NNG_DECL void nng_aio_set_timeout(nng_aio *, nng_duration);

// nng_aio_set_expire is like nng_aio_set_timeout, except it sets an absolute
// expiration time.  This is useful when chaining actions on a single aio
// as part of a state machine.
NNG_DECL void nng_aio_set_expire(nng_aio *, nng_time);

// nng_aio_set_iov sets a scatter/gather vector on the aio.  The iov array
// itself is copied. Data members (the memory regions referenced) *may* be
// copied as well, depending on the operation.  This operation is guaranteed
// to succeed if n <= 4, otherwise it may fail due to NNG_ENOMEM.
NNG_DECL int nng_aio_set_iov(nng_aio *, unsigned, const nng_iov *);

// nng_aio_reset is called by the provider before doing other operations on the
// aio.  Its purpose is to clear certain output fields, to avoid accidental
// reuse from prior operations on the aio.
NNG_DECL void nng_aio_reset(nng_aio *);

// nng_aio_finish is used to "finish" an asynchronous operation.
// It should only be called by "providers" (such as HTTP server API users).
// The argument is the value that nng_aio_result() should return.
// IMPORTANT: Callers must ensure that this is called EXACTLY ONCE on any
// given aio.
NNG_DECL void nng_aio_finish(nng_aio *, nng_err);

// nng_aio_start is used to register a cancellation routine, and indicate
// that the operation will be completed asynchronously.  It must only be
// called once per operation on an aio, and must only be called by providers.
// If the operation is canceled by the consumer, the cancellation callback
// will be called.  The provider *must* still ensure that the nng_aio_finish()
// function is called EXACTLY ONCE.  If the operation cannot be canceled
// for any reason, the cancellation callback should do nothing.  The
// final argument is passed to the cancelfn.  The final argument of the
// cancellation function is the error number (will not be zero) corresponding
// to the reason for cancellation, e.g. NNG_ETIMEDOUT or NNG_ECANCELED.
// This returns false if the operation cannot be deferred (because the AIO
// has been stopped with nng_aio_stop.)  If it does so, then the aio's
// completion callback will fire with a result of NNG_ESTOPPED.
typedef void (*nng_aio_cancelfn)(nng_aio *, void *, nng_err);
NNG_DECL bool nng_aio_start(nng_aio *, nng_aio_cancelfn, void *);

// nng_aio_sleep does a "sleeping" operation, basically does nothing
// but wait for the specified number of milliseconds to expire, then
// calls the callback.  This returns 0, rather than NNG_ETIMEDOUT.
NNG_DECL void nng_sleep_aio(nng_duration, nng_aio *);

// Message API.
NNG_DECL int      nng_msg_alloc(nng_msg **, size_t);
NNG_DECL void     nng_msg_free(nng_msg *);
NNG_DECL int      nng_msg_realloc(nng_msg *, size_t);
NNG_DECL int      nng_msg_reserve(nng_msg *, size_t);
NNG_DECL size_t   nng_msg_capacity(nng_msg *);
NNG_DECL void    *nng_msg_header(nng_msg *);
NNG_DECL size_t   nng_msg_header_len(const nng_msg *);
NNG_DECL void    *nng_msg_body(nng_msg *);
NNG_DECL size_t   nng_msg_len(const nng_msg *);
NNG_DECL int      nng_msg_append(nng_msg *, const void *, size_t);
NNG_DECL int      nng_msg_insert(nng_msg *, const void *, size_t);
NNG_DECL int      nng_msg_trim(nng_msg *, size_t);
NNG_DECL int      nng_msg_chop(nng_msg *, size_t);
NNG_DECL int      nng_msg_header_append(nng_msg *, const void *, size_t);
NNG_DECL int      nng_msg_header_insert(nng_msg *, const void *, size_t);
NNG_DECL int      nng_msg_header_trim(nng_msg *, size_t);
NNG_DECL int      nng_msg_header_chop(nng_msg *, size_t);
NNG_DECL int      nng_msg_header_append_u16(nng_msg *, uint16_t);
NNG_DECL int      nng_msg_header_append_u32(nng_msg *, uint32_t);
NNG_DECL int      nng_msg_header_append_u64(nng_msg *, uint64_t);
NNG_DECL int      nng_msg_header_insert_u16(nng_msg *, uint16_t);
NNG_DECL int      nng_msg_header_insert_u32(nng_msg *, uint32_t);
NNG_DECL int      nng_msg_header_insert_u64(nng_msg *, uint64_t);
NNG_DECL int      nng_msg_header_chop_u16(nng_msg *, uint16_t *);
NNG_DECL int      nng_msg_header_chop_u32(nng_msg *, uint32_t *);
NNG_DECL int      nng_msg_header_chop_u64(nng_msg *, uint64_t *);
NNG_DECL int      nng_msg_header_trim_u16(nng_msg *, uint16_t *);
NNG_DECL int      nng_msg_header_trim_u32(nng_msg *, uint32_t *);
NNG_DECL int      nng_msg_header_trim_u64(nng_msg *, uint64_t *);
NNG_DECL int      nng_msg_append_u16(nng_msg *, uint16_t);
NNG_DECL int      nng_msg_append_u32(nng_msg *, uint32_t);
NNG_DECL int      nng_msg_append_u64(nng_msg *, uint64_t);
NNG_DECL int      nng_msg_insert_u16(nng_msg *, uint16_t);
NNG_DECL int      nng_msg_insert_u32(nng_msg *, uint32_t);
NNG_DECL int      nng_msg_insert_u64(nng_msg *, uint64_t);
NNG_DECL int      nng_msg_chop_u16(nng_msg *, uint16_t *);
NNG_DECL int      nng_msg_chop_u32(nng_msg *, uint32_t *);
NNG_DECL int      nng_msg_chop_u64(nng_msg *, uint64_t *);
NNG_DECL int      nng_msg_trim_u16(nng_msg *, uint16_t *);
NNG_DECL int      nng_msg_trim_u32(nng_msg *, uint32_t *);
NNG_DECL int      nng_msg_trim_u64(nng_msg *, uint64_t *);
NNG_DECL int      nng_msg_dup(nng_msg **, const nng_msg *);
NNG_DECL void     nng_msg_clear(nng_msg *);
NNG_DECL void     nng_msg_header_clear(nng_msg *);
NNG_DECL void     nng_msg_set_pipe(nng_msg *, nng_pipe);
NNG_DECL nng_pipe nng_msg_get_pipe(const nng_msg *);

// Pipe API. Generally pipes are only "observable" to applications, but
// we do permit an application to close a pipe. This can be useful, for
// example during a connection notification, to disconnect a pipe that
// is associated with an invalid or untrusted remote peer.
NNG_DECL nng_err nng_pipe_get_bool(nng_pipe, const char *, bool *);
NNG_DECL nng_err nng_pipe_get_int(nng_pipe, const char *, int *);
NNG_DECL nng_err nng_pipe_get_ms(nng_pipe, const char *, nng_duration *);
NNG_DECL nng_err nng_pipe_get_size(nng_pipe, const char *, size_t *);
NNG_DECL nng_err nng_pipe_get_string(nng_pipe, const char *, const char **);
NNG_DECL nng_err nng_pipe_get_strdup(nng_pipe, const char *, char **);
NNG_DECL nng_err nng_pipe_get_strcpy(nng_pipe, const char *, char *, size_t);
NNG_DECL nng_err nng_pipe_get_strlen(nng_pipe, const char *, size_t *);
NNG_DECL nng_err nng_pipe_peer_addr(nng_pipe, nng_sockaddr *);
NNG_DECL nng_err nng_pipe_self_addr(nng_pipe, nng_sockaddr *);
NNG_DECL nng_err nng_pipe_peer_cert(nng_pipe, nng_tls_cert **);

NNG_DECL nng_err      nng_pipe_close(nng_pipe);
NNG_DECL int          nng_pipe_id(nng_pipe);
NNG_DECL nng_socket   nng_pipe_socket(nng_pipe);
NNG_DECL nng_dialer   nng_pipe_dialer(nng_pipe);
NNG_DECL nng_listener nng_pipe_listener(nng_pipe);

// Flags.
#define NNG_FLAG_NONBLOCK 2u // Non-blocking operations

// Options.
#define NNG_OPT_RECVBUF "recv-buffer"
#define NNG_OPT_SENDBUF "send-buffer"
#define NNG_OPT_RECVTIMEO "recv-timeout"
#define NNG_OPT_SENDTIMEO "send-timeout"
#define NNG_OPT_LOCADDR "local-address"
#define NNG_OPT_MAXTTL "ttl-max"
#define NNG_OPT_RECVMAXSZ "recv-size-max"
#define NNG_OPT_RECONNMINT "reconnect-time-min"
#define NNG_OPT_RECONNMAXT "reconnect-time-max"

// TLS options are only used when the underlying transport supports TLS.

// NNG_OPT_TLS_VERIFIED returns a boolean indicating whether the peer has
// been verified (true) or not (false). Typically, this is read-only, and
// only available for pipes. This option may return incorrect results if
// peer authentication is disabled with `NNG_TLS_AUTH_MODE_NONE`.
#define NNG_OPT_TLS_VERIFIED "tls-verified"

// NNG_OPT_TLS_PEER_CN returns the string with the common name
// of the peer certificate. Typically, this is read-only and
// only available for pipes. This option may return incorrect results if
// peer authentication is disabled with `NNG_TLS_AUTH_MODE_NONE`.
#define NNG_OPT_TLS_PEER_CN "tls-peer-cn"

// TCP options.  These may be supported on various transports that use
// TCP underneath such as TLS, or not.

// TCP nodelay disables the use of Nagle, so that messages are sent
// as soon as data is available. This tends to reduce latency, but
// can come at the cost of extra messages being sent, and may have
// a detrimental effect on performance. For most uses, we recommend
// enabling this. (Disable it if you are on a very slow network.)
// This is a boolean.
#define NNG_OPT_TCP_NODELAY "tcp-nodelay"

// TCP keepalive causes the underlying transport to send keep-alive
// messages, and keep the session active. Keepalives are zero length
// messages with the ACK flag turned on. If we don't get an ACK back,
// then we know the other side is gone. This is useful for detecting
// dead peers, and is also used to prevent disconnections caused by
// middle boxes thinking the session has gone idle (e.g. keeping NAT
// state current). This is a boolean.
#define NNG_OPT_TCP_KEEPALIVE "tcp-keepalive"

// Local TCP or UDP port number.  This is used on a listener, and is intended
// to be used after starting the listener in combination with a wildcard
// (0) local port.  This determines the actual ephemeral port that was
// selected and bound.  The value is provided as an int, but in practice
// port numbers are only 16-bits.
#define NNG_OPT_BOUND_PORT "bound-port"

// UDP options.

// UDP short message size.  Messages smaller than (or equal to) this
// will be copied, instead of loan up.  This can allow for a faster
// pass up as we can allocate smaller message buffers instead of having
// to replace a full message buffer.
#define NNG_OPT_UDP_COPY_MAX "udp:copy-max"

// IPC options.  These will largely vary depending on the platform,
// as POSIX systems have very different options than Windows.

// Permissions bits.  This option is only valid for listeners on
// POSIX platforms and others that honor UNIX style permission bits.
// Note that some platforms may not honor the permissions here, although
// at least Linux and macOS seem to do so.  Check before you rely on
// this for security.
#define NNG_OPT_IPC_PERMISSIONS "ipc:permissions"

// IPC peer options may also be used in some cases with other socket types.

// Peer UID.  This is only available on POSIX style systems.
#define NNG_OPT_PEER_UID "ipc:peer-uid"
#define NNG_OPT_IPC_PEER_UID NNG_OPT_PEER_UID

// Peer GID (primary group).  This is only available on POSIX style systems.
#define NNG_OPT_PEER_GID "ipc:peer-gid"
#define NNG_OPT_IPC_PEER_GID NNG_OPT_PEER_GID

// Peer process ID.  Available on Windows, Linux, and SunOS.
// In theory, we could obtain this with the first message sent,
// but we have elected not to do this for now. (Nice RFE for a FreeBSD
// guru though.)
#define NNG_OPT_PEER_PID "ipc:peer-pid"
#define NNG_OPT_IPC_PEER_PID NNG_OPT_PEER_PID

// Peer Zone ID.  Only on SunOS systems.  (Linux containers have no
// definable kernel identity; they are a user-land fabrication made up
// from various pieces of different namespaces. FreeBSD does have
// something called JailIDs, but it isn't obvious how to determine this,
// or even if processes can use IPC across jail boundaries.)
#define NNG_OPT_PEER_ZONEID "ipc:peer-zoneid"
#define NNG_OPT_IPC_PEER_ZONEID NNG_OPT_PEER_ZONEID

// WebSocket Options.

// NNG_OPT_WS_HEADER is a prefix, for a dynamic property name.
// This allows direct access to any named header to set a header on
// a dialer or listener.  This property can be used to set headers
// on outgoing dialer or listeners, and can be used to return the
// headers from the peer on a pipe.
#define NNG_OPT_WS_HEADER "ws:header:"

// These options allow for iterating over HTTP headers.  The iteration is
// started and advances by getting NNG_OPT_WS_HEADER_NEXT (which returns a bool
// that is true if there was a header, or false if no more headers are
// available).  The HTTP_OPT_WS_HEADER_RESET is a boolean option that always
// returns true. Reading it resets the iteration to the beginning.  The
// NNG_OPT_WS_HEADER_KEY and NNG_OPT_WS_HEADER_VALUE options obtain the header
// name and value for the current (established by NNG_OPT_WS_HEADER_NEXT) HTTP
// header.
#define NNG_OPT_WS_HEADER_NEXT "ws:hdr-next"
#define NNG_OPT_WS_HEADER_RESET "ws:hdr-reset"
#define NNG_OPT_WS_HEADER_KEY "ws:hdr-key"
#define NNG_OPT_WS_HEADER_VALUE "ws:hdr-val"

// NNG_OPT_WS_REQUEST_URI is used to obtain the URI sent by the client.
// This can be useful when a handler supports an entire directory tree.
#define NNG_OPT_WS_REQUEST_URI "ws:request-uri"

// NNG_OPT_WS_SENDMAXFRAME is used to configure the fragmentation size
// used for frames.  This has a default value of 64k.  Large values
// are good for throughput, but penalize latency.  They also require
// additional buffering on the peer.  This value must not be larger
// than what the peer will accept, and unfortunately there is no way
// to negotiate this.
#define NNG_OPT_WS_SENDMAXFRAME "ws:txframe-max"

// NNG_OPT_WS_RECVMAXFRAME is the largest frame we will accept.  This should
// probably not be larger than NNG_OPT_RECVMAXSZ. If the sender attempts
// to send more data than this in a single message, it will be dropped.
#define NNG_OPT_WS_RECVMAXFRAME "ws:rxframe-max"

// NNG_OPT_WS_PROTOCOL is the "websocket sub-protocol" -- it's a string.
// This is also known as the Sec-WebSocket-Protocol header. It is treated
// specially.  This is part of the websocket handshake.
#define NNG_OPT_WS_PROTOCOL "ws:protocol"

// NNG_OPT_WS_SEND_TEXT is a boolean used to tell the WS stream
// transport to send text messages.  This is not supported for the
// core WebSocket transport, but when using streams it might be useful
// to speak with 3rd party WebSocket applications.  This mode should
// not be used unless absolutely required. No validation of the message
// contents is performed by NNG; applications are expected to honor
// the requirement to send only valid UTF-8.  (Compliant applications
// will close the socket if they see this message type with invalid UTF-8.)
#define NNG_OPT_WS_SEND_TEXT "ws:send-text"

// NNG_OPT_WS_RECV_TEXT is a boolean that enables NNG to receive
// TEXT frames.  This is only useful for stream mode applications --
// SP protocol requires the use of binary frames.  Note also that
// NNG does not validate the message contents for valid UTF-8; this
// means it will not be conformant with RFC-6455 on it's own. Applications
// that need this should check the message contents themselves, and
// close the connection if invalid UTF-8 is received.  This option
// should not be used unless required to communication with 3rd party
// peers that cannot be coerced into sending binary frames.
#define NNG_OPT_WS_RECV_TEXT "ws:recv-text"

// NNG_OPT_SOCKET_FD is a write-only integer property that is used to
// file descriptors (or FILE HANDLE objects on Windows) to a
// socket:// based listener.  This file descriptor will be taken
// over and used as a stream connection.  The protocol is compatible
// with SP over TCP.  This facility is experimental, and intended to
// allow use with descriptors created via socketpair() or similar.
// Note that unidirectional pipes (such as those from pipe(2) or mkfifo)
// are not supported.
#define NNG_OPT_SOCKET_FD "socket:fd"

// NNG_OPT_LISTEN_FD is a write-only integer property that can be used
// with some transports to pass a file descriptor that is already listening
// for inbound connections.  The transport will then call accept on it.
// The file descriptor has to be of a suitable type.  The intended use
// for this is socket activation.  Not all transports support this.
#define NNG_OPT_LISTEN_FD "listen-fd"

// XXX: TBD: priorities, ipv4only

// Statistics. These are for informational purposes only, and subject
// to change without notice. The API for accessing these is stable,
// but the individual statistic names, values, and meanings are all
// subject to change.

// nng_stats_get takes a snapshot of the entire set of statistics.
// While the operation can be somewhat expensive (allocations), it
// is done in a way that minimizes impact to running operations.
// Note that the statistics are provided as a tree, with parents
// used for grouping, and with child statistics underneath.  The
// top stat returned will be of type NNG_STAT_SCOPE with name "".
// Applications may choose to consider this root scope as "root", if
// the empty string is not suitable.
NNG_DECL int nng_stats_get(nng_stat **);

// nng_stats_free frees a previous list of snapshots.  This should only
// be called on the parent statistic that obtained via nng_stats_get.
NNG_DECL void nng_stats_free(nng_stat *);

// nng_stats_dump is a debugging function that dumps the entire set of
// statistics to stdout.
NNG_DECL void nng_stats_dump(const nng_stat *);

// nng_stat_next finds the next sibling for the current stat.  If there
// are no more siblings, it returns NULL.
NNG_DECL const nng_stat *nng_stat_next(const nng_stat *);

// nng_stat_child finds the first child of the current stat.  If no children
// exist, then NULL is returned.
NNG_DECL const nng_stat *nng_stat_child(const nng_stat *);

// nng_stat_name is used to determine the name of the statistic.
// This is a human-readable name.  Statistic names, as well as the presence
// or absence or semantic of any particular statistic are not part of any
// stable API, and may be changed without notice in future updates.
NNG_DECL const char *nng_stat_name(const nng_stat *);

// nng_stat_type is used to determine the type of the statistic.
// Counters generally increment, and therefore changes in the value over
// time are likely more interesting than the actual level.  Level
// values reflect some absolute state however, and should be presented to the
// user as is.
NNG_DECL int nng_stat_type(const nng_stat *);

// nng_stat_find is used to find a specific named statistic within
// a statistic tree.  NULL is returned if no such statistic exists.
NNG_DECL const nng_stat *nng_stat_find(const nng_stat *, const char *);

// nng_stat_find_socket is used to find the stats for the given socket.
NNG_DECL const nng_stat *nng_stat_find_socket(const nng_stat *, nng_socket);

// nng_stat_find_dialer is used to find the stats for the given dialer.
NNG_DECL const nng_stat *nng_stat_find_dialer(const nng_stat *, nng_dialer);

// nng_stat_find_listener is used to find the stats for the given listener.
NNG_DECL const nng_stat *nng_stat_find_listener(
    const nng_stat *, nng_listener);

enum nng_stat_type_enum {
	NNG_STAT_SCOPE   = 0, // Stat is for scoping, and carries no value
	NNG_STAT_LEVEL   = 1, // Numeric "absolute" value, diffs meaningless
	NNG_STAT_COUNTER = 2, // Incrementing value (diffs are meaningful)
	NNG_STAT_STRING  = 3, // Value is a string
	NNG_STAT_BOOLEAN = 4, // Value is a boolean
	NNG_STAT_ID      = 5, // Value is a numeric ID
};

// nng_stat_unit provides information about the unit for the statistic,
// such as NNG_UNIT_BYTES or NNG_UNIT_BYTES.  If no specific unit is
// applicable, such as a relative priority, then NN_UNIT_NONE is returned.
NNG_DECL int nng_stat_unit(const nng_stat *);

enum nng_unit_enum {
	NNG_UNIT_NONE     = 0, // No special units
	NNG_UNIT_BYTES    = 1, // Bytes, e.g. bytes sent, etc.
	NNG_UNIT_MESSAGES = 2, // Messages, one per message
	NNG_UNIT_MILLIS   = 3, // Milliseconds
	NNG_UNIT_EVENTS   = 4  // Some other type of event
};

// nng_stat_value returns the actual value of the statistic.
// Statistic values reflect their value at the time that the corresponding
// snapshot was updated, and are undefined until an update is performed.
NNG_DECL uint64_t nng_stat_value(const nng_stat *);

// nng_stat_bool returns the boolean value of the statistic.
NNG_DECL bool nng_stat_bool(const nng_stat *);

// nng_stat_string returns the string associated with a string statistic,
// or NULL if the statistic is not part of the string.  The value returned
// is valid until the associated statistic is freed.
NNG_DECL const char *nng_stat_string(const nng_stat *);

// nng_stat_desc returns a human-readable description of the statistic.
// This may be useful for display in diagnostic interfaces, etc.
NNG_DECL const char *nng_stat_desc(const nng_stat *);

// nng_stat_timestamp returns a timestamp (milliseconds) when the statistic
// was captured.  The base offset is the same as used by nng_clock().
// We don't use nng_time though, because that's in the supplemental header.
NNG_DECL uint64_t nng_stat_timestamp(const nng_stat *);

// Device functionality.  This connects two sockets together in a device,
// which means that messages from one side are forwarded to the other.
// This version is synchronous, which means the caller will block until
// one of the sockets is closed. Note that caller is responsible for
// finally closing both sockets when this function returns.
NNG_DECL nng_err nng_device(nng_socket, nng_socket);

// Asynchronous form of nng_device.  When this succeeds, the device is
// left intact and functioning in the background, until one of the sockets
// is closed or the application exits.  The sockets may be shut down if
// the device fails, but the caller is responsible for ultimately closing
// the sockets properly after the device is torn down.
NNG_DECL void nng_device_aio(nng_aio *, nng_socket, nng_socket);

// Symbol name and visibility.  TBD.  The only symbols that really should
// be directly exported to runtimes IMO are the option symbols.  And frankly
// they have enough special logic around them that it might be best not to
// automate the promotion of them to other APIs.  This is an area open
// for discussion.

// nng_url_parse parses a URL string into a structured form.
// Note that the u_port member will be filled out with a numeric
// port if one isn't specified and a default port is appropriate for
// the scheme.  The URL structure is allocated, along with individual
// members.  It can be freed with nng_url_free.
NNG_DECL nng_err nng_url_parse(nng_url **, const char *);

// nng_url_free frees a URL structure that was created by nng_url_parse().
NNG_DECL void nng_url_free(nng_url *);

// nng_url_clone clones a URL structure.
NNG_DECL nng_err nng_url_clone(nng_url **, const nng_url *);

// nng_url_sprintf prints a URL to a string using semantics similar to
// snprintf.
NNG_DECL int nng_url_sprintf(char *, size_t, const nng_url *);

NNG_DECL const char *nng_url_scheme(const nng_url *);

// Port (such as UDP or TCP) for a URL, can be zero for ports are not used by
// the scheme.
NNG_DECL uint32_t nng_url_port(const nng_url *);

// Update a URL with a zero port to a non-zero port (useful
// after a bind to port 0).  Does nothing if the URL's port is not
// zero to start with.
NNG_DECL void nng_url_resolve_port(nng_url *url, uint32_t port);

// hostname part of URL, can be NULL if irerelvant to scheme
NNG_DECL const char *nng_url_hostname(const nng_url *);

// user info part (thing before '@') of URL, NULL if absent.
NNG_DECL const char *nng_url_userinfo(const nng_url *);

// path portion of URL, will always non-NULL, but may be empty.
NNG_DECL const char *nng_url_path(const nng_url *);

// query info part of URL, not including '?, NULL if absent'
NNG_DECL const char *nng_url_query(const nng_url *);

// fragment part of URL, not including '#', NULL if absent.
NNG_DECL const char *nng_url_fragment(const nng_url *);

// nng_version returns the library version as a human readable string.
NNG_DECL const char *nng_version(void);

// nng_stream operations permit direct access to low level streams,
// which can have a variety of uses.  Internally most of the transports
// are built on top of these.  Streams are created by other dialers or
// listeners.  The API for creating dialers and listeners varies.

typedef struct nng_stream          nng_stream;
typedef struct nng_stream_dialer   nng_stream_dialer;
typedef struct nng_stream_listener nng_stream_listener;

NNG_DECL void    nng_stream_free(nng_stream *);
NNG_DECL void    nng_stream_close(nng_stream *);
NNG_DECL void    nng_stream_stop(nng_stream *);
NNG_DECL void    nng_stream_send(nng_stream *, nng_aio *);
NNG_DECL void    nng_stream_recv(nng_stream *, nng_aio *);
NNG_DECL nng_err nng_stream_get_bool(nng_stream *, const char *, bool *);
NNG_DECL nng_err nng_stream_get_int(nng_stream *, const char *, int *);
NNG_DECL nng_err nng_stream_get_ms(nng_stream *, const char *, nng_duration *);
NNG_DECL nng_err nng_stream_get_size(nng_stream *, const char *, size_t *);
NNG_DECL nng_err nng_stream_get_uint64(nng_stream *, const char *, uint64_t *);
NNG_DECL nng_err nng_stream_get_string(
    nng_stream *, const char *, const char **);
NNG_DECL const nng_sockaddr *nng_stream_peer_addr(nng_stream *);
NNG_DECL const nng_sockaddr *nng_stream_self_addr(nng_stream *);
NNG_DECL nng_err nng_stream_peer_cert(nng_stream *, nng_tls_cert **);

NNG_DECL nng_err nng_stream_dialer_alloc(nng_stream_dialer **, const char *);
NNG_DECL nng_err nng_stream_dialer_alloc_url(
    nng_stream_dialer **, const nng_url *);
NNG_DECL void    nng_stream_dialer_free(nng_stream_dialer *);
NNG_DECL void    nng_stream_dialer_close(nng_stream_dialer *);
NNG_DECL void    nng_stream_dialer_stop(nng_stream_dialer *);
NNG_DECL void    nng_stream_dialer_dial(nng_stream_dialer *, nng_aio *);
NNG_DECL nng_err nng_stream_dialer_get_bool(
    nng_stream_dialer *, const char *, bool *);
NNG_DECL nng_err nng_stream_dialer_get_int(
    nng_stream_dialer *, const char *, int *);
NNG_DECL nng_err nng_stream_dialer_get_ms(
    nng_stream_dialer *, const char *, nng_duration *);
NNG_DECL nng_err nng_stream_dialer_get_size(
    nng_stream_dialer *, const char *, size_t *);
NNG_DECL nng_err nng_stream_dialer_get_uint64(
    nng_stream_dialer *, const char *, uint64_t *);
NNG_DECL nng_err nng_stream_dialer_get_string(
    nng_stream_dialer *, const char *, const char **);
NNG_DECL nng_err nng_stream_dialer_set_bool(
    nng_stream_dialer *, const char *, bool);
NNG_DECL nng_err nng_stream_dialer_set_int(
    nng_stream_dialer *, const char *, int);
NNG_DECL nng_err nng_stream_dialer_set_ms(
    nng_stream_dialer *, const char *, nng_duration);
NNG_DECL nng_err nng_stream_dialer_set_size(
    nng_stream_dialer *, const char *, size_t);
NNG_DECL nng_err nng_stream_dialer_set_uint64(
    nng_stream_dialer *, const char *, uint64_t);
NNG_DECL nng_err nng_stream_dialer_set_string(
    nng_stream_dialer *, const char *, const char *);
NNG_DECL nng_err nng_stream_dialer_set_addr(
    nng_stream_dialer *, const char *, const nng_sockaddr *);

// Note that when configuring the object, a hold is placed on the TLS
// configuration, using a reference count.  When retrieving the object, no such
// hold is placed, and so the caller must take care not to use the associated
// object after the endpoint it is associated with is closed.
NNG_DECL nng_err nng_stream_dialer_get_tls(
    nng_stream_dialer *, nng_tls_config **);
NNG_DECL nng_err nng_stream_dialer_set_tls(
    nng_stream_dialer *, nng_tls_config *);

NNG_DECL nng_err nng_stream_listener_alloc(
    nng_stream_listener **, const char *);
NNG_DECL nng_err nng_stream_listener_alloc_url(
    nng_stream_listener **, const nng_url *);
NNG_DECL void    nng_stream_listener_free(nng_stream_listener *);
NNG_DECL void    nng_stream_listener_close(nng_stream_listener *);
NNG_DECL void    nng_stream_listener_stop(nng_stream_listener *);
NNG_DECL nng_err nng_stream_listener_listen(nng_stream_listener *);
NNG_DECL void    nng_stream_listener_accept(nng_stream_listener *, nng_aio *);
NNG_DECL nng_err nng_stream_listener_get_bool(
    nng_stream_listener *, const char *, bool *);
NNG_DECL nng_err nng_stream_listener_get_int(
    nng_stream_listener *, const char *, int *);
NNG_DECL nng_err nng_stream_listener_get_ms(
    nng_stream_listener *, const char *, nng_duration *);
NNG_DECL nng_err nng_stream_listener_get_size(
    nng_stream_listener *, const char *, size_t *);
NNG_DECL nng_err nng_stream_listener_get_uint64(
    nng_stream_listener *, const char *, uint64_t *);
NNG_DECL nng_err nng_stream_listener_get_string(
    nng_stream_listener *, const char *, const char **);
NNG_DECL nng_err nng_stream_listener_set_bool(
    nng_stream_listener *, const char *, bool);
NNG_DECL nng_err nng_stream_listener_set_int(
    nng_stream_listener *, const char *, int);
NNG_DECL nng_err nng_stream_listener_set_ms(
    nng_stream_listener *, const char *, nng_duration);
NNG_DECL nng_err nng_stream_listener_set_size(
    nng_stream_listener *, const char *, size_t);
NNG_DECL nng_err nng_stream_listener_set_uint64(
    nng_stream_listener *, const char *, uint64_t);
NNG_DECL nng_err nng_stream_listener_set_string(
    nng_stream_listener *, const char *, const char *);
NNG_DECL nng_err nng_stream_listener_set_addr(
    nng_stream_listener *, const char *, const nng_sockaddr *);

NNG_DECL nng_err nng_stream_listener_get_tls(
    nng_stream_listener *, nng_tls_config **);
NNG_DECL nng_err nng_stream_listener_set_tls(
    nng_stream_listener *, nng_tls_config *);

// Security Descriptor only valid for IPC streams on Windows
// Parameter is a PSECURITY_DESCRIPTOR.
NNG_DECL nng_err nng_stream_listener_set_security_descriptor(
    nng_stream_listener *, void *);

// UDP operations.  These are provided for convenience,
// and should be considered somewhat experimental.

// nng_udp represents a socket / file descriptor for use with UDP
typedef struct nng_udp nng_udp;

// nng_udp_open initializes a UDP socket.  The socket is bound
// to the specified address.
NNG_DECL int nng_udp_open(nng_udp **udpp, nng_sockaddr *sa);

// nng_udp_stop stops the UDP socket from transferring data, before closing it.
// This may be useful if data flows need to be stopped but freeing the
// structure must be done at a later time.  Note that this may wait for I/O to
// be canceled.
NNG_DECL void nng_udp_stop(nng_udp *udp);

// nng_udp_close closes the underlying UDP socket and frees the associated
// resources. Calls nng_udp_stop implicitly.
NNG_DECL void nng_udp_close(nng_udp *udp);

// nng_udp_sockname determines the locally bound address.
// This is useful to determine a chosen port after binding to port 0.
NNG_DECL int nng_udp_sockname(nng_udp *udp, nng_sockaddr *sa);

// nng_udp_send sends the data in the aio to the the
// destination specified in the nng_aio.  The iovs are the UDP payload.
// The destination address is the first input (0th) for the aio.
NNG_DECL void nng_udp_send(nng_udp *udp, nng_aio *aio);

// nng_udp_recv receives a message, storing it in the iovs
// from the UDP payload.  If the UDP payload will not fit, then
// NNG_EMSGSIZE results.  The senders address is stored in the
// socket address (nng_sockaddr), which should have been specified
// in the aio's first input.
NNG_DECL void nng_udp_recv(nng_udp *udp, nng_aio *aio);

// nng_udp_membership provides for joining or leaving multicast groups.
NNG_DECL int nng_udp_multicast_membership(
    nng_udp *udp, nng_sockaddr *sa, bool join);

// Initialization parameters.
// Applications can tweak behavior by passing a non-empty set
// values here, but only the first caller to nng_init may supply
// values.
typedef struct {
	// Fix the number of threads used for tasks (callbacks),
	// Default is 2 threads per core, capped to max_task_threads below.
	// At least 2 threads will be created in any case.  0 leaves this at
	// the default.
	int16_t num_task_threads;

	// Limit the number of threads of created for tasks.
	// NNG will always create at least 2 of these in order to prevent
	// deadlocks. -1 means no limit.  Default is determined by
	// NNG_MAX_TASKQ_THREADS compile time variable.
	int16_t max_task_threads;

	// Fix the number of threads used for expiration.  Default is one
	// thread per core, capped to max_expires_threads below.  At least
	// one thread will be created.
	int16_t num_expire_threads;

	// Limit the number of threads created for expiration.  -1 means no
	// limit. Default is determined by the NNG_MAX_EXPIRE_THREADS compile
	// time variable.
	int16_t max_expire_threads;

	// Fix the number of poller threads (used for I/O).  Support varies
	// by platform (many platforms only support a single poller thread.)
	int16_t num_poller_threads;

	// Limit the number of poller/IO threads created.  -1 means no limit.
	// Default is determined by NNG_MAX_POLLER_THREADS compile time
	// variable.
	int16_t max_poller_threads;

	// Fix the number of threads used for DNS resolution.  At least one
	// will be used. Default is controlled by NNG_RESOLV_CONCURRENCY
	// compile time variable.
	int16_t num_resolver_threads;
} nng_init_params;

// Initialize the library.  May be called multiple times, but
// only the first call can contain a non-NULL params.  If already
// initialized with non-NULL params, will return NNG_EALREADY.
// Applications should *not* call a matching nng_fini() in that case.
NNG_DECL nng_err nng_init(const nng_init_params *params);

// nng_fini is used to terminate the library, freeing certain global resources.
// Each call to nng_fini is paired to a call to nng_init.  The last such
// call will tear down any resources associated with the library.  Thus,
// applications must not call other functions in the library after calling
// this.
NNG_DECL void nng_fini(void);

// Logging support.

// Log levels.  These correspond to RFC 5424 (syslog) levels.
// NNG never only uses priorities 3 - 7.
//
// Note that LOG_EMERG is 0, but we don't let applications submit'
// such messages, so this is a useful value to prevent logging altogether.
typedef enum nng_log_level {
	NNG_LOG_NONE   = 0, // used for filters only, NNG suppresses these
	NNG_LOG_ERR    = 3,
	NNG_LOG_WARN   = 4,
	NNG_LOG_NOTICE = 5,
	NNG_LOG_INFO   = 6,
	NNG_LOG_DEBUG  = 7
} nng_log_level;

// Facilities.  Also from RFC 5424.
// Not all values are enumerated here. Values not enumerated here
// should be assumed reserved for system use, and not available for
// NNG or general applications.
typedef enum nng_log_facility {
	NNG_LOG_USER   = 1,
	NNG_LOG_DAEMON = 3,
	NNG_LOG_AUTH   = 10, // actually AUTHPRIV, for sensitive logs
	NNG_LOG_LOCAL0 = 16,
	NNG_LOG_LOCAL1 = 17,
	NNG_LOG_LOCAL2 = 18,
	NNG_LOG_LOCAL3 = 19,
	NNG_LOG_LOCAL4 = 20,
	NNG_LOG_LOCAL5 = 21,
	NNG_LOG_LOCAL6 = 22,
	NNG_LOG_LOCAL7 = 23,
} nng_log_facility;

// Logging function, which may be supplied by application code.  Only
// one logging function may be registered.  The level and facility are
// as above.  The message ID is chosen by the submitter - internal NNG
// messages will have MSGIDs starting with "NNG-".  The MSGID should be
// not more than 8 characters, though this is not a hard requirement.
// Loggers are required to make a copy of the msgid and message if required,
// because the values will not be valid once the logger returns.
typedef void (*nng_logger)(nng_log_level level, nng_log_facility facility,
    const char *msgid, const char *msg);

// Discard logger, simply throws logs away.
NNG_DECL void nng_null_logger(
    nng_log_level, nng_log_facility, const char *, const char *);

// Very simple, prints formatted messages to stderr.
NNG_DECL void nng_stderr_logger(
    nng_log_level, nng_log_facility, const char *, const char *);

// Performs an appropriate logging function for the system.  On
// POSIX systems it uses syslog(3).  Details vary by system, and the
// logging may be influenced by other APIs not provided by NNG, such as
// openlog() for POSIX systems.  This may be nng_stderr_logger on
// other systems.
NNG_DECL void nng_system_logger(
    nng_log_level, nng_log_facility, const char *, const char *);

// Set the default facility to use when logging.  NNG uses NNG_LOG_USER by
// default.
NNG_DECL void nng_log_set_facility(nng_log_facility facility);

// Set the default logging level.  Use NNG_LOG_DEBUG to get everything.
// Use NNG_LOG_NONE to prevent logging altogether.  Logs that are less
// severe (numeric level is higher) will be discarded.
NNG_DECL void nng_log_set_level(nng_log_level level);

// Get the current logging level.  The intention here os to allow
// bypassing expensive formatting operations that will be discarded
// anyway.
NNG_DECL nng_log_level nng_log_get_level(void);

// Register a logger.
NNG_DECL void nng_log_set_logger(nng_logger logger);

// Log a message.  The msg is formatted using following arguments as per
// sprintf. The msgid may be NULL.
NNG_DECL void nng_log_err(const char *msgid, const char *msg, ...);
NNG_DECL void nng_log_warn(const char *msgid, const char *msg, ...);
NNG_DECL void nng_log_notice(const char *msgid, const char *msg, ...);
NNG_DECL void nng_log_info(const char *msgid, const char *msg, ...);
NNG_DECL void nng_log_debug(const char *msgid, const char *msg, ...);

// Log an authentication related message.  These will use the NNG_LOG_AUTH
// facility.
NNG_DECL void nng_log_auth(
    nng_log_level level, const char *msgid, const char *msg, ...);

// Return an absolute time from some arbitrary point.  The value is
// provided in milliseconds, and is of limited resolution based on the
// system clock.  (Do not use it for fine-grained performance measurements.)
NNG_DECL nng_time nng_clock(void);

// Sleep for specified msecs.
NNG_DECL void nng_msleep(nng_duration);

// nng_random returns a "strong" (cryptographic sense) random number.
NNG_DECL uint32_t nng_random(void);

// nng_socket_pair is used to create a bound pair of file descriptors
// typically using the socketpair() call.  The descriptors are backed
// by reliable, bidirectional, byte streams.  This will return NNG_ENOTSUP
// if the platform lacks support for this.  The argument is a pointer
// to an array of file descriptors (or HANDLES or similar).
NNG_DECL nng_err nng_socket_pair(int[2]);

// Multithreading and synchronization functions.

// nng_thread is a handle to a "thread", which may be a real system
// thread, or a coroutine on some platforms.
typedef struct nng_thread nng_thread;

// Create and start a thread.  Note that on some platforms, this might
// actually be a coroutine, with limitations about what system APIs
// you can call.  Therefore, these threads should only be used with the
// I/O APIs provided by nng.  The thread runs until completion.
NNG_DECL int nng_thread_create(nng_thread **, void (*)(void *), void *);

// Set the thread name.  Support for this is platform specific and varies.
// It is intended to provide information for use when debugging applications,
// and not for programmatic use beyond that.
NNG_DECL void nng_thread_set_name(nng_thread *, const char *);

// Destroy a thread (waiting for it to complete.)  When this function
// returns all resources for the thread are cleaned up.
NNG_DECL void nng_thread_destroy(nng_thread *);

// nng_mtx represents a mutex, which is a simple, non-reentrant, boolean lock.
typedef struct nng_mtx nng_mtx;

// nng_mtx_alloc allocates a mutex structure.
NNG_DECL int nng_mtx_alloc(nng_mtx **);

// nng_mtx_free frees the mutex.  It must not be locked.
NNG_DECL void nng_mtx_free(nng_mtx *);

// nng_mtx_lock locks the mutex; if it is already locked it will block
// until it can be locked.  If the caller already holds the lock, the
// results are undefined (a panic may occur).
NNG_DECL void nng_mtx_lock(nng_mtx *);

// nng_mtx_unlock unlocks a previously locked mutex.  It is an error to
// call this on a mutex which is not owned by caller.
NNG_DECL void nng_mtx_unlock(nng_mtx *);

// nng_cv is a condition variable.  It is always allocated with an
// associated mutex, which must be held when waiting for it, or
// when signaling it.
typedef struct nng_cv nng_cv;

NNG_DECL int nng_cv_alloc(nng_cv **, nng_mtx *);

// nng_cv_free frees the condition variable.
NNG_DECL void nng_cv_free(nng_cv *);

// nng_cv_wait waits until the condition variable is "signaled".
NNG_DECL void nng_cv_wait(nng_cv *);

// nng_cv_until waits until either the condition is signaled, or
// the timeout expires.  It returns NNG_ETIMEDOUT in that case.
NNG_DECL int nng_cv_until(nng_cv *, nng_time);

// nng_cv_wake wakes all threads waiting on the condition.
NNG_DECL void nng_cv_wake(nng_cv *);

// nng_cv_wake1 wakes only one thread waiting on the condition.  This may
// reduce the thundering herd problem, but care must be taken to ensure
// that no waiter starves forever.
NNG_DECL void nng_cv_wake1(nng_cv *);

// Note that TLS functions may be stubbed out if TLS is not enabled in
// the build.

typedef enum nng_tls_mode {
	NNG_TLS_MODE_CLIENT = 0,
	NNG_TLS_MODE_SERVER = 1,
} nng_tls_mode;

typedef enum nng_tls_auth_mode {
	NNG_TLS_AUTH_MODE_NONE     = 0, // No verification is performed
	NNG_TLS_AUTH_MODE_OPTIONAL = 1, // Verify cert if presented
	NNG_TLS_AUTH_MODE_REQUIRED = 2, // Verify cert, close if invalid
} nng_tls_auth_mode;

// TLS version numbers.  We encode the major number and minor number
// as separate byte fields.  No support for TLS 1.1 or earlier -- older
// versions are known to be insecure and should not be used.
typedef enum nng_tls_version {
	NNG_TLS_1_2 = 0x303,
	NNG_TLS_1_3 = 0x304
} nng_tls_version;

// nng_tls_config_alloc creates a TLS configuration using
// reasonable defaults.  This configuration can be shared
// with multiple pipes or services/servers.
NNG_DECL int nng_tls_config_alloc(nng_tls_config **, nng_tls_mode);

// nng_tls_config_hold increments the reference count on the TLS
// configuration object.  The hold can be dropped by calling
// nng_tls_config_free later.
NNG_DECL void nng_tls_config_hold(nng_tls_config *);

// nng_tls_config_free drops the reference count on the TLS
// configuration object, and if zero, deallocates it.
NNG_DECL void nng_tls_config_free(nng_tls_config *);

// nng_tls_config_server_name sets the server name.  This is
// called by clients to set the name that the server supplied
// certificate should be matched against.  This can also cause
// the SNI to be sent to the server to tell it which cert to
// use if it supports more than one.
NNG_DECL int nng_tls_config_server_name(nng_tls_config *, const char *);

// nng_tls_config_ca_cert configures one or more CAs used for validation
// of peer certificates.  Multiple CAs (and their chains) may be configured
// by either calling this multiple times, or by specifying a list of
// certificates as concatenated data.  The final argument is an optional CRL
// (revocation list) for the CA, also in PEM.  Both PEM strings are ASCIIZ
// format (except that the CRL may be NULL).
NNG_DECL int nng_tls_config_ca_chain(
    nng_tls_config *, const char *, const char *);

// nng_tls_config_own_cert is used to load our own certificate and public
// key.  For servers, this may be called more than once to configure multiple
// different keys, for example with different algorithms depending on what
// the peer supports. On the client, only a single option is available.
// The first two arguments are the cert (or validation chain) and the
// key as PEM format ASCIIZ strings.  The final argument is an optional
// password and may be NULL.
NNG_DECL int nng_tls_config_own_cert(
    nng_tls_config *, const char *, const char *, const char *);

// nng_tls_config_key is used to pass our own private key.
NNG_DECL int nng_tls_config_key(nng_tls_config *, const uint8_t *, size_t);

// nng_tls_config_pass is used to pass a password used to decrypt
// private keys that are encrypted.
NNG_DECL int nng_tls_config_pass(nng_tls_config *, const char *);

// nng_tls_config_auth_mode is used to configure the authentication mode use.
// The default is that servers have this off (i.e. no client authentication)
// and clients have it on (they verify the server), which matches typical
// practice.
NNG_DECL int nng_tls_config_auth_mode(nng_tls_config *, nng_tls_auth_mode);

// nng_tls_config_ca_file is used to pass a CA chain and optional CRL
// via the filesystem.  If CRL data is present, it must be contained
// in the file, along with the CA certificate data.  The format is PEM.
// The path name must be a legal file name.
NNG_DECL int nng_tls_config_ca_file(nng_tls_config *, const char *);

// nng_tls_config_cert_key_file is used to pass our own certificate and
// private key data via the filesystem.  Both the key and certificate
// must be present as PEM blocks in the same file.  A password is used to
// decrypt the private key if it is encrypted and the password supplied is not
// NULL. This may be called multiple times on servers, but only once on a
// client. (Servers can support multiple different certificates and keys for
// different cryptographic algorithms.  Clients only get one.)
NNG_DECL int nng_tls_config_cert_key_file(
    nng_tls_config *, const char *, const char *);

// nng_tls_config_psk_identity is used to pass TLS PSK parameters.  The
// identity, and an associated key.  Clients can only do this once.
// Servers can do it multiple times, potentially, to provide for different
// keys for different client identities.  There is no way to remove these
// from a configuration.
NNG_DECL int nng_tls_config_psk(
    nng_tls_config *, const char *, const uint8_t *, size_t);

// Configure supported TLS version.  By default we usually restrict
// ourselves to TLS 1.2 and newer.  We do not support older versions.
// If the implementation cannot support any version (for example if
// the minimum requested is 1.3 but the TLS implementation lacks support
// for TLS 1.3) then NNG_ENOTSUP will be returned.
NNG_DECL int nng_tls_config_version(
    nng_tls_config *, nng_tls_version, nng_tls_version);

// nng_tls_engine_name returns the "name" of the TLS engine.  If no
// TLS engine support is enabled, then "none" is returned.
NNG_DECL const char *nng_tls_engine_name(void);

// nng_tls_engine_description returns the "description" of the TLS engine.
// If no TLS engine support is enabled, then an empty string is returned.
NNG_DECL const char *nng_tls_engine_description(void);

// nng_tls_engine_fips_mode returns true if the engine is in FIPS 140 mode.
NNG_DECL bool nng_tls_engine_fips_mode(void);

// nng_tls_cert_parse parses PEM content to obtain an object suitable for
// use with TLS APIs.
NNG_DECL nng_err nng_tls_cert_parse_pem(nng_tls_cert **, const char *, size_t);

// nng_tls_cert_parse_der parses a DER (distinguished encoding rules) format
// certificate.
NNG_DECL nng_err nng_tls_cert_parse_der(
    nng_tls_cert **, const uint8_t *, size_t);

// nng_tls_cert_der extracts the certificate as DER content.  This can be
// useful for importing into other APIs such as OpenSSL or mbedTLS directly.
NNG_DECL void nng_tls_cert_der(nng_tls_cert *cert, uint8_t *, size_t *);

// nng_tls_cert_free releases the certificate from memory.
NNG_DECL void nng_tls_cert_free(nng_tls_cert *);

NNG_DECL nng_err nng_tls_cert_subject(nng_tls_cert *, char **);
NNG_DECL nng_err nng_tls_cert_issuer(nng_tls_cert *, char **);
NNG_DECL nng_err nng_tls_cert_serial_number(nng_tls_cert *, char **);
NNG_DECL nng_err nng_tls_cert_subject_cn(nng_tls_cert *, char **);
NNG_DECL nng_err nng_tls_cert_next_alt(nng_tls_cert *, char **);
NNG_DECL nng_err nng_tls_cert_not_before(nng_tls_cert *, struct tm *);
NNG_DECL nng_err nng_tls_cert_not_after(nng_tls_cert *, struct tm *);

// Public ID map support.
typedef struct nng_id_map_s nng_id_map;

#define NNG_MAP_RANDOM 1

NNG_DECL int nng_id_map_alloc(
    nng_id_map **map, uint64_t lo, uint64_t hi, int flags);
NNG_DECL void  nng_id_map_free(nng_id_map *map);
NNG_DECL void *nng_id_get(nng_id_map *, uint64_t);
NNG_DECL int   nng_id_set(nng_id_map *, uint64_t, void *);
NNG_DECL int   nng_id_alloc(nng_id_map *, uint64_t *, void *);
NNG_DECL int   nng_id_remove(nng_id_map *, uint64_t);
NNG_DECL bool  nng_id_visit(nng_id_map *, uint64_t *, void **, uint32_t *);

// Protocol specific values.  These were formerly located in protocol specific
// headers, but we are bringing them here for ease of use.

// BUS0
NNG_DECL int nng_bus0_open(nng_socket *);
NNG_DECL int nng_bus0_open_raw(nng_socket *);

// PAIR0
NNG_DECL int nng_pair0_open(nng_socket *);
NNG_DECL int nng_pair0_open_raw(nng_socket *);

// PAIR1
NNG_DECL int nng_pair1_open(nng_socket *);
NNG_DECL int nng_pair1_open_raw(nng_socket *);
NNG_DECL int nng_pair1_open_poly(nng_socket *);
#define NNG_OPT_PAIR1_POLY "pair1:polyamorous"

// PIPELINE0
NNG_DECL int nng_pull0_open(nng_socket *);
NNG_DECL int nng_pull0_open_raw(nng_socket *);
NNG_DECL int nng_push0_open(nng_socket *);
NNG_DECL int nng_push0_open_raw(nng_socket *);

// PUBSUB0
NNG_DECL int nng_pub0_open(nng_socket *);
NNG_DECL int nng_pub0_open_raw(nng_socket *);
NNG_DECL int nng_sub0_open(nng_socket *);
NNG_DECL int nng_sub0_open_raw(nng_socket *);
NNG_DECL int nng_sub0_socket_subscribe(
    nng_socket id, const void *buf, size_t sz);
NNG_DECL int nng_sub0_socket_unsubscribe(
    nng_socket id, const void *buf, size_t sz);
NNG_DECL int nng_sub0_ctx_subscribe(nng_ctx id, const void *buf, size_t sz);
NNG_DECL int nng_sub0_ctx_unsubscribe(nng_ctx id, const void *buf, size_t sz);
#define NNG_OPT_SUB_PREFNEW "sub:prefnew"

// REQREP0
NNG_DECL int nng_rep0_open(nng_socket *);
NNG_DECL int nng_rep0_open_raw(nng_socket *);
NNG_DECL int nng_req0_open(nng_socket *);
NNG_DECL int nng_req0_open_raw(nng_socket *);
#define NNG_OPT_REQ_RESENDTIME "req:resend-time"
#define NNG_OPT_REQ_RESENDTICK "req:resend-tick"

// SURVEY0
NNG_DECL int nng_respondent0_open(nng_socket *);
NNG_DECL int nng_respondent0_open_raw(nng_socket *);
NNG_DECL int nng_surveyor0_open(nng_socket *);
NNG_DECL int nng_surveyor0_open_raw(nng_socket *);
#define NNG_OPT_SURVEYOR_SURVEYTIME "surveyor:survey-time"

// These transition macros may help with migration from NNG1.
// Applications should try to avoid depending on these any longer than
// necessary, as they may be removed in a future update.  This is far from a
// sufficient set for a transition.
#ifdef NNG1_TRANSITION
#define nng_nop() \
	do {      \
	} while (0)
#define nng_close(s) nng_socket_close(s)
#define nng_send_aio(s, a) nng_socket_send(s, a)
#define nng_recv_aio(s, a) nng_socket_recv(s, a)
#define nng_inproc_register() nng_nop()
#define nng_ipc_register() nng_nop()
#define nng_tls_register() nng_nop()
#define nng_ws_register() nng_nop()
#define nng_wss_register() nng_nop()
#define nng_zt_register() nng_nop()

// protocol "wrappers" -- applications should just be using the version
// specific macros
#define nng_bus_open nng_bus0_open
#define nng_bus_open_raw nng_bus0_open_raw
#define nng_pair_open nng_pair1_open
#define nng_pair_open_raw nng_pair1_open_raw
#define nng_pull_open nng_pull0_open
#define nng_pull_open_raw nng_pull0_open_raw
#define nng_push_open nng_push0_open
#define nng_push_open_raw nng_push0_open_raw
#define nng_pub_open nng_pub0_open
#define nng_pub_open_raw nng_pub0_open_raw
#define nng_sub_open nng_sub0_open
#define nng_sub_open_raw nng_sub0_open_raw
#define nng_rep_open nng_rep0_open
#define nng_rep_open_raw nng_rep0_open_raw
#define nng_req_open nng_req0_open
#define nng_req_open_raw nng_req0_open_raw
#define nng_respondent_open nng_respondent0_open
#define nng_respondent_open_raw nng_respondent0_open_raw
#define nng_surveyor_open nng_surveyor0_open
#define nng_surveyor_open_raw nng_surveyor0_open_raw

#endif // NNG1_TRANSITION

#ifdef __cplusplus
}
#endif

#endif // NNG_NNG_H
