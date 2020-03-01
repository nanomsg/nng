//
// Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
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

// NNG Library & API version.
// We use SemVer, and these versions are about the API, and
// may not necessarily match the ABI versions. Right now at
// version 0, you should not be making any forward compatibility
// assumptions.
#define NNG_MAJOR_VERSION 1
#define NNG_MINOR_VERSION 3
#define NNG_PATCH_VERSION 0
#define NNG_RELEASE_SUFFIX "" // if non-empty, this is a pre-release

// Maximum length of a socket address. This includes the terminating NUL.
// This limit is built into other implementations, so do not change it.
// Note that some transports are quite happy to let you use addresses
// in excess of this, but if you do you may not be able to communicate
// with other implementations.
#define NNG_MAXADDRLEN (128)

// NNG_PROTOCOL_NUMBER is used by protocol headers to calculate their
// protocol number from a major and minor number.  Applications should
// probably not need to use this.
#define NNG_PROTOCOL_NUMBER(maj, min) (((x) *16) + (y))

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

typedef int32_t         nng_duration; // in milliseconds
typedef struct nng_msg  nng_msg;
typedef struct nng_stat nng_stat;
typedef struct nng_aio  nng_aio;

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
typedef struct nng_sockaddr_inproc nng_sockaddr_inproc;

struct nng_sockaddr_path {
	uint16_t sa_family;
	char     sa_path[NNG_MAXADDRLEN];
};
typedef struct nng_sockaddr_path nng_sockaddr_path;
typedef struct nng_sockaddr_path nng_sockaddr_ipc;

struct nng_sockaddr_in6 {
	uint16_t sa_family;
	uint16_t sa_port;
	uint8_t  sa_addr[16];
};
typedef struct nng_sockaddr_in6 nng_sockaddr_in6;
typedef struct nng_sockaddr_in6 nng_sockaddr_udp6;
typedef struct nng_sockaddr_in6 nng_sockaddr_tcp6;

struct nng_sockaddr_in {
	uint16_t sa_family;
	uint16_t sa_port;
	uint32_t sa_addr;
};

struct nng_sockaddr_zt {
	uint16_t sa_family;
	uint64_t sa_nwid;
	uint64_t sa_nodeid;
	uint32_t sa_port;
};

typedef struct nng_sockaddr_in nng_sockaddr_in;
typedef struct nng_sockaddr_in nng_sockaddr_udp;
typedef struct nng_sockaddr_in nng_sockaddr_tcp;
typedef struct nng_sockaddr_zt nng_sockaddr_zt;

typedef union nng_sockaddr {
	uint16_t            s_family;
	nng_sockaddr_ipc    s_ipc;
	nng_sockaddr_inproc s_inproc;
	nng_sockaddr_in6    s_in6;
	nng_sockaddr_in     s_in;
	nng_sockaddr_zt     s_zt;
} nng_sockaddr;

enum nng_sockaddr_family {
	NNG_AF_UNSPEC = 0,
	NNG_AF_INPROC = 1,
	NNG_AF_IPC    = 2,
	NNG_AF_INET   = 3,
	NNG_AF_INET6  = 4,
	NNG_AF_ZT     = 5 // ZeroTier
};

// Scatter/gather I/O.
typedef struct nng_iov {
	void * iov_buf;
	size_t iov_len;
} nng_iov;

// Some definitions for durations used with timeouts.
#define NNG_DURATION_INFINITE (-1)
#define NNG_DURATION_DEFAULT (-2)
#define NNG_DURATION_ZERO (0)

// nng_fini is used to terminate the library, freeing certain global resources.
// This should only be called during atexit() or just before dlclose().
// THIS FUNCTION MUST NOT BE CALLED CONCURRENTLY WITH ANY OTHER FUNCTION
// IN THIS LIBRARY; IT IS NOT REENTRANT OR THREADSAFE.
//
// For most cases, this call is unnecessary, but it is provided to assist
// when debugging with memory checkers (e.g. valgrind).  Calling this
// function prevents global library resources from being reported incorrectly
// as memory leaks.  In those cases, we recommend doing this with atexit().
NNG_DECL void nng_fini(void);

// nng_close closes the socket, terminating all activity and
// closing any underlying connections and releasing any associated
// resources.
NNG_DECL int nng_close(nng_socket);

// nng_socket_id returns the positive socket id for the socket, or -1
// if the socket is not valid.
NNG_DECL int nng_socket_id(nng_socket);

// nng_closeall closes all open sockets. Do not call this from
// a library; it will affect all sockets.
NNG_DECL void nng_closeall(void);

// nng_setopt sets an option for a specific socket.
NNG_DECL int nng_setopt(nng_socket, const char *, const void *, size_t);
NNG_DECL int nng_setopt_bool(nng_socket, const char *, bool);
NNG_DECL int nng_setopt_int(nng_socket, const char *, int);
NNG_DECL int nng_setopt_ms(nng_socket, const char *, nng_duration);
NNG_DECL int nng_setopt_size(nng_socket, const char *, size_t);
NNG_DECL int nng_setopt_uint64(nng_socket, const char *, uint64_t);
NNG_DECL int nng_setopt_string(nng_socket, const char *, const char *);
NNG_DECL int nng_setopt_ptr(nng_socket, const char *, void *);

// nng_socket_getopt obtains the option for a socket.
NNG_DECL int nng_getopt(nng_socket, const char *, void *, size_t *);
NNG_DECL int nng_getopt_bool(nng_socket, const char *, bool *);
NNG_DECL int nng_getopt_int(nng_socket, const char *, int *);
NNG_DECL int nng_getopt_ms(nng_socket, const char *, nng_duration *);
NNG_DECL int nng_getopt_size(nng_socket, const char *, size_t *);
NNG_DECL int nng_getopt_uint64(nng_socket, const char *, uint64_t *);
NNG_DECL int nng_getopt_ptr(nng_socket, const char *, void **);

// nng_getopt_string is special -- it allocates a string to hold the
// resulting string, which should be freed with nng_strfree when it is
// no logner needed.
NNG_DECL int nng_getopt_string(nng_socket, const char *, char **);

NNG_DECL int nng_socket_set(nng_socket, const char *, const void *, size_t);
NNG_DECL int nng_socket_set_bool(nng_socket, const char *, bool);
NNG_DECL int nng_socket_set_int(nng_socket, const char *, int);
NNG_DECL int nng_socket_set_size(nng_socket, const char *, size_t);
NNG_DECL int nng_socket_set_uint64(nng_socket, const char *, uint64_t);
NNG_DECL int nng_socket_set_string(nng_socket, const char *, const char *);
NNG_DECL int nng_socket_set_ptr(nng_socket, const char *, void *);
NNG_DECL int nng_socket_set_ms(nng_socket, const char *, nng_duration);
NNG_DECL int nng_socket_set_addr(
    nng_socket, const char *, const nng_sockaddr *);

NNG_DECL int nng_socket_get(nng_socket, const char *, void *, size_t *);
NNG_DECL int nng_socket_get_bool(nng_socket, const char *, bool *);
NNG_DECL int nng_socket_get_int(nng_socket, const char *, int *);
NNG_DECL int nng_socket_get_size(nng_socket, const char *, size_t *);
NNG_DECL int nng_socket_get_uint64(nng_socket, const char *, uint64_t *);
NNG_DECL int nng_socket_get_string(nng_socket, const char *, char **);
NNG_DECL int nng_socket_get_ptr(nng_socket, const char *, void **);
NNG_DECL int nng_socket_get_ms(nng_socket, const char *, nng_duration *);
NNG_DECL int nng_socket_get_addr(nng_socket, const char *, nng_sockaddr *);

// Arguably the pipe callback functions could be handled as an option,
// but with the need to specify an argument, we find it best to unify
// this as a separate function to pass in the argument and the callback.
// Only one callback can be set on a given socket, and there is no way
// to retrieve the old value.
typedef enum {
	NNG_PIPE_EV_ADD_PRE,  // Called just before pipe added to socket
	NNG_PIPE_EV_ADD_POST, // Called just after pipe added to socket
	NNG_PIPE_EV_REM_POST, // Called just after pipe removed from socket
	NNG_PIPE_EV_NUM,      // Used internally, must be last.
} nng_pipe_ev;

typedef void (*nng_pipe_cb)(nng_pipe, nng_pipe_ev, void *);

// nng_pipe_notify registers a callback to be executed when the
// given event is triggered.  To watch for different events, register
// multiple times.  Each event can have at most one callback registered.
NNG_DECL int nng_pipe_notify(nng_socket, nng_pipe_ev, nng_pipe_cb, void *);

// nng_listen creates a listening endpoint with no special options,
// and starts it listening.  It is functionally equivalent to the legacy
// nn_bind(). The underlying endpoint is returned back to the caller in the
// endpoint pointer, if it is not NULL.  The flags are ignored at present.
NNG_DECL int nng_listen(nng_socket, const char *, nng_listener *, int);

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

// nng_dialer_create creates a new dialer, that is not yet started.
NNG_DECL int nng_dialer_create(nng_dialer *, nng_socket, const char *);

// nng_listener_create creates a new listener, that is not yet started.
NNG_DECL int nng_listener_create(nng_listener *, nng_socket, const char *);

// nng_dialer_start starts the endpoint dialing.  This is only possible if
// the dialer is not already dialing.
NNG_DECL int nng_dialer_start(nng_dialer, int);

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

// nng_dialer_setopt sets an option for a specific dialer.  Note
// dialer options may not be altered on a running dialer.
NNG_DECL int nng_dialer_setopt(nng_dialer, const char *, const void *, size_t);
NNG_DECL int nng_dialer_setopt_bool(nng_dialer, const char *, bool);
NNG_DECL int nng_dialer_setopt_int(nng_dialer, const char *, int);
NNG_DECL int nng_dialer_setopt_ms(nng_dialer, const char *, nng_duration);
NNG_DECL int nng_dialer_setopt_size(nng_dialer, const char *, size_t);
NNG_DECL int nng_dialer_setopt_uint64(nng_dialer, const char *, uint64_t);
NNG_DECL int nng_dialer_setopt_ptr(nng_dialer, const char *, void *);
NNG_DECL int nng_dialer_setopt_string(nng_dialer, const char *, const char *);

// nng_dialer_getopt obtains the option for a dialer. This will
// fail for options that a particular dialer is not interested in,
// even if they were set on the socket.
NNG_DECL int nng_dialer_getopt(nng_dialer, const char *, void *, size_t *);
NNG_DECL int nng_dialer_getopt_bool(nng_dialer, const char *, bool *);
NNG_DECL int nng_dialer_getopt_int(nng_dialer, const char *, int *);
NNG_DECL int nng_dialer_getopt_ms(nng_dialer, const char *, nng_duration *);
NNG_DECL int nng_dialer_getopt_size(nng_dialer, const char *, size_t *);
NNG_DECL int nng_dialer_getopt_sockaddr(
    nng_dialer, const char *, nng_sockaddr *);
NNG_DECL int nng_dialer_getopt_uint64(nng_dialer, const char *, uint64_t *);
NNG_DECL int nng_dialer_getopt_ptr(nng_dialer, const char *, void **);

// nng_dialer_getopt_string is special -- it allocates a string to hold the
// resulting string, which should be freed with nng_strfree when it is
// no logner needed.
NNG_DECL int nng_dialer_getopt_string(nng_dialer, const char *, char **);

NNG_DECL int nng_dialer_set(nng_dialer, const char *, const void *, size_t);
NNG_DECL int nng_dialer_set_bool(nng_dialer, const char *, bool);
NNG_DECL int nng_dialer_set_int(nng_dialer, const char *, int);
NNG_DECL int nng_dialer_set_size(nng_dialer, const char *, size_t);
NNG_DECL int nng_dialer_set_uint64(nng_dialer, const char *, uint64_t);
NNG_DECL int nng_dialer_set_string(nng_dialer, const char *, const char *);
NNG_DECL int nng_dialer_set_ptr(nng_dialer, const char *, void *);
NNG_DECL int nng_dialer_set_ms(nng_dialer, const char *, nng_duration);
NNG_DECL int nng_dialer_set_addr(
    nng_dialer, const char *, const nng_sockaddr *);

NNG_DECL int nng_dialer_get(nng_dialer, const char *, void *, size_t *);
NNG_DECL int nng_dialer_get_bool(nng_dialer, const char *, bool *);
NNG_DECL int nng_dialer_get_int(nng_dialer, const char *, int *);
NNG_DECL int nng_dialer_get_size(nng_dialer, const char *, size_t *);
NNG_DECL int nng_dialer_get_uint64(nng_dialer, const char *, uint64_t *);
NNG_DECL int nng_dialer_get_string(nng_dialer, const char *, char **);
NNG_DECL int nng_dialer_get_ptr(nng_dialer, const char *, void **);
NNG_DECL int nng_dialer_get_ms(nng_dialer, const char *, nng_duration *);
NNG_DECL int nng_dialer_get_addr(nng_dialer, const char *, nng_sockaddr *);

// nng_listener_setopt sets an option for a dialer.  This value is
// not stored in the socket.  Subsequent setopts on the socket may
// override these value however.  Note listener options may not be altered
// on a running listener.
NNG_DECL int nng_listener_setopt(
    nng_listener, const char *, const void *, size_t);
NNG_DECL int nng_listener_setopt_bool(nng_listener, const char *, bool);
NNG_DECL int nng_listener_setopt_int(nng_listener, const char *, int);
NNG_DECL int nng_listener_setopt_ms(nng_listener, const char *, nng_duration);
NNG_DECL int nng_listener_setopt_size(nng_listener, const char *, size_t);
NNG_DECL int nng_listener_setopt_uint64(nng_listener, const char *, uint64_t);
NNG_DECL int nng_listener_setopt_ptr(nng_listener, const char *, void *);
NNG_DECL int nng_listener_setopt_string(
    nng_listener, const char *, const char *);

// nng_listener_getopt obtains the option for a listener.  This will
// fail for options that a particular listener is not interested in,
// even if they were set on the socket.
NNG_DECL int nng_listener_getopt(nng_listener, const char *, void *, size_t *);
NNG_DECL int nng_listener_getopt_bool(nng_listener, const char *, bool *);
NNG_DECL int nng_listener_getopt_int(nng_listener, const char *, int *);
NNG_DECL int nng_listener_getopt_ms(
    nng_listener, const char *, nng_duration *);
NNG_DECL int nng_listener_getopt_size(nng_listener, const char *, size_t *);
NNG_DECL int nng_listener_getopt_sockaddr(
    nng_listener, const char *, nng_sockaddr *);
NNG_DECL int nng_listener_getopt_uint64(
    nng_listener, const char *, uint64_t *);
NNG_DECL int nng_listener_getopt_ptr(nng_listener, const char *, void **);

// nng_listener_getopt_string is special -- it allocates a string to hold the
// resulting string, which should be freed with nng_strfree when it is
// no logner needed.
NNG_DECL int nng_listener_getopt_string(nng_listener, const char *, char **);

NNG_DECL int nng_listener_set(
    nng_listener, const char *, const void *, size_t);
NNG_DECL int nng_listener_set_bool(nng_listener, const char *, bool);
NNG_DECL int nng_listener_set_int(nng_listener, const char *, int);
NNG_DECL int nng_listener_set_size(nng_listener, const char *, size_t);
NNG_DECL int nng_listener_set_uint64(nng_listener, const char *, uint64_t);
NNG_DECL int nng_listener_set_string(nng_listener, const char *, const char *);
NNG_DECL int nng_listener_set_ptr(nng_listener, const char *, void *);
NNG_DECL int nng_listener_set_ms(nng_listener, const char *, nng_duration);
NNG_DECL int nng_listener_set_addr(
    nng_listener, const char *, const nng_sockaddr *);

NNG_DECL int nng_listener_get(nng_listener, const char *, void *, size_t *);
NNG_DECL int nng_listener_get_bool(nng_listener, const char *, bool *);
NNG_DECL int nng_listener_get_int(nng_listener, const char *, int *);
NNG_DECL int nng_listener_get_size(nng_listener, const char *, size_t *);
NNG_DECL int nng_listener_get_uint64(nng_listener, const char *, uint64_t *);
NNG_DECL int nng_listener_get_string(nng_listener, const char *, char **);
NNG_DECL int nng_listener_get_ptr(nng_listener, const char *, void **);
NNG_DECL int nng_listener_get_ms(nng_listener, const char *, nng_duration *);
NNG_DECL int nng_listener_get_addr(nng_listener, const char *, nng_sockaddr *);

// nng_strerror returns a human readable string associated with the error
// code supplied.
NNG_DECL const char *nng_strerror(int);

// nng_send sends (or arranges to send) the data on the socket.  Note that
// this function may (will!) return before any receiver has actually
// received the data.  The return value will be zero to indicate that the
// socket has accepted the entire data for send, or an errno to indicate
// failure.  The flags may include NNG_FLAG_NONBLOCK or NNG_FLAG_ALLOC.
// If the flag includes NNG_FLAG_ALLOC, then the function will call
// nng_free() on the supplied pointer & size on success. (If the call
// fails then the memory is not freed.)
NNG_DECL int nng_send(nng_socket, void *, size_t, int);

// nng_recv receives message data into the socket, up to the supplied size.
// The actual size of the message data will be written to the value pointed
// to by size.  The flags may include NNG_FLAG_NONBLOCK and NNG_FLAG_ALLOC.
// If NNG_FLAG_ALLOC is supplied then the library will allocate memory for
// the caller.  In that case the pointer to the allocated will be stored
// instead of the data itself.  The caller is responsible for freeing the
// associated memory with nng_free().
NNG_DECL int nng_recv(nng_socket, void *, size_t *, int);

// nng_sendmsg is like nng_send, but offers up a message structure, which
// gives the ability to provide more control over the message, including
// providing backtrace information.  It also can take a message that was
// obtain via nn_recvmsg, allowing for zero copy forwarding.
NNG_DECL int nng_sendmsg(nng_socket, nng_msg *, int);

// nng_recvmsg is like nng_recv, but is used to obtain a message structure
// as well as the data buffer.  This can be used to obtain more information
// about where the message came from, access raw headers, etc.  It also
// can be passed off directly to nng_sendmsg.
NNG_DECL int nng_recvmsg(nng_socket, nng_msg **, int);

// nng_send_aio sends data on the socket asynchronously.  As with nng_send,
// the completion may be executed before the data has actually been delivered,
// but only when it is accepted for delivery.  The supplied AIO must have
// been initialized, and have an associated message.  The message will be
// "owned" by the socket if the operation completes successfully.  Otherwise
// the caller is responsible for freeing it.
NNG_DECL void nng_send_aio(nng_socket, nng_aio *);

// nng_recv_aio receives data on the socket asynchronously.  On a successful
// result, the AIO will have an associated message, that can be obtained
// with nng_aio_get_msg().  The caller takes ownership of the message at
// this point.
NNG_DECL void nng_recv_aio(nng_socket, nng_aio *);

// Context support.  User contexts are not supported by all protocols,
// but for those that do, they give a way to create multiple contexts
// on a single socket, each of which runs the protocol's state machinery
// independently, offering a way to achieve concurrent protocol support
// without resorting to raw mode sockets.  See the protocol specific
// documentation for further details.  (Note that at this time, only
// asynchronous send/recv are supported for contexts, but its easy enough
// to make synchronous versions with nng_aio_wait().)  Note that nng_close
// of the parent socket will *block* as long as any contexts are open.

// nng_ctx_open creates a context.  This returns NNG_ENOTSUP if the
// protocol implementation does not support separate contexts.
NNG_DECL int nng_ctx_open(nng_ctx *, nng_socket);

// nng_ctx_close closes the context.
NNG_DECL int nng_ctx_close(nng_ctx);

// nng_ctx_id returns the numeric id for the context; this will be
// a positive value for a valid context, or < 0 for an invalid context.
// A valid context is not necessarily an *open* context.
NNG_DECL int nng_ctx_id(nng_ctx);

// nng_ctx_recv receives asynchronously.  It works like nng_recv_aio, but
// uses a local context instead of the socket global context.
NNG_DECL void nng_ctx_recv(nng_ctx, nng_aio *);

// nng_ctx_send sends asynchronously. It works like nng_send_aio, but
// uses a local context instead of the socket global context.
NNG_DECL void nng_ctx_send(nng_ctx, nng_aio *);

// nng_ctx_getopt is used to retrieve a context-specific option.  This
// can only be used for those options that relate to specific context
// tunables (which does include NNG_OPT_SENDTIMEO and NNG_OPT_RECVTIMEO);
// see the protocol documentation for more details.
NNG_DECL int nng_ctx_getopt(nng_ctx, const char *, void *, size_t *);
NNG_DECL int nng_ctx_getopt_bool(nng_ctx, const char *, bool *);
NNG_DECL int nng_ctx_getopt_int(nng_ctx, const char *, int *);
NNG_DECL int nng_ctx_getopt_ms(nng_ctx, const char *, nng_duration *);
NNG_DECL int nng_ctx_getopt_size(nng_ctx, const char *, size_t *);

// nng_ctx_setopt is used to set a context-specific option.  This
// can only be used for those options that relate to specific context
// tunables (which does include NNG_OPT_SENDTIMEO and NNG_OPT_RECVTIMEO);
// see the protocol documentation for more details.
NNG_DECL int nng_ctx_setopt(nng_ctx, const char *, const void *, size_t);
NNG_DECL int nng_ctx_setopt_bool(nng_ctx, const char *, bool);
NNG_DECL int nng_ctx_setopt_int(nng_ctx, const char *, int);
NNG_DECL int nng_ctx_setopt_ms(nng_ctx, const char *, nng_duration);
NNG_DECL int nng_ctx_setopt_size(nng_ctx, const char *, size_t);

NNG_DECL int nng_ctx_get(nng_ctx, const char *, void *, size_t *);
NNG_DECL int nng_ctx_get_bool(nng_ctx, const char *, bool *);
NNG_DECL int nng_ctx_get_int(nng_ctx, const char *, int *);
NNG_DECL int nng_ctx_get_size(nng_ctx, const char *, size_t *);
NNG_DECL int nng_ctx_get_uint64(nng_ctx, const char *, uint64_t *);
NNG_DECL int nng_ctx_get_string(nng_ctx, const char *, char **);
NNG_DECL int nng_ctx_get_ptr(nng_ctx, const char *, void **);
NNG_DECL int nng_ctx_get_ms(nng_ctx, const char *, nng_duration *);
NNG_DECL int nng_ctx_get_addr(nng_ctx, const char *, nng_sockaddr *);

NNG_DECL int nng_ctx_set(nng_ctx, const char *, const void *, size_t);
NNG_DECL int nng_ctx_set_bool(nng_ctx, const char *, bool);
NNG_DECL int nng_ctx_set_int(nng_ctx, const char *, int);
NNG_DECL int nng_ctx_set_size(nng_ctx, const char *, size_t);
NNG_DECL int nng_ctx_set_uint64(nng_ctx, const char *, uint64_t);
NNG_DECL int nng_ctx_set_string(nng_ctx, const char *, const char *);
NNG_DECL int nng_ctx_set_ptr(nng_ctx, const char *, void *);
NNG_DECL int nng_ctx_set_ms(nng_ctx, const char *, nng_duration);
NNG_DECL int nng_ctx_set_addr(nng_ctx, const char *, const nng_sockaddr *);

// nng_alloc is used to allocate memory.  It's intended purpose is for
// allocating memory suitable for message buffers with nng_send().
// Applications that need memory for other purposes should use their platform
// specific API.
NNG_DECL void *nng_alloc(size_t);

// nng_free is used to free memory allocated with nng_alloc, which includes
// memory allocated by nng_recv() when the NNG_FLAG_ALLOC message is supplied.
// As the application is required to keep track of the size of memory, this
// is probably less convenient for general uses than the C library malloc and
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
NNG_DECL int nng_aio_alloc(nng_aio **, void (*)(void *), void *);

// nng_aio_free frees the AIO and any associated resources.
// It *must not* be in use at the time it is freed.
NNG_DECL void nng_aio_free(nng_aio *);

// nng_aio_stop stops any outstanding operation, and waits for the
// AIO to be free, including for the callback to have completed
// execution.  Therefore the caller must NOT hold any locks that
// are acquired in the callback, or deadlock will occur.
NNG_DECL void nng_aio_stop(nng_aio *);

// nng_aio_result returns the status/result of the operation. This
// will be zero on successful completion, or an nng error code on
// failure.
NNG_DECL int nng_aio_result(nng_aio *);

// nng_aio_count returns the number of bytes transferred for certain
// I/O operations.  This is meaningless for other operations (e.g.
// DNS lookups or TCP connection setup).
NNG_DECL size_t nng_aio_count(nng_aio *);

// nng_aio_cancel attempts to cancel any in-progress I/O operation.
// The AIO callback will still be executed, but if the cancellation is
// successful then the status will be NNG_ECANCELED.
NNG_DECL void nng_aio_cancel(nng_aio *);

// nng_aio_abort is like nng_aio_cancel, but allows for a different
// error result to be returned.
NNG_DECL void nng_aio_abort(nng_aio *, int);

// nng_aio_wait waits synchronously for any pending operation to complete.
// It also waits for the callback to have completed execution.  Therefore,
// the caller of this function must not hold any locks acquired by the
// callback or deadlock may occur.
NNG_DECL void nng_aio_wait(nng_aio *);

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

// nng_aio_set_iov sets a scatter/gather vector on the aio.  The iov array
// itself is copied. Data members (the memory regions referenced) *may* be
// copied as well, depending on the operation.  This operation is guaranteed
// to succeed if n <= 4, otherwise it may fail due to NNG_ENOMEM.
NNG_DECL int nng_aio_set_iov(nng_aio *, unsigned, const nng_iov *);

// nng_aio_begin is called by the provider to mark the operation as
// beginning.  If it returns false, then the provider must take no
// further action on the aio.
NNG_DECL bool nng_aio_begin(nng_aio *);

// nng_aio_finish is used to "finish" an asynchronous operation.
// It should only be called by "providers" (such as HTTP server API users).
// The argument is the value that nng_aio_result() should return.
// IMPORTANT: Callers must ensure that this is called EXACTLY ONCE on any
// given aio.
NNG_DECL void nng_aio_finish(nng_aio *, int);

// nng_aio_defer is used to register a cancellation routine, and indicate
// that the operation will be completed asynchronously.  It must only be
// called once per operation on an aio, and must only be called by providers.
// If the operation is canceled by the consumer, the cancellation callback
// will be called.  The provider *must* still ensure that the nng_aio_finish()
// function is called EXACTLY ONCE.  If the operation cannot be canceled
// for any reason, the cancellation callback should do nothing.  The
// final argument is passed to the cancelfn.  The final argument of the
// cancellation function is the error number (will not be zero) corresponding
// to the reason for cancellation, e.g. NNG_ETIMEDOUT or NNG_ECANCELED.
typedef void (*nng_aio_cancelfn)(nng_aio *, void *, int);
NNG_DECL void nng_aio_defer(nng_aio *, nng_aio_cancelfn, void *);

// nng_aio_sleep does a "sleeping" operation, basically does nothing
// but wait for the specified number of milliseconds to expire, then
// calls the callback.  This returns 0, rather than NNG_ETIMEDOUT.
NNG_DECL void nng_sleep_aio(nng_duration, nng_aio *);

// Message API.
NNG_DECL int      nng_msg_alloc(nng_msg **, size_t);
NNG_DECL void     nng_msg_free(nng_msg *);
NNG_DECL int      nng_msg_realloc(nng_msg *, size_t);
NNG_DECL void *   nng_msg_header(nng_msg *);
NNG_DECL size_t   nng_msg_header_len(const nng_msg *);
NNG_DECL void *   nng_msg_body(nng_msg *);
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

// nng_msg_getopt is defunct, and should not be used by programs. It
// always returns NNG_ENOTSUP.
NNG_DECL int nng_msg_getopt(nng_msg *, int, void *, size_t *);

// Pipe API. Generally pipes are only "observable" to applications, but
// we do permit an application to close a pipe. This can be useful, for
// example during a connection notification, to disconnect a pipe that
// is associated with an invalid or untrusted remote peer.
NNG_DECL int nng_pipe_getopt(nng_pipe, const char *, void *, size_t *);
NNG_DECL int nng_pipe_getopt_bool(nng_pipe, const char *, bool *);
NNG_DECL int nng_pipe_getopt_int(nng_pipe, const char *, int *);
NNG_DECL int nng_pipe_getopt_ms(nng_pipe, const char *, nng_duration *);
NNG_DECL int nng_pipe_getopt_size(nng_pipe, const char *, size_t *);
NNG_DECL int nng_pipe_getopt_sockaddr(nng_pipe, const char *, nng_sockaddr *);
NNG_DECL int nng_pipe_getopt_uint64(nng_pipe, const char *, uint64_t *);
NNG_DECL int nng_pipe_getopt_ptr(nng_pipe, const char *, void **);
NNG_DECL int nng_pipe_getopt_string(nng_pipe, const char *, char **);

NNG_DECL int nng_pipe_get(nng_pipe, const char *, void *, size_t *);
NNG_DECL int nng_pipe_get_bool(nng_pipe, const char *, bool *);
NNG_DECL int nng_pipe_get_int(nng_pipe, const char *, int *);
NNG_DECL int nng_pipe_get_ms(nng_pipe, const char *, nng_duration *);
NNG_DECL int nng_pipe_get_size(nng_pipe, const char *, size_t *);
NNG_DECL int nng_pipe_get_uint64(nng_pipe, const char *, uint64_t *);
NNG_DECL int nng_pipe_get_string(nng_pipe, const char *, char **);
NNG_DECL int nng_pipe_get_ptr(nng_pipe, const char *, void **);
NNG_DECL int nng_pipe_get_addr(nng_pipe, const char *, nng_sockaddr *);

NNG_DECL int          nng_pipe_close(nng_pipe);
NNG_DECL int          nng_pipe_id(nng_pipe);
NNG_DECL nng_socket   nng_pipe_socket(nng_pipe);
NNG_DECL nng_dialer   nng_pipe_dialer(nng_pipe);
NNG_DECL nng_listener nng_pipe_listener(nng_pipe);

// Flags.
enum nng_flag_enum {
	NNG_FLAG_ALLOC    = 1, // Recv to allocate receive buffer.
	NNG_FLAG_NONBLOCK = 2  // Non-blocking operations.
};

// Options.
#define NNG_OPT_SOCKNAME "socket-name"
#define NNG_OPT_RAW "raw"
#define NNG_OPT_PROTO "protocol"
#define NNG_OPT_PROTONAME "protocol-name"
#define NNG_OPT_PEER "peer"
#define NNG_OPT_PEERNAME "peer-name"
#define NNG_OPT_RECVBUF "recv-buffer"
#define NNG_OPT_SENDBUF "send-buffer"
#define NNG_OPT_RECVFD "recv-fd"
#define NNG_OPT_SENDFD "send-fd"
#define NNG_OPT_RECVTIMEO "recv-timeout"
#define NNG_OPT_SENDTIMEO "send-timeout"
#define NNG_OPT_LOCADDR "local-address"
#define NNG_OPT_REMADDR "remote-address"
#define NNG_OPT_URL "url"
#define NNG_OPT_MAXTTL "ttl-max"
#define NNG_OPT_RECVMAXSZ "recv-size-max"
#define NNG_OPT_RECONNMINT "reconnect-time-min"
#define NNG_OPT_RECONNMAXT "reconnect-time-max"

// TLS options are only used when the underlying transport supports TLS.

// NNG_OPT_TLS_CONFIG is a pointer to an nng_tls_config object.  Generally
// this can used with endpoints, although once an endpoint is started, or
// once a configuration is used, the value becomes read-only. Note that
// when configuring the object, a hold is placed on the TLS configuration,
// using a reference count.  When retrieving the object, no such hold is
// placed, and so the caller must take care not to use the associated object
// after the endpoint it is associated with is closed.
#define NNG_OPT_TLS_CONFIG "tls-config"

// NNG_OPT_TLS_AUTH_MODE is a write-only integer (int) option that specifies
// whether peer authentication is needed.  The option can take one of the
// values of NNG_TLS_AUTH_MODE_NONE, NNG_TLS_AUTH_MODE_OPTIONAL, or
// NNG_TLS_AUTH_MODE_REQUIRED.  The default is typically NNG_TLS_AUTH_MODE_NONE
// for listeners, and NNG_TLS_AUTH_MODE_REQUIRED for dialers. If set to
// REQUIRED, then connections will be rejected if the peer cannot be verified.
// If set to OPTIONAL, then a verification step takes place, but the connection
// is still permitted.  (The result can be checked with NNG_OPT_TLS_VERIFIED).
#define NNG_OPT_TLS_AUTH_MODE "tls-authmode"

// NNG_OPT_TLS_CERT_KEY_FILE names a single file that contains a certificate
// and key identifying the endpoint.  This is a write-only value.  This can be
// set multiple times for times for different keys/certs corresponding to
// different algorithms on listeners, whereas dialers only support one.  The
// file must contain both cert and key as PEM blocks, and the key must
// not be encrypted.  (If more flexibility is needed, use the TLS configuration
// directly, via NNG_OPT_TLS_CONFIG.)
#define NNG_OPT_TLS_CERT_KEY_FILE "tls-cert-key-file"

// NNG_OPT_TLS_CA_FILE names a single file that contains certificate(s) for a
// CA, and optionally CRLs, which are used to validate the peer's certificate.
// This is a write-only value, but multiple CAs can be loaded by setting this
// multiple times.
#define NNG_OPT_TLS_CA_FILE "tls-ca-file"

// NNG_OPT_TLS_SERVER_NAME is a write-only string that can typically be
// set on dialers to check the CN of the server for a match.  This
// can also affect SNI (server name indication).  It usually has no effect
// on listeners.
#define NNG_OPT_TLS_SERVER_NAME "tls-server-name"

// NNG_OPT_TLS_VERIFIED returns a boolean indicating whether the peer has
// been verified (true) or not (false). Typically this is read-only, and
// only available for pipes. This option may return incorrect results if
// peer authentication is disabled with `NNG_TLS_AUTH_MODE_NONE`.
#define NNG_OPT_TLS_VERIFIED "tls-verified"

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

// Local TCP port number.  This is used on a listener, and is intended
// to be used after starting the listener in combination with a wildcard
// (0) local port.  This determines the actual ephemeral port that was
// selected and bound.  The value is provided as an int, but only the
// low order 16 bits will be set.  This is provided in native byte order,
// which makes it more convenient than using the NNG_OPT_LOCADDR option.
#define NNG_OPT_TCP_BOUND_PORT "tcp-bound-port"

// IPC options.  These will largely vary depending on the platform,
// as POSIX systems have very different options than Windows.

// Security Descriptor.  This option may only be set on listeners
// on the Windows platform, where the object is a pointer to a
// a Windows SECURITY_DESCRIPTOR.
#define NNG_OPT_IPC_SECURITY_DESCRIPTOR "ipc:security-descriptor"

// Permissions bits.  This option is only valid for listeners on
// POSIX platforms and others that honor UNIX style permission bits.
// Note that some platforms may not honor the permissions here, although
// at least Linux and macOS seem to do so.  Check before you rely on
// this for security.
#define NNG_OPT_IPC_PERMISSIONS "ipc:permissions"

// Peer UID.  This is only available on POSIX style systems.
#define NNG_OPT_IPC_PEER_UID "ipc:peer-uid"

// Peer GID (primary group).  This is only available on POSIX style systems.
#define NNG_OPT_IPC_PEER_GID "ipc:peer-gid"

// Peer process ID.  Available on Windows, Linux, and SunOS.
// In theory we could obtain this with the first message sent,
// but we have elected not to do this for now. (Nice RFE for a FreeBSD
// guru though.)
#define NNG_OPT_IPC_PEER_PID "ipc:peer-pid"

// Peer Zone ID.  Only on SunOS systems.  (Linux containers have no
// definable kernel identity; they are a user-land fabrication made up
// from various pieces of different namespaces. FreeBSD does have
// something called JailIDs, but it isn't obvious how to determine this,
// or even if processes can use IPC across jail boundaries.)
#define NNG_OPT_IPC_PEER_ZONEID "ipc:peer-zoneid"

// WebSocket Options.

// NNG_OPT_WS_REQUEST_HEADERS is a string containing the
// request headers, formatted as CRLF terminated lines.
#define NNG_OPT_WS_REQUEST_HEADERS "ws:request-headers"

// NNG_OPT_WS_RESPONSE_HEADERS is a string containing the
// response headers, formatted as CRLF terminated lines.
#define NNG_OPT_WS_RESPONSE_HEADERS "ws:response-headers"

// NNG_OPT_WS_REQUEST_HEADER is a prefix, for a dynamic
// property name.  This allows direct access to any named header.
// Concatenate this with the name of the property (case is not sensitive).
// Only the first such header is returned.
#define NNG_OPT_WS_RESPONSE_HEADER "ws:response-header:"

// NNG_OPT_WS_RESPONSE_HEADER is like NNG_OPT_REQUEST_HEADER, but used for
// accessing the request headers.
#define NNG_OPT_WS_REQUEST_HEADER "ws:request-header:"

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

// NNG_OPT_WS_PROTOCOL is the "websocket subprotocol" -- it's a string.
// This is also known as the Sec-WebSocket-Protocol header. It is treated
// specially.  This is part of the websocket handshake.
#define NNG_OPT_WS_PROTOCOL "ws:protocol"

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
NNG_DECL void nng_stats_dump(nng_stat *);

// nng_stat_next finds the next sibling for the current stat.  If there
// are no more siblings, it returns NULL.
NNG_DECL nng_stat *nng_stat_next(nng_stat *);

// nng_stat_child finds the first child of the current stat.  If no children
// exist, then NULL is returned.
NNG_DECL nng_stat *nng_stat_child(nng_stat *);

// nng_stat_name is used to determine the name of the statistic.
// This is a human readable name.  Statistic names, as well as the presence
// or absence or semantic of any particular statistic are not part of any
// stable API, and may be changed without notice in future updates.
NNG_DECL const char *nng_stat_name(nng_stat *);

// nng_stat_type is used to determine the type of the statistic.
// Counters generally increment, and therefore changes in the value over
// time are likely more interesting than the actual level.  Level
// values reflect some absolute state however, and should be presented to the
// user as is.
NNG_DECL int nng_stat_type(nng_stat *);

// nng_stat_find is used to find a specific named statistic within
// a statistic tree.  NULL is returned if no such statistic exists.
NNG_DECL nng_stat *nng_stat_find(nng_stat *, const char *);

// nng_stat_find_socket is used to find the stats for the given socket.
NNG_DECL nng_stat *nng_stat_find_socket(nng_stat *, nng_socket);

// nng_stat_find_dialer is used to find the stats for the given dialer.
NNG_DECL nng_stat *nng_stat_find_dialer(nng_stat *, nng_dialer);

// nng_stat_find_listener is used to find the stats for the given listener.
NNG_DECL nng_stat *nng_stat_find_listener(nng_stat *, nng_listener);

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
NNG_DECL int nng_stat_unit(nng_stat *);

enum nng_unit_enum {
	NNG_UNIT_NONE     = 0, // No special units
	NNG_UNIT_BYTES    = 1, // Bytes, e.g. bytes sent, etc.
	NNG_UNIT_MESSAGES = 2, // Messages, one per message
	NNG_UNIT_MILLIS   = 3, // Milliseconds
	NNG_UNIT_EVENTS   = 4  // Some other type of event
};

// nng_stat_value returns returns the actual value of the statistic.
// Statistic values reflect their value at the time that the corresponding
// snapshot was updated, and are undefined until an update is performed.
NNG_DECL uint64_t nng_stat_value(nng_stat *);

// nng_stat_string returns the string associated with a string statistic,
// or NULL if the statistic is not part of the string.  The value returned
// is valid until the associated statistic is freed.
NNG_DECL const char *nng_stat_string(nng_stat *);

// nng_stat_desc returns a human readable description of the statistic.
// This may be useful for display in diagnostic interfaces, etc.
NNG_DECL const char *nng_stat_desc(nng_stat *);

// nng_stat_timestamp returns a timestamp (milliseconds) when the statistic
// was captured.  The base offset is the same as used by nng_clock().
// We don't use nng_time though, because that's in the supplemental header.
NNG_DECL uint64_t nng_stat_timestamp(nng_stat *);

// Device functionality.  This connects two sockets together in a device,
// which means that messages from one side are forwarded to the other.
NNG_DECL int nng_device(nng_socket, nng_socket);

// Symbol name and visibility.  TBD.  The only symbols that really should
// be directly exported to runtimes IMO are the option symbols.  And frankly
// they have enough special logic around them that it might be best not to
// automate the promotion of them to other APIs.  This is an area open
// for discussion.

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

enum nng_errno_enum {
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
	NNG_ENOARG       = 28,
	NNG_EAMBIGUOUS   = 29,
	NNG_EBADTYPE     = 30,
	NNG_ECONNSHUT    = 31,
	NNG_EINTERNAL    = 1000,
	NNG_ESYSERR      = 0x10000000,
	NNG_ETRANERR     = 0x20000000
};

// URL support.  We frequently want to process a URL, and these methods
// give us a convenient way of doing so.

typedef struct nng_url {
	char *u_rawurl;   // never NULL
	char *u_scheme;   // never NULL
	char *u_userinfo; // will be NULL if not specified
	char *u_host;     // including colon and port
	char *u_hostname; // name only, will be "" if not specified
	char *u_port;     // port, will be "" if not specified
	char *u_path;     // path, will be "" if not specified
	char *u_query;    // without '?', will be NULL if not specified
	char *u_fragment; // without '#', will be NULL if not specified
	char *u_requri;   // includes query and fragment, "" if not specified
} nng_url;

// nng_url_parse parses a URL string into a structured form.
// Note that the u_port member will be filled out with a numeric
// port if one isn't specified and a default port is appropriate for
// the scheme.  The URL structure is allocated, along with individual
// members.  It can be freed with nng_url_free.
NNG_DECL int nng_url_parse(nng_url **, const char *);

// nng_url_free frees a URL structure that was created by nng_url_parse().
NNG_DECL void nng_url_free(nng_url *);

// nng_url_clone clones a URL structure.
NNG_DECL int nng_url_clone(nng_url **, const nng_url *);

// nng_version returns the library version as a human readable string.
NNG_DECL const char *nng_version(void);

// nng_stream operations permit direct access to low level streams,
// which can have a variety of uses.  Internally most of the transports
// are built on top of these.  Streams are created by other dialers or
// listeners.  The API for creating dialers and listeners varies.

typedef struct nng_stream          nng_stream;
typedef struct nng_stream_dialer   nng_stream_dialer;
typedef struct nng_stream_listener nng_stream_listener;

NNG_DECL void nng_stream_free(nng_stream *);
NNG_DECL void nng_stream_close(nng_stream *);
NNG_DECL void nng_stream_send(nng_stream *, nng_aio *);
NNG_DECL void nng_stream_recv(nng_stream *, nng_aio *);
NNG_DECL int  nng_stream_get(nng_stream *, const char *, void *, size_t *);
NNG_DECL int  nng_stream_get_bool(nng_stream *, const char *, bool *);
NNG_DECL int  nng_stream_get_int(nng_stream *, const char *, int *);
NNG_DECL int  nng_stream_get_ms(nng_stream *, const char *, nng_duration *);
NNG_DECL int  nng_stream_get_size(nng_stream *, const char *, size_t *);
NNG_DECL int  nng_stream_get_uint64(nng_stream *, const char *, uint64_t *);
NNG_DECL int  nng_stream_get_string(nng_stream *, const char *, char **);
NNG_DECL int  nng_stream_get_ptr(nng_stream *, const char *, void **);
NNG_DECL int  nng_stream_get_addr(nng_stream *, const char *, nng_sockaddr *);
NNG_DECL int  nng_stream_set(nng_stream *, const char *, const void *, size_t);
NNG_DECL int  nng_stream_set_bool(nng_stream *, const char *, bool);
NNG_DECL int  nng_stream_set_int(nng_stream *, const char *, int);
NNG_DECL int  nng_stream_set_ms(nng_stream *, const char *, nng_duration);
NNG_DECL int  nng_stream_set_size(nng_stream *, const char *, size_t);
NNG_DECL int  nng_stream_set_uint64(nng_stream *, const char *, uint64_t);
NNG_DECL int  nng_stream_set_string(nng_stream *, const char *, const char *);
NNG_DECL int  nng_stream_set_ptr(nng_stream *, const char *, void *);
NNG_DECL int  nng_stream_set_addr(
     nng_stream *, const char *, const nng_sockaddr *);

NNG_DECL int nng_stream_dialer_alloc(nng_stream_dialer **, const char *);
NNG_DECL int nng_stream_dialer_alloc_url(
    nng_stream_dialer **, const nng_url *);
NNG_DECL void nng_stream_dialer_free(nng_stream_dialer *);
NNG_DECL void nng_stream_dialer_close(nng_stream_dialer *);
NNG_DECL void nng_stream_dialer_dial(nng_stream_dialer *, nng_aio *);
NNG_DECL int  nng_stream_dialer_set(
     nng_stream_dialer *, const char *, const void *, size_t);
NNG_DECL int nng_stream_dialer_get(
    nng_stream_dialer *, const char *, void *, size_t *);
NNG_DECL int nng_stream_dialer_get_bool(
    nng_stream_dialer *, const char *, bool *);
NNG_DECL int nng_stream_dialer_get_int(
    nng_stream_dialer *, const char *, int *);
NNG_DECL int nng_stream_dialer_get_ms(
    nng_stream_dialer *, const char *, nng_duration *);
NNG_DECL int nng_stream_dialer_get_size(
    nng_stream_dialer *, const char *, size_t *);
NNG_DECL int nng_stream_dialer_get_uint64(
    nng_stream_dialer *, const char *, uint64_t *);
NNG_DECL int nng_stream_dialer_get_string(
    nng_stream_dialer *, const char *, char **);
NNG_DECL int nng_stream_dialer_get_ptr(
    nng_stream_dialer *, const char *, void **);
NNG_DECL int nng_stream_dialer_get_addr(
    nng_stream_dialer *, const char *, nng_sockaddr *);
NNG_DECL int nng_stream_dialer_set_bool(
    nng_stream_dialer *, const char *, bool);
NNG_DECL int nng_stream_dialer_set_int(nng_stream_dialer *, const char *, int);
NNG_DECL int nng_stream_dialer_set_ms(
    nng_stream_dialer *, const char *, nng_duration);
NNG_DECL int nng_stream_dialer_set_size(
    nng_stream_dialer *, const char *, size_t);
NNG_DECL int nng_stream_dialer_set_uint64(
    nng_stream_dialer *, const char *, uint64_t);
NNG_DECL int nng_stream_dialer_set_string(
    nng_stream_dialer *, const char *, const char *);
NNG_DECL int nng_stream_dialer_set_ptr(
    nng_stream_dialer *, const char *, void *);
NNG_DECL int nng_stream_dialer_set_addr(
    nng_stream_dialer *, const char *, const nng_sockaddr *);

NNG_DECL int nng_stream_listener_alloc(nng_stream_listener **, const char *);
NNG_DECL int nng_stream_listener_alloc_url(
    nng_stream_listener **, const nng_url *);
NNG_DECL void nng_stream_listener_free(nng_stream_listener *);
NNG_DECL void nng_stream_listener_close(nng_stream_listener *);
NNG_DECL int  nng_stream_listener_listen(nng_stream_listener *);
NNG_DECL void nng_stream_listener_accept(nng_stream_listener *, nng_aio *);
NNG_DECL int  nng_stream_listener_set(
     nng_stream_listener *, const char *, const void *, size_t);
NNG_DECL int nng_stream_listener_get(
    nng_stream_listener *, const char *, void *, size_t *);
NNG_DECL int nng_stream_listener_get_bool(
    nng_stream_listener *, const char *, bool *);
NNG_DECL int nng_stream_listener_get_int(
    nng_stream_listener *, const char *, int *);
NNG_DECL int nng_stream_listener_get_ms(
    nng_stream_listener *, const char *, nng_duration *);
NNG_DECL int nng_stream_listener_get_size(
    nng_stream_listener *, const char *, size_t *);
NNG_DECL int nng_stream_listener_get_uint64(
    nng_stream_listener *, const char *, uint64_t *);
NNG_DECL int nng_stream_listener_get_string(
    nng_stream_listener *, const char *, char **);
NNG_DECL int nng_stream_listener_get_ptr(
    nng_stream_listener *, const char *, void **);
NNG_DECL int nng_stream_listener_get_addr(
    nng_stream_listener *, const char *, nng_sockaddr *);
NNG_DECL int nng_stream_listener_set_bool(
    nng_stream_listener *, const char *, bool);
NNG_DECL int nng_stream_listener_set_int(
    nng_stream_listener *, const char *, int);
NNG_DECL int nng_stream_listener_set_ms(
    nng_stream_listener *, const char *, nng_duration);
NNG_DECL int nng_stream_listener_set_size(
    nng_stream_listener *, const char *, size_t);
NNG_DECL int nng_stream_listener_set_uint64(
    nng_stream_listener *, const char *, uint64_t);
NNG_DECL int nng_stream_listener_set_string(
    nng_stream_listener *, const char *, const char *);
NNG_DECL int nng_stream_listener_set_ptr(
    nng_stream_listener *, const char *, void *);
NNG_DECL int nng_stream_listener_set_addr(
    nng_stream_listener *, const char *, const nng_sockaddr *);

#ifdef __cplusplus
}
#endif

#endif // NNG_NNG_H
