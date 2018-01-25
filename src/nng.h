//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef NNG_H
#define NNG_H

// NNG (nanomsg-next-gen) is an improved implementation of the SP protocols.
// The APIs have changed, and there is no attempt to provide API compatibility
// with legacy libnanomsg.  This file defines the library consumer-facing
// Public API. Use of definitions or declarations not found in this header
// file is specfically unsupported and strongly discouraged.

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// NNG_DECL is used on declarations to deal with scope.
// For building Windows DLLs, it should be the appropriate
// __declspec().  (We recommend *not* building this library
// as a DLL, but instead linking it statically for your projects
// to minimize questions about link dependencies later.)
#ifndef NNG_DECL
#if defined(_WIN32) && !defined(NNG_STATIC_LIB)
#if defined(NNG_SHARED_LIB)
#define NNG_DECL __declspec(dllexport)
#else
#define NNG_DECL __declspec(dllimport)
#endif // NNG_SHARED_LIB
#else
#define NNG_DECL extern
#endif // _WIN32 && !NNG_STATIC_LIB
#endif // NNG_DECL

// Types common to nng.
typedef uint32_t            nng_socket;
typedef uint32_t            nng_dialer;
typedef uint32_t            nng_listener;
typedef uint32_t            nng_pipe;
typedef int32_t             nng_duration; // in milliseconds
typedef struct nng_msg      nng_msg;
typedef struct nng_snapshot nng_snapshot;
typedef struct nng_stat     nng_stat;
typedef struct nng_aio      nng_aio;

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

// nng_closeall closes all open sockets.  Do not call this from
// a library; it will affect all sockets.
NNG_DECL void nng_closeall(void);

// nng_setopt sets an option for a specific socket.
NNG_DECL int nng_setopt(nng_socket, const char *, const void *, size_t);
NNG_DECL int nng_setopt_int(nng_socket, const char *, int);
NNG_DECL int nng_setopt_ms(nng_socket, const char *, nng_duration);
NNG_DECL int nng_setopt_size(nng_socket, const char *, size_t);
NNG_DECL int nng_setopt_uint64(nng_socket, const char *, uint64_t);
NNG_DECL int nng_setopt_string(nng_socket, const char *, const char *);

// nng_socket_getopt obtains the option for a socket.
NNG_DECL int nng_getopt(nng_socket, const char *, void *, size_t *);
NNG_DECL int nng_getopt_int(nng_socket, const char *, int *);
NNG_DECL int nng_getopt_ms(nng_socket, const char *, nng_duration *);
NNG_DECL int nng_getopt_size(nng_socket, const char *, size_t *);
NNG_DECL int nng_getopt_uint64(nng_socket, const char *, uint64_t *);
NNG_DECL int nng_getopt_ptr(nng_socket, const char *, void **);

// nng_listen creates a listening endpoint with no special options,
// and starts it listening.  It is functionally equivalent to the legacy
// nn_bind(). The underlying endpoint is returned back to the caller in the
// endpoint pointer, if it is not NULL.  The flags may be NNG_FLAG_SYNCH to
// indicate that a failure setting the socket up should return an error
// back to the caller immediately.
NNG_DECL int nng_listen(nng_socket, const char *, nng_listener *, int);

// nng_dial creates a dialing endpoint, with no special options, and
// starts it dialing.  Dialers have at most one active connection at a time
// This is similar to the legacy nn_connect().  The underlying endpoint
// is returned back to the caller in the endpoint pointer, if it is not NULL.
// The flags may be NNG_FLAG_SYNCH to indicate that the first attempt to
// dial will be made synchronously, and a failure condition returned back
// to the caller.  (If the connection is dropped, it will still be
// reconnected in the background -- only the initial connect is synchronous.)
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

// nng_dialer_setopt sets an option for a specific dialer.  Note
// dialer options may not be altered on a running dialer.
NNG_DECL int nng_dialer_setopt(nng_dialer, const char *, const void *, size_t);
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
NNG_DECL int nng_dialer_getopt_int(nng_dialer, const char *, int *);
NNG_DECL int nng_dialer_getopt_ms(nng_dialer, const char *, nng_duration *);
NNG_DECL int nng_dialer_getopt_size(nng_dialer, const char *, size_t *);
NNG_DECL int nng_dialer_getopt_uint64(nng_dialer, const char *, uint64_t *);
NNG_DECL int nng_dialer_getopt_ptr(nng_dialer, const char *, void **);

// nng_listener_setopt sets an option for a dialer.  This value is
// not stored in the socket.  Subsequent setopts on the socket may
// override these value however.  Note listener options may not be altered
// on a running listener.
NNG_DECL int nng_listener_setopt(
    nng_listener, const char *, const void *, size_t);
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
NNG_DECL int nng_listener_getopt_int(nng_listener, const char *, int *);
NNG_DECL int nng_listener_getopt_ms(
    nng_listener, const char *, nng_duration *);
NNG_DECL int nng_listener_getopt_size(nng_listener, const char *, size_t *);
NNG_DECL int nng_listener_getopt_uint64(
    nng_listener, const char *, uint64_t *);
NNG_DECL int nng_listener_getopt_ptr(nng_listener, const char *, void **);

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

// nng_aio_set_data sets an opaque data at the given index.  The intention
// is to allow consumers to pass additional state for use in callback
// functions.
NNG_DECL int nng_aio_set_data(nng_aio *, unsigned, void *);

// nng_aio_get_data retrieves the data that was previously stored.
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
NNG_DECL int nng_aio_set_iov(nng_aio *, int, nng_iov *);

// Message API.
NNG_DECL int   nng_msg_alloc(nng_msg **, size_t);
NNG_DECL void  nng_msg_free(nng_msg *);
NNG_DECL int   nng_msg_realloc(nng_msg *, size_t);
NNG_DECL void *nng_msg_header(nng_msg *);
NNG_DECL size_t nng_msg_header_len(const nng_msg *);
NNG_DECL void * nng_msg_body(nng_msg *);
NNG_DECL size_t nng_msg_len(const nng_msg *);
NNG_DECL int    nng_msg_append(nng_msg *, const void *, size_t);
NNG_DECL int    nng_msg_insert(nng_msg *, const void *, size_t);
NNG_DECL int    nng_msg_trim(nng_msg *, size_t);
NNG_DECL int    nng_msg_chop(nng_msg *, size_t);
NNG_DECL int    nng_msg_header_append(nng_msg *, const void *, size_t);
NNG_DECL int    nng_msg_header_insert(nng_msg *, const void *, size_t);
NNG_DECL int    nng_msg_header_trim(nng_msg *, size_t);
NNG_DECL int    nng_msg_header_chop(nng_msg *, size_t);
NNG_DECL int    nng_msg_header_append_u32(nng_msg *, uint32_t);
NNG_DECL int    nng_msg_header_insert_u32(nng_msg *, uint32_t);
NNG_DECL int    nng_msg_header_chop_u32(nng_msg *, uint32_t *);
NNG_DECL int    nng_msg_header_trim_u32(nng_msg *, uint32_t *);
NNG_DECL int    nng_msg_append_u32(nng_msg *, uint32_t);
NNG_DECL int    nng_msg_insert_u32(nng_msg *, uint32_t);
NNG_DECL int    nng_msg_chop_u32(nng_msg *, uint32_t *);
NNG_DECL int    nng_msg_trim_u32(nng_msg *, uint32_t *);

NNG_DECL int  nng_msg_dup(nng_msg **, const nng_msg *);
NNG_DECL void nng_msg_clear(nng_msg *);
NNG_DECL void nng_msg_header_clear(nng_msg *);
NNG_DECL void nng_msg_set_pipe(nng_msg *, nng_pipe);
NNG_DECL nng_pipe nng_msg_get_pipe(const nng_msg *);
NNG_DECL int      nng_msg_getopt(nng_msg *, int, void *, size_t *);

// Pipe API. Generally pipes are only "observable" to applications, but
// we do permit an application to close a pipe. This can be useful, for
// example during a connection notification, to disconnect a pipe that
// is associated with an invalid or untrusted remote peer.
NNG_DECL int nng_pipe_getopt(nng_pipe, const char *, void *, size_t *);
NNG_DECL int nng_pipe_getopt_int(nng_pipe, const char *, int *);
NNG_DECL int nng_pipe_getopt_ms(nng_pipe, const char *, nng_duration *);
NNG_DECL int nng_pipe_getopt_size(nng_pipe, const char *, size_t *);
NNG_DECL int nng_pipe_getopt_uint64(nng_pipe, const char *, uint64_t *);
NNG_DECL int nng_pipe_close(nng_pipe);

// Flags.
enum nng_flag_enum {
	NNG_FLAG_ALLOC    = 1, // Recv to allocate receive buffer.
	NNG_FLAG_NONBLOCK = 2, // Non-blocking operations.
};

// Options.
#define NNG_OPT_SOCKNAME "socket-name"
#define NNG_OPT_DOMAIN "compat:domain" // legacy compat only
#define NNG_OPT_RAW "raw"
#define NNG_OPT_LINGER "linger"
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
#define NNG_OPT_PROTOCOL "protocol"
#define NNG_OPT_TRANSPORT "transport"
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

// NNG_OPT_TLS_VERIFIED returns a single integer, indicating whether the peer
// has been verified (1) or not (0).  Typically this is read-only, and only
// available for pipes. This option may return incorrect results if peer
// authentication is disabled with `NNG_TLS_AUTH_MODE_NONE`.
#define NNG_OPT_TLS_VERIFIED "tls-verified"

// XXX: TBD: priorities, socket names, ipv4only

// Statistics.  These are for informational purposes only, and subject
// to change without notice.  The API for accessing these is stable,
// but the individual statistic names, values, and meanings are all
// subject to change.

// nng_snapshot_create creates a statistics snapshot.  The snapshot
// object must be deallocated expressly by the user, and may persist beyond
// the lifetime of any socket object used to update it.  Note that the
// values of the statistics are initially unset.
NNG_DECL int nng_snapshot_create(nng_socket, nng_snapshot **);

// nng_snapshot_free frees a snapshot object.  All statistic objects
// contained therein are destroyed as well.
NNG_DECL void nng_snapshot_free(nng_snapshot *);

// nng_snapshot_update updates a snapshot of all the statistics
// relevant to a particular socket.  All prior values are overwritten.
NNG_DECL int nng_snapshot_update(nng_snapshot *);

// nng_snapshot_next is used to iterate over the individual statistic
// objects inside the snapshot. Note that the statistic object, and the
// meta-data for the object (name, type, units) is fixed, and does not
// change for the entire life of the snapshot.  Only the value
// is subject to change, and then only when a snapshot is updated.
//
// Iteration begins by providing NULL in the value referenced. Successive
// calls will update this value, returning NULL when no more statistics
// are available in the snapshot.
NNG_DECL int nng_snapshot_next(nng_snapshot *, nng_stat **);

// nng_stat_name is used to determine the name of the statistic.
// This is a human readable name.  Statistic names, as well as the presence
// or absence or semantic of any particular statistic are not part of any
// stable API, and may be changed without notice in future updates.
NNG_DECL const char *nng_stat_name(nng_stat *);

// nng_stat_type is used to determine the type of the statistic.
// At present, only NNG_STAT_TYPE_LEVEL and and NNG_STAT_TYPE_COUNTER
// are defined.  Counters generally increment, and therefore changes in the
// value over time are likely more interesting than the actual level.  Level
// values reflect some absolute state however, and should be presented to the
// user as is.
NNG_DECL int nng_stat_type(nng_stat *);

enum nng_stat_type_enum {
	NNG_STAT_LEVEL   = 0,
	NNG_STAT_COUNTER = 1,
};

// nng_stat_unit provides information about the unit for the statistic,
// such as NNG_UNIT_BYTES or NNG_UNIT_BYTES.  If no specific unit is
// applicable, such as a relative priority, then NN_UNIT_NONE is
// returned.
NNG_DECL int nng_stat_unit(nng_stat *);

enum nng_unit_enum {
	NNG_UNIT_NONE     = 0,
	NNG_UNIT_BYTES    = 1,
	NNG_UNIT_MESSAGES = 2,
	NNG_UNIT_BOOLEAN  = 3,
	NNG_UNIT_MILLIS   = 4,
	NNG_UNIT_EVENTS   = 5,
};

// nng_stat_value returns returns the actual value of the statistic.
// Statistic values reflect their value at the time that the corresponding
// snapshot was updated, and are undefined until an update is performed.
NNG_DECL int64_t nng_stat_value(nng_stat *);

// Device functionality.  This connects two sockets together in a device,
// which means that messages from one side are forwarded to the other.
NNG_DECL int nng_device(nng_socket, nng_socket);

// The following functions are not intrinsic to nanomsg, and so do not
// represent our public API.  Avoid their use in other applications.

#ifdef NNG_PRIVATE

// Sleep for specified msecs.
NNG_DECL void nng_msleep(nng_duration);

// Create and start a thread.
NNG_DECL int nng_thread_create(void **, void (*)(void *), void *);

// Destroy a thread (waiting for it to complete.)
NNG_DECL void nng_thread_destroy(void *);

#endif // NNG_PRIVATE

// Symbol name and visibility.  TBD.  The only symbols that really should
// be directly exported to runtimes IMO are the option symbols.  And frankly
// they have enough special logic around them that it might be best not to
// automate the promotion of them to other APIs.  This is an area open
// for discussion.

// Error codes.  These generally have different values from UNIX errnos,
// so take care about converting them.  The one exception is that 0 is
// unambigiously "success".
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
	NNG_EINTERNAL    = 1000,
	NNG_ESYSERR      = 0x10000000,
	NNG_ETRANERR     = 0x20000000,
};

// Maximum length of a socket address.  This includes the terminating NUL.
// This limit is built into other implementations, so do not change it.
#define NNG_MAXADDRLEN (128)

// Some address details.  This is in some ways like a traditional sockets
// sockaddr, but we have our own to cope with our unique families, etc.
// The details of this structure are directly exposed to applications.
// These structures can be obtained via property lookups, etc.
struct nng_sockaddr_path {
	uint16_t sa_family;
	char     sa_path[NNG_MAXADDRLEN];
};
typedef struct nng_sockaddr_path nng_sockaddr_path;
typedef struct nng_sockaddr_path nng_sockaddr_ipc;
typedef struct nng_sockaddr_path nng_sockaddr_inproc;

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

typedef struct nng_sockaddr {
	union {
		uint16_t            s_family;
		nng_sockaddr_path   s_path;
		nng_sockaddr_inproc s_inproc;
		nng_sockaddr_in6    s_in6;
		nng_sockaddr_in     s_in;
		nng_sockaddr_zt     s_zt;
	} s_un;
} nng_sockaddr;

enum nng_sockaddr_family {
	NNG_AF_UNSPEC = 0,
	NNG_AF_INPROC = 1,
	NNG_AF_IPC    = 2,
	NNG_AF_INET   = 3,
	NNG_AF_INET6  = 4,
	NNG_AF_ZT     = 5, // ZeroTier
};

// For some transports, we need TLS configuration, including certificates
// and so forth.  Note that these symbols are only actually present at link
// time if TLS support is enabled in your build.  A TLS configuration cannot
// be changed once it is in use.
typedef struct nng_tls_config nng_tls_config;

typedef enum nng_tls_mode {
	NNG_TLS_MODE_CLIENT = 0,
	NNG_TLS_MODE_SERVER = 1,
} nng_tls_mode;

typedef enum nng_tls_auth_mode {
	NNG_TLS_AUTH_MODE_NONE     = 0, // No verification is performed
	NNG_TLS_AUTH_MODE_OPTIONAL = 1, // Verify cert if presented
	NNG_TLS_AUTH_MODE_REQUIRED = 2, // Verify cert, close if invalid
} nng_tls_auth_mode;

// nng_tls_config_alloc creates a TLS configuration using
// reasonable defaults.  This configuration can be shared
// with multiple pipes or services/servers.
NNG_DECL int nng_tls_config_alloc(nng_tls_config **, nng_tls_mode);

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
// (revokation list) for the CA, also in PEM.  Both PEM strings are ASCIIZ
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
	char *u_rawpath;  // includes query and fragment, "" if not specified
} nng_url;

// nng_url_parse parses a URL string into a structured form.
// Note that the u_port member will be filled out with a numeric
// port if one isn't specified and a default port is appropriate for
// the scheme.  The URL structure is allocated, along with individual
// members.  It can be freed with nng_url_free.
NNG_DECL int nng_url_parse(nng_url **, const char *);

// nng_url_free frees a URL structure that was created by nng_url_parse9().
NNG_DECL void nng_url_free(nng_url *);

// nng_url_clone clones a URL structure.
NNG_DECL int nng_url_clone(nng_url **, const nng_url *);

// HTTP API.  Only present if HTTP support compiled into the library.
// Functions will return NNG_ENOTSUP (or NULL or 0 as appropriate)
// if the library lacks support for HTTP.

// HTTP status codes.  This list is not exhaustive.
enum nng_http_status {
	NNG_HTTP_STATUS_CONTINUE                 = 100,
	NNG_HTTP_STATUS_SWITCHING                = 101,
	NNG_HTTP_STATUS_PROCESSING               = 102,
	NNG_HTTP_STATUS_OK                       = 200,
	NNG_HTTP_STATUS_CREATED                  = 201,
	NNG_HTTP_STATUS_ACCEPTED                 = 202,
	NNG_HTTP_STATUS_NOT_AUTHORITATIVE        = 203,
	NNG_HTTP_STATUS_NO_CONTENT               = 204,
	NNG_HTTP_STATUS_RESET_CONTENT            = 205,
	NNG_HTTP_STATUS_PARTIAL_CONTENT          = 206,
	NNG_HTTP_STATUS_MULTI_STATUS             = 207,
	NNG_HTTP_STATUS_ALREADY_REPORTED         = 208,
	NNG_HTTP_STATUS_IM_USED                  = 226,
	NNG_HTTP_STATUS_MULTIPLE_CHOICES         = 300,
	NNG_HTTP_STATUS_STATUS_MOVED_PERMANENTLY = 301,
	NNG_HTTP_STATUS_FOUND                    = 302,
	NNG_HTTP_STATUS_SEE_OTHER                = 303,
	NNG_HTTP_STATUS_NOT_MODIFIED             = 304,
	NNG_HTTP_STATUS_USE_PROXY                = 305,
	NNG_HTTP_STATUS_TEMPORARY_REDIRECT       = 307,
	NNG_HTTP_STATUS_PERMANENT_REDIRECT       = 308,
	NNG_HTTP_STATUS_BAD_REQUEST              = 400,
	NNG_HTTP_STATUS_UNAUTHORIZED             = 401,
	NNG_HTTP_STATUS_PAYMENT_REQUIRED         = 402,
	NNG_HTTP_STATUS_FORBIDDEN                = 403,
	NNG_HTTP_STATUS_NOT_FOUND                = 404,
	NNG_HTTP_STATUS_METHOD_NOT_ALLOWED       = 405,
	NNG_HTTP_STATUS_NOT_ACCEPTABLE           = 406,
	NNG_HTTP_STATUS_PROXY_AUTH_REQUIRED      = 407,
	NNG_HTTP_STATUS_REQUEST_TIMEOUT          = 408,
	NNG_HTTP_STATUS_CONFLICT                 = 409,
	NNG_HTTP_STATUS_GONE                     = 410,
	NNG_HTTP_STATUS_LENGTH_REQUIRED          = 411,
	NNG_HTTP_STATUS_PRECONDITION_FAILED      = 412,
	NNG_HTTP_STATUS_PAYLOAD_TOO_LARGE        = 413,
	NNG_HTTP_STATUS_ENTITY_TOO_LONG          = 414,
	NNG_HTTP_STATUS_UNSUPPORTED_MEDIA_TYPE   = 415,
	NNG_HTTP_STATUS_RANGE_NOT_SATISFIABLE    = 416,
	NNG_HTTP_STATUS_EXPECTATION_FAILED       = 417,
	NNG_HTTP_STATUS_TEAPOT                   = 418,
	NNG_HTTP_STATUS_UNPROCESSABLE_ENTITY     = 422,
	NNG_HTTP_STATUS_LOCKED                   = 423,
	NNG_HTTP_STATUS_FAILED_DEPENDENCY        = 424,
	NNG_HTTP_STATUS_UPGRADE_REQUIRED         = 426,
	NNG_HTTP_STATUS_PRECONDITION_REQUIRED    = 428,
	NNG_HTTP_STATUS_TOO_MANY_REQUESTS        = 429,
	NNG_HTTP_STATUS_HEADERS_TOO_LARGE        = 431,
	NNG_HTTP_STATUS_UNAVAIL_LEGAL_REASONS    = 451,
	NNG_HTTP_STATUS_INTERNAL_SERVER_ERROR    = 500,
	NNG_HTTP_STATUS_NOT_IMPLEMENTED          = 501,
	NNG_HTTP_STATUS_BAD_GATEWAY              = 502,
	NNG_HTTP_STATUS_SERVICE_UNAVAILABLE      = 503,
	NNG_HTTP_STATUS_GATEWAY_TIMEOUT          = 504,
	NNG_HTTP_STATUS_HTTP_VERSION_NOT_SUPP    = 505,
	NNG_HTTP_STATUS_VARIANT_ALSO_NEGOTIATES  = 506,
	NNG_HTTP_STATUS_INSUFFICIENT_STORAGE     = 507,
	NNG_HTTP_STATUS_LOOP_DETECTED            = 508,
	NNG_HTTP_STATUS_NOT_EXTENDED             = 510,
	NNG_HTTP_STATUS_NETWORK_AUTH_REQUIRED    = 511,
};

// nng_http_req represents an HTTP request.
typedef struct nng_http_req nng_http_req;

// nng_http_req_alloc creates a vanilla HTTP request object.  The object is
// initialized with the given URL object for an HTTP/1.1 GET request by
// default. It also adds the Host: header required for HTTP/1.1.  If the
// url is NULL, then the uri and Host: header are uninitialized, and will
// need to be set explicitly.
NNG_DECL int nng_http_req_alloc(nng_http_req **, const nng_url *);

// nng_http_req_free frees an HTTP request object.
NNG_DECL void nng_http_req_free(nng_http_req *);

// nng_http_req_get_method returns the method.
NNG_DECL const char *nng_http_req_get_method(nng_http_req *);

// nng_http_req_get_version returns the version, usually HTTP/1.1.
NNG_DECL const char *nng_http_req_get_version(nng_http_req *);

// nng_http_req_get_uri returns the "abs-uri", which is URL without
// the scheme, host, or port.
NNG_DECL const char *nng_http_req_get_uri(nng_http_req *);

// nng_http_req_set_header sets an HTTP header, replacing any previous value
// that might have been present.
NNG_DECL int nng_http_req_set_header(
    nng_http_req *, const char *, const char *);

// nng_http_req_add_header adds an HTTP header, without disrupting any other
// with the same name that might have been present.
NNG_DECL int nng_http_req_add_header(
    nng_http_req *, const char *, const char *);

// nng_http_req_del_header deletes all occurrences of a named header.
NNG_DECL int nng_http_req_del_header(nng_http_req *, const char *);

// nng_http_req_get_header looks up a header with the named, returns NULL
// if not found.
NNG_DECL const char *nng_http_req_get_header(nng_http_req *, const char *);

// nng_http_req_set_method is used to change the method of a request.
// The method should be an upper case HTTP method, like POST, or DELETE.
// Null sets the default ("GET").
NNG_DECL int nng_http_req_set_method(nng_http_req *, const char *);

// nng_http_req_set_version is used to change the version of a request.
// Normally the version is "HTTP/1.1".  Note that the framework does
// not support HTTP/2 at all.  Null sets the default ("HTTP/1.1").
NNG_DECL int nng_http_req_set_version(nng_http_req *, const char *);

// nng_http_req_set_uri is used to change the URI of a request.  This
// should be an "abs-uri", that is a path, plus query and fragment if
// needed.  The scheme, host, and port don't belong here.  The URI should
// start with a leading '/' per HTTP.
NNG_DECL int nng_http_req_set_uri(nng_http_req *, const char *);

// nng_http_req_set_data adds entity data to the request.  The
// data object must persist (so only really useful for static data).
// The content-length header is updated as well, but the caller should
// probably set the content-type header.
NNG_DECL int nng_http_req_set_data(nng_http_req *, const void *, size_t);

// nng_http_req_copy_data adds entity data to the response. A private
// copy of the data is made (will be freed with the request).
// The content-length header is updated as well, but the caller should
// probably set the content-type header.
NNG_DECL int nng_http_req_copy_data(nng_http_req *, const void *, size_t);

// nng_http_res represents an HTTP response.
typedef struct nng_http_res nng_http_res;

// nng_http_res_alloc creates a vanilla HTTP response object.  The object is
// initialized for an HTTP/1.1 200 OK response by default.
NNG_DECL int nng_http_res_alloc(nng_http_res **);

// nng_http_res_alloc_error creates an error HTTP response object.  The object
// is initialized for an HTTP/1.1 response, and contains an associated
// generic HTML error page.
NNG_DECL int nng_http_res_alloc_error(nng_http_res **, uint16_t);

// nng_http_res_free frees an HTTP response object.
NNG_DECL void nng_http_res_free(nng_http_res *);

// nng_http_res_get_status returns the HTTP status code from the server.
NNG_DECL uint16_t nng_http_res_get_status(nng_http_res *);

// nng_http_res_set_status sets the HTTP status code.
NNG_DECL int nng_http_res_set_status(nng_http_res *, uint16_t);

// nng_http_res_get_reason returns the human readable status message
// that the server responds (or responded) with.
NNG_DECL const char *nng_http_res_get_reason(nng_http_res *);

// nng_http_res_set_rason sets the human readable status message.
// NULL means that a default reason is used based on the status code.
NNG_DECL int nng_http_res_set_reason(nng_http_res *, const char *);

// nng_http_res_set_header sets an HTTP header, replacing any previous value
// that might have been present.
NNG_DECL int nng_http_res_set_header(
    nng_http_res *, const char *, const char *);

// nng_http_res_add_header adds an HTTP header, without disrupting any other
// with the same name that might have been present.
NNG_DECL int nng_http_res_add_header(
    nng_http_res *, const char *, const char *);

// nng_http_res_del_header deletes all occurrences of a named header.
NNG_DECL int nng_http_res_del_header(nng_http_res *, const char *);

// nng_http_res_get_header looks up a header with the named, returns NULL
// if not found.
NNG_DECL const char *nng_http_res_get_header(nng_http_res *, const char *);

// nng_http_res_set_version is used to change the version of a response.
// Normally the version is "HTTP/1.1".  Note that the framework does
// not support HTTP/2 at all.  NULL sets the default ("HTTP/1.1").
NNG_DECL int nng_http_res_set_version(nng_http_res *, const char *);

// nng_http_res_get_version returns the version, usually HTTP/1.1.
NNG_DECL const char *nng_http_res_get_version(nng_http_res *);

// nng_http_res_set_data adds entity data to the response.  The
// data object must persist (so only really useful for static data).
// The content-length header is updated as well, but the caller should
// probably set the content-type header.
NNG_DECL int nng_http_res_set_data(nng_http_res *, const void *, size_t);

// nng_http_res_copy_data adds entity data to the response. A private
// copy of the data is made (will be freed with the request).
// The content-length header is updated as well, but the caller should
// probably set the content-type header.
NNG_DECL int nng_http_res_copy_data(nng_http_res *, const void *, size_t);

// An nng_http_conn represents an underlyinjg "connection".  It may be
// a TCP channel, or a TLS channel, but the main thing is that this is
// normally only used for exchanging HTTP requests and responses.
typedef struct nng_http_conn nng_http_conn;

// nng_http_conn_close closes the underlying channel.  Applications should
// not use this channel after this operation is performed.
NNG_DECL void nng_http_conn_close(nng_http_conn *);

// nng_http_conn_read attempts to read data from the connection.  This
// completes as soon as at least one byte is read; it does not wait
// for the entire aio to be filled.
NNG_DECL void nng_http_conn_read(nng_http_conn *, nng_aio *);

// nng_http_conn_read_all is like nng_http_conn_read, but it does not
// finish until either all the requested data is read, or an error occurs.
NNG_DECL void nng_http_conn_read_all(nng_http_conn *, nng_aio *);

// nng_http_conn_write attempts to write data, but it can write less
// than the amount requested. (It completes as soon as at least one
// byte is written.)
NNG_DECL void nng_http_conn_write(nng_http_conn *, nng_aio *);

// nng_http_conn_write_all is like nng_http_conn_write, but it does not
// finish until either all the requested data is written, or an error occurs.
NNG_DECL void nng_http_conn_write_all(nng_http_conn *, nng_aio *);

// nng_http_conn_write_req writes the entire request.  It will also write any
// data that has been attached.
NNG_DECL void nng_http_conn_write_req(
    nng_http_conn *, nng_http_req *, nng_aio *);

// nng_http_conn_write_res writes the entire response.  It will also write any
// data that has been attached.
NNG_DECL void nng_http_conn_write_res(
    nng_http_conn *, nng_http_res *, nng_aio *);

// nng_http_conn_read_req reads an entire request, EXCEPT for any entity
// data.  The caller is responsible for processing the headers in the request
// and reading any submitted entity data itself.
NNG_DECL void nng_http_conn_read_req(
    nng_http_conn *, nng_http_req *, nng_aio *);

// nng_http_conn_read_res reads an entire response, EXCEPT for any entity
// data.  The caller is responsible for processing the headers in the response
// and reading any submitted entity data itself.
NNG_DECL void nng_http_conn_read_res(
    nng_http_conn *, nng_http_res *, nng_aio *);

// nng_http_handler is a handler used on the server side to handle HTTP
// requests coming into a specific URL.
typedef struct nng_http_handler nng_http_handler;

// nng_http_handler_alloc creates a server handler object, for the supplied
// absolute URI (path only) with the callback.  By default the handler
// is assumed to handle only GET requests (and implictly HEAD requests
// as well.)
//
// Note that methods which modify a handler cannot be called while the handler
// is registered with the server, and that a handler can only be registered
// once per server.
//
// The callback function will receive the following arguments (via
// nng_aio_get_input(): nng_http_request *, nng_http_handler *, and
// nng_http_conn *.  The first is a request object, for convenience.
// The second is the handler, from which the callback can obtain any other
// data it has set.  The final is the http connection, which can be used
// to hijack the session.
//
// Upon completion, the handler should store an nng_http_res * as the
// first output using nng_aio_set_output.  If it does not do so, or supplies
// NULL, then it must send a response itself.
//
// The callback should return 0 in most circumstances; if it returns anything
// other than 0 then the connection is terminated (after possibly sending
// a 500 error response to the client.)
NNG_DECL int nng_http_handler_alloc(
    nng_http_handler **, const char *, void (*)(nng_aio *));

// nng_http_handler_free frees the handler. This actually just drops a
// reference count on the handler, as it may be in use by an existing
// server.  The server will also call this when it is destroyed.
NNG_DECL void nng_http_handler_free(nng_http_handler *);

// nng_http_handler_alloc_file creates a "file" based handler, that
// serves up static content from the given file path.  The content-type
// supplied is determined from the file name using a simple built-in map.
NNG_DECL int nng_http_handler_alloc_file(
    nng_http_handler **, const char *, const char *);

// nng_http_handler_alloc_static creates a static-content handler.
// The last argument is the content-type, which may be NULL (in which case
// "application/octet-stream" is assumed.)
NNG_DECL int nng_http_handler_alloc_static(
    nng_http_handler **, const char *, const void *, size_t, const char *);

// nng_http_handler_alloc_file creates a "directory" based handler, that
// serves up static content from the given directory tree.  Directories
// that contain an index.html or index.htm file use that file for the
// directory content, otherwise a suitable error page is returned (the server
// does not generate index pages automatically.)  The content-type for
// files is determined from the file name using a simple built-in map.
NNG_DECL int nng_http_handler_alloc_directory(
    nng_http_handler **, const char *, const char *);

// nng_http_handler_set_method sets the method that the handler will be
// called for.  By default this is GET.  If NULL is supplied for the
// method, then the handler is executed regardless of method, and must
// inspect the method itself.
NNG_DECL int nng_http_handler_set_method(nng_http_handler *, const char *);

// nng_http_handler_set_host sets the Host: that the handler will be
// called for (to allow for virtual hosts).  If the value is NULL (the
// default, then the Host: header is not considered when matching the
// handler.)  Note that the Host: header must match *exactly* (except
// that case is not considered.)
NNG_DECL int nng_http_handler_set_host(nng_http_handler *, const char *);

// nng_http_handler_set_tree indicates that the handler is being registered
// for a heirarchical tree, rather than just a single path, so it will be
// called for all child paths supplied.  By default the handler is only
// called for an exact path match.
NNG_DECL int nng_http_handler_set_tree(nng_http_handler *);

// nng_http_handler_set_data is used to store additional data, along with
// a possible clean up routine.  (The clean up is a custom deallocator and
// will be called with the supplied data as an argument, when the handler
// is being deallocated.)
NNG_DECL int nng_http_handler_set_data(
    nng_http_handler *, void *, void (*)(void *));

// nng_http_handler_get_data returns the data that was previously stored.
NNG_DECL void *nng_http_handler_get_data(nng_http_handler *);

// nng_http_server is a handle to an HTTP server instance.  Servers
// only serve a single port / address at this time.

typedef struct nng_http_server nng_http_server;

// nng_http_server_hold gets a server structure, using the address determined
// from the URL.  If a server already exists, then a hold is placed on it, and
// that instance is returned.  If no such server exists, then a new instance
// is created.
NNG_DECL int nng_http_server_hold(nng_http_server **, const nng_url *);

// nng_http_server_release releases the hold on the server.  If this is the
// last instance of the server, then it is shutdown and resources are freed.
NNG_DECL void nng_http_server_release(nng_http_server *);

// nng_http_server_start starts the server handling HTTP.  Once this is
// called, it will not be possible to change certain parameters (such as
// any TLS configuration).
NNG_DECL int nng_http_server_start(nng_http_server *);

// nng_http_server_stop stops the server.  No new client connections are
// accepted after this returns.
NNG_DECL void nng_http_server_stop(nng_http_server *);

// nng_http_server_add_handler registers a handler on the server.
// This function will return NNG_EADDRINUSE if a conflicting handler
// is already registered (i.e. a handler with the same value for Host,
// Method, and URL.)
NNG_DECL int nng_http_server_add_handler(
    nng_http_server *, nng_http_handler *);

// nni_http_del_handler removes the given handler.  The caller is
// responsible for finalizing it afterwards.  If the handler was not found
// (not registered), NNG_ENOENT is returned.  In this case it is unsafe
// to make assumptions about the validity of the handler.
NNG_DECL int nng_http_server_del_handler(
    nng_http_server *, nng_http_handler *);

// nng_http_server_set_tls adds a TLS configuration to the server,
// and enables the use of it.  This returns NNG_EBUSY if the server is
// already started.   This wipes out the entire TLS configuration on the
// server client, so the caller must have configured it reasonably.
// This API is not recommended unless the caller needs complete control
// over the TLS configuration.
NNG_DECL int nng_http_server_set_tls(nng_http_server *, nng_tls_config *);

// nng_http_server_get_tls obtains the TLS configuration if one is present,
// or returns NNG_EINVAL.  The TLS configuration is invalidated if the
// nng_http_server_set_tls function is called, so be careful.
NNG_DECL int nng_http_server_get_tls(nng_http_server *, nng_tls_config **);

// nng_http_hijack is intended to be called by a handler that wishes to
// take over the processing of the HTTP session -- usually to change protocols
// (such as in the case of websocket).  The caller is responsible for the
// final disposal of the associated nng_http_conn.  Also, this completely
// disassociates the http session from the server, so the server may be
// stopped or destroyed without affecting the hijacked session.  Note also
// that the hijacker will need to issue any HTTP reply itself.  Finally,
// when a session is hijacked, the caller is also responsible for disposing
// of the request structure.  (Some hijackers may keep the request for
// further processing.)

NNG_DECL int nng_http_hijack(nng_http_conn *);

#ifdef __cplusplus
}
#endif

#endif // NNG_H
