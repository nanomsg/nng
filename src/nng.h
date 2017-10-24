//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
// Copyright 2017 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef NNG_H
#define NNG_H

// NNG (nanomsg-ng) is a next generation implementation of the SP protocols.
// The APIs have changed, and there is no attempt to provide API compatibility
// with legacy libnanomsg.  This file defines the library consumer-facing
// Public API. Use of definitions or declarations not found in this header
// file is specfically unsupported and strongly discouraged.

#ifdef __cplusplus
extern "C" {
#endif

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

// nng_fini is used to terminate the library, freeing certain global resources.
// For most cases, this call is optional, but failure to do so may cause
// memory checkers like valgrind to incorrectly flag memory leaks associated
// with global library resources.
//
// NOTE: THIS API IS NOT THREADSAFE, and MUST NOT BE CALLED WHILE ANY
// OTHER APIS ARE IN USE.  (It is safe however to call other functions such
// as nng_open *after* this function returns, provided that the functions do
// not run concurrently!)
NNG_DECL void nng_fini(void);

// nng_close closes the socket, terminating all activity and
// closing any underlying connections and releasing any associated
// resources.
NNG_DECL int nng_close(nng_socket);

// nng_closeall closes all open sockets.  Do not call this from
// a library; it will affect all sockets.
NNG_DECL void nng_closeall(void);

// nng_shutdown shuts down the socket.  This causes any threads doing
// work for the socket or blocked in socket functions to be woken (and
// return NNG_ECLOSED).  The socket resources are still present, so it
// is safe to call other functions; they will just return NNG_ECLOSED.
// A call to nng_close is still required to release the resources.
NNG_DECL int nng_shutdown(nng_socket);

// nng_protocol returns the protocol number of the socket.
NNG_DECL uint16_t nng_protocol(nng_socket);

// nng_peer returns the protocol number for the socket's peer.
NNG_DECL uint16_t nng_peer(nng_socket);

// nng_setopt sets an option for a specific socket.
NNG_DECL int nng_setopt(nng_socket, const char *, const void *, size_t);
NNG_DECL int nng_setopt_int(nng_socket, const char *, int);
NNG_DECL int nng_setopt_ms(nng_socket, const char *, nng_duration);
NNG_DECL int nng_setopt_size(nng_socket, const char *, size_t);
NNG_DECL int nng_setopt_uint64(nng_socket, const char *, uint64_t);

// nng_socket_getopt obtains the option for a socket.
NNG_DECL int nng_getopt(nng_socket, const char *, void *, size_t *);
NNG_DECL int nng_getopt_int(nng_socket, const char *, int *);
NNG_DECL int nng_getopt_ms(nng_socket, const char *, nng_duration *);
NNG_DECL int nng_getopt_size(nng_socket, const char *, size_t *);
NNG_DECL int nng_getopt_uint64(nng_socket, const char *, uint64_t *);

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

// nng_dialer_getopt obtains the option for a dialer. This will
// fail for options that a particular dialer is not interested in,
// even if they were set on the socket.
NNG_DECL int nng_dialer_getopt(nng_dialer, const char *, void *, size_t *);
NNG_DECL int nng_dialer_getopt_int(nng_dialer, const char *, int *);
NNG_DECL int nng_dialer_getopt_ms(nng_dialer, const char *, nng_duration *);
NNG_DECL int nng_dialer_getopt_size(nng_dialer, const char *, size_t *);
NNG_DECL int nng_dialer_getopt_uint64(nng_dialer, const char *, uint64_t *);

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

// Lookup an option by name.  This returns either the option value,
// or -1 if the option name is unknown.
NNG_DECL int nng_option_lookup(const char *);

// Lookup an option name by id.  Returns NULL if not known.
NNG_DECL const char *nng_option_name(int);

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
	NNG_FLAG_DRYRUN   = 4, // Setopt dry-run (internally used).
};

// Protocol numbers.  These are to be used with nng_socket_create().
// These values are used on the wire, so must not be changed.  The major
// number of the protocol is shifted left by 4 bits, and a subprotocol is
// assigned in the lower 4 bits.
//
// There are gaps in the list, which are obsolete or unsupported protocols.
// Protocol numbers are never more than 16 bits.  Also, there will never be
// a valid protocol numbered 0 (NNG_PROTO_NONE).
#define NNG_PROTO(major, minor) (((major) *16) + (minor))
enum nng_proto_enum {
	NNG_PROTO_NONE          = NNG_PROTO(0, 0),
	NNG_PROTO_PAIR_V0       = NNG_PROTO(1, 0),
	NNG_PROTO_PAIR_V1       = NNG_PROTO(1, 1),
	NNG_PROTO_PUB_V0        = NNG_PROTO(2, 0),
	NNG_PROTO_SUB_V0        = NNG_PROTO(2, 1),
	NNG_PROTO_REQ_V0        = NNG_PROTO(3, 0),
	NNG_PROTO_REP_V0        = NNG_PROTO(3, 1),
	NNG_PROTO_PUSH_V0       = NNG_PROTO(5, 0),
	NNG_PROTO_PULL_V0       = NNG_PROTO(5, 1),
	NNG_PROTO_SURVEYOR_V0   = NNG_PROTO(6, 2),
	NNG_PROTO_RESPONDENT_V0 = NNG_PROTO(6, 3),
	NNG_PROTO_BUS_V0        = NNG_PROTO(7, 0),
	NNG_PROTO_STAR_V0       = NNG_PROTO(100, 0),

	// "Default" names.  Use the explicit version to guarantee
	// backwards compatibility.
	NNG_PROTO_BUS        = NNG_PROTO_BUS_V0,
	NNG_PROTO_PAIR       = NNG_PROTO_PAIR_V1,
	NNG_PROTO_SUB        = NNG_PROTO_SUB_V0,
	NNG_PROTO_PUB        = NNG_PROTO_PUB_V0,
	NNG_PROTO_REQ        = NNG_PROTO_REQ_V0,
	NNG_PROTO_REP        = NNG_PROTO_REP_V0,
	NNG_PROTO_PUSH       = NNG_PROTO_PUSH_V0,
	NNG_PROTO_PULL       = NNG_PROTO_PULL_V0,
	NNG_PROTO_SURVEYOR   = NNG_PROTO_SURVEYOR_V0,
	NNG_PROTO_RESPONDENT = NNG_PROTO_RESPONDENT_V0,
};

// Builtin protocol socket constructors.
NNG_DECL int nng_bus0_open(nng_socket *);
NNG_DECL int nng_pair0_open(nng_socket *);
NNG_DECL int nng_pair1_open(nng_socket *);
NNG_DECL int nng_pub0_open(nng_socket *);
NNG_DECL int nng_sub0_open(nng_socket *);
NNG_DECL int nng_push0_open(nng_socket *);
NNG_DECL int nng_pull0_open(nng_socket *);
NNG_DECL int nng_req0_open(nng_socket *);
NNG_DECL int nng_rep0_open(nng_socket *);
NNG_DECL int nng_surveyor0_open(nng_socket *);
NNG_DECL int nng_respondent0_open(nng_socket *);

// Default versions.  These provide compile time defaults; note that
// the actual protocols are baked into the binary; this should avoid
// suprising.  Choosing a new protocol should be done explicitly.
#define nng_bus_open nng_bus0_open
#define nng_pair_open nng_pair1_open
#define nng_pub_open nng_pub0_open
#define nng_sub_open nng_sub0_open
#define nng_push_open nng_push0_open
#define nng_pull_open nng_pull0_open
#define nng_req_open nng_req0_open
#define nng_rep_open nng_rep0_open
#define nng_surveyor_open nng_surveyor0_open
#define nng_respondent_open nng_respondent0_open

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

#define NNG_OPT_PAIR1_POLY "pair1:polyamorous"

#define NNG_OPT_SUB_SUBSCRIBE "sub:subscribe"
#define NNG_OPT_SUB_UNSUBSCRIBE "sub:unsubscribe"

#define NNG_OPT_REQ_RESENDTIME "req:resend-time"

#define NNG_OPT_SURVEYOR_SURVEYTIME "surveyor:survey-time"

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

// Pollset functionality.  TBD.  (Note that I'd rather avoid this
// altogether, because I believe that the notification mechanism I've
// created offers a superior way to handle this. I don't think many
// direct consumers of nn_poll existed in the wild, except via nn_device().
// I suspect that there not even many nn_device() consumers.)

// Symbol name and visibility.  TBD.  The only symbols that really should
// be directly exported to runtimes IMO are the option symbols.  And frankly
// they have enough special logic around them that it might be best not to
// automate the promotion of them to other APIs.  This is an area open
// for discussion.

// Error codes.  These may happen to align to errnos used on your platform,
// but do not count on this.
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

#ifdef __cplusplus
}
#endif

#endif // NNG_H
