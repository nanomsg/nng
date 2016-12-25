//
// Copyright 2016 Garrett D'Amore <garrett@damore.org>
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

#include <errno.h>
#include <stddef.h>
#include <stdint.h>

// NNG_DECL is used on declarations to deal with scope.
// For building Windows DLLs, it should be the appropriate
// __declspec().  (We recommend *not* building this library
// as a DLL, but instead linking it statically for your projects
// to minimize questions about link dependencies later.)
#ifndef NNG_DECL
#define NNG_DECL    extern
#endif

// Types common to nng.
typedef struct nng_socket	nng_socket;
typedef struct nng_endpt	nng_endpt;
typedef struct nng_pipe		nng_pipe;
typedef struct nng_msg		nng_msg;
typedef struct nng_event	nng_event;
typedef struct nng_notify	nng_notify;
typedef struct nng_snapshot	nng_snapshot;
typedef struct nng_stat		nng_stat;

// nng_open simply creates a socket of the given class. It returns an
// error code on failure, or zero on success.  The socket starts in cooked
// mode.
NNG_DECL int nng_open(nng_socket **, uint16_t proto);

// nng_close closes the socket, terminating all activity and
// closing any underlying connections and releasing any associated
// resources. Memory associated with the socket is freed, so it is an
// error to reference the socket in any way after this is called. Likewise,
// it is an error to reference any resources such as endpoints or
// pipes associated with the socket.
NNG_DECL int nng_close(nng_socket *);

// nng_protocol returns the protocol number of the socket.
uint16_t nng_protocol(nng_socket *);

// nng_setopt sets an option for a specific socket.
NNG_DECL int nng_setopt(nng_socket *, int, const void *, size_t);

// nng_socket_getopt obtains the option for a socket.
NNG_DECL int nng_getopt(nng_socket *, int, void *, size_t *);

// nng_notify_func is a user function that is executed upon certain
// events.  See below.
typedef void (*nng_notify_func)(nng_event *, void *);

// nng_setnotify sets a notification callback.  The callback will be
// called for any of the requested events, and will be executed on a
// separate thread.  Event delivery is not guaranteed, and can fail
// if events occur more quickly than the callback can handle, or
// if memory or other resources are scarce.
NNG_DECL nng_notify *nng_setnotify(nng_socket *, int, nng_notify_func, void *);

// nng_unsetnotify unregisters a previously registered notification callback.
// Once this returns, the associated callback will not be executed any longer.
// If the callback is running when this called, then it will wait until that
// callback completes.  (The caller of this function should not hold any
// locks acqured by the callback, in order to avoid a deadlock.)
NNG_DECL int nng_unsetnotify(nng_socket *, nng_notify *);

// Event types.  Sockets can have multiple different kind of events.
// Note that these are edge triggered -- therefore the status indicated
// may have changed since the notification occurred.
//
// NNG_EVENT_RECV	- A message is ready for receive.
// NNG_EVENT_SEND	- A message can be sent.
// NNG_EVENT_ERROR	- An error condition on the socket occurred.
// NNG_EVENT_PIPE_ADD	- A new pipe (connection) is added to the socket.
// NNG_EVENT_PIPE_RM	- A pipe (connection) is removed from the socket.
// NNG_EVENT_ENDPT_ADD	- An endpoint is added to the socket.
// NNG_EVENT_ENDPT_RM	- An endpoint is removed from the socket.
#define NNG_EVENT_BIT(x)    (1U << (x))
#define NNG_EVENT_RECV		NNG_EVENT_BIT(0)
#define NNG_EVENT_SEND		NNG_EVENT_BIT(1)
#define NNG_EVENT_ERROR		NNG_EVENT_BIT(2)
#define NNG_EVENT_PIPE_ADD	NNG_EVENT_BIT(3)
#define NNG_EVENT_PIPE_RM	NNG_EVENT_BIT(4)
#define NNG_EVENT_ENDPT_ADD	NNG_EVENT_BIT(5)
#define NNG_EVENT_ENDPT_RM	NNG_EVENT_BIT(6)

// The following functions return more detailed information about the event.
// Some of the values will not make sense for some event types, in which case
// the value returned will be NULL.
NNG_DECL int nng_event_type(nng_event *);
NNG_DECL nng_socket *nng_event_socket(nng_event *);
NNG_DECL nng_endpt *nng_event_endpt(nng_event *);
NNG_DECL nng_pipe *nng_event_pipe(nng_event *);
NNG_DECL const char *nng_event_reason(nng_event *);

// nng_listen creates a listening endpoint with no special options,
// and starts it listening.  It is functionally equivalent to the legacy
// nn_bind(). The underlying endpoint is returned back to the caller in the
// endpt pointer, if it is not NULL.  The flags may be NNG_FLAG_SYNCH to
// indicate that a failure setting the socket up should return an error
// back to the caller immediately.
NNG_DECL int nng_listen(nng_socket *, const char *, nng_endpt **, int);

// nng_dial creates a dialing endpoint, with no special options, and
// starts it dialing.  Dialers have at most one active connection at a time
// This is similar to the legacy nn_connect().  The underlying endpoint
// is returned back to the caller in the endpt pointer, if it is not NULL.
// The flags may be NNG_FLAG_SYNCH to indicate that the first attempt to
// dial will be made synchronously, and a failure condition returned back
// to the caller.  (If the connection is dropped, it will still be
// reconnected in the background -- only the initial connect is synchronous.)
NNG_DECL int nng_dial(nng_socket *, const char *, nng_endpt **, int);

// nng_endpt_create creates an endpoint on the socket, but does not
// start it either dialing or listening.
NNG_DECL int nng_endpt_create(nng_endpt **, nng_socket *, const char *);

// nng_endpt_dial starts the endpoint dialing.  This is only possible if
// the endpoint is not already dialing or listening.
NNG_DECL int nng_endpt_dial(nng_endpt *, int);

// nng_endpt_listen starts the endpoint listening.  This is only possible if
// the endpoint is not already dialing or listening.
NNG_DECL int nng_endpt_listen(nng_endpt *, int);

// nng_endpt_close closes the endpt, shutting down all underlying
// connections and releasing all associated resources.  It is an error to
// refer to the endpoint after this is called.
NNG_DECL int nng_endpt_close(nng_endpt *);

// nng_endpt_setopt sets an option for a specific endpoint.  Note
// endpoint options may not be altered on a running endpoint.
NNG_DECL int nng_endpt_setopt(nng_endpt *, int, void *, size_t);

// nng_endpt_getopt obtains the option for an endpoint.
NNG_DECL int nng_endpt_getopt(nng_endpt *, int, void *, size_t *);

// nng_strerror returns a human readable string associated with the error
// code supplied.
NNG_DECL const char *nng_strerror(int);

// nng_send sends (or arranges to send) the data on the socket.  Note that
// this function may (will!) return before any receiver has actually
// received the data.  The return value will be zero to indicate that the
// socket has accepted the entire data for send, or an errno to indicate
// failure.  The flags may include NNG_FLAG_NONBLOCK.
NNG_DECL int nng_send(nng_socket *, const void *, size_t, int);

// nng_recv receives message data into the socket, up to the supplied size.
// The actual size of the message data will be written to the value pointed
// to by size.  The flags may include NNG_FLAG_NONBLOCK and NNG_FLAG_ALLOC.
// If NNG_FLAG_ALLOC is supplied then the library will allocate memory for
// the caller.  In that case the pointer to the allocated will be stored
// instead of the data itself.  The caller is responsible for freeing the
// associated memory with free().
NNG_DECL int nng_recv(nng_socket *, void *, size_t *, int);

// nng_sendmsg is like nng_send, but offers up a message structure, which
// gives the ability to provide more control over the message, including
// providing backtrace information.  It also can take a message that was
// obtain via nn_recvmsg, allowing for zero copy forwarding.
NNG_DECL int nng_sendmsg(nng_socket *, nng_msg *, int);

// nng_recvmsg is like nng_recv, but is used to obtain a message structure
// as well as the data buffer.  This can be used to obtain more information
// about where the message came from, access raw headers, etc.  It also
// can be passed off directly to nng_sendmsg.
NNG_DECL int nng_recvmsg(nng_socket *, nng_msg **, int);

// Message API.
NNG_DECL int nng_msg_alloc(nng_msg **, size_t);
NNG_DECL void nng_msg_free(nng_msg *);
NNG_DECL int nng_msg_realloc(nng_msg *, size_t);
NNG_DECL void *nng_msg_header(nng_msg *, size_t *);
NNG_DECL void *nng_msg_body(nng_msg *, size_t *);
NNG_DECL int nng_msg_append(nng_msg *, const void *, size_t);
NNG_DECL int nng_msg_prepend(nng_msg *, const void *, size_t);
NNG_DECL int nng_msg_trim(nng_msg *, size_t);
NNG_DECL int nng_msg_trunc(nng_msg *, size_t);
NNG_DECL int nng_msg_append_header(nng_msg *, const void *, size_t);
NNG_DECL int nng_msg_prepend_header(nng_msg *, const void *, size_t);
NNG_DECL int nng_msg_trim_header(nng_msg *, size_t);
NNG_DECL int nng_msg_trunc_header(nng_msg *, size_t);
NNG_DECL int nng_msg_getopt(nng_msg *, int, void *, size_t *);

// Pipe API. Generally pipes are only "observable" to applications, but
// we do permit an application to close a pipe. This can be useful, for
// example during a connection notification, to disconnect a pipe that
// is associated with an invalid or untrusted remote peer.
NNG_DECL int nng_pipe_getopt(nng_pipe *, int, void *, size_t *);
NNG_DECL int nng_pipe_close(nng_pipe *);

// Flags.
#define NNG_FLAG_ALLOC		1       // Recv to allocate receive buffer.
#define NNG_FLAG_NONBLOCK	2       // Non-block send/recv.
#define NNG_FLAG_SYNCH		4       // Synchronous dial / listen

// Protocol numbers.  These are to be used with nng_socket_create().
// These values are used on the wire, so must not be changed.  The major
// number of the protocol is shifted left by 4 bits, and a subprotocol is
// assigned in the lower 4 bits.
//
// There are gaps in the list, which are obsolete or unsupported protocols.
// Protocol numbers are never more than 16 bits.  Also, there will never be
// a valid protocol numbered 0 (NNG_PROTO_NONE).
#define NNG_PROTO(major, minor)    (((major) * 16) + (minor))
#define NNG_PROTO_NONE		NNG_PROTO(0, 0)
#define NNG_PROTO_PAIR		NNG_PROTO(1, 0)
#define NNG_PROTO_PUB		NNG_PROTO(2, 0)
#define NNG_PROTO_SUB		NNG_PROTO(2, 1)
#define NNG_PROTO_REQ		NNG_PROTO(3, 0)
#define NNG_PROTO_REP		NNG_PROTO(3, 1)
#define NNG_PROTO_PUSH		NNG_PROTO(5, 0)
#define NNG_PROTO_PULL		NNG_PROTO(5, 1)
#define NNG_PROTO_SURVEYOR	NNG_PROTO(6, 2)
#define NNG_PROTO_RESPONDENT	NNG_PROTO(6, 3)
#define NNG_PROTO_BUS		NNG_PROTO(7, 0)
#define NNG_PROTO_STAR		NNG_PROTO(100, 0)

// Options. We encode option numbers as follows:
//
// <level>	- 0: socket, 1: transport
// <type>	- zero (socket), or transport (8 bits)
// <code>	- specific value (16 bits)
#define NNG_OPT_SOCKET(c)		(c)
#define NNG_OPT_TRANSPORT_OPT(t, c)	(0x10000 | ((p) << 16) | (c))

#define NNG_OPT_RAW			NNG_OPT_SOCKET(0)
#define NNG_OPT_LINGER			NNG_OPT_SOCKET(1)
#define NNG_OPT_RCVBUF			NNG_OPT_SOCKET(2)
#define NNG_OPT_SNDBUF			NNG_OPT_SOCKET(3)
#define NNG_OPT_RCVTIMEO		NNG_OPT_SOCKET(4)
#define NNG_OPT_SNDTIMEO		NNG_OPT_SOCKET(5)
#define NNG_OPT_RECONN_TIME		NNG_OPT_SOCKET(6)
#define NNG_OPT_RECONN_MAXTIME		NNG_OPT_SOCKET(7)
#define NNG_OPT_RCVMAXSZ		NNG_OPT_SOCKET(8)
#define NNG_OPT_MAXTTL			NNG_OPT_SOCKET(9)
#define NNG_OPT_PROTOCOL		NNG_OPT_SOCKET(10)
#define NNG_OPT_SUBSCRIBE		NNG_OPT_SOCKET(11)
#define NNG_OPT_UNSUBSCRIBE		NNG_OPT_SOCKET(12)
#define NNG_OPT_SURVEYTIME		NNG_OPT_SOCKET(13)
#define NNG_OPT_RESENDTIME		NNG_OPT_SOCKET(14)
#define NNG_OPT_TRANSPORT		NNG_OPT_SOCKET(15)
#define NNG_OPT_LOCALADDR		NNG_OPT_SOCKET(16)
#define NNG_OPT_REMOTEADDR		NNG_OPT_SOCKET(17)
#define NNG_OPT_RECVFD			NNG_OPT_SOCKET(18)
#define NNG_OPT_SENDFD			NNG_OPT_SOCKET(19)

// XXX: TBD: priorities, socket names, ipv4only

// Statistics.  These are for informational purposes only, and subject
// to change without notice.  The API for accessing these is stable,
// but the individual statistic names, values, and meanings are all
// subject to change.

// nng_snapshot_create creates a statistics snapshot.  The snapshot
// object must be deallocated expressly by the user, and may persist beyond
// the lifetime of any socket object used to update it.  Note that the
// values of the statistics are initially unset.
NNG_DECL int nng_snapshot_create(nng_snapshot **);

// nng_snapshot_free frees a snapshot object.  All statistic objects
// contained therein are destroyed as well.
NNG_DECL void nng_snapshot_free(nng_snapshot *);

// nng_snapshot_update updates a snapshot of all the statistics
// relevant to a particular socket.  All prior values are overwritten.
// It is acceptable to use the same snapshot object with different
// sockets.
NNG_DECL int nng_snapshot_update(nng_socket *, nng_snapshot *);

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

#define NNG_STAT_LEVEL		0
#define NNG_STAT_COUNTER	1

// nng_stat_unit provides information about the unit for the statistic,
// such as NNG_UNIT_BYTES or NNG_UNIT_BYTES.  If no specific unit is
// applicable, such as a relative priority, then NN_UNIT_NONE is
// returned.
NNG_DECL int nng_stat_unit(nng_stat *);

#define NNG_UNIT_NONE		0
#define NNG_UNIT_BYTES		1
#define NNG_UNIT_MESSAGES	2
#define NNG_UNIT_BOOLEAN	3
#define NNG_UNIT_MILLIS		4
#define NNG_UNIT_EVENTS		5

// nng_stat_value returns returns the actual value of the statistic.
// Statistic values reflect their value at the time that the corresponding
// snapshot was updated, and are undefined until an update is performed.
NNG_DECL int64_t nng_stat_value(nng_stat *);

// Device functionality.  This connects two sockets together in a device,
// which means that messages from one side are forwarded to the other.
NNG_DECL int nng_device(nng_socket *, nng_socket *);

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
#define NNG_EINTR		(-1)
#define NNG_ENOMEM		(-2)
#define NNG_EINVAL		(-3)
#define NNG_EBUSY		(-4)
#define NNG_ETIMEDOUT		(-5)
#define NNG_ECONNREFUSED	(-6)
#define NNG_ECLOSED		(-7)
#define NNG_EAGAIN		(-8)
#define NNG_ENOTSUP		(-9)
#define NNG_EADDRINUSE		(-10)

// Maximum length of a socket address.  This includes the terminating NUL.
// This limit is built into other implementations, so do not change it.
#define NNG_MAXADDRLEN    (128)

#ifdef __cplusplus
}
#endif

#endif // NNG_H
