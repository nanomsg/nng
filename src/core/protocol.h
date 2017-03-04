//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef CORE_PROTOCOL_H
#define CORE_PROTOCOL_H

// Protocol implementation details.  Protocols must implement the
// interfaces in this file.  Note that implementing new protocols is
// not necessarily intended to be a trivial task.  The protocol developer
// must understand the nature of nng, as they are responsible for handling
// most of the logic.  The protocol generally does most of the work for
// locking, and calls into the transport's pipe functions to do actual
// work, and the pipe functions generally assume no locking is needed.
// As a consequence, most of the concurrency in nng exists in the protocol
// implementations.

// nni_proto_pipe contains protocol-specific per-pipe operations.
struct nni_proto_pipe_ops {
	// pipe_init creates the protocol-specific per pipe data structure.
	// The last argument is the per-socket protocol private data.
	int		(*pipe_init)(void **, nni_pipe *, void *);

	// pipe_fini releases any pipe data structures.  This is called after
	// the pipe has been removed from the protocol, and the generic
	// pipe threads have been stopped.
	void		(*pipe_fini)(void *);

	// pipe_add is called to register a pipe with the protocol.  The
	// protocol can reject this, for example if another pipe is already
	// active on a 1:1 protocol.  The protocol may not block during this,
	// as the socket lock is held.
	int		(*pipe_add)(void *);

	// pipe_rem is called to unregister a pipe from the protocol.
	// Threads may still acccess data structures, so the protocol
	// should not free anything yet.  This is called with the socket
	// lock held, so the protocol may not call back into the socket, and
	// must not block.
	void		(*pipe_rem)(void *);

	// Worker functions.  If non-NULL, each worker is executed and
	// given the protocol pipe data as a argument.  All workers are
	// started, or none are started.  The pipe_fini function is obliged
	// to ensure that workers have exited.
	nni_worker	pipe_worker[NNI_MAXWORKERS];
};

struct nni_proto_sock_ops {
	// sock_initf creates the protocol instance, which will be stored on
	// the socket. This is run without the sock lock held, and allocates
	// storage or other resources for the socket.
	int		(*sock_init)(void **, nni_sock *);

	// sock_fini destroys the protocol instance.  This is run without the
	// socket lock held, and is intended to release resources.  It may
	// block as needed.
	void		(*sock_fini)(void *);

	// Open the protocol instance.  This is run with the lock held,
	// and intended to allow the protocol to start any asynchronous
	// processing.
	void		(*sock_open)(void *);

	// Close the protocol instance.  This is run with the lock held,
	// and intended to initiate closure of the socket.  For example,
	// it can signal the socket worker threads to exit.
	void		(*sock_close)(void *);

	// Option manipulation.  These may be NULL.
	int		(*sock_setopt)(void *, int, const void *, size_t);
	int		(*sock_getopt)(void *, int, void *, size_t *);

	// Receive filter.  This may be NULL, but if it isn't, then
	// messages coming into the system are routed here just before being
	// delivered to the application.  To drop the message, the prtocol
	// should return NULL, otherwise the message (possibly modified).
	nni_msg *	(*sock_rfilter)(void *, nni_msg *);

	// Send filter.  This may be NULL, but if it isn't, then messages
	// here are filtered just after they come from the application.
	nni_msg *	(*sock_sfilter)(void *, nni_msg *);

	// Worker functions.  If non-NULL, each worker is executed and given
	// the protocol socket data as an argument.  These will all be started
	// at about the same time, and all will be started, or none will be
	// started.  They are obliged to exit in response to sock_close.
	nni_worker	sock_worker[NNI_MAXWORKERS];
};

struct nni_proto {
	uint16_t			proto_self;     // our 16-bit D
	uint16_t			proto_peer;     // who we peer with (ID)
	const char *			proto_name;     // Our name
	uint32_t			proto_flags;    // Protocol flags
	const nni_proto_sock_ops *	proto_sock_ops; // Per-socket opeations
	const nni_proto_pipe_ops *	proto_pipe_ops; // Per-pipe operations.
};

// These flags determine which operations make sense.  We use them so that
// we can reject attempts to create notification fds for operations that make
// no sense.
#define NNI_PROTO_FLAG_RCV		1       // Protocol can receive
#define NNI_PROTO_FLAG_SND		2       // Protocol can send
#define NNI_PROTO_FLAG_SNDRCV		3       // Protocol can both send & recv

// These functions are not used by protocols, but rather by the socket
// core implementation. The lookups can be used by transports as well.
extern nni_proto *nni_proto_find(uint16_t);
extern const char *nni_proto_name(uint16_t);
extern uint16_t nni_proto_number(const char *);
extern uint16_t nni_proto_peer(uint16_t);

#endif // CORE_PROTOCOL_H
