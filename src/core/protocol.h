//
// Copyright 2016 Garrett D'Amore <garrett@damore.org>
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
struct nni_proto_pipe {
	// pipe_init creates the protocol-specific per pipe data structure.
	// The last argument is the per-socket protocol private data.
	int	(*pipe_init)(void **, nni_pipe *, void *);

	// pipe_fini releases any pipe data structures.  This is called after
	// the pipe has been removed from the protocol, and the generic
	// pipe threads have been stopped.
	void	(*pipe_fini)(void *);

	// pipe_add is called to register a pipe with the protocol.  The
	// protocol can reject this, for example if another pipe is already
	// active on a 1:1 protocol.  The protocol may not block during this,
	// as the socket lock is held.
	int	(*pipe_add)(void *);

	// pipe_rem is called to unregister a pipe from the protocol.
	// Threads may still acccess data structures, so the protocol
	// should not free anything yet.  This is called with the socket
	// lock held, so the protocol may not call back into the socket, and
	// must not block.
	void	(*pipe_rem)(void *);

	// pipe_send is a function run in a thread per pipe, to process
	// send activity.  This can be NULL.
	void	(*pipe_send)(void *);

	// pipe_recv is a function run in a thread per pipe, to process
	// receive activity.  While this can be NULL, it should NOT be, as
	// otherwise the protocol may not be able to discover the closure of
	// the underlying transport (such as a remote disconnect).
	void	(*pipe_recv)(void *);
};

struct nni_proto {
	uint16_t		proto_self;     // our 16-bit protocol ID
	uint16_t		proto_peer;     // who we peer with (ID)
	const char *		proto_name;     // string version of our name
	const nni_proto_pipe *	proto_pipe;     // Per-pipe operations.

	// Create protocol instance, which will be stored on the socket.
	int			(*proto_init)(void **, nni_sock *);

	// Destroy the protocol instance.
	void			(*proto_fini)(void *);

	// Option manipulation.  These may be NULL.
	int			(*proto_setopt)(void *, int, const void *,
	    size_t);
	int			(*proto_getopt)(void *, int, void *, size_t *);

	// Receive filter.  This may be NULL, but if it isn't, then
	// messages coming into the system are routed here just before being
	// delivered to the application.  To drop the message, the prtocol
	// should return NULL, otherwise the message (possibly modified).
	nni_msg *		(*proto_recv_filter)(void *, nni_msg *);

	// Send filter.  This may be NULL, but if it isn't, then messages
	// here are filtered just after they come from the application.
	nni_msg *		(*proto_send_filter)(void *, nni_msg *);
};

// These functions are not used by protocols, but rather by the socket
// core implementation. The lookups can be used by transports as well.
extern nni_proto *nni_proto_find(uint16_t);
extern const char *nni_proto_name(uint16_t);
extern uint16_t nni_proto_number(const char *);
extern uint16_t nni_proto_peer(uint16_t);

#endif // CORE_PROTOCOL_H
