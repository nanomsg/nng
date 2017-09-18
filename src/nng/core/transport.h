//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
// Copyright 2017 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef CORE_TRANSPORT_H
#define CORE_TRANSPORT_H

// Transport implementation details.  Transports must implement the
// interfaces in this file.

struct nni_tran {
	// tran_version is the version of the transport ops that this
	// transport implements.  We only bother to version the main
	// ops vector.
	uint32_t tran_version;

	// tran_scheme is the transport scheme, such as "tcp" or "inproc".
	const char *tran_scheme;

	// tran_ep links our endpoint-specific operations.
	const nni_tran_ep *tran_ep;

	// tran_pipe links our pipe-specific operations.
	const nni_tran_pipe *tran_pipe;

	// tran_chkopt, if not NULL, is used to validate that the
	// option data presented is valid. This allows an option to
	// be set on a socket, even if no endpoints are configured.
	int (*tran_chkopt)(int, const void *, size_t);

	// tran_init, if not NULL, is called once during library
	// initialization.
	int (*tran_init)(void);

	// tran_fini, if not NULL, is called during library deinitialization.
	// It should release any global resources, close any open files, etc.
	void (*tran_fini)(void);
};

// We quite intentionally use a signature where the upper word is nonzero,
// which ensures that if we get garbage we will reject it.  This is more
// likely to mismatch than all zero bytes would.  The actual version is
// stored in the lower word; this is not semver -- the numbers are just
// increasing - we doubt it will increase more than a handful of times
// during the life of the project.  If we add a new version, please keep
// the old version around -- it may be possible to automatically convert
// older versions in the future.
#define NNI_TRANSPORT_V0 0x54520000
#define NNI_TRANSPORT_VERSION NNI_TRANSPORT_V0

// Endpoint operations are called by the socket in a protocol-independent
// fashion.  The socket makes individual calls, which are expected to block
// if appropriate (except for destroy). Endpoints are unable to call back
// into the socket, to prevent recusive entry and deadlock.
struct nni_tran_ep {
	// ep_init creates a vanilla endpoint. The value created is
	// used for the first argument for all other endpoint functions.
	int (*ep_init)(void **, const char *, nni_sock *, int);

	// ep_fini frees the resources associated with the endpoint.
	// The endpoint will already have been closed.
	void (*ep_fini)(void *);

	// ep_connect establishes a connection.  It can return errors
	// NNG_EACCESS, NNG_ECONNREFUSED, NNG_EBADADDR, NNG_ECONNFAILED,
	// NNG_ETIMEDOUT, and NNG_EPROTO.
	void (*ep_connect)(void *, nni_aio *);

	// ep_bind just does the bind() and listen() work,
	// reserving the address but not creating any connections.
	// It should return NNG_EADDRINUSE if the address is already
	// taken.  It can also return NNG_EBADADDR for an unsuitable
	// address, or NNG_EACCESS for permission problems.
	int (*ep_bind)(void *);

	// ep_accept accepts an inbound connection.
	void (*ep_accept)(void *, nni_aio *);

	// ep_close stops the endpoint from operating altogether.  It does
	// not affect pipes that have already been created.
	void (*ep_close)(void *);

	// ep_setopt sets an endpoint (transport-specific) option.
	int (*ep_setopt)(void *, int, const void *, size_t);

	// ep_getopt gets an endpoint (transport-specific) option.
	int (*ep_getopt)(void *, int, void *, size_t *);
};

// Pipe operations are entry points called by the socket. These may be called
// with socket locks held, so it is forbidden for the transport to call
// back into the socket at this point.  (Which is one reason pointers back
// to socket or even enclosing pipe state, are not provided.)
struct nni_tran_pipe {
	// p_fini destroys the pipe.  This should clean up all local
	// resources, including closing files and freeing memory, used by
	// the pipe.  After this call returns, the system will not make
	// further calls on the same pipe.
	void (*p_fini)(void *);

	// p_start starts the pipe running.  This gives the transport a
	// chance to hook into any transport specific negotiation phase.
	// The pipe will not have its p_send or p_recv calls started, and
	// will not be access by the "socket" until the pipe has indicated
	// its readiness by finishing the aio.
	void (*p_start)(void *, nni_aio *);

	// p_aio_send queues the message for transmit.  If this fails, then
	// the caller may try again with the same message (or free it).  If
	// the call succeeds, then the transport has taken ownership of the
	// message, and the caller may not use it again.  The transport will
	// have the responsibility to free the message (nng_msg_free()) when
	// it is finished with it.
	void (*p_send)(void *, nni_aio *);

	// p_recv schedules a message receive. This will be performed even for
	// cases where no data is expected, to allow detection of a remote
	// disconnect.
	void (*p_recv)(void *, nni_aio *);

	// p_close closes the pipe.  Further recv or send operations should
	// return back NNG_ECLOSED.
	void (*p_close)(void *);

	// p_peer returns the peer protocol. This may arrive in whatever
	// transport specific manner is appropriate.
	uint16_t (*p_peer)(void *);

	// p_getopt gets an pipe (transport-specific) property.  These values
	// may not be changed once the pipe is created.
	int (*p_getopt)(void *, int, void *, size_t *);
};

// These APIs are used by the framework internally, and not for use by
// transport implementations.
extern nni_tran *nni_tran_find(const char *);
extern int       nni_tran_chkopt(int, const void *, size_t);
extern int       nni_tran_sys_init(void);
extern void      nni_tran_sys_fini(void);
extern int       nni_tran_register(const nni_tran *);

#endif // CORE_TRANSPORT_H
