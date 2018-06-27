//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef CORE_TRANSPORT_H
#define CORE_TRANSPORT_H

// Endpoint modes.  Currently used by transports.  Remove this when we make
// transport dialers and listeners explicit.
enum nni_ep_mode {
	NNI_EP_MODE_DIAL   = 1,
	NNI_EP_MODE_LISTEN = 2,
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
#define NNI_TRANSPORT_V1 0x54520001
#define NNI_TRANSPORT_V2 0x54520002
#define NNI_TRANSPORT_V3 0x54520003
#define NNI_TRANSPORT_VERSION NNI_TRANSPORT_V3

// Option handlers.
struct nni_tran_option {
	// o_name is the name of the option.
	const char *o_name;

	// o_type is the type of the option.
	nni_opt_type o_type;

	// o_get retrieves the value of the option. The first argument is the
	// dialer, listener, or pipe where the request is being made.
	int (*o_get)(void *, void *, size_t *, nni_opt_type);

	// o_set sets the value of the option.  The first argument is the
	// dialer, listener, or pipe where the request is being made.
	int (*o_set)(void *, const void *, size_t, nni_opt_type);

	// o_chk checks to see if the proposed value is legal -- this is
	// checks only the type, size, and generic range validation.  This
	// function can be called before any transport objects are created.
	int (*o_chk)(const void *, size_t, nni_opt_type);
};

// Endpoint operations are called by the socket in a
// protocol-independent fashion.  The socket makes individual calls,
// which are expected to block if appropriate (except for destroy), or
// run asynchronously if an aio is provided. Endpoints are unable to
// call back into the socket, to prevent recusive entry and deadlock.
//
// For a given endpoint, the framework holds a lock so that each entry
// point is run exclusively of the others. (Transports must still guard
// against any asynchronous operations they manage themselves, though.)

struct nni_tran_dialer_ops {
	// d_init creates a vanilla dialer. The value created is
	// used for the first argument for all other dialer functions.
	int (*d_init)(void **, nni_url *, nni_sock *);

	// d_fini frees the resources associated with the dialer.
	// The dialer will already have been closed.
	void (*d_fini)(void *);

	// d_connect establishes a connection.  It can return errors
	// NNG_EACCESS, NNG_ECONNREFUSED, NNG_EBADADDR,
	// NNG_ECONNFAILED, NNG_ETIMEDOUT, and NNG_EPROTO.
	void (*d_connect)(void *, nni_aio *);

	// d_close stops the dialer from operating altogether.  It
	// does not affect pipes that have already been created.  It is
	// nonblocking.
	void (*d_close)(void *);

	// d_options is an array of dialer options.  The final
	// element must have a NULL name. If this member is NULL, then
	// no dialer specific options are available.
	nni_tran_option *d_options;
};

struct nni_tran_listener_ops {
	// l_init creates a vanilla listener. The value created is
	// used for the first argument for all other listener functions.
	int (*l_init)(void **, nni_url *, nni_sock *);

	// l_fini frees the resources associated with the listener.
	// The listener will already have been closed.
	void (*l_fini)(void *);

	// l_bind just does the bind() and listen() work,
	// reserving the address but not creating any connections.
	// It should return NNG_EADDRINUSE if the address is already
	// taken.  It can also return NNG_EBADADDR for an unsuitable
	// address, or NNG_EACCESS for permission problems.
	int (*l_bind)(void *);

	// l_accept accepts an inbound connection.
	void (*l_accept)(void *, nni_aio *);

	// l_close stops the listener from operating altogether.  It
	// does not affect pipes that have already been created.  It is
	// nonblocking.
	void (*l_close)(void *);

	// l_options is an array of listener options.  The final
	// element must have a NULL name. If this member is NULL, then
	// no dialer specific options are available.
	nni_tran_option *l_options;
};

// Pipe operations are entry points called by the socket. These may be
// called with socket locks held, so it is forbidden for the transport
// to call back into the socket at this point.  (Which is one reason
// pointers back to socket or even enclosing pipe state, are not
// provided.)
struct nni_tran_pipe_ops {
	// p_fini destroys the pipe.  This should clean up all local
	// resources, including closing files and freeing memory, used
	// by the pipe.  After this call returns, the system will not
	// make further calls on the same pipe.
	void (*p_fini)(void *);

	// p_start starts the pipe running.  This gives the transport a
	// chance to hook into any transport specific negotiation
	// phase. The pipe will not have its p_send or p_recv calls
	// started, and will not be access by the "socket" until the
	// pipe has indicated its readiness by finishing the aio.
	void (*p_start)(void *, nni_aio *);

	// p_stop stops the pipe, waiting for any callbacks that are
	// outstanding to complete.  This is done before tearing down
	// resources with p_fini.
	void (*p_stop)(void *);

	// p_aio_send queues the message for transmit.  If this fails,
	// then the caller may try again with the same message (or free
	// it).  If the call succeeds, then the transport has taken
	// ownership of the message, and the caller may not use it
	// again.  The transport will have the responsibility to free
	// the message (nng_msg_free()) when it is finished with it.
	void (*p_send)(void *, nni_aio *);

	// p_recv schedules a message receive. This will be performed
	// even for cases where no data is expected, to allow detection
	// of a remote disconnect.
	void (*p_recv)(void *, nni_aio *);

	// p_close closes the pipe.  Further recv or send operations
	// should return back NNG_ECLOSED.
	void (*p_close)(void *);

	// p_peer returns the peer protocol. This may arrive in
	// whatever transport specific manner is appropriate.
	uint16_t (*p_peer)(void *);

	// p_options is an array of pipe options.  The final element
	// must have a NULL name. If this member is NULL, then no
	// transport specific options are available.
	nni_tran_option *p_options;
};

// Transport implementation details.  Transports must implement the
// interfaces in this file.
struct nni_tran {
	// tran_version is the version of the transport ops that this
	// transport implements.  We only bother to version the main
	// ops vector.
	uint32_t tran_version;

	// tran_scheme is the transport scheme, such as "tcp" or "inproc".
	const char *tran_scheme;

	// tran_dialer links our dialer-specific operations.
	const nni_tran_dialer_ops *tran_dialer;

	// tran_listener links our listener-specific operations.
	const nni_tran_listener_ops *tran_listener;

	// tran_pipe links our pipe-specific operations.
	const nni_tran_pipe_ops *tran_pipe;

	// tran_init, if not NULL, is called once during library
	// initialization.
	int (*tran_init)(void);

	// tran_fini, if not NULL, is called during library deinitialization.
	// It should release any global resources, close any open files, etc.
	void (*tran_fini)(void);
};

// These APIs are used by the framework internally, and not for use by
// transport implementations.
extern nni_tran *nni_tran_find(nni_url *);
extern int       nni_tran_chkopt(const char *, const void *, size_t, int);
extern int       nni_tran_sys_init(void);
extern void      nni_tran_sys_fini(void);
extern int       nni_tran_register(const nni_tran *);

#endif // CORE_TRANSPORT_H
