/*
 * Copyright 2016 Garrett D'Amore <garrett@damore.org>
 *
 * This software is supplied under the terms of the MIT License, a
 * copy of which should be located in the distribution where this
 * file was obtained (LICENSE.txt).  A copy of the license may also be
 * found online at https://opensource.org/licenses/MIT.
 */

#ifndef CORE_TRANSPORT_H
#define CORE_TRANSPORT_H

/*
 * Transport implementation details.  Transports must implement the
 * interfaces in this file.
 */

struct nni_transport {
	/*
	 * tran_scheme is the transport scheme, such as "tcp" or "inproc".
	 */
	const char *			tran_scheme;

	/*
	 * tran_ep_ops links our endpoint operations.
	 */
	const struct nni_endpt_ops *	tran_ep_ops;

	/*
	 * tran_pipe_ops links our pipe operations.
	 */
	const struct nni_pipe_ops *	tran_pipe_ops;

	/*
	 * tran_init, if not NULL, is called once during library
	 * initialization.
	 */
	int				(*tran_init)(void);

	/*
	 * tran_fini, if not NULL, is called during library deinitialization.
	 * It should release any global resources, close any open files, etc.
	 *
	 * There will be no locks held, and no other threads running in the
	 * library.
	 *
	 * It is invalid to use any mutexes, condition variables, or
	 * threading routines.  Mutexes and condition variables may be
	 * safely destroyed.
	 */
	void				(*tran_fini)(void);
};

/*
 * Endpoint operations are called by the socket in a protocol-independent
 * fashion.  The socket makes individual calls, which are expected to block
 * if appropriate (except for destroy). Endpoints are unable to call back
 * into the socket, to prevent recusive entry and deadlock.
 */
struct nni_endpt_ops {
	/*
	 * ep_create creates a vanilla endpoint. The value created is
	 * used for the first argument for all other endpoint functions.
	 */
	int	(*ep_create)(void **, const char *, uint16_t);

	/*
	 * ep_destroy frees the resources associated with the endpoint.
	 * The endpoint will already have been closed.
	 */
	void	(*ep_destroy)(void *);

	/*
	 * ep_dial starts dialing, and creates a new pipe,
	 * which is returned in the final argument.  It can return errors
	 * NNG_EACCESS, NNG_ECONNREFUSED, NNG_EBADADDR, NNG_ECONNFAILED,
	 * NNG_ETIMEDOUT, and NNG_EPROTO.
	 */
	int	(*ep_dial)(void *, void **);

	/*
	 * ep_listen just does the bind() and listen() work,
	 * reserving the address but not creating any connections.
	 * It should return NNG_EADDRINUSE if the address is already
	 * taken.  It can also return NNG_EBADADDR for an unsuitable
	 * address, or NNG_EACCESS for permission problems.
	 */
	int	(*ep_listen)(void *);

	/*
	 * ep_accept accepts an inbound connection, and creates
	 * a transport pipe, which is returned in the final argument.
	 */
	int	(*ep_accept)(void *, void **);

	/*
	 * ep_close stops the endpoint from operating altogether.  It does
	 * not affect pipes that have already been created.
	 */
	void	(*ep_close)(void *);

	/* ep_setopt sets an endpoint (transport-specific) option */
	int	(*ep_setopt)(void *, int, const void *, size_t);

	/* ep_getopt gets an endpoint (transport-specific) option */
	int	(*ep_getopt)(void *, int, void *, size_t *);
};

/*
 * Pipe operations are entry points called by the socket. These may be called
 * with socket locks held, so it is forbidden for the transport to call
 * back into the socket at this point.  (Which is one reason pointers back
 * to socket or even enclosing pipe state, are not provided.)
 */
struct nni_pipe_ops {
	/*
	 * p_destroy destroys the pipe.  This should clean up all local resources,
	 * including closing files and freeing memory, used by the pipe.  After
	 * this call returns, the system will not make further calls on the same
	 * pipe.
	 */
	void		(*p_destroy)(void *);

	/*
	 * p_send sends the message.  If the message cannot be received, then
	 * the caller may try again with the same message (or free it).  If the
	 * call succeeds, then the transport has taken ownership of the message,
	 * and the caller may not use it again.  The transport will have the
	 * responsibility to free the message (nng_msg_free()) when it is
	 * finished with it.
	 */
	int		(*p_send)(void *, nng_msg_t);

	/*
	 * p_recv recvs the message. This is a blocking operation, and a read
	 * will be performed even for cases where no data is expected.  This
	 * allows the socket to detect a closed socket, by the returned error
	 * NNG_ECLOSED. Note that the closed socket condition can arise as either
	 * a result of a remote peer closing the connection, or a synchronous
	 * call to p_close.
	 */
	int		(*p_recv)(void *, nng_msg_t *);

	/*
	 * p_close closes the pipe.  Further recv or send operations should
	 * return back NNG_ECLOSED.
	 */
	void		(*p_close)(void *);

	/*
	 * p_peer returns the peer protocol. This may arrive in whatever
	 * transport specific manner is appropriate.
	 */
	uint16_t	(*p_peer)(void *);

	/*
	 * p_getopt gets an pipe (transport-specific) property.  These values
	 * may not be changed once the pipe is created.
	 */
	int		(*p_getopt)(void *, int, void *, size_t *);
};

/*
 * These APIs are used by the framework internally, and not for use by
 * transport implementations.
 */
extern struct nni_transport *nni_transport_find(const char *);
extern void nni_transport_init(void);
extern void nni_transport_fini(void);

#endif /* CORE_TRANSPORT_H */
