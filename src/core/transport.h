/*
 * Copyright 2016 Garrett D'Amore <garrett@damore.org>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom
 * the Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
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
	const char *tran_scheme;

	/*
	 * tran_ep_ops links our endpoint operations.
	 */
	const struct nni_endpt_ops *tran_ep_ops;

	/*
	 * tran_pipe_ops links our pipe operations.
	 */
	const struct nni_pipe_ops *tran_pipe_ops;

	/*
	 * tran_init, if not NULL, is called once during library
	 * initialization.
	 */
	int (*tran_init)(void);

	/*
	 * tran_fini, if not NULL, is called during library deinitialization.
	 * It should release any global resources.
	 */
	void (*tran_fini)(void);

	/*
	 * tran_fork, if not NULL, is called just before fork
	 * (e.g. during pthread_atfork() for the prefork phase),
	 * and again just after returning in the parent.  There is
	 * nothing called for the child.  If the transport does not
	 * create any threads of its own, this can be NULL.  (The
	 * intended use is to prevent O_CLOEXEC races.)
	 */
	void (*tran_fork)(int prefork);
};

struct nni_endpt_ops {
	/*
	 * ep_create creates a vanilla endpoint. The value created is
	 * used for the first argument for all other endpoint functions.
	 */
	int (*ep_create)(void **, const char *, uint16_t);

	/*
	 * ep_destroy frees the resources associated with the endpoint.
	 * The endpoint will already have been closed.
	 */
	void (*ep_destroy)(void *);

	/*
	 * ep_dial starts dialing, and creates a new pipe,
	 * which is returned in the final argument.  It can return errors
	 * NNG_EACCESS, NNG_ECONNREFUSED, NNG_EBADADDR, NNG_ECONNFAILED,
	 * NNG_ETIMEDOUT, and NNG_EPROTO.
	 */
	int (*ep_dial)(void *, void **);

	/*
	 * ep_listen just does the bind() and listen() work,
	 * reserving the address but not creating any connections.
	 * It should return NNG_EADDRINUSE if the address is already
	 * taken.  It can also return NNG_EBADADDR for an unsuitable
	 * address, or NNG_EACCESS for permission problems.
	 */
	int (*ep_listen)(void *);

	/*
	 * ep_accept accepts an inbound connection, and creates
	 * a transport pipe, which is returned in the final argument.
	 */
	int (*ep_accept)(void *, void **);

	/*
	 * ep_close stops the endpoint from operating altogether.  It does
	 * not affect pipes that have already been created.
	 */
	void (*ep_close)(void *);

	/* ep_setopt sets an endpoint (transport-specific) option */
	int (*ep_setopt)(void *, int, const void *, size_t);

	/* ep_getopt gets an endpoint (transport-specific) option */
	int (*ep_getopt)(void *, int, void *, size_t *);
};

struct nni_pipe_ops {
	/* p_destroy destroys the pipe */
	void (*p_destroy)(void *);

	/* p_send sends the message */
	int (*p_send)(void *, nng_msg_t);

	/* p_recv recvs the message */
	int (*p_recv)(void *, nng_msg_t *);

	/* p_close closes the pipe */
	void (*p_close)(void *);

	/* p_proto returns the peer protocol */
	uint16_t (*p_proto)(void *);

	/* p_getopt gets an pipe (transport-specific) property */
	int (*p_getopt)(void *, int, void *, size_t *);
};

#endif /* CORE_TRANSPORT_H */
