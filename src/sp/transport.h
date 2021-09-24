//
// Copyright 2021 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
// Copyright 2018 Devolutions <info@devolutions.net>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef PROTOCOL_SP_TRANSPORT_H
#define PROTOCOL_SP_TRANSPORT_H

#include "core/nng_impl.h"

// Endpoint operations are called by the socket in a
// protocol-independent fashion.  The socket makes individual calls,
// which are expected to block if appropriate (except for destroy), or
// run asynchronously if an aio is provided. Endpoints are unable to
// call back into the socket, to prevent recusive entry and deadlock.
//
// For a given endpoint, the framework holds a lock so that each entry
// point is run exclusively of the others. (Transports must still guard
// against any asynchronous operations they manage themselves, though.)

struct nni_sp_dialer_ops {
	// d_init creates a vanilla dialer. The value created is
	// used for the first argument for all other dialer functions.
	int (*d_init)(void **, nni_url *, nni_dialer *);

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

	// d_getopt is used to obtain an option.
	int (*d_getopt)(void *, const char *, void *, size_t *, nni_type);

	// d_setopt is used to set or change an option.
	int (*d_setopt)(void *, const char *, const void *, size_t, nni_type);

	// d_options is an array of dialer options.  The final
	// element must have a NULL name. If this member is NULL, then
	// no dialer specific options are available.
	nni_option *d_options;
};

struct nni_sp_listener_ops {
	// l_init creates a vanilla listener. The value created is
	// used for the first argument for all other listener functions.
	int (*l_init)(void **, nni_url *, nni_listener *);

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

	// l_getopt is used to obtain an option.
	int (*l_getopt)(void *, const char *, void *, size_t *, nni_type);

	// l_setopt is used to set or change an option.
	int (*l_setopt)(void *, const char *, const void *, size_t, nni_type);

	// l_options is an array of listener options.  The final
	// element must have a NULL name. If this member is NULL, then
	// no dialer specific options are available.
	nni_option *l_options;
};

// Pipe operations are entry points called by the socket. These may be
// called with socket locks held, so it is forbidden for the transport
// to call back into the socket at this point.  (Which is one reason
// pointers back to socket or even enclosing pipe state, are not
// provided.)
struct nni_sp_pipe_ops {
	// p_init initializes the pipe data structures.  The main
	// purpose of this is so that the pipe will see the upper
	// layer nni_pipe and get a chance to register stats and such.
	int (*p_init)(void *, nni_pipe *);

	// p_fini destroys the pipe.  This should clean up all local
	// resources, including closing files and freeing memory, used
	// by the pipe.  After this call returns, the system will not
	// make further calls on the same pipe.
	void (*p_fini)(void *);

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

	// p_getopt is used to obtain an option.  Pipes don't implement
	// option setting.
	int (*p_getopt)(void *, const char *, void *, size_t *, nni_type);
};

// Transport implementation details.  Transports must implement the
// interfaces in this file.
struct nni_sp_tran {
	// tran_link is for framework use only - it must initialized
	// to zero before registration.
	nni_list_node tran_link;

	// tran_scheme is the transport scheme, such as "tcp" or "inproc".
	const char *tran_scheme;

	// tran_dialer links our dialer-specific operations.
	const nni_sp_dialer_ops *tran_dialer;

	// tran_listener links our listener-specific operations.
	const nni_sp_listener_ops *tran_listener;

	// tran_pipe links our pipe-specific operations.
	const nni_sp_pipe_ops *tran_pipe;

	// tran_init is called once during library initialization.
	void (*tran_init)(void);

	// tran_fini is called during library shutdown.
	// It should release any global resources.
	void (*tran_fini)(void);
};

// nni_sp_tran_pipe is one end of a connection.
struct nni_sp_tran_pipe {
	nni_mtx              mtx;
	bool                 closed;
	nni_atomic_flag      reaped;
	nni_sp_tran_ep *     ep;
	nng_stream *         conn;
	nni_pipe *           pipe;
	uint16_t             peer;
	uint16_t             proto;
	size_t               rcvmax;
	uint8_t              rxbuf[sizeof(uint64_t)];
	uint8_t              txbuf[sizeof(uint64_t)];
	size_t               gottxhead;
	size_t               gotrxhead;
	size_t               wanttxhead;
	size_t               wantrxhead;
	nni_list             recvq;
	nni_list             sendq;
	nni_aio              txaio;
	nni_aio              rxaio;
	nni_aio              negoaio;
	nni_msg *            rxmsg;
	nni_list_node        node;
	nni_reap_node        reap;
};

// Stuff that is common to both dialers and listeners.
struct nni_sp_tran_ep {
	nni_mtx              mtx;
	uint16_t             proto;
	size_t               rcvmax;
	bool                 fini;
	bool                 started;
	bool                 closed;
	int                  authmode;
	nng_url *            url;
	const char *         host; // for dialers
	nni_sockaddr         sa;
	int                  refcnt; // active pipes
	nni_aio *            useraio;
	nni_aio *            connaio;
	nni_aio *            timeaio;
	nni_list             busypipes; // busy pipes -- ones passed to socket
	nni_list             waitpipes; // pipes waiting to match to socket
	nni_list             negopipes; // pipes busy negotiating
	nni_reap_node        reap;
	nng_stream_dialer *  dialer;
	nng_stream_listener *listener;

#ifdef NNG_ENABLE_STATS
	nni_stat_item st_rcv_max;
#endif
};

// Some common routines.

void     nni_sp_tran_init(void);
void     nni_sp_tran_fini(void);

int      nni_sp_pipe_init(void *, nni_pipe *);
void     nni_sp_pipe_fini(void *);
void     nni_sp_pipe_stop(void *);
void     nni_sp_pipe_send(void *, nni_aio *);
void     nni_sp_pipe_recv(void *, nni_aio *);
void     nni_sp_pipe_close(void *);
uint16_t nni_sp_pipe_peer(void *);
int      nni_sp_pipe_getopt(void *, const char *, void *, size_t *, nni_type);

int      nni_sp_ep_dialer_init(nni_sp_tran_ep **, nng_url *, nng_url *, nni_sock *);
int      nni_sp_ep_dialer_get(nni_sp_tran_ep *, const nni_option *, const char *, void *, size_t *, nni_type);
int      nni_sp_ep_dialer_set(nni_sp_tran_ep *, const nni_option *, const char *, const void *, size_t, nni_type);
int      nni_sp_ep_listener_init(nni_sp_tran_ep **, nng_url *, nni_sock *);
int      nni_sp_ep_listener_get(nni_sp_tran_ep *, const nni_option *, const char *, void *, size_t *, nni_type);
int      nni_sp_ep_listener_set(nni_sp_tran_ep *, const nni_option *, const char *, const void *, size_t, nni_type);
void     nni_sp_ep_fini(void *);
void     nni_sp_ep_close(void *);
int      nni_sp_ep_bind(void *);
void     nni_sp_ep_accept(void *, nni_aio *);
void     nni_sp_ep_connect(void *, nni_aio *);
void     nni_sp_ep_match(nni_sp_tran_ep *);

int      nni_sp_ep_get_url(void *arg, void *v, size_t *szp, nni_opt_type t);
int      nni_sp_ep_get_recvmaxsz(void *arg, void *v, size_t *szp, nni_opt_type t);
int      nni_sp_ep_set_recvmaxsz(void *arg, const void *v, size_t sz, nni_opt_type t);

int      nni_sp_url_parse_source(nni_url *url, nng_sockaddr *sa, const nni_url *surl,
				 int (* getaf)(const nni_url *, int *));

// These APIs are used by the framework internally, and not for use by
// transport implementations.
extern nni_sp_tran *nni_sp_tran_find(nni_url *);
extern void         nni_sp_tran_sys_init(void);
extern void         nni_sp_tran_sys_fini(void);
extern void         nni_sp_tran_register(nni_sp_tran *);

#endif // PROTOCOL_SP_TRANSPORT_H
