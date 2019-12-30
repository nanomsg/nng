//
// Copyright 2019 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
// Copyright 2018 Devolutions <info@devolutions.net>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <string.h>

#include "core/nng_impl.h"

// Inproc transport.  This just transports messages from one
// peer to another.  The inproc transport is only valid within the same
// process.

typedef struct inproc_pair inproc_pair;
typedef struct inproc_pipe inproc_pipe;
typedef struct inproc_ep   inproc_ep;

typedef struct {
	nni_mtx  mx;
	nni_list servers;
} inproc_global;

// inproc_pipe represents one half of a connection.
struct inproc_pipe {
	const char * addr;
	inproc_pair *pair;
	nni_msgq *   rq;
	nni_msgq *   wq;
	nni_pipe *   npipe;
	uint16_t     peer;
	uint16_t     proto;
};

// inproc_pair represents a pair of pipes.  Because we control both
// sides of the pipes, we can allocate and free this in one structure.
struct inproc_pair {
	nni_mtx      mx;
	int          refcnt;
	nni_msgq *   q[2];
	inproc_pipe *pipes[2];
};

struct inproc_ep {
	const char *  addr;
	bool          listener;
	nni_list_node node;
	uint16_t      proto;
	nni_cv        cv;
	nni_list      clients;
	nni_list      aios;
	size_t        rcvmax;
	nni_mtx       mtx;
	nni_dialer *  ndialer;
	nni_listener *nlistener;
};

// nni_inproc is our global state - this contains the list of active endpoints
// which we use for coordinating rendezvous.
static inproc_global nni_inproc;

static int
inproc_init(void)
{
	NNI_LIST_INIT(&nni_inproc.servers, inproc_ep, node);

	nni_mtx_init(&nni_inproc.mx);
	return (0);
}

static void
inproc_fini(void)
{
	nni_mtx_fini(&nni_inproc.mx);
}

static void
inproc_pipe_close(void *arg)
{
	inproc_pipe *pipe = arg;

	if (pipe->rq != NULL) {
		nni_msgq_close(pipe->rq);
	}
	if (pipe->wq != NULL) {
		nni_msgq_close(pipe->wq);
	}
}

// inproc_pair destroy is called when both pipe-ends of the pipe
// have been destroyed.
static void
inproc_pair_destroy(inproc_pair *pair)
{
	nni_msgq_fini(pair->q[0]);
	nni_msgq_fini(pair->q[1]);
	nni_mtx_fini(&pair->mx);
	NNI_FREE_STRUCT(pair);
}

static int
inproc_pipe_alloc(inproc_pipe **pipep, inproc_ep *ep)
{
	inproc_pipe *pipe;

	if ((pipe = NNI_ALLOC_STRUCT(pipe)) == NULL) {
		return (NNG_ENOMEM);
	}

	pipe->proto = ep->proto;
	pipe->addr  = ep->addr;
	*pipep      = pipe;
	return (0);
}

static int
inproc_pipe_init(void *arg, nni_pipe *p)
{
	inproc_pipe *pipe = arg;
	pipe->npipe       = p;

	return (0);
}

static void
inproc_pipe_fini(void *arg)
{
	inproc_pipe *pipe = arg;
	inproc_pair *pair;

	if ((pair = pipe->pair) != NULL) {
		// If we are the last peer, then toss the pair structure.
		nni_mtx_lock(&pair->mx);
		if (pair->pipes[0] == pipe) {
			pair->pipes[0] = NULL;
		} else if (pair->pipes[1] == pipe) {
			pair->pipes[1] = NULL;
		}
		pair->refcnt--;
		if (pair->refcnt == 0) {
			nni_mtx_unlock(&pair->mx);
			inproc_pair_destroy(pair);
		} else {
			nni_mtx_unlock(&pair->mx);
		}
	}

	NNI_FREE_STRUCT(pipe);
}

static void
inproc_pipe_send(void *arg, nni_aio *aio)
{
	inproc_pipe *pipe = arg;
	nni_msg *    msg  = nni_aio_get_msg(aio);
	char *       h;
	size_t       l;
	int          rv;

	// We need to move any header data to the body, because the other
	// side won't know what to do otherwise.
	h = nni_msg_header(msg);
	l = nni_msg_header_len(msg);
	if ((rv = nni_msg_insert(msg, h, l)) != 0) {
		nni_aio_finish(aio, rv, nni_aio_count(aio));
		return;
	}
	nni_msg_header_chop(msg, l);
	nni_msgq_aio_put(pipe->wq, aio);
}

static void
inproc_pipe_recv(void *arg, nni_aio *aio)
{
	inproc_pipe *pipe = arg;

	nni_msgq_aio_get(pipe->rq, aio);
}

static uint16_t
inproc_pipe_peer(void *arg)
{
	inproc_pipe *pipe = arg;

	return (pipe->peer);
}

static int
inproc_pipe_get_addr(void *arg, void *buf, size_t *szp, nni_opt_type t)
{
	inproc_pipe *p = arg;
	nni_sockaddr sa;

	memset(&sa, 0, sizeof(sa));
	sa.s_inproc.sa_family = NNG_AF_INPROC;
	nni_strlcpy(sa.s_inproc.sa_name, p->addr, sizeof(sa.s_inproc.sa_name));
	return (nni_copyout_sockaddr(&sa, buf, szp, t));
}

static int
inproc_dialer_init(void **epp, nni_url *url, nni_dialer *ndialer)
{
	inproc_ep *ep;
	nni_sock * sock = nni_dialer_sock(ndialer);

	if ((ep = NNI_ALLOC_STRUCT(ep)) == NULL) {
		return (NNG_ENOMEM);
	}
	nni_mtx_init(&ep->mtx);

	ep->listener = false;
	ep->proto    = nni_sock_proto_id(sock);
	ep->rcvmax   = 0;
	ep->ndialer  = ndialer;
	NNI_LIST_INIT(&ep->clients, inproc_ep, node);
	nni_aio_list_init(&ep->aios);

	ep->addr = url->u_rawurl; // we match on the full URL.

	*epp = ep;
	return (0);
}

static int
inproc_listener_init(void **epp, nni_url *url, nni_listener *nlistener)
{
	inproc_ep *ep;
	nni_sock * sock = nni_listener_sock(nlistener);

	if ((ep = NNI_ALLOC_STRUCT(ep)) == NULL) {
		return (NNG_ENOMEM);
	}
	nni_mtx_init(&ep->mtx);

	ep->listener  = true;
	ep->proto     = nni_sock_proto_id(sock);
	ep->rcvmax    = 0;
	ep->nlistener = nlistener;
	NNI_LIST_INIT(&ep->clients, inproc_ep, node);
	nni_aio_list_init(&ep->aios);

	ep->addr = url->u_rawurl; // we match on the full URL.

	*epp = ep;
	return (0);
}

static void
inproc_ep_fini(void *arg)
{
	inproc_ep *ep = arg;
	nni_mtx_fini(&ep->mtx);
	NNI_FREE_STRUCT(ep);
}

static void
inproc_conn_finish(nni_aio *aio, int rv, inproc_ep *ep, inproc_pipe *pipe)
{
	nni_aio_list_remove(aio);

	if ((ep != NULL) && (!ep->listener) && nni_list_empty(&ep->aios)) {
		nni_list_node_remove(&ep->node);
	}

	if (rv == 0) {
		nni_aio_set_output(aio, 0, pipe);
		nni_aio_finish(aio, 0, 0);
	} else {
		if (ep != NULL) {
			if (ep->ndialer != NULL) {
				nni_dialer_bump_error(ep->ndialer, rv);
			} else {
				nni_listener_bump_error(ep->nlistener, rv);
			}
		}
		NNI_ASSERT(pipe == NULL);
		nni_aio_finish_error(aio, rv);
	}
}

static void
inproc_ep_close(void *arg)
{
	inproc_ep *ep = arg;
	inproc_ep *client;
	nni_aio *  aio;

	nni_mtx_lock(&nni_inproc.mx);
	if (nni_list_active(&nni_inproc.servers, ep)) {
		nni_list_remove(&nni_inproc.servers, ep);
	}
	// Notify any waiting clients that we are closed.
	while ((client = nni_list_first(&ep->clients)) != NULL) {
		while ((aio = nni_list_first(&client->aios)) != NULL) {
			inproc_conn_finish(aio, NNG_ECONNREFUSED, ep, NULL);
		}
		nni_list_remove(&ep->clients, client);
	}
	while ((aio = nni_list_first(&ep->aios)) != NULL) {
		inproc_conn_finish(aio, NNG_ECLOSED, ep, NULL);
	}
	nni_mtx_unlock(&nni_inproc.mx);
}

static void
inproc_accept_clients(inproc_ep *srv)
{
	inproc_ep *cli, *nclient;

	nclient = nni_list_first(&srv->clients);
	while ((cli = nclient) != NULL) {
		nni_aio *caio;
		nclient = nni_list_next(&srv->clients, nclient);
		NNI_LIST_FOREACH (&cli->aios, caio) {

			inproc_pipe *cpipe;
			inproc_pipe *spipe;
			inproc_pair *pair;
			nni_aio *    saio;
			int          rv;

			if ((saio = nni_list_first(&srv->aios)) == NULL) {
				// No outstanding accept() calls.
				break;
			}

			if ((pair = NNI_ALLOC_STRUCT(pair)) == NULL) {
				inproc_conn_finish(
				    caio, NNG_ENOMEM, cli, NULL);
				inproc_conn_finish(
				    saio, NNG_ENOMEM, srv, NULL);
				continue;
			}
			nni_mtx_init(&pair->mx);

			spipe = cpipe = NULL;
			if (((rv = inproc_pipe_alloc(&cpipe, cli)) != 0) ||
			    ((rv = inproc_pipe_alloc(&spipe, srv)) != 0) ||
			    ((rv = nni_msgq_init(&pair->q[0], 1)) != 0) ||
			    ((rv = nni_msgq_init(&pair->q[1], 1)) != 0)) {

				if (cpipe != NULL) {
					inproc_pipe_fini(cpipe);
				}
				if (spipe != NULL) {
					inproc_pipe_fini(spipe);
				}
				inproc_conn_finish(caio, rv, cli, NULL);
				inproc_conn_finish(saio, rv, srv, NULL);
				inproc_pair_destroy(pair);
				continue;
			}

			spipe->peer    = cpipe->proto;
			cpipe->peer    = spipe->proto;
			pair->pipes[0] = cpipe;
			pair->pipes[1] = spipe;
			pair->refcnt   = 2;
			cpipe->pair = spipe->pair = pair;
			cpipe->rq = spipe->wq = pair->q[0];
			cpipe->wq = spipe->rq = pair->q[1];

			inproc_conn_finish(caio, 0, cli, cpipe);
			inproc_conn_finish(saio, 0, srv, spipe);
		}

		if (nni_list_first(&cli->aios) == NULL) {
			// No more outstanding client connects.
			// Normally there should only be one.
			if (nni_list_active(&srv->clients, cli)) {
				nni_list_remove(&srv->clients, cli);
			}
		}
	}
}

static void
inproc_ep_cancel(nni_aio *aio, void *arg, int rv)
{
	inproc_ep *ep = arg;

	nni_mtx_lock(&nni_inproc.mx);
	if (nni_aio_list_active(aio)) {
		nni_aio_list_remove(aio);
		nni_list_node_remove(&ep->node);
		nni_aio_finish_error(aio, rv);
	}
	if (ep->ndialer != NULL) {
		nni_dialer_bump_error(ep->ndialer, rv);
	} else {
		nni_listener_bump_error(ep->nlistener, rv);
	}
	nni_mtx_unlock(&nni_inproc.mx);
}

static void
inproc_ep_connect(void *arg, nni_aio *aio)
{
	inproc_ep *ep = arg;
	inproc_ep *server;
	int        rv;

	if (nni_aio_begin(aio) != 0) {
		return;
	}

	nni_mtx_lock(&nni_inproc.mx);

	// Find a server.
	NNI_LIST_FOREACH (&nni_inproc.servers, server) {
		if (strcmp(server->addr, ep->addr) == 0) {
			break;
		}
	}
	if (server == NULL) {
		nni_mtx_unlock(&nni_inproc.mx);
		nni_dialer_bump_error(ep->ndialer, NNG_ECONNREFUSED);
		nni_aio_finish_error(aio, NNG_ECONNREFUSED);
		return;
	}

	// We don't have to worry about the case where a zero timeout
	// on connect was specified, as there is no option to specify
	// that in the upper API.
	if ((rv = nni_aio_schedule(aio, inproc_ep_cancel, ep)) != 0) {
		nni_mtx_unlock(&nni_inproc.mx);
		nni_dialer_bump_error(ep->ndialer, rv);
		nni_aio_finish_error(aio, rv);
		return;
	}

	nni_list_append(&server->clients, ep);
	nni_aio_list_append(&ep->aios, aio);

	inproc_accept_clients(server);
	nni_mtx_unlock(&nni_inproc.mx);
}

static int
inproc_ep_bind(void *arg)
{
	inproc_ep *ep = arg;
	inproc_ep *srch;
	nni_list * list = &nni_inproc.servers;

	nni_mtx_lock(&nni_inproc.mx);
	NNI_LIST_FOREACH (list, srch) {
		if (strcmp(srch->addr, ep->addr) == 0) {
			nni_mtx_unlock(&nni_inproc.mx);
			nni_listener_bump_error(ep->nlistener, NNG_EADDRINUSE);
			return (NNG_EADDRINUSE);
		}
	}
	nni_list_append(list, ep);
	nni_mtx_unlock(&nni_inproc.mx);
	return (0);
}

static void
inproc_ep_accept(void *arg, nni_aio *aio)
{
	inproc_ep *ep = arg;
	int        rv;

	if (nni_aio_begin(aio) != 0) {
		return;
	}

	nni_mtx_lock(&nni_inproc.mx);

	// We need not worry about the case where a non-blocking
	// accept was tried -- there is no API to do such a thing.
	if ((rv = nni_aio_schedule(aio, inproc_ep_cancel, ep)) != 0) {
		nni_mtx_unlock(&nni_inproc.mx);
		nni_listener_bump_error(ep->nlistener, rv);
		nni_aio_finish_error(aio, rv);
		return;
	}

	// We are already on the master list of servers, thanks to bind.
	// Insert us into pending server aios, and then run accept list.
	nni_aio_list_append(&ep->aios, aio);
	inproc_accept_clients(ep);
	nni_mtx_unlock(&nni_inproc.mx);
}

static int
inproc_ep_get_recvmaxsz(void *arg, void *v, size_t *szp, nni_opt_type t)
{
	inproc_ep *ep = arg;
	int        rv;
	nni_mtx_lock(&ep->mtx);
	rv = nni_copyout_size(ep->rcvmax, v, szp, t);
	nni_mtx_unlock(&ep->mtx);
	return (rv);
}

static int
inproc_ep_set_recvmaxsz(void *arg, const void *v, size_t sz, nni_opt_type t)
{
	inproc_ep *ep = arg;
	size_t     val;
	int        rv;
	if ((rv = nni_copyin_size(&val, v, sz, 0, NNI_MAXSZ, t)) == 0) {
		nni_mtx_lock(&ep->mtx);
		ep->rcvmax = val;
		nni_mtx_unlock(&ep->mtx);
	}
	return (rv);
}

static int
inproc_ep_get_addr(void *arg, void *v, size_t *szp, nni_opt_type t)
{
	inproc_ep *  ep = arg;
	nng_sockaddr sa;
	sa.s_inproc.sa_family = NNG_AF_INPROC;
	nni_strlcpy(
	    sa.s_inproc.sa_name, ep->addr, sizeof(sa.s_inproc.sa_name));
	return (nni_copyout_sockaddr(&sa, v, szp, t));
}

static const nni_option inproc_pipe_options[] = {
	{
	    .o_name = NNG_OPT_LOCADDR,
	    .o_get  = inproc_pipe_get_addr,
	},
	{
	    .o_name = NNG_OPT_REMADDR,
	    .o_get  = inproc_pipe_get_addr,
	},
	// terminate list
	{
	    .o_name = NULL,
	},
};

static int
inproc_pipe_getopt(
    void *arg, const char *name, void *v, size_t *szp, nni_type t)
{
	return (nni_getopt(inproc_pipe_options, name, arg, v, szp, t));
}

static nni_tran_pipe_ops inproc_pipe_ops = {
	.p_init   = inproc_pipe_init,
	.p_fini   = inproc_pipe_fini,
	.p_send   = inproc_pipe_send,
	.p_recv   = inproc_pipe_recv,
	.p_close  = inproc_pipe_close,
	.p_peer   = inproc_pipe_peer,
	.p_getopt = inproc_pipe_getopt,
};

static const nni_option inproc_ep_options[] = {
	{
	    .o_name = NNG_OPT_RECVMAXSZ,
	    .o_get  = inproc_ep_get_recvmaxsz,
	    .o_set  = inproc_ep_set_recvmaxsz,
	},
	{
	    .o_name = NNG_OPT_LOCADDR,
	    .o_get  = inproc_ep_get_addr,
	},
	{
	    .o_name = NNG_OPT_REMADDR,
	    .o_get  = inproc_ep_get_addr,
	},
	// terminate list
	{
	    .o_name = NULL,
	},
};

static int
inproc_ep_get_option(void *arg, const char *name, void *v, size_t *szp, nni_type t)
{
	return (nni_getopt(inproc_ep_options, name, arg, v, szp, t));
}

static int
inproc_ep_set_option(
    void *arg, const char *name, const void *v, size_t sz, nni_type t)
{
	return (nni_setopt(inproc_ep_options, name, arg, v, sz, t));
}

static nni_chkoption inproc_checkopts[] = {
	{
	    .o_name  = NNG_OPT_RECVMAXSZ,
	    .o_check = nni_check_opt_size,
	},
	{
	    .o_name = NNG_OPT_LOCADDR,
	},
	{
	    .o_name = NNG_OPT_REMADDR,
	},
	{
	    .o_name = NULL,
	},
};

static int
inproc_check_option(const char *name, const void *buf, size_t sz, nni_type t)
{
	int rv;
	rv = nni_chkopt(inproc_checkopts, name, buf, sz, t);
	return (rv);
}

static nni_tran_dialer_ops inproc_dialer_ops = {
	.d_init    = inproc_dialer_init,
	.d_fini    = inproc_ep_fini,
	.d_connect = inproc_ep_connect,
	.d_close   = inproc_ep_close,
	.d_getopt  = inproc_ep_get_option,
	.d_setopt  = inproc_ep_set_option,
};

static nni_tran_listener_ops inproc_listener_ops = {
	.l_init   = inproc_listener_init,
	.l_fini   = inproc_ep_fini,
	.l_bind   = inproc_ep_bind,
	.l_accept = inproc_ep_accept,
	.l_close  = inproc_ep_close,
	.l_getopt = inproc_ep_get_option,
	.l_setopt = inproc_ep_set_option,
};

// This is the inproc transport linkage, and should be the only global
// symbol in this entire file.
struct nni_tran nni_inproc_tran = {
	.tran_version  = NNI_TRANSPORT_VERSION,
	.tran_scheme   = "inproc",
	.tran_dialer   = &inproc_dialer_ops,
	.tran_listener = &inproc_listener_ops,
	.tran_pipe     = &inproc_pipe_ops,
	.tran_init     = inproc_init,
	.tran_fini     = inproc_fini,
	.tran_checkopt = inproc_check_option,
};

int
nng_inproc_register(void)
{
	return (nni_tran_register(&nni_inproc_tran));
}
