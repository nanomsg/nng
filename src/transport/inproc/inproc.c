//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/nng_impl.h"

// Inproc transport.  This just transports messages from one
// peer to another.  The inproc transport is only valid within the same
// process.

typedef struct nni_inproc_pair nni_inproc_pair;
typedef struct nni_inproc_pipe nni_inproc_pipe;
typedef struct nni_inproc_ep   nni_inproc_ep;

typedef struct {
	nni_mtx  mx;
	nni_list servers;
} nni_inproc_global;

// nni_inproc_pipe represents one half of a connection.
struct nni_inproc_pipe {
	const char *     addr;
	nni_inproc_pair *pair;
	nni_msgq *       rq;
	nni_msgq *       wq;
	uint16_t         peer;
	uint16_t         proto;
};

// nni_inproc_pair represents a pair of pipes.  Because we control both
// sides of the pipes, we can allocate and free this in one structure.
struct nni_inproc_pair {
	nni_mtx          mx;
	int              refcnt;
	nni_msgq *       q[2];
	nni_inproc_pipe *pipes[2];
};

struct nni_inproc_ep {
	const char *  addr;
	int           mode;
	nni_list_node node;
	uint16_t      proto;
	nni_cv        cv;
	nni_list      clients;
	nni_list      aios;
};

// nni_inproc is our global state - this contains the list of active endpoints
// which we use for coordinating rendezvous.
static nni_inproc_global nni_inproc;

static int
nni_inproc_init(void)
{
	NNI_LIST_INIT(&nni_inproc.servers, nni_inproc_ep, node);

	nni_mtx_init(&nni_inproc.mx);
	return (0);
}

static void
nni_inproc_fini(void)
{
	nni_mtx_fini(&nni_inproc.mx);
}

static void
nni_inproc_pipe_close(void *arg)
{
	nni_inproc_pipe *pipe = arg;

	if (pipe->rq != NULL) {
		nni_msgq_close(pipe->rq);
	}
	if (pipe->wq != NULL) {
		nni_msgq_close(pipe->wq);
	}
}

// nni_inproc_pair destroy is called when both pipe-ends of the pipe
// have been destroyed.
static void
nni_inproc_pair_destroy(nni_inproc_pair *pair)
{
	nni_msgq_fini(pair->q[0]);
	nni_msgq_fini(pair->q[1]);
	nni_mtx_fini(&pair->mx);
	NNI_FREE_STRUCT(pair);
}

static int
nni_inproc_pipe_init(nni_inproc_pipe **pipep, nni_inproc_ep *ep)
{
	nni_inproc_pipe *pipe;

	if ((pipe = NNI_ALLOC_STRUCT(pipe)) == NULL) {
		return (NNG_ENOMEM);
	}
	pipe->proto = ep->proto;
	pipe->addr  = ep->addr;
	*pipep      = pipe;
	return (0);
}

static void
nni_inproc_pipe_fini(void *arg)
{
	nni_inproc_pipe *pipe = arg;
	nni_inproc_pair *pair;

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
			nni_inproc_pair_destroy(pair);
		} else {
			nni_mtx_unlock(&pair->mx);
		}
	}

	NNI_FREE_STRUCT(pipe);
}

static void
nni_inproc_pipe_send(void *arg, nni_aio *aio)
{
	nni_inproc_pipe *pipe = arg;
	nni_msg *        msg  = aio->a_msg;
	char *           h;
	size_t           l;
	int              rv;

	// We need to move any header data to the body, because the other
	// side won't know what to do otherwise.
	h = nni_msg_header(msg);
	l = nni_msg_header_len(msg);
	if ((rv = nni_msg_insert(msg, h, l)) != 0) {
		nni_aio_finish(aio, rv, aio->a_count);
		return;
	}
	nni_msg_header_chop(msg, l);
	nni_msgq_aio_put(pipe->wq, aio);
}

static void
nni_inproc_pipe_recv(void *arg, nni_aio *aio)
{
	nni_inproc_pipe *pipe = arg;

	nni_msgq_aio_get(pipe->rq, aio);
}

static uint16_t
nni_inproc_pipe_peer(void *arg)
{
	nni_inproc_pipe *pipe = arg;

	return (pipe->peer);
}

static int
nni_inproc_pipe_get_addr(void *arg, void *buf, size_t *szp)
{
	nni_inproc_pipe *p = arg;
	nni_sockaddr     sa;

	memset(&sa, 0, sizeof(sa));
	sa.s_un.s_inproc.sa_family = NNG_AF_INPROC;
	nni_strlcpy(sa.s_un.s_inproc.sa_path, p->addr,
	    sizeof(sa.s_un.s_inproc.sa_path));
	return (nni_getopt_sockaddr(&sa, buf, szp));
}

static int
nni_inproc_ep_init(void **epp, nni_url *url, nni_sock *sock, int mode)
{
	nni_inproc_ep *ep;

	if ((ep = NNI_ALLOC_STRUCT(ep)) == NULL) {
		return (NNG_ENOMEM);
	}

	ep->mode  = mode;
	ep->proto = nni_sock_proto(sock);
	NNI_LIST_INIT(&ep->clients, nni_inproc_ep, node);
	nni_aio_list_init(&ep->aios);

	ep->addr = url->u_rawurl; // we match on the full URL.
	*epp     = ep;
	return (0);
}

static void
nni_inproc_ep_fini(void *arg)
{
	nni_inproc_ep *ep = arg;

	NNI_FREE_STRUCT(ep);
}

static void
nni_inproc_conn_finish(nni_aio *aio, int rv)
{
	nni_inproc_ep *ep = aio->a_prov_extra[0];
	void *         pipe;

	nni_aio_list_remove(aio);
	pipe        = aio->a_pipe;
	aio->a_pipe = NULL;

	if ((ep != NULL) && (ep->mode != NNI_EP_MODE_LISTEN) &&
	    nni_list_empty(&ep->aios)) {
		nni_list_node_remove(&ep->node);
	}

	if (rv == 0) {
		nni_aio_finish_pipe(aio, pipe);
	} else {
		if (pipe != NULL) {
			nni_inproc_pipe_fini(pipe);
		}
		nni_aio_finish_error(aio, rv);
	}
}

static void
nni_inproc_ep_close(void *arg)
{
	nni_inproc_ep *ep = arg;
	nni_inproc_ep *client;
	nni_aio *      aio;

	nni_mtx_lock(&nni_inproc.mx);
	if (nni_list_active(&nni_inproc.servers, ep)) {
		nni_list_remove(&nni_inproc.servers, ep);
	}
	// Notify any waiting clients that we are closed.
	while ((client = nni_list_first(&ep->clients)) != NULL) {
		while ((aio = nni_list_first(&client->aios)) != NULL) {
			nni_inproc_conn_finish(aio, NNG_ECONNREFUSED);
		}
		nni_list_remove(&ep->clients, client);
	}
	while ((aio = nni_list_first(&ep->aios)) != NULL) {
		nni_inproc_conn_finish(aio, NNG_ECLOSED);
	}
	nni_mtx_unlock(&nni_inproc.mx);
}

static void
nni_inproc_accept_clients(nni_inproc_ep *server)
{
	nni_inproc_ep *  client, *nclient;
	nni_aio *        saio, *caio;
	nni_inproc_pair *pair;
	int              rv;

	nclient = nni_list_first(&server->clients);
	while ((client = nclient) != NULL) {
		nclient = nni_list_next(&server->clients, nclient);
		NNI_LIST_FOREACH (&client->aios, caio) {
			if ((saio = nni_list_first(&server->aios)) == NULL) {
				// No outstanding accept() calls.
				break;
			}

			if ((pair = NNI_ALLOC_STRUCT(pair)) == NULL) {
				nni_inproc_conn_finish(caio, NNG_ENOMEM);
				nni_inproc_conn_finish(saio, NNG_ENOMEM);
				continue;
			}

			if (((rv = nni_msgq_init(&pair->q[0], 4)) != 0) ||
			    ((rv = nni_msgq_init(&pair->q[1], 4)) != 0)) {
				nni_inproc_pair_destroy(pair);
				nni_inproc_conn_finish(caio, rv);
				nni_inproc_conn_finish(saio, rv);
				continue;
			}

			nni_mtx_init(&pair->mx);

			pair->pipes[0]     = caio->a_pipe;
			pair->pipes[1]     = saio->a_pipe;
			pair->pipes[0]->rq = pair->pipes[1]->wq = pair->q[0];
			pair->pipes[1]->rq = pair->pipes[0]->wq = pair->q[1];
			pair->pipes[0]->pair = pair->pipes[1]->pair = pair;
			pair->pipes[1]->peer = pair->pipes[0]->proto;
			pair->pipes[0]->peer = pair->pipes[1]->proto;
			pair->refcnt         = 2;

			nni_inproc_conn_finish(caio, 0);
			nni_inproc_conn_finish(saio, 0);
		}

		if (nni_list_first(&client->aios) == NULL) {
			// No more outstanding client connects.  Normally
			// there should only be one.
			if (nni_list_active(&server->clients, client)) {
				nni_list_remove(&server->clients, client);
			}
		}
	}
}

static void
nni_inproc_ep_cancel(nni_aio *aio, int rv)
{
	nni_inproc_ep *  ep = aio->a_prov_data;
	nni_inproc_pipe *pipe;

	nni_mtx_lock(&nni_inproc.mx);
	if (nni_aio_list_active(aio)) {
		nni_aio_list_remove(aio);
		nni_list_node_remove(&ep->node);
		if ((pipe = aio->a_pipe) != NULL) {
			aio->a_pipe = NULL;
			nni_inproc_pipe_fini(pipe);
		}
		nni_aio_finish_error(aio, rv);
	}
	nni_mtx_unlock(&nni_inproc.mx);
}

static void
nni_inproc_ep_connect(void *arg, nni_aio *aio)
{
	nni_inproc_ep *ep = arg;
	nni_inproc_ep *server;
	int            rv;

	if (ep->mode != NNI_EP_MODE_DIAL) {
		nni_aio_finish_error(aio, NNG_EINVAL);
		return;
	}
	nni_mtx_lock(&nni_inproc.mx);

	if ((rv = nni_aio_start(aio, nni_inproc_ep_cancel, ep)) != 0) {
		nni_mtx_unlock(&nni_inproc.mx);
		return;
	}

	aio->a_prov_extra[0] = ep;
	if ((rv = nni_inproc_pipe_init((void *) &aio->a_pipe, ep)) != 0) {
		nni_aio_finish_error(aio, rv);
		nni_mtx_unlock(&nni_inproc.mx);
		return;
	}

	// Find a server.
	NNI_LIST_FOREACH (&nni_inproc.servers, server) {
		if (strcmp(server->addr, ep->addr) == 0) {
			break;
		}
	}
	if (server == NULL) {
		nni_inproc_conn_finish(aio, NNG_ECONNREFUSED);
		nni_mtx_unlock(&nni_inproc.mx);
		return;
	}

	nni_list_append(&server->clients, ep);
	nni_aio_list_append(&ep->aios, aio);

	nni_inproc_accept_clients(server);
	nni_mtx_unlock(&nni_inproc.mx);
}

static int
nni_inproc_ep_bind(void *arg)
{
	nni_inproc_ep *ep = arg;
	nni_inproc_ep *srch;
	nni_list *     list = &nni_inproc.servers;

	nni_mtx_lock(&nni_inproc.mx);
	NNI_LIST_FOREACH (list, srch) {
		if (strcmp(srch->addr, ep->addr) == 0) {
			nni_mtx_unlock(&nni_inproc.mx);
			return (NNG_EADDRINUSE);
		}
	}
	nni_list_append(list, ep);
	nni_mtx_unlock(&nni_inproc.mx);
	return (0);
}

static void
nni_inproc_ep_accept(void *arg, nni_aio *aio)
{
	nni_inproc_ep *ep = arg;
	int            rv;

	nni_mtx_lock(&nni_inproc.mx);

	if ((rv = nni_aio_start(aio, nni_inproc_ep_cancel, ep)) != 0) {
		nni_mtx_unlock(&nni_inproc.mx);
		return;
	}

	aio->a_prov_extra[0] = ep;

	// We are already on the master list of servers, thanks to bind.

	if ((rv = nni_inproc_pipe_init((void *) &aio->a_pipe, ep)) != 0) {
		nni_aio_finish_error(aio, rv);
		nni_mtx_unlock(&nni_inproc.mx);
		return;
	}

	// Insert us into the pending server aios, and then run the
	// accept list.
	nni_aio_list_append(&ep->aios, aio);
	nni_inproc_accept_clients(ep);
	nni_mtx_unlock(&nni_inproc.mx);
}

static nni_tran_pipe_option nni_inproc_pipe_options[] = {
	{ NNG_OPT_LOCADDR, nni_inproc_pipe_get_addr },
	{ NNG_OPT_REMADDR, nni_inproc_pipe_get_addr },
	// terminate list
	{ NULL, NULL },
};

static nni_tran_pipe nni_inproc_pipe_ops = {
	.p_fini    = nni_inproc_pipe_fini,
	.p_send    = nni_inproc_pipe_send,
	.p_recv    = nni_inproc_pipe_recv,
	.p_close   = nni_inproc_pipe_close,
	.p_peer    = nni_inproc_pipe_peer,
	.p_options = nni_inproc_pipe_options,
};

static nni_tran_ep_option nni_inproc_ep_options[] = {
	// terminate list
	{ NULL, NULL, NULL },
};

static nni_tran_ep nni_inproc_ep_ops = {
	.ep_init    = nni_inproc_ep_init,
	.ep_fini    = nni_inproc_ep_fini,
	.ep_connect = nni_inproc_ep_connect,
	.ep_bind    = nni_inproc_ep_bind,
	.ep_accept  = nni_inproc_ep_accept,
	.ep_close   = nni_inproc_ep_close,
	.ep_options = nni_inproc_ep_options,
};

// This is the inproc transport linkage, and should be the only global
// symbol in this entire file.
struct nni_tran nni_inproc_tran = {
	.tran_version = NNI_TRANSPORT_VERSION,
	.tran_scheme  = "inproc",
	.tran_ep      = &nni_inproc_ep_ops,
	.tran_pipe    = &nni_inproc_pipe_ops,
	.tran_init    = nni_inproc_init,
	.tran_fini    = nni_inproc_fini,
};

int
nng_inproc_register(void)
{
	return (nni_tran_register(&nni_inproc_tran));
}
