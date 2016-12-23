//
// Copyright 2016 Garrett D'Amore <garrett@damore.org>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "core/nng_impl.h"

// Inproc transport.  This just transports messages from one
// peer to another.  The inproc transport is only valid within the same
// process.

typedef struct nni_inproc_pair		nni_inproc_pair;
typedef struct nni_inproc_pipe		nni_inproc_pipe;
typedef struct nni_inproc_ep		nni_inproc_ep;

typedef struct {
	nni_mutex	mx;
	nni_cond	cv;
	nni_list_t	eps;
} nni_inproc_global;

// nni_inproc_pipe represents one half of a connection.
struct nni_inproc_pipe {
	const char *		addr;
	nni_inproc_pair *	pair;
	nni_msgqueue *		rq;
	nni_msgqueue *		wq;
	uint16_t		peer;
};

// nni_inproc_pair represents a pair of pipes.  Because we control both
// sides of the pipes, we can allocate and free this in one structure.
struct nni_inproc_pair {
	nni_mutex	mx;
	int		refcnt;
	nni_msgqueue *	q[2];
	nni_inproc_pipe pipe[2];
	char		addr[NNG_MAXADDRLEN+1];
};

struct nni_inproc_ep {
	char		addr[NNG_MAXADDRLEN+1];
	int		mode;
	int		closed;
	nni_list_node_t node;
	uint16_t	proto;
	void *		cpipe;  // connected pipe (DIAL only)
};

#define NNI_INPROC_EP_IDLE	0
#define NNI_INPROC_EP_DIAL	1
#define NNI_INPROC_EP_LISTEN	2

// nni_inproc is our global state - this contains the list of active endpoints
// which we use for coordinating rendezvous.
static nni_inproc_global nni_inproc;

static int
nni_inproc_init(void)
{
	int rv;

	if ((rv = nni_mutex_init(&nni_inproc.mx)) != 0) {
		return (rv);
	}
	if ((rv = nni_cond_init(&nni_inproc.cv, &nni_inproc.mx)) != 0) {
		nni_mutex_fini(&nni_inproc.mx);
		return (rv);
	}
	NNI_LIST_INIT(&nni_inproc.eps, nni_inproc_ep, node);

	return (0);
}


static void
nni_inproc_fini(void)
{
	nni_cond_fini(&nni_inproc.cv);
	nni_mutex_fini(&nni_inproc.mx);
}


static void
nni_inproc_pipe_close(void *arg)
{
	nni_inproc_pipe *pipe = arg;

	nni_msgqueue_close(pipe->rq);
	nni_msgqueue_close(pipe->wq);
}


// nni_inproc_pair destroy is called when both pipe-ends of the pipe
// have been destroyed.
static void
nni_inproc_pair_destroy(nni_inproc_pair *pair)
{
	if (pair->q[0]) {
		nni_msgqueue_destroy(pair->q[0]);
	}
	if (pair->q[1]) {
		nni_msgqueue_destroy(pair->q[1]);
	}
	nni_mutex_fini(&pair->mx);
	nni_free(pair, sizeof (*pair));
}


static void
nni_inproc_pipe_destroy(void *arg)
{
	nni_inproc_pipe *pipe = arg;
	nni_inproc_pair *pair = pipe->pair;

	// We could assert the pipe closed...

	// If we are the last peer, then toss the pair structure.
	nni_mutex_enter(&pair->mx);
	pair->refcnt--;
	if (pair->refcnt == 0) {
		nni_mutex_exit(&pair->mx);
		nni_inproc_pair_destroy(pair);
	} else {
		nni_mutex_exit(&pair->mx);
	}
}


static int
nni_inproc_pipe_send(void *arg, nni_msg *msg)
{
	nni_inproc_pipe *pipe = arg;

	return (nni_msgqueue_put(pipe->wq, msg));
}


static int
nni_inproc_pipe_recv(void *arg, nni_msg **msgp)
{
	nni_inproc_pipe *pipe = arg;

	return (nni_msgqueue_get(pipe->rq, msgp));
}


static uint16_t
nni_inproc_pipe_peer(void *arg)
{
	nni_inproc_pipe *pipe = arg;

	return (pipe->peer);
}


static int
nni_inproc_pipe_getopt(void *arg, int option, void *buf, size_t *szp)
{
	nni_inproc_pipe *pipe = arg;
	size_t len;

	switch (option) {
	case NNG_OPT_LOCALADDR:
	case NNG_OPT_REMOTEADDR:
		len = strlen(pipe->addr) + 1;
		if (len > *szp) {
			(void) memcpy(buf, pipe->addr, *szp);
		} else {
			(void) memcpy(buf, pipe->addr, len);
		}
		*szp = len;
		return (0);
	}
	return (NNG_ENOTSUP);
}


static int
nni_inproc_ep_create(void **epp, const char *url, uint16_t proto)
{
	nni_inproc_ep *ep;

	if (strlen(url) > NNG_MAXADDRLEN-1) {
		return (NNG_EINVAL);
	}
	if ((ep = nni_alloc(sizeof (*ep))) == NULL) {
		return (NNG_ENOMEM);
	}

	ep->mode = NNI_INPROC_EP_IDLE;
	ep->closed = 0;
	ep->proto = proto;
	nni_list_node_init(&nni_inproc.eps, ep);
	(void) snprintf(ep->addr, sizeof (ep->addr), "%s", url);
	*epp = ep;
	return (0);
}


static void
nni_inproc_ep_destroy(void *arg)
{
	nni_inproc_ep *ep = arg;

	if (!ep->closed) {
		nni_panic("inproc_ep_destroy while not closed!");
	}
	nni_free(ep, sizeof (*free));
}


static void
nni_inproc_ep_close(void *arg)
{
	nni_inproc_ep *ep = arg;

	nni_mutex_enter(&nni_inproc.mx);
	if (!ep->closed) {
		ep->closed = 1;
		nni_list_remove(&nni_inproc.eps, ep);
		nni_cond_broadcast(&nni_inproc.cv);
	}
	nni_mutex_exit(&nni_inproc.mx);
}


static int
nni_inproc_ep_dial(void *arg, void **pipep)
{
	nni_inproc_ep *ep = arg;
	nni_inproc_ep *srch;
	nni_list_t *list = &nni_inproc.eps;

	if (ep->mode != NNI_INPROC_EP_IDLE) {
		return (NNG_EINVAL);
	}
	nni_mutex_enter(&nni_inproc.mx);
	NNI_LIST_FOREACH (list, srch) {
		if (srch->mode != NNI_INPROC_EP_LISTEN) {
			continue;
		}
		if (strcmp(srch->addr, ep->addr) == 0) {
			break;
		}
	}
	if (srch == NULL) {
		// No listeners available.
		nni_mutex_exit(&nni_inproc.mx);
		return (NNG_ECONNREFUSED);
	}
	ep->mode = NNI_INPROC_EP_DIAL;
	nni_list_append(list, ep);
	nni_cond_broadcast(&nni_inproc.cv);
	for (;;) {
		if (ep->closed) {
			// Closer will have removed us from list.
			nni_mutex_exit(&nni_inproc.mx);
			return (NNG_ECLOSED);
		}
		if (ep->cpipe != NULL) {
			break;
		}
		nni_cond_wait(&nni_inproc.cv);
	}
	// NB: The acceptor or closer removes us from the list.
	ep->mode = NNI_INPROC_EP_IDLE;
	*pipep = ep->cpipe;
	nni_mutex_exit(&nni_inproc.mx);
	return (ep->closed ? NNG_ECLOSED : 0);
}


static int
nni_inproc_ep_listen(void *arg)
{
	nni_inproc_ep *ep = arg;
	nni_inproc_ep *srch;
	nni_list_t *list = &nni_inproc.eps;

	if (ep->mode != NNI_INPROC_EP_IDLE) {
		return (NNG_EINVAL);
	}
	nni_mutex_enter(&nni_inproc.mx);
	if (ep->closed) {
		nni_mutex_exit(&nni_inproc.mx);
		return (NNG_ECLOSED);
	}
	NNI_LIST_FOREACH (list, srch) {
		if (srch->mode != NNI_INPROC_EP_LISTEN) {
			continue;
		}
		if (strcmp(srch->addr, ep->addr) == 0) {
			nni_mutex_exit(&nni_inproc.mx);
			return (NNG_EADDRINUSE);
		}
	}
	ep->mode = NNI_INPROC_EP_LISTEN;
	nni_list_append(list, ep);
	nni_mutex_exit(&nni_inproc.mx);
	return (0);
}


static int
nni_inproc_ep_accept(void *arg, void **pipep)
{
	nni_inproc_ep *ep = arg;
	nni_inproc_ep *srch;
	nni_inproc_pair *pair;
	nni_list_t *list = &nni_inproc.eps;
	int rv;

	if (ep->mode != NNI_INPROC_EP_LISTEN) {
		return (NNG_EINVAL);
	}

	// Preallocate the pair, so we don't do it while holding a lock
	if ((pair = nni_alloc(sizeof (*pair))) == NULL) {
		return (NNG_ENOMEM);
	}
	if ((rv = nni_mutex_init(&pair->mx)) != 0) {
		nni_free(pair, sizeof (*pair));
		return (rv);
	}
	if (((rv = nni_msgqueue_create(&pair->q[0], 4)) != 0) ||
	    ((rv = nni_msgqueue_create(&pair->q[0], 4)) != 0)) {
		nni_inproc_pair_destroy(pair);
		return (rv);
	}

	nni_mutex_enter(&nni_inproc.mx);
	for (;;) {
		if (ep->closed) {
			// This is the only possible error path from the
			// time we acquired the lock.
			nni_mutex_exit(&nni_inproc.mx);
			nni_inproc_pair_destroy(pair);
			return (NNG_ECLOSED);
		}
		NNI_LIST_FOREACH (list, srch) {
			if (srch->mode != NNI_INPROC_EP_DIAL) {
				continue;
			}
			if (strcmp(srch->addr, ep->addr) == 0) {
				break;
			}
		}
		if (srch != NULL) {
			break;
		}
		nni_cond_wait(&nni_inproc.cv);
	}
	(void) snprintf(pair->addr, sizeof (pair->addr), "%s", ep->addr);
	pair->pipe[0].rq = pair->pipe[1].wq = pair->q[0];
	pair->pipe[1].rq = pair->pipe[0].wq = pair->q[1];
	pair->pipe[0].pair = pair->pipe[1].pair = pair;
	pair->pipe[0].addr = pair->pipe[1].addr = pair->addr;
	pair->pipe[1].peer = srch->proto;
	pair->pipe[0].peer = ep->proto;
	pair->refcnt = 2;
	srch->cpipe = &pair->pipe[0];
	*pipep = &pair->pipe[1];
	nni_cond_broadcast(&nni_inproc.cv);

	nni_mutex_exit(&nni_inproc.mx);

	return (0);
}


static struct nni_pipe_ops nni_inproc_pipe_ops = {
	.p_destroy	= nni_inproc_pipe_destroy,
	.p_send		= nni_inproc_pipe_send,
	.p_recv		= nni_inproc_pipe_recv,
	.p_close	= nni_inproc_pipe_close,
	.p_peer		= nni_inproc_pipe_peer,
	.p_getopt	= nni_inproc_pipe_getopt,
};

static struct nni_endpt_ops nni_inproc_ep_ops = {
	.ep_create	= nni_inproc_ep_create,
	.ep_destroy	= nni_inproc_ep_destroy,
	.ep_dial	= nni_inproc_ep_dial,
	.ep_listen	= nni_inproc_ep_listen,
	.ep_accept	= nni_inproc_ep_accept,
	.ep_close	= nni_inproc_ep_close,
	.ep_pipe_ops	= &nni_inproc_pipe_ops,
	.ep_setopt	= NULL,
	.ep_getopt	= NULL,
};

// This is the inproc transport linkage, and should be the only global
// symbol in this entire file.
struct nni_transport nni_inproc_transport = {
	.tran_scheme	= "inproc",
	.tran_ep_ops	= &nni_inproc_ep_ops,
	.tran_init	= nni_inproc_init,
	.tran_fini	= nni_inproc_fini,
};
