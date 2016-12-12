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

#include <stdlib.h>
#include <string.h>

#include "core/nng_impl.h"

/*
 * Inproc transport.  This just transports messages from one
 * peer to another.
 */

typedef struct inproc_pair *inproc_pair_t;
typedef struct inproc_pipe *inproc_pipe_t;
typedef struct inproc_ep *inproc_ep_t;

typedef struct {
	nni_mutex_t	mx;
	nni_cond_t	cv;
	nni_list_t	eps;
} inproc_global_t;

struct inproc_pipe {
	const char	*addr;
	inproc_pair_t	pair;
	nni_msgqueue_t	rq;
	nni_msgqueue_t	wq;
	uint16_t	peer;
};

struct inproc_pair {
	nni_mutex_t		mx;
	int			refcnt;
	nni_msgqueue_t		q[2];
	struct inproc_pipe	pipe[2];
	char			addr[NNG_MAXADDRLEN];
};

struct inproc_ep {
	char		addr[NNG_MAXADDRLEN];
	int		mode;
	int		closed;
	nni_list_node_t	node;
	uint16_t	proto;
	void		*cpipe;	/* connected pipe (DIAL only) */
};

#define	INPROC_EP_IDLE		0
#define	INPROC_EP_DIAL		1
#define	INPROC_EP_LISTEN	2

/*
 * Global inproc state - this contains the list of active endpoints
 * which we use for coordinating rendezvous.
 */
static inproc_global_t inproc;

void
inproc_pipe_close(void *arg)
{
	inproc_pipe_t	pipe = arg;

	nni_msgqueue_close(pipe->rq);
	nni_msgqueue_close(pipe->wq);
}

static void
inproc_pair_destroy(inproc_pair_t pair)
{
	if (pair == NULL) {
		return;
	}
	if (pair->q[0]) {
		nni_msgqueue_destroy(pair->q[0]);
	}
	if (pair->q[1]) {
		nni_msgqueue_destroy(pair->q[1]);
	}
	if (pair->mx) {
		nni_mutex_destroy(pair->mx);
	}
	nni_free(pair, sizeof (*pair));
}

void
inproc_pipe_destroy(void *arg)
{
	inproc_pipe_t	pipe = arg;
	inproc_pair_t	pair = pipe->pair;

	/* We could assert the pipe closed... */

	/* If we are the last peer, then toss the pair structure. */
	nni_mutex_enter(pair->mx);
	pair->refcnt--;
	if (pair->refcnt == 0) {
		nni_mutex_exit(pair->mx);
		inproc_pair_destroy(pair);
	} else {
		nni_mutex_exit(pair->mx);
	}
}

int
inproc_pipe_send(void *arg, nng_msg_t msg)
{
	inproc_pipe_t pipe = arg;

	/*
	 * TODO: look at the message expiration and use that to set up
	 * the timeout.  (And if it expired already, throw it away.)
	 */
	return (nni_msgqueue_put(pipe->wq, msg, -1));
}

int
inproc_pipe_recv(void *arg, nng_msg_t *msgp)
{
	inproc_pipe_t pipe = arg;

	return (nni_msgqueue_get(pipe->rq, msgp, -1));
}

uint16_t
inproc_pipe_peer(void *arg)
{
	inproc_pipe_t pipe = arg;

	return (pipe->peer);
}

int
inproc_pipe_getopt(void *arg, int option, void *buf, size_t *szp)
{
	inproc_pipe_t pipe = arg;
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

int
inproc_ep_create(void **epp, const char *url, uint16_t proto)
{
	inproc_ep_t	ep;

	if (strlen(url) > NNG_MAXADDRLEN-1) {
		return (NNG_EINVAL);
	}
	if ((ep = nni_alloc(sizeof (*ep))) == NULL) {
		return (NNG_ENOMEM);
	}

	ep->mode = INPROC_EP_IDLE;
	ep->closed = 0;
	ep->proto = proto;
	nni_list_node_init(&inproc.eps, ep);
	nni_snprintf(ep->addr, sizeof (ep->addr), "%s", url);
	*epp = ep;
	return (0);
}

void
inproc_ep_destroy(void *arg)
{
	NNI_ARG_UNUSED(arg);
}

void
inproc_ep_close(void *arg)
{
	inproc_ep_t	ep = arg;

	nni_mutex_enter(inproc.mx);
	if (!ep->closed) {
		ep->closed = 1;
		nni_list_remove(&inproc.eps, ep);
		nni_cond_broadcast(inproc.cv);
	}
	nni_mutex_exit(inproc.mx);
}
int
inproc_ep_dial(void *arg, void **pipep)
{
	inproc_ep_t ep = arg;
	inproc_ep_t srch;
	nni_list_t *list = &inproc.eps;
	
	if (ep->mode != INPROC_EP_IDLE) {
		return (NNG_EINVAL);
	}
	nni_mutex_enter(inproc.mx);
	NNI_LIST_FOREACH(list, srch) {
		if (srch->mode != INPROC_EP_LISTEN) {
			continue;
		}
		if (strcmp(srch->addr, ep->addr) == 0) {
			break;
		}
	}
	if (srch == NULL) {
		/* No listeners available. */
		nni_mutex_exit(inproc.mx);
		return (NNG_ECONNREFUSED);
	}
	ep->mode = INPROC_EP_DIAL;
	nni_list_append(list, ep);
	nni_cond_broadcast(inproc.cv);
	for (;;) {
		if (ep->closed) {
			/* Closer will have removed us from list. */
			nni_mutex_exit(inproc.mx);
			return (NNG_ECLOSED);
		}
		if (ep->cpipe != NULL) {
			break;
		}
		nni_cond_wait(inproc.cv);
	}
	/* NB: The acceptor or closer removes us from the list. */
	ep->mode = INPROC_EP_IDLE;
	*pipep = ep->cpipe;
	nni_mutex_exit(inproc.mx);
	return (ep->closed ? NNG_ECLOSED : 0);
}

int
inproc_ep_listen(void *arg)
{
	inproc_ep_t ep = arg;
	inproc_ep_t srch;
	nni_list_t *list = &inproc.eps;

	if (ep->mode != INPROC_EP_IDLE) {
		return (NNG_EINVAL);
	}
	nni_mutex_enter(inproc.mx);
	if (ep->closed) {
		nni_mutex_exit(inproc.mx);
		return (NNG_ECLOSED);
	}
	NNI_LIST_FOREACH(list, srch) {
		if (srch->mode != INPROC_EP_LISTEN) {
			continue;
		}
		if (strcmp(srch->addr, ep->addr) == 0) {
			nni_mutex_exit(inproc.mx);
			return (NNG_EADDRINUSE);
		}
	}
	ep->mode = INPROC_EP_LISTEN;
	nni_list_append(list, ep);
	nni_mutex_exit(inproc.mx);
	return (0);
}

int
inproc_ep_accept(void *arg, void **pipep)
{
	inproc_ep_t ep = arg;
	inproc_ep_t srch;
	inproc_pair_t pair;
	nni_list_t *list = &inproc.eps;
	int rv;

	nni_mutex_enter(inproc.mx);
	if (ep->mode != INPROC_EP_LISTEN) {
		nni_mutex_exit(inproc.mx);
		return (NNG_EINVAL);
	}
	for (;;) {
		if (ep->closed) {
			nni_mutex_exit(inproc.mx);
			return (NNG_ECLOSED);
		}
		NNI_LIST_FOREACH(list, srch) {
			if (srch->mode != INPROC_EP_DIAL) {
				continue;
			}
			if (strcmp(srch->addr, ep->addr) == 0) {
				break;
			}
		}
		if (srch != NULL) {
			break;
		}
		nni_cond_wait(inproc.cv);
	}
	if ((pair = nni_alloc(sizeof (*pair))) == NULL) {
		nni_mutex_exit(inproc.mx);
		return (NNG_ENOMEM);
	}
	if (((rv = nni_mutex_create(&pair->mx)) != 0) ||
	    ((rv = nni_msgqueue_create(&pair->q[0], 4)) != 0) ||
	    ((rv = nni_msgqueue_create(&pair->q[0], 4)) != 0)) {
		inproc_pair_destroy(pair);
	}
	nni_snprintf(pair->addr, sizeof (pair->addr), "%s", ep->addr);
	pair->pipe[0].rq = pair->pipe[1].wq = pair->q[0];
	pair->pipe[1].rq = pair->pipe[0].wq = pair->q[1];
	pair->pipe[0].pair = pair->pipe[1].pair = pair;
	pair->pipe[0].addr = pair->pipe[1].addr = pair->addr;
	pair->pipe[1].peer = srch->proto;
	pair->pipe[0].peer = ep->proto;
	pair->refcnt = 2;
	srch->cpipe = &pair->pipe[0];
	*pipep = &pair->pipe[1];
	nni_cond_broadcast(inproc.cv);
	
	nni_mutex_exit(inproc.mx);

	return (0);
}

int
nni_inproc_init(void)
{
	int rv;
	if ((rv = nni_mutex_create(&inproc.mx)) != 0) {
		return (rv);
	}
	if ((rv = nni_cond_create(&inproc.cv, inproc.mx)) != 0) {
		nni_mutex_destroy(inproc.mx);
		return (rv);
	}
	NNI_LIST_INIT(&inproc.eps, struct inproc_ep, node);
	/* XXX: nni_register_transport(); */
	return (0);
}

void
nni_inproc_term(void)
{
}

static struct nni_pipe_ops inproc_pipe_ops = {
	inproc_pipe_destroy,
	inproc_pipe_send,
	inproc_pipe_recv,
	inproc_pipe_close,
	inproc_pipe_peer,
	inproc_pipe_getopt,
};

static struct nni_endpt_ops inproc_ep_ops = {
	inproc_ep_create,
	inproc_ep_destroy,
	inproc_ep_dial,
	inproc_ep_listen,
	inproc_ep_accept,
	inproc_ep_close,
	NULL,	/* inproc_ep_setopt */
	NULL,	/* inproc_ep_getopt */
};

struct nni_transport_ops inproc_tran_ops = {
	"inproc",		/* tran_scheme */
	&inproc_ep_ops,
	&inproc_pipe_ops,
};
