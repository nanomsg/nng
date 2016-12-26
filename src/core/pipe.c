//
// Copyright 2016 Garrett D'Amore <garrett@damore.org>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/nng_impl.h"

// This file contains functions relating to pipes.
//
// Operations on pipes (to the transport) are generally blocking operations,
// performed in the context of the protocol.

// nni_pipe_id returns the 32-bit pipe id, which can be used in backtraces.
uint32_t
nni_pipe_id(nni_pipe *p)
{
	return (p->p_id);
}


int
nni_pipe_send(nni_pipe *p, nng_msg *msg)
{
	return (p->p_ops.p_send(p->p_trandata, msg));
}


int
nni_pipe_recv(nni_pipe *p, nng_msg **msgp)
{
	return (p->p_ops.p_recv(p->p_trandata, msgp));
}


// nni_pipe_close closes the underlying connection.  It is expected that
// subsequent attempts receive or send (including any waiting receive) will
// simply return NNG_ECLOSED.
void
nni_pipe_close(nni_pipe *p)
{
	nni_socket *sock = p->p_sock;

	p->p_ops.p_close(p->p_trandata);

	nni_mutex_enter(&sock->s_mx);
	if (!p->p_reap) {
		// schedule deferred reap/close
		p->p_reap = 1;
		if (p->p_active) {
			nni_list_remove(&sock->s_pipes, p);
			p->p_active = 0;
		}
		nni_list_append(&sock->s_reaps, p);
		nni_cond_broadcast(&sock->s_cv);
	}
	nni_mutex_exit(&sock->s_mx);
}


uint16_t
nni_pipe_peer(nni_pipe *p)
{
	return (p->p_ops.p_peer(p->p_trandata));
}


void
nni_pipe_destroy(nni_pipe *p)
{
	if (p->p_trandata != NULL) {
		p->p_ops.p_destroy(p->p_trandata);
	}
	nni_free(p, sizeof (*p));
}


int
nni_pipe_create(nni_pipe **pp, nni_endpt *ep)
{
	nni_pipe *p;

	if ((p = nni_alloc(sizeof (*p))) == NULL) {
		return (NNG_ENOMEM);
	}
	p->p_trandata = NULL;
	p->p_protdata = NULL;
	p->p_ops = *ep->ep_ops.ep_pipe_ops;
	p->p_id = nni_plat_nextid();
	p->p_ep = ep;
	p->p_sock = ep->ep_sock;
	if (ep->ep_dialer != NULL) {
		ep->ep_pipe = p;
	}
	NNI_LIST_NODE_INIT(&p->p_node);
	*pp = p;
	return (0);
}


int
nni_pipe_getopt(nni_pipe *p, int opt, void *val, size_t *szp)
{
	/*  This should only be called with the mutex held... */
	if (p->p_ops.p_getopt == NULL) {
		return (NNG_ENOTSUP);
	}
	return (p->p_ops.p_getopt(p->p_trandata, opt, val, szp));
}
