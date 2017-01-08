//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
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
	return (p->p_tran_ops.pipe_send(p->p_tran_data, msg));
}


int
nni_pipe_recv(nni_pipe *p, nng_msg **msgp)
{
	return (p->p_tran_ops.pipe_recv(p->p_tran_data, msgp));
}


// nni_pipe_close closes the underlying connection.  It is expected that
// subsequent attempts receive or send (including any waiting receive) will
// simply return NNG_ECLOSED.
void
nni_pipe_close(nni_pipe *p)
{
	nni_sock *sock = p->p_sock;

	if (p->p_tran_data != NULL) {
		p->p_tran_ops.pipe_close(p->p_tran_data);
	}

	nni_mtx_lock(&sock->s_mx);
	if (!p->p_reap) {
		// schedule deferred reap/close
		p->p_reap = 1;
		nni_list_remove(&sock->s_pipes, p);
		nni_list_append(&sock->s_reaps, p);
		nni_cv_wake(&sock->s_cv);
	}
	nni_mtx_unlock(&sock->s_mx);
}


uint16_t
nni_pipe_peer(nni_pipe *p)
{
	return (p->p_tran_ops.pipe_peer(p->p_tran_data));
}


void
nni_pipe_destroy(nni_pipe *p)
{
	nni_thr_fini(&p->p_send_thr);
	nni_thr_fini(&p->p_recv_thr);

	if (p->p_tran_data != NULL) {
		p->p_tran_ops.pipe_destroy(p->p_tran_data);
	}
	if (p->p_proto_data != NULL) {
		p->p_sock->s_pipe_ops.pipe_fini(p->p_proto_data);
	}
	NNI_FREE_STRUCT(p);
}


int
nni_pipe_create(nni_pipe **pp, nni_ep *ep)
{
	nni_pipe *p;
	nni_sock *sock = ep->ep_sock;
	const nni_proto_pipe_ops *ops = &sock->s_pipe_ops;
	void *pdata;
	int rv;

	if ((p = NNI_ALLOC_STRUCT(p)) == NULL) {
		return (NNG_ENOMEM);
	}
	p->p_sock = sock;
	p->p_tran_data = NULL;
	p->p_proto_data = NULL;
	p->p_active = 0;
	NNI_LIST_NODE_INIT(&p->p_node);

	// Make a copy of the transport ops.  We can override entry points
	// and we avoid an extra dereference on hot code paths.
	p->p_tran_ops = *ep->ep_tran->tran_pipe;

	if ((rv = ops->pipe_init(&pdata, p, sock->s_data)) != 0) {
		NNI_FREE_STRUCT(p);
		return (rv);
	}
	p->p_proto_data = pdata;
	if ((rv = nni_thr_init(&p->p_recv_thr, ops->pipe_recv, pdata)) != 0) {
		ops->pipe_fini(&p->p_proto_data);
		NNI_FREE_STRUCT(p);
		return (rv);
	}
	if ((rv = nni_thr_init(&p->p_send_thr, ops->pipe_send, pdata)) != 0) {
		nni_thr_fini(&p->p_recv_thr);
		ops->pipe_fini(&p->p_proto_data);
		NNI_FREE_STRUCT(p);
		return (rv);
	}
	nni_mtx_lock(&sock->s_mx);
	nni_list_append(&sock->s_pipes, p);
	nni_mtx_unlock(&sock->s_mx);

	*pp = p;
	return (0);
}


int
nni_pipe_getopt(nni_pipe *p, int opt, void *val, size_t *szp)
{
	/*  This should only be called with the mutex held... */
	if (p->p_tran_ops.pipe_getopt == NULL) {
		return (NNG_ENOTSUP);
	}
	return (p->p_tran_ops.pipe_getopt(p->p_tran_data, opt, val, szp));
}


int
nni_pipe_start(nni_pipe *pipe)
{
	int rv;
	int collide;
	nni_sock *sock = pipe->p_sock;

	nni_mtx_lock(&sock->s_mx);
	if (sock->s_closing) {
		nni_mtx_unlock(&sock->s_mx);
		nni_pipe_close(pipe);
		return (NNG_ECLOSED);
	}

	if (nni_pipe_peer(pipe) != sock->s_peer) {
		nni_mtx_unlock(&sock->s_mx);
		nni_pipe_close(pipe);
		return (NNG_EPROTO);
	}

	do {
		// We generate a new pipe ID, but we make sure it does not
		// collide with any we already have.  This can only normally
		// happen if we wrap -- i.e. we've had 4 billion or so pipes.
		// XXX: consider making this a hash table!!
		nni_pipe *check;
		pipe->p_id = nni_plat_nextid() & 0x7FFFFFFF;
		collide = 0;
		NNI_LIST_FOREACH (&sock->s_pipes, check) {
			if ((pipe != check) && (check->p_id == pipe->p_id)) {
				collide = 1;
				break;
			}
		}
	} while (collide);

	if ((rv = sock->s_pipe_ops.pipe_add(pipe->p_proto_data)) != 0) {
		nni_mtx_unlock(&sock->s_mx);
		nni_pipe_close(pipe);
		return (rv);
	}
	nni_thr_run(&pipe->p_send_thr);
	nni_thr_run(&pipe->p_recv_thr);
	pipe->p_active = 1;

	// XXX: Publish event

	nni_mtx_unlock(&sock->s_mx);
	return (0);
}
