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


int
nni_pipe_aio_recv(nni_pipe *p, nni_aio *aio)
{
	return (p->p_tran_ops.pipe_aio_recv(p->p_tran_data, aio));
}


int
nni_pipe_aio_send(nni_pipe *p, nni_aio *aio)
{
	return (p->p_tran_ops.pipe_aio_send(p->p_tran_data, aio));
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


// nni_pipe_bail is a special version of close, that is used to abort
// from nni_pipe_start, when it fails.  It requires the lock to be held,
// and this prevents us from dropping the lock, possibly leading to race
// conditions.  It's critical that this not be called after the pipe is
// started, or deadlock will occur.
static void
nni_pipe_bail(nni_pipe *p)
{
	nni_sock *sock = p->p_sock;

	if (p->p_tran_data != NULL) {
		p->p_tran_ops.pipe_close(p->p_tran_data);
	}

	nni_pipe_destroy(p);
}


uint16_t
nni_pipe_peer(nni_pipe *p)
{
	return (p->p_tran_ops.pipe_peer(p->p_tran_data));
}


void
nni_pipe_destroy(nni_pipe *p)
{
	int i;

	for (i = 0; i < NNI_MAXWORKERS; i++) {
		nni_thr_fini(&p->p_worker_thr[i]);
	}

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
	int i;

	if ((p = NNI_ALLOC_STRUCT(p)) == NULL) {
		return (NNG_ENOMEM);
	}
	p->p_sock = sock;
	p->p_tran_data = NULL;
	p->p_proto_data = NULL;
	p->p_active = 0;
	p->p_id = 0;
	NNI_LIST_NODE_INIT(&p->p_node);

	// Make a copy of the transport ops.  We can override entry points
	// and we avoid an extra dereference on hot code paths.
	p->p_tran_ops = *ep->ep_tran->tran_pipe;

	if ((rv = ops->pipe_init(&pdata, p, sock->s_data)) != 0) {
		NNI_FREE_STRUCT(p);
		return (rv);
	}
	p->p_proto_data = pdata;

	for (i = 0; i < NNI_MAXWORKERS; i++) {
		nni_worker fn = ops->pipe_worker[i];
		rv = nni_thr_init(&p->p_worker_thr[i], fn, pdata);
		if (rv != 0) {
			while (i > 0) {
				i--;
				nni_thr_fini(&p->p_worker_thr[i]);
			}
			ops->pipe_fini(pdata);
			NNI_FREE_STRUCT(p);
			return (rv);
		}
	}

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
	int i;
	nni_sock *sock = pipe->p_sock;

	nni_mtx_lock(&sock->s_mx);
	if (sock->s_closing) {
		nni_pipe_bail(pipe);
		nni_mtx_unlock(&sock->s_mx);
		return (NNG_ECLOSED);
	}

	if (nni_pipe_peer(pipe) != sock->s_peer) {
		nni_pipe_bail(pipe);
		nni_mtx_unlock(&sock->s_mx);
		return (NNG_EPROTO);
	}

	nni_mtx_lock(nni_idlock);
	rv = nni_idhash_alloc(nni_pipes, &pipe->p_id, pipe);
	nni_mtx_unlock(nni_idlock);

	if (rv != 0) {
		nni_pipe_bail(pipe);
		nni_mtx_unlock(&sock->s_mx);
		return (rv);
	}

	if ((rv = sock->s_pipe_ops.pipe_add(pipe->p_proto_data)) != 0) {
		nni_mtx_lock(nni_idlock);
		nni_idhash_remove(nni_pipes, pipe->p_id);
		pipe->p_id = 0;
		nni_mtx_unlock(nni_idlock);

		nni_pipe_bail(pipe);
		nni_mtx_unlock(&sock->s_mx);
		return (rv);
	}

	pipe->p_active = 1;
	nni_list_append(&sock->s_pipes, pipe);

	for (i = 0; i < NNI_MAXWORKERS; i++) {
		nni_thr_run(&pipe->p_worker_thr[i]);
	}

	// XXX: Publish event

	nni_mtx_unlock(&sock->s_mx);
	return (0);
}
