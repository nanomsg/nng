//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
// Copyright 2017 Capitar IT Group BV <info@capitar.com>
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

static nni_idhash *nni_pipes;

int
nni_pipe_sys_init(void)
{
	int rv;

	rv = nni_idhash_init(&nni_pipes);
	if (rv != 0) {
		return (rv);
	}

	// Note that pipes have their own namespace.  ID hash will
	// guarantee the that the first value is reasonable (non-zero),
	// if we supply an out of range value (0).  (Consequently the
	// value "1" has a bias -- its roughly twice as likely to be
	// chosen as any other value.  This does not mater.)
	nni_idhash_set_limits(
	    nni_pipes, 1, 0x7fffffff, nni_random() & 0x7fffffff);

	return (0);
}

void
nni_pipe_sys_fini(void)
{
	if (nni_pipes != NULL) {
		nni_idhash_fini(nni_pipes);
		nni_pipes = NULL;
	}
}

static void
nni_pipe_destroy(nni_pipe *p)
{
	if (p == NULL) {
		return;
	}

	nni_aio_fini(&p->p_start_aio);
	if (p->p_proto_data != NULL) {
		p->p_proto_dtor(p->p_proto_data);
	}
	if (p->p_tran_data != NULL) {
		p->p_tran_ops.p_fini(p->p_tran_data);
	}
	if (p->p_id != 0) {
		nni_idhash_remove(nni_pipes, p->p_id);
	}
	nni_mtx_fini(&p->p_mtx);
}

// nni_pipe_id returns the 32-bit pipe id, which can be used in backtraces.
uint32_t
nni_pipe_id(nni_pipe *p)
{
	return (p->p_id);
}

void
nni_pipe_recv(nni_pipe *p, nni_aio *aio)
{
	p->p_tran_ops.p_recv(p->p_tran_data, aio);
}

void
nni_pipe_send(nni_pipe *p, nni_aio *aio)
{
	p->p_tran_ops.p_send(p->p_tran_data, aio);
}

// nni_pipe_close closes the underlying connection.  It is expected that
// subsequent attempts receive or send (including any waiting receive) will
// simply return NNG_ECLOSED.
void
nni_pipe_close(nni_pipe *p)
{
	nni_sock *sock = p->p_sock;

	nni_mtx_lock(&p->p_mtx);
	if (p->p_reap == 1) {
		// We already did a close.
		nni_mtx_unlock(&p->p_mtx);
		return;
	}
	p->p_reap = 1;

	// Close the underlying transport.
	if (p->p_tran_data != NULL) {
		p->p_tran_ops.p_close(p->p_tran_data);
	}

	nni_mtx_unlock(&p->p_mtx);
}

// We have to stop asynchronously using a task, because otherwise we can
// wind up having a callback from an AIO trying to cancel itself.  That
// simply will not work.
void
nni_pipe_remove(nni_pipe *p)
{
	// Transport close...
	nni_pipe_close(p);

	nni_ep_pipe_remove(p->p_ep, p);

	// Tell the protocol to stop.
	nni_sock_pipe_stop(p->p_sock, p);

	// XXX: would be simpler to just do a destroy here
	nni_pipe_destroy(p);
}

void
nni_pipe_stop(nni_pipe *p)
{
	// Guard against recursive calls.
	nni_mtx_lock(&p->p_mtx);
	if (p->p_stop) {
		nni_mtx_unlock(&p->p_mtx);
		return;
	}
	p->p_stop = 1;
	nni_mtx_unlock(&p->p_mtx);
	nni_taskq_ent_init(&p->p_reap_tqe, (nni_cb) nni_pipe_remove, p);
	nni_taskq_dispatch(NULL, &p->p_reap_tqe);
}

uint16_t
nni_pipe_peer(nni_pipe *p)
{
	return (p->p_tran_ops.p_peer(p->p_tran_data));
}

static void
nni_pipe_start_cb(void *arg)
{
	nni_pipe *p   = arg;
	nni_aio * aio = &p->p_start_aio;
	int       rv;

	nni_mtx_lock(&p->p_mtx);
	if ((rv = nni_aio_result(aio)) != 0) {
		nni_mtx_unlock(&p->p_mtx);
		nni_pipe_stop(p);
		return;
	}

	nni_mtx_unlock(&p->p_mtx);

	if ((rv = nni_sock_pipe_ready(p->p_sock, p)) != 0) {
		nni_pipe_stop(p);
	}
}

int
nni_pipe_create(nni_pipe **pp, nni_ep *ep, nni_sock *sock, nni_tran *tran)
{
	nni_pipe *p;
	int       rv;

	if ((p = NNI_ALLOC_STRUCT(p)) == NULL) {
		return (NNG_ENOMEM);
	}
	if ((rv = nni_mtx_init(&p->p_mtx)) != 0) {
		nni_pipe_destroy(p);
		return (rv);
	}
	if ((rv = nni_idhash_alloc(nni_pipes, &p->p_id, p)) != 0) {
		nni_pipe_destroy(p);
		return (rv);
	}

	p->p_tran_data  = NULL;
	p->p_proto_data = NULL;
	p->p_proto_dtor = NULL;

	NNI_LIST_NODE_INIT(&p->p_sock_node);
	NNI_LIST_NODE_INIT(&p->p_ep_node);

	if ((rv = nni_aio_init(&p->p_start_aio, nni_pipe_start_cb, p)) != 0) {
		nni_pipe_destroy(p);
		return (rv);
	}
	p->p_sock = sock;
	p->p_ep   = ep;

	// Make a copy of the transport ops.  We can override entry points
	// and we avoid an extra dereference on hot code paths.
	p->p_tran_ops = *tran->tran_pipe;

	// Save the protocol destructor.
	p->p_proto_dtor = sock->s_pipe_ops.pipe_fini;

	// Initialize protocol pipe data.
	rv = sock->s_pipe_ops.pipe_init(&p->p_proto_data, p, sock->s_data);
	if (rv != 0) {
		nni_pipe_destroy(p);
		return (rv);
	}

	if ((rv = nni_ep_pipe_add(ep, p)) != 0) {
		nni_pipe_destroy(p);
		return (rv);
	}

	*pp = p;
	return (0);
}

int
nni_pipe_getopt(nni_pipe *p, int opt, void *val, size_t *szp)
{
	/*  This should only be called with the mutex held... */
	if (p->p_tran_ops.p_getopt == NULL) {
		return (NNG_ENOTSUP);
	}
	return (p->p_tran_ops.p_getopt(p->p_tran_data, opt, val, szp));
}

int
nni_pipe_start(nni_pipe *p)
{
	int rv;

	if (p->p_tran_ops.p_start == NULL) {
		rv = nni_sock_pipe_ready(p->p_sock, p);
		return (rv);
	}

	p->p_tran_ops.p_start(p->p_tran_data, &p->p_start_aio);
	// XXX: Publish event

	return (0);
}

void *
nni_pipe_get_proto_data(nni_pipe *p)
{
	return (p->p_proto_data);
}

void
nni_pipe_sock_list_init(nni_list *list)
{
	NNI_LIST_INIT(list, nni_pipe, p_sock_node);
}

void
nni_pipe_ep_list_init(nni_list *list)
{
	NNI_LIST_INIT(list, nni_pipe, p_ep_node);
}
