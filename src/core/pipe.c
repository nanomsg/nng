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

static nni_objhash *nni_allpipes;

static void *
nni_pipe_ctor(uint32_t id)
{
	nni_pipe *p;

	if ((p = NNI_ALLOC_STRUCT(p)) == NULL) {
		return (NULL);
	}
	if (nni_mtx_init(&p->p_mtx) != 0) {
		NNI_FREE_STRUCT(p);
		return (NULL);
	}

	p->p_tran_data = NULL;
	p->p_proto_data = NULL;
	p->p_id = id;

	NNI_LIST_NODE_INIT(&p->p_sock_node);
	NNI_LIST_NODE_INIT(&p->p_ep_node);

	return (p);
}


static void
nni_pipe_dtor(void *ptr)
{
	nni_pipe *p = ptr;

	nni_sock_pipe_rem(p->p_sock, p);

	if (p->p_tran_data != NULL) {
		p->p_tran_ops.p_fini(p->p_tran_data);
	}

	nni_mtx_fini(&p->p_mtx);
	NNI_FREE_STRUCT(p);
}


int
nni_pipe_sys_init(void)
{
	int rv;

	rv = nni_objhash_init(&nni_allpipes, nni_pipe_ctor, nni_pipe_dtor);

	if (rv != 0) {
		return (rv);
	}

	return (0);
}


void
nni_pipe_sys_fini(void)
{
	nni_objhash_fini(nni_allpipes);
	nni_allpipes = NULL;
}


// nni_pipe_id returns the 32-bit pipe id, which can be used in backtraces.
uint32_t
nni_pipe_id(nni_pipe *p)
{
	return (p->p_id);
}


int
nni_pipe_aio_recv(nni_pipe *p, nni_aio *aio)
{
	return (p->p_tran_ops.p_aio_recv(p->p_tran_data, aio));
}


int
nni_pipe_aio_send(nni_pipe *p, nni_aio *aio)
{
	return (p->p_tran_ops.p_aio_send(p->p_tran_data, aio));
}


void
nni_pipe_incref(nni_pipe *p)
{
	int rv;
	nni_pipe *scratch;

	rv = nni_objhash_find(nni_allpipes, p->p_id, (void **) &scratch);
	NNI_ASSERT(rv == 0);
	NNI_ASSERT(p == scratch);
}


void
nni_pipe_decref(nni_pipe *p)
{
	nni_objhash_unref(nni_allpipes, p->p_id);
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

	// Let the socket (and endpoint) know we have closed.
	nni_sock_pipe_closed(sock, p);

	nni_objhash_unref(nni_allpipes, p->p_id);
}


uint16_t
nni_pipe_peer(nni_pipe *p)
{
	return (p->p_tran_ops.p_peer(p->p_tran_data));
}


int
nni_pipe_create(nni_pipe **pp, nni_ep *ep, nni_sock *sock, nni_tran *tran)
{
	nni_pipe *p;
	int rv;
	uint32_t id;

	rv = nni_objhash_alloc(nni_allpipes, &id, (void **) &p);
	if (rv != 0) {
		return (rv);
	}
	p->p_sock = sock;

	// Make a copy of the transport ops.  We can override entry points
	// and we avoid an extra dereference on hot code paths.
	p->p_tran_ops = *tran->tran_pipe;

	// Initialize the transport pipe data.
	if ((rv = p->p_tran_ops.p_init(&p->p_tran_data)) != 0) {
		nni_objhash_unref(nni_allpipes, p->p_id);
		return (rv);
	}

	if ((rv = nni_sock_pipe_add(sock, p)) != 0) {
		nni_objhash_unref(nni_allpipes, p->p_id);
		return (rv);
	}

	*pp = p;
	return (0);
}


void
nni_pipe_destroy(nni_pipe *p)
{
	NNI_ASSERT(p->p_refcnt == 0);

	nni_objhash_unref(nni_allpipes, p->p_id);
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
	nni_pipe *scratch;

	rv = nni_objhash_find(nni_allpipes, p->p_id, (void **) &scratch);
	if (rv != 0) {
		return (rv);
	}
	NNI_ASSERT(p == scratch);

	if ((rv = nni_sock_pipe_ready(p->p_sock, p)) != 0) {
		nni_pipe_close(p);
		return (rv);
	}

	// XXX: Publish event

	return (0);
}


void
nni_pipe_set_proto_data(nni_pipe *p, void *data)
{
	p->p_proto_data = data;
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
