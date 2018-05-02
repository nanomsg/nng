//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/nng_impl.h"

#include <string.h>

// This file contains functions relating to pipes.
//
// Operations on pipes (to the transport) are generally blocking operations,
// performed in the context of the protocol.

struct nni_pipe {
	uint32_t      p_id;
	nni_tran_pipe p_tran_ops;
	void *        p_tran_data;
	void *        p_proto_data;
	nni_list_node p_sock_node;
	nni_list_node p_ep_node;
	nni_sock *    p_sock;
	nni_ep *      p_ep;
	bool          p_closed;
	bool          p_stop;
	int           p_refcnt;
	nni_mtx       p_mtx;
	nni_cv        p_cv;
	nni_list_node p_reap_node;
	nni_aio *     p_start_aio;
};

static nni_idhash *nni_pipes;
static nni_mtx     nni_pipe_lk;

static nni_list nni_pipe_reap_list;
static nni_mtx  nni_pipe_reap_lk;
static nni_cv   nni_pipe_reap_cv;
static nni_thr  nni_pipe_reap_thr;
static int      nni_pipe_reap_run;

static void nni_pipe_reaper(void *);

int
nni_pipe_sys_init(void)
{
	int rv;

	NNI_LIST_INIT(&nni_pipe_reap_list, nni_pipe, p_reap_node);
	nni_mtx_init(&nni_pipe_lk);
	nni_mtx_init(&nni_pipe_reap_lk);
	nni_cv_init(&nni_pipe_reap_cv, &nni_pipe_reap_lk);

	if (((rv = nni_idhash_init(&nni_pipes)) != 0) ||
	    ((rv = nni_thr_init(&nni_pipe_reap_thr, nni_pipe_reaper, 0)) !=
	        0)) {
		return (rv);
	}

	// Note that pipes have their own namespace.  ID hash will
	// guarantee the that the first value is reasonable (non-zero),
	// if we supply an out of range value (0).  (Consequently the
	// value "1" has a bias -- its roughly twice as likely to be
	// chosen as any other value.  This does not mater.)
	nni_idhash_set_limits(
	    nni_pipes, 1, 0x7fffffff, nni_random() & 0x7fffffff);

	nni_pipe_reap_run = 1;
	nni_thr_run(&nni_pipe_reap_thr);

	return (0);
}

void
nni_pipe_sys_fini(void)
{
	if (nni_pipe_reap_run) {
		nni_mtx_lock(&nni_pipe_reap_lk);
		nni_pipe_reap_run = 0;
		nni_cv_wake(&nni_pipe_reap_cv);
		nni_mtx_unlock(&nni_pipe_reap_lk);
	}

	nni_thr_fini(&nni_pipe_reap_thr);
	nni_cv_fini(&nni_pipe_reap_cv);
	nni_mtx_fini(&nni_pipe_reap_lk);
	nni_mtx_fini(&nni_pipe_lk);
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

	// Stop any pending negotiation.
	nni_aio_stop(p->p_start_aio);

	// We have exclusive access at this point, so we can check if
	// we are still on any lists.
	if (nni_list_node_active(&p->p_ep_node)) {
		nni_ep_pipe_remove(p->p_ep, p);
	}
	if (nni_list_node_active(&p->p_sock_node)) {
		nni_sock_pipe_remove(p->p_sock, p);
	}

	// Make sure any unlocked holders are done with this.
	// This happens during initialization for example.
	nni_mtx_lock(&nni_pipe_lk);
	if (p->p_id != 0) {
		nni_idhash_remove(nni_pipes, p->p_id);
	}
	while (p->p_refcnt != 0) {
		nni_cv_wait(&p->p_cv);
	}
	nni_mtx_unlock(&nni_pipe_lk);

	if (p->p_tran_data != NULL) {
		p->p_tran_ops.p_fini(p->p_tran_data);
	}
	nni_aio_fini(p->p_start_aio);
	nni_mtx_fini(&p->p_mtx);
	NNI_FREE_STRUCT(p);
}

int
nni_pipe_find(nni_pipe **pp, uint32_t id)
{
	int       rv;
	nni_pipe *p;
	nni_mtx_lock(&nni_pipe_lk);

	// We don't care if the pipe is "closed".  End users only have
	// access to the pipe in order to obtain properties (which may
	// be retried during the post-close notification callback) or to
	// close the pipe.
	if ((rv = nni_idhash_find(nni_pipes, id, (void **) &p)) == 0) {
		p->p_refcnt++;
		*pp = p;
	}
	nni_mtx_unlock(&nni_pipe_lk);
	return (rv);
}

void
nni_pipe_rele(nni_pipe *p)
{
	nni_mtx_lock(&nni_pipe_lk);
	p->p_refcnt--;
	if (p->p_refcnt == 0) {
		nni_cv_wake(&p->p_cv);
	}
	nni_mtx_unlock(&nni_pipe_lk);
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
// subsequent attempts to receive or send (including any waiting receive) will
// simply return NNG_ECLOSED.
void
nni_pipe_close(nni_pipe *p)
{
	nni_mtx_lock(&p->p_mtx);
	if (p->p_closed) {
		// We already did a close.
		nni_mtx_unlock(&p->p_mtx);
		return;
	}
	p->p_closed = true;

	// Close the underlying transport.
	if (p->p_tran_data != NULL) {
		p->p_tran_ops.p_close(p->p_tran_data);
	}

	nni_mtx_unlock(&p->p_mtx);

	// abort any pending negotiation/start process.
	nni_aio_abort(p->p_start_aio, NNG_ECLOSED);
}

bool
nni_pipe_closed(nni_pipe *p)
{
	bool rv;
	nni_mtx_lock(&p->p_mtx);
	rv = p->p_closed;
	nni_mtx_unlock(&p->p_mtx);
	return (rv);
}

void
nni_pipe_stop(nni_pipe *p)
{
	// Guard against recursive calls.
	nni_pipe_close(p);
	nni_mtx_lock(&p->p_mtx);
	if (p->p_stop) {
		nni_mtx_unlock(&p->p_mtx);
		return;
	}
	p->p_stop = true;
	nni_mtx_unlock(&p->p_mtx);

	// Put it on the reaplist for async cleanup
	nni_mtx_lock(&nni_pipe_reap_lk);
	nni_list_append(&nni_pipe_reap_list, p);
	nni_cv_wake(&nni_pipe_reap_cv);
	nni_mtx_unlock(&nni_pipe_reap_lk);
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
	nni_aio * aio = p->p_start_aio;

	if (nni_aio_result(aio) != 0) {
		nni_pipe_stop(p);
		return;
	}

	if (nni_sock_pipe_start(p->p_sock, p) != 0) {
		nni_pipe_stop(p);
	}
}

int
nni_pipe_create(nni_ep *ep, void *tdata)
{
	nni_pipe *p;
	int       rv;
	nni_tran *tran = nni_ep_tran(ep);
	nni_sock *sock = nni_ep_sock(ep);

	if ((p = NNI_ALLOC_STRUCT(p)) == NULL) {
		// In this case we just toss the pipe...
		tran->tran_pipe->p_fini(tdata);
		return (NNG_ENOMEM);
	}

	// Make a private copy of the transport ops.
	p->p_tran_ops   = *tran->tran_pipe;
	p->p_tran_data  = tdata;
	p->p_proto_data = NULL;
	p->p_ep         = ep;
	p->p_sock       = sock;
	p->p_closed     = false;
	p->p_stop       = false;
	p->p_refcnt     = 0;

	NNI_LIST_NODE_INIT(&p->p_reap_node);
	NNI_LIST_NODE_INIT(&p->p_sock_node);
	NNI_LIST_NODE_INIT(&p->p_ep_node);

	nni_mtx_init(&p->p_mtx);
	nni_cv_init(&p->p_cv, &nni_pipe_lk);
	if ((rv = nni_aio_init(&p->p_start_aio, nni_pipe_start_cb, p)) == 0) {
		uint64_t id;
		nni_mtx_lock(&nni_pipe_lk);
		if ((rv = nni_idhash_alloc(nni_pipes, &id, p)) == 0) {
			p->p_id = (uint32_t) id;
		}
		nni_mtx_unlock(&nni_pipe_lk);
	}

	if ((rv != 0) || ((rv = nni_ep_pipe_add(ep, p)) != 0) ||
	    ((rv = nni_sock_pipe_add(sock, p)) != 0)) {
		nni_pipe_destroy(p);
	}

	return (rv);
}

int
nni_pipe_getopt(nni_pipe *p, const char *name, void *val, size_t *szp, int typ)
{
	nni_tran_pipe_option *po;

	for (po = p->p_tran_ops.p_options; po && po->po_name; po++) {
		if (strcmp(po->po_name, name) != 0) {
			continue;
		}
		return (po->po_getopt(p->p_tran_data, val, szp, typ));
	}
	// Maybe the endpoint knows?
	return (nni_ep_getopt(p->p_ep, name, val, szp, typ));
}

void
nni_pipe_start(nni_pipe *p)
{
	if (p->p_tran_ops.p_start == NULL) {
		nni_aio_finish(p->p_start_aio, 0, 0);
	} else {
		p->p_tran_ops.p_start(p->p_tran_data, p->p_start_aio);
	}
}

void *
nni_pipe_get_proto_data(nni_pipe *p)
{
	return (p->p_proto_data);
}

void
nni_pipe_set_proto_data(nni_pipe *p, void *data)
{
	p->p_proto_data = data;
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

uint32_t
nni_pipe_sock_id(nni_pipe *p)
{
	return (nni_sock_id(p->p_sock));
}

uint32_t
nni_pipe_ep_id(nni_pipe *p)
{
	return (nni_ep_id(p->p_ep));
}

int
nni_pipe_ep_mode(nni_pipe *p)
{
	return (nni_ep_mode(p->p_ep));
}

static void
nni_pipe_reaper(void *notused)
{
	NNI_ARG_UNUSED(notused);

	nni_mtx_lock(&nni_pipe_reap_lk);
	for (;;) {
		nni_pipe *p;
		if ((p = nni_list_first(&nni_pipe_reap_list)) != NULL) {
			nni_list_remove(&nni_pipe_reap_list, p);

			nni_mtx_unlock(&nni_pipe_reap_lk);
			nni_pipe_destroy(p);
			nni_mtx_lock(&nni_pipe_reap_lk);
			continue;
		}
		if (!nni_pipe_reap_run) {
			break;
		}
		nni_cv_wait(&nni_pipe_reap_cv);
	}
	nni_mtx_unlock(&nni_pipe_reap_lk);
}
