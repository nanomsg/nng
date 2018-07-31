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
#include "sockimpl.h"

#include <string.h>

// This file contains functions relating to pipes.
//
// Operations on pipes (to the transport) are generally blocking operations,
// performed in the context of the protocol.

static nni_idhash *nni_pipes;
static nni_mtx     nni_pipe_lk;

int
nni_pipe_sys_init(void)
{
	int rv;

	nni_mtx_init(&nni_pipe_lk);

	if ((rv = nni_idhash_init(&nni_pipes)) != 0) {
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
	nni_reap_drain();
	nni_mtx_fini(&nni_pipe_lk);
	if (nni_pipes != NULL) {
		nni_idhash_fini(nni_pipes);
		nni_pipes = NULL;
	}
}

static void
pipe_destroy(nni_pipe *p)
{
	if (p == NULL) {
		return;
	}

	nni_pipe_run_cb(p, NNG_PIPE_EV_REM_POST);

	// Make sure any unlocked holders are done with this.
	// This happens during initialization for example.
	nni_mtx_lock(&nni_pipe_lk);
	if (p->p_id != 0) {
		nni_idhash_remove(nni_pipes, p->p_id);
	}
	// This wait guarantees that all callers are done with us.
	while (p->p_refcnt != 0) {
		nni_cv_wait(&p->p_cv);
	}
	nni_mtx_unlock(&nni_pipe_lk);

	if (p->p_proto_data != NULL) {
		p->p_proto_ops.pipe_stop(p->p_proto_data);
	}
	if ((p->p_tran_data != NULL) && (p->p_tran_ops.p_stop != NULL)) {
		p->p_tran_ops.p_stop(p->p_tran_data);
	}

	nni_pipe_remove(p);

	if (p->p_proto_data != NULL) {
		p->p_proto_ops.pipe_fini(p->p_proto_data);
	}
	if (p->p_tran_data != NULL) {
		p->p_tran_ops.p_fini(p->p_tran_data);
	}
	nni_cv_fini(&p->p_cv);
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
	nni_mtx_unlock(&p->p_mtx);

	if (p->p_proto_data != NULL) {
		p->p_proto_ops.pipe_close(p->p_proto_data);
	}

	// Close the underlying transport.
	if (p->p_tran_data != NULL) {
		p->p_tran_ops.p_close(p->p_tran_data);
	}

	nni_reap(&p->p_reap, (nni_cb) pipe_destroy, p);
}

uint16_t
nni_pipe_peer(nni_pipe *p)
{
	return (p->p_tran_ops.p_peer(p->p_tran_data));
}

int
nni_pipe_create(nni_pipe **pp, nni_sock *sock, nni_tran *tran, void *tdata)
{
	nni_pipe *          p;
	int                 rv;
	void *              sdata = nni_sock_proto_data(sock);
	nni_proto_pipe_ops *pops  = nni_sock_proto_pipe_ops(sock);
	uint64_t            id;

	if ((p = NNI_ALLOC_STRUCT(p)) == NULL) {
		// In this case we just toss the pipe...
		tran->tran_pipe->p_fini(tdata);
		return (NNG_ENOMEM);
	}

	// Make a private copy of the transport ops.
	p->p_tran_ops   = *tran->tran_pipe;
	p->p_tran_data  = tdata;
	p->p_proto_ops  = *pops;
	p->p_proto_data = NULL;
	p->p_sock       = sock;
	p->p_closed     = false;
	p->p_cbs        = false;
	p->p_refcnt     = 0;

	nni_atomic_flag_reset(&p->p_stop);
	NNI_LIST_NODE_INIT(&p->p_sock_node);
	NNI_LIST_NODE_INIT(&p->p_ep_node);

	nni_mtx_init(&p->p_mtx);
	nni_cv_init(&p->p_cv, &nni_pipe_lk);

	nni_mtx_lock(&nni_pipe_lk);
	if ((rv = nni_idhash_alloc(nni_pipes, &id, p)) == 0) {
		p->p_id = (uint32_t) id;
	}
	nni_mtx_unlock(&nni_pipe_lk);

	if ((rv != 0) ||
	    ((rv = pops->pipe_init(&p->p_proto_data, p, sdata)) != 0)) {
		nni_pipe_close(p);
		return (rv);
	}

	*pp = p;
	return (0);
}

int
nni_pipe_getopt(
    nni_pipe *p, const char *name, void *val, size_t *szp, nni_opt_type t)
{
	nni_tran_option *o;

	for (o = p->p_tran_ops.p_options; o && o->o_name; o++) {
		if (strcmp(o->o_name, name) != 0) {
			continue;
		}
		return (o->o_get(p->p_tran_data, val, szp, t));
	}

	// Maybe the endpoint knows? The guarantees on pipes ensure that the
	// pipe will not outlive its creating endpoint.
	if (p->p_dialer != NULL) {
		return (nni_dialer_getopt(p->p_dialer, name, val, szp, t));
	}
	if (p->p_listener != NULL) {
		return (nni_listener_getopt(p->p_listener, name, val, szp, t));
	}
	return (NNG_ENOTSUP);
}

void *
nni_pipe_get_proto_data(nni_pipe *p)
{
	return (p->p_proto_data);
}

uint32_t
nni_pipe_sock_id(nni_pipe *p)
{
	return (nni_sock_id(p->p_sock));
}

uint32_t
nni_pipe_listener_id(nni_pipe *p)
{
	return (p->p_listener ? nni_listener_id(p->p_listener) : 0);
}

uint32_t
nni_pipe_dialer_id(nni_pipe *p)
{
	return (p->p_dialer ? nni_dialer_id(p->p_dialer) : 0);
}
