//
// Copyright 2021 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <stdlib.h>

#include "core/nng_impl.h"
#include "nng/protocol/pipeline0/pull.h"

// Pull protocol.  The PULL protocol is the "read" side of a pipeline.

#ifndef NNI_PROTO_PULL_V0
#define NNI_PROTO_PULL_V0 NNI_PROTO(5, 1)
#endif

#ifndef NNI_PROTO_PUSH_V0
#define NNI_PROTO_PUSH_V0 NNI_PROTO(5, 0)
#endif

typedef struct pull0_pipe pull0_pipe;
typedef struct pull0_sock pull0_sock;

static void pull0_recv_cb(void *);

// pull0_sock is our per-socket protocol private structure.
struct pull0_sock {
	bool         raw;
	nni_list     pl; // pipe list (pipes with data ready)
	nni_list     rq; // recv queue (aio list)
	nni_mtx      m;
	nni_pollable readable;
};

// pull0_pipe is our per-pipe protocol private structure.
struct pull0_pipe {
	nni_pipe *    p;
	pull0_sock *  s;
	nni_msg *     m;
	nni_aio       aio;
	bool          closed;
	nni_list_node node;
};

static void
pull0_sock_init(void *arg, nni_sock *sock)
{
	pull0_sock *s = arg;
	NNI_ARG_UNUSED(sock);

	nni_aio_list_init(&s->rq);
	NNI_LIST_INIT(&s->pl, pull0_pipe, node);
	nni_mtx_init(&s->m);
	nni_pollable_init(&s->readable);
}

static void
pull0_sock_fini(void *arg)
{
	pull0_sock *s = arg;
	nni_mtx_fini(&s->m);
	nni_pollable_fini(&s->readable);
}

static void
pull0_pipe_stop(void *arg)
{
	pull0_pipe *p = arg;

	nni_aio_stop(&p->aio);
}

static void
pull0_pipe_fini(void *arg)
{
	pull0_pipe *p = arg;

	nni_aio_fini(&p->aio);
	if (p->m) {
		nni_msg_free(p->m);
	}
}

static int
pull0_pipe_init(void *arg, nni_pipe *pipe, void *s)
{
	pull0_pipe *p = arg;

	nni_aio_init(&p->aio, pull0_recv_cb, p);
	p->p = pipe;
	p->s = s;
	return (0);
}

static int
pull0_pipe_start(void *arg)
{
	pull0_pipe *p = arg;

	if (nni_pipe_peer(p->p) != NNI_PROTO_PUSH_V0) {
		// Peer protocol mismatch.
		return (NNG_EPROTO);
	}

	// Start the pending receive...
	nni_pipe_recv(p->p, &p->aio);

	return (0);
}

static void
pull0_pipe_close(void *arg)
{
	pull0_pipe *p = arg;
	pull0_sock *s = p->s;

	nni_mtx_lock(&s->m);
	p->closed = true;
	if (nni_list_node_active(&p->node)) {
		nni_list_node_remove(&p->node);
		if (nni_list_empty(&s->pl)) {
			nni_pollable_clear(&s->readable);
		}
	}
	nni_mtx_unlock(&s->m);

	nni_aio_close(&p->aio);
}

static void
pull0_recv_cb(void *arg)
{
	pull0_pipe *p  = arg;
	pull0_sock *s  = p->s;
	nni_aio *   ap = &p->aio;
	nni_aio *   as;
	nni_msg *   m;

	if (nni_aio_result(ap) != 0) {
		// Failed to get a message, probably the pipe is closed.
		nni_pipe_close(p->p);
		return;
	}

	// Got a message... start the put to send it up to the application.
	m = nni_aio_get_msg(ap);
	nni_aio_set_msg(ap, NULL);
	nni_msg_set_pipe(m, nni_pipe_id(p->p));

	nni_mtx_lock(&s->m);
	if (p->closed) {
		nni_mtx_unlock(&s->m);
		nni_msg_free(m);
		return;
	}
	if (nni_list_empty(&s->rq)) {
		nni_list_append(&s->pl, p);
		if (nni_list_first(&s->pl) == p) {
			nni_pollable_raise(&s->readable);
		}
		p->m = m;
		nni_mtx_unlock(&s->m);
		return;
	}
	nni_pipe_recv(p->p, ap);
	as = nni_list_first(&s->rq);
	nni_aio_list_remove(as);
	nni_mtx_unlock(&s->m);
	nni_aio_set_msg(as, m);
	nni_aio_finish_sync(as, 0, nni_msg_len(m));
}

static void
pull0_sock_open(void *arg)
{
	NNI_ARG_UNUSED(arg);
}

static void
pull0_sock_close(void *arg)
{
	pull0_sock *s = arg;
	nni_aio *   a;
	nni_mtx_lock(&s->m);
	while ((a = nni_list_first(&s->rq)) != NULL) {
		nni_aio_list_remove(a);
		nni_aio_finish_error(a, NNG_ECLOSED);
	}
	// NB: The common socket framework closes pipes before this.
	nni_mtx_unlock(&s->m);
}

static void
pull0_sock_send(void *arg, nni_aio *aio)
{
	NNI_ARG_UNUSED(arg);
	nni_aio_finish_error(aio, NNG_ENOTSUP);
}

static void
pull0_cancel(nni_aio *aio, void *arg, int rv)
{
	pull0_sock *s = arg;
	nni_mtx_lock(&s->m);
	if (nni_aio_list_active(aio)) {
		nni_aio_list_remove(aio);
		nni_aio_finish_error(aio, rv);
	}
	nni_mtx_unlock(&s->m);
}

static void
pull0_sock_recv(void *arg, nni_aio *aio)
{
	pull0_sock *s = arg;
	pull0_pipe *p;

	if (nni_aio_begin(aio) != 0) {
		return;
	}

	nni_mtx_lock(&s->m);
	if ((p = nni_list_first(&s->pl)) == NULL) {

		int rv;
		if ((rv = nni_aio_schedule(aio, pull0_cancel, s)) != 0) {
			nni_mtx_unlock(&s->m);
			nni_aio_finish_error(aio, rv);
			return;
		}

		nni_aio_list_append(&s->rq, aio);
		nni_mtx_unlock(&s->m);
		return;
	}

	nni_list_remove(&s->pl, p);
	if (nni_list_empty(&s->pl)) {
		nni_pollable_clear(&s->readable);
	}
	nni_aio_finish_msg(aio, p->m);
	p->m = NULL;
	nni_pipe_recv(p->p, &p->aio);
	nni_mtx_unlock(&s->m);
}

static int
pull0_sock_get_recv_fd(void *arg, void *buf, size_t *szp, nni_opt_type t)
{
	pull0_sock *s = arg;
	int         rv;
	int         fd;

	if ((rv = nni_pollable_getfd(&s->readable, &fd)) != 0) {
		return (rv);
	}
	return (nni_copyout_int(fd, buf, szp, t));
}

static nni_option pull0_sock_options[] = {
	{
	    .o_name = NNG_OPT_RECVFD,
	    .o_get  = pull0_sock_get_recv_fd,
	},
	// terminate list
	{
	    .o_name = NULL,
	},
};

static nni_proto_pipe_ops pull0_pipe_ops = {
	.pipe_size  = sizeof(pull0_pipe),
	.pipe_init  = pull0_pipe_init,
	.pipe_fini  = pull0_pipe_fini,
	.pipe_start = pull0_pipe_start,
	.pipe_close = pull0_pipe_close,
	.pipe_stop  = pull0_pipe_stop,
};

static nni_proto_sock_ops pull0_sock_ops = {
	.sock_size    = sizeof(pull0_sock),
	.sock_init    = pull0_sock_init,
	.sock_fini    = pull0_sock_fini,
	.sock_open    = pull0_sock_open,
	.sock_close   = pull0_sock_close,
	.sock_send    = pull0_sock_send,
	.sock_recv    = pull0_sock_recv,
	.sock_options = pull0_sock_options,
};

static nni_proto pull0_proto = {
	.proto_version  = NNI_PROTOCOL_VERSION,
	.proto_self     = { NNI_PROTO_PULL_V0, "pull" },
	.proto_peer     = { NNI_PROTO_PUSH_V0, "push" },
	.proto_flags    = NNI_PROTO_FLAG_RCV,
	.proto_pipe_ops = &pull0_pipe_ops,
	.proto_sock_ops = &pull0_sock_ops,
};

static nni_proto pull0_proto_raw = {
	.proto_version  = NNI_PROTOCOL_VERSION,
	.proto_self     = { NNI_PROTO_PULL_V0, "pull" },
	.proto_peer     = { NNI_PROTO_PUSH_V0, "push" },
	.proto_flags    = NNI_PROTO_FLAG_RCV | NNI_PROTO_FLAG_RAW,
	.proto_pipe_ops = &pull0_pipe_ops,
	.proto_sock_ops = &pull0_sock_ops,
};

int
nng_pull0_open(nng_socket *s)
{
	return (nni_proto_open(s, &pull0_proto));
}

int
nng_pull0_open_raw(nng_socket *s)
{
	return (nni_proto_open(s, &pull0_proto_raw));
}
