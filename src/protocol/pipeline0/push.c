//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <stdlib.h>
#include <string.h>

#include "core/nng_impl.h"
#include "protocol/pipeline0/push.h"

// Push protocol.  The PUSH protocol is the "write" side of a pipeline.
// Push distributes fairly, or tries to, by giving messages in round-robin
// order.

#ifndef NNI_PROTO_PULL_V0
#define NNI_PROTO_PULL_V0 NNI_PROTO(5, 1)
#endif

#ifndef NNI_PROTO_PUSH_V0
#define NNI_PROTO_PUSH_V0 NNI_PROTO(5, 0)
#endif

typedef struct push0_pipe push0_pipe;
typedef struct push0_sock push0_sock;

static void push0_send_cb(void *);
static void push0_recv_cb(void *);
static void push0_getq_cb(void *);

// push0_sock is our per-socket protocol private structure.
struct push0_sock {
	nni_msgq *uwq;
	bool      raw;
};

// push0_pipe is our per-pipe protocol private structure.
struct push0_pipe {
	nni_pipe *    pipe;
	push0_sock *  push;
	nni_list_node node;

	nni_aio *aio_recv;
	nni_aio *aio_send;
	nni_aio *aio_getq;
};

static int
push0_sock_init(void **sp, nni_sock *sock)
{
	push0_sock *s;

	if ((s = NNI_ALLOC_STRUCT(s)) == NULL) {
		return (NNG_ENOMEM);
	}
	s->raw = false;
	s->uwq = nni_sock_sendq(sock);
	*sp    = s;
	return (0);
}

static void
push0_sock_fini(void *arg)
{
	push0_sock *s = arg;

	NNI_FREE_STRUCT(s);
}

static void
push0_sock_open(void *arg)
{
	NNI_ARG_UNUSED(arg);
}

static void
push0_sock_close(void *arg)
{
	NNI_ARG_UNUSED(arg);
}

static void
push0_pipe_fini(void *arg)
{
	push0_pipe *p = arg;

	nni_aio_fini(p->aio_recv);
	nni_aio_fini(p->aio_send);
	nni_aio_fini(p->aio_getq);
	NNI_FREE_STRUCT(p);
}

static int
push0_pipe_init(void **pp, nni_pipe *pipe, void *s)
{
	push0_pipe *p;
	int         rv;

	if ((p = NNI_ALLOC_STRUCT(p)) == NULL) {
		return (NNG_ENOMEM);
	}
	if (((rv = nni_aio_init(&p->aio_recv, push0_recv_cb, p)) != 0) ||
	    ((rv = nni_aio_init(&p->aio_send, push0_send_cb, p)) != 0) ||
	    ((rv = nni_aio_init(&p->aio_getq, push0_getq_cb, p)) != 0)) {
		push0_pipe_fini(p);
		return (rv);
	}
	NNI_LIST_NODE_INIT(&p->node);
	p->pipe = pipe;
	p->push = s;
	*pp     = p;
	return (0);
}

static int
push0_pipe_start(void *arg)
{
	push0_pipe *p = arg;
	push0_sock *s = p->push;

	if (nni_pipe_peer(p->pipe) != NNI_PROTO_PULL_V0) {
		return (NNG_EPROTO);
	}

	// Schedule a receiver.  This is mostly so that we can detect
	// a closed transport pipe.
	nni_pipe_recv(p->pipe, p->aio_recv);

	// Schedule a sender.
	nni_msgq_aio_get(s->uwq, p->aio_getq);

	return (0);
}

static void
push0_pipe_stop(void *arg)
{
	push0_pipe *p = arg;

	nni_aio_stop(p->aio_recv);
	nni_aio_stop(p->aio_send);
	nni_aio_stop(p->aio_getq);
}

static void
push0_recv_cb(void *arg)
{
	push0_pipe *p = arg;

	// We normally expect to receive an error.  If a pipe actually
	// sends us data, we just discard it.
	if (nni_aio_result(p->aio_recv) != 0) {
		nni_pipe_stop(p->pipe);
		return;
	}
	nni_msg_free(nni_aio_get_msg(p->aio_recv));
	nni_aio_set_msg(p->aio_recv, NULL);
	nni_pipe_recv(p->pipe, p->aio_recv);
}

static void
push0_send_cb(void *arg)
{
	push0_pipe *p = arg;
	push0_sock *s = p->push;

	if (nni_aio_result(p->aio_send) != 0) {
		nni_msg_free(nni_aio_get_msg(p->aio_send));
		nni_aio_set_msg(p->aio_send, NULL);
		nni_pipe_stop(p->pipe);
		return;
	}

	nni_msgq_aio_get(s->uwq, p->aio_getq);
}

static void
push0_getq_cb(void *arg)
{
	push0_pipe *p   = arg;
	nni_aio *   aio = p->aio_getq;

	if (nni_aio_result(aio) != 0) {
		// If the socket is closing, nothing else we can do.
		nni_pipe_stop(p->pipe);
		return;
	}

	nni_aio_set_msg(p->aio_send, nni_aio_get_msg(aio));
	nni_aio_set_msg(aio, NULL);

	nni_pipe_send(p->pipe, p->aio_send);
}

static int
push0_sock_setopt_raw(void *arg, const void *buf, size_t sz)
{
	push0_sock *s = arg;
	return (nni_setopt_bool(&s->raw, buf, sz));
}

static int
push0_sock_getopt_raw(void *arg, void *buf, size_t *szp)
{
	push0_sock *s = arg;
	return (nni_getopt_bool(s->raw, buf, szp));
}

static void
push0_sock_send(void *arg, nni_aio *aio)
{
	push0_sock *s = arg;

	nni_msgq_aio_put(s->uwq, aio);
}

static void
push0_sock_recv(void *arg, nni_aio *aio)
{
	NNI_ARG_UNUSED(arg);
	nni_aio_finish_error(aio, NNG_ENOTSUP);
}

static nni_proto_pipe_ops push0_pipe_ops = {
	.pipe_init  = push0_pipe_init,
	.pipe_fini  = push0_pipe_fini,
	.pipe_start = push0_pipe_start,
	.pipe_stop  = push0_pipe_stop,
};

static nni_proto_sock_option push0_sock_options[] = {
	{
	    .pso_name   = NNG_OPT_RAW,
	    .pso_getopt = push0_sock_getopt_raw,
	    .pso_setopt = push0_sock_setopt_raw,
	},
	// terminate list
	{ NULL, NULL, NULL },
};

static nni_proto_sock_ops push0_sock_ops = {
	.sock_init    = push0_sock_init,
	.sock_fini    = push0_sock_fini,
	.sock_open    = push0_sock_open,
	.sock_close   = push0_sock_close,
	.sock_options = push0_sock_options,
	.sock_send    = push0_sock_send,
	.sock_recv    = push0_sock_recv,
};

static nni_proto push0_proto = {
	.proto_version  = NNI_PROTOCOL_VERSION,
	.proto_self     = { NNI_PROTO_PUSH_V0, "push" },
	.proto_peer     = { NNI_PROTO_PULL_V0, "pull" },
	.proto_flags    = NNI_PROTO_FLAG_SND,
	.proto_pipe_ops = &push0_pipe_ops,
	.proto_sock_ops = &push0_sock_ops,
};

int
nng_push0_open(nng_socket *sidp)
{
	return (nni_proto_open(sidp, &push0_proto));
}
