//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
// Copyright 2017 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <stdlib.h>
#include <string.h>

#include "core/nng_impl.h"

// Push protocol.  The PUSH protocol is the "write" side of a pipeline.
// Push distributes fairly, or tries to, by giving messages in round-robin
// order.

typedef struct push_pipe push_pipe;
typedef struct push_sock push_sock;

static void push_send_cb(void *);
static void push_recv_cb(void *);
static void push_getq_cb(void *);

// An nni_push_sock is our per-socket protocol private structure.
struct push_sock {
	nni_msgq *uwq;
	int       raw;
	nni_sock *sock;
};

// An nni_push_pipe is our per-pipe protocol private structure.
struct push_pipe {
	nni_pipe *    pipe;
	push_sock *   push;
	nni_list_node node;

	nni_aio *aio_recv;
	nni_aio *aio_send;
	nni_aio *aio_getq;
};

static int
push_sock_init(void **sp, nni_sock *sock)
{
	push_sock *s;

	if ((s = NNI_ALLOC_STRUCT(s)) == NULL) {
		return (NNG_ENOMEM);
	}
	s->raw  = 0;
	s->sock = sock;
	s->uwq  = nni_sock_sendq(sock);
	*sp     = s;
	nni_sock_recverr(sock, NNG_ENOTSUP);
	return (0);
}

static void
push_sock_fini(void *arg)
{
	push_sock *s = arg;

	NNI_FREE_STRUCT(s);
}

static void
push_sock_open(void *arg)
{
	NNI_ARG_UNUSED(arg);
}

static void
push_sock_close(void *arg)
{
	NNI_ARG_UNUSED(arg);
}

static void
push_pipe_fini(void *arg)
{
	push_pipe *p = arg;

	nni_aio_fini(p->aio_recv);
	nni_aio_fini(p->aio_send);
	nni_aio_fini(p->aio_getq);
	NNI_FREE_STRUCT(p);
}

static int
push_pipe_init(void **pp, nni_pipe *pipe, void *s)
{
	push_pipe *p;
	int        rv;

	if ((p = NNI_ALLOC_STRUCT(p)) == NULL) {
		return (NNG_ENOMEM);
	}
	if (((rv = nni_aio_init(&p->aio_recv, push_recv_cb, p)) != 0) ||
	    ((rv = nni_aio_init(&p->aio_send, push_send_cb, p)) != 0) ||
	    ((rv = nni_aio_init(&p->aio_getq, push_getq_cb, p)) != 0)) {
		push_pipe_fini(p);
		return (rv);
	}
	NNI_LIST_NODE_INIT(&p->node);
	p->pipe = pipe;
	p->push = s;
	*pp     = p;
	return (0);
}

static int
push_pipe_start(void *arg)
{
	push_pipe *p = arg;
	push_sock *s = p->push;

	if (nni_pipe_peer(p->pipe) != NNG_PROTO_PULL) {
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
push_pipe_stop(void *arg)
{
	push_pipe *p = arg;

	nni_aio_stop(p->aio_recv);
	nni_aio_stop(p->aio_send);
	nni_aio_stop(p->aio_getq);
}

static void
push_recv_cb(void *arg)
{
	push_pipe *p = arg;

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
push_send_cb(void *arg)
{
	push_pipe *p = arg;
	push_sock *s = p->push;

	if (nni_aio_result(p->aio_send) != 0) {
		nni_msg_free(nni_aio_get_msg(p->aio_send));
		nni_aio_set_msg(p->aio_send, NULL);
		nni_pipe_stop(p->pipe);
		return;
	}

	nni_msgq_aio_get(s->uwq, p->aio_getq);
}

static void
push_getq_cb(void *arg)
{
	push_pipe *p   = arg;
	nni_aio *  aio = p->aio_getq;

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
push_sock_setopt(void *arg, int opt, const void *buf, size_t sz)
{
	push_sock *s  = arg;
	int        rv = NNG_ENOTSUP;

	if (opt == nng_optid_raw) {
		rv = nni_setopt_int(&s->raw, buf, sz, 0, 1);
	}
	return (rv);
}

static int
push_sock_getopt(void *arg, int opt, void *buf, size_t *szp)
{
	push_sock *s  = arg;
	int        rv = NNG_ENOTSUP;

	if (opt == nng_optid_raw) {
		rv = nni_getopt_int(&s->raw, buf, szp);
	}
	return (rv);
}

static nni_proto_pipe_ops push_pipe_ops = {
	.pipe_init  = push_pipe_init,
	.pipe_fini  = push_pipe_fini,
	.pipe_start = push_pipe_start,
	.pipe_stop  = push_pipe_stop,
};

static nni_proto_sock_ops push_sock_ops = {
	.sock_init   = push_sock_init,
	.sock_fini   = push_sock_fini,
	.sock_open   = push_sock_open,
	.sock_close  = push_sock_close,
	.sock_setopt = push_sock_setopt,
	.sock_getopt = push_sock_getopt,
};

static nni_proto push_proto = {
	.proto_version  = NNI_PROTOCOL_VERSION,
	.proto_self     = { NNG_PROTO_PUSH_V0, "push" },
	.proto_peer     = { NNG_PROTO_PULL_V0, "pull" },
	.proto_flags    = NNI_PROTO_FLAG_SND,
	.proto_pipe_ops = &push_pipe_ops,
	.proto_sock_ops = &push_sock_ops,
};

int
nng_push0_open(nng_socket *sidp)
{
	return (nni_proto_open(sidp, &push_proto));
}
