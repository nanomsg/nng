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

// Pair protocol.  The PAIR protocol is a simple 1:1 messaging pattern.
// While a peer is connected to the server, all other peer connection
// attempts are discarded.

typedef struct pair0_pipe pair0_pipe;
typedef struct pair0_sock pair0_sock;

static void pair0_send_cb(void *);
static void pair0_recv_cb(void *);
static void pair0_getq_cb(void *);
static void pair0_putq_cb(void *);
static void pair0_pipe_fini(void *);

// pair0_sock is our per-socket protocol private structure.
struct pair0_sock {
	nni_sock *  nsock;
	pair0_pipe *ppipe;
	nni_msgq *  uwq;
	nni_msgq *  urq;
	int         raw;
	nni_mtx     mtx;
};

// An pair0_pipe is our per-pipe protocol private structure.  We keep
// one of these even though in theory we'd only have a single underlying
// pipe.  The separate data structure is more like other protocols that do
// manage multiple pipes.
struct pair0_pipe {
	nni_pipe *  npipe;
	pair0_sock *psock;
	nni_aio     aio_send;
	nni_aio     aio_recv;
	nni_aio     aio_getq;
	nni_aio     aio_putq;
};

static int
pair0_sock_init(void **sp, nni_sock *nsock)
{
	pair0_sock *s;

	if ((s = NNI_ALLOC_STRUCT(s)) == NULL) {
		return (NNG_ENOMEM);
	}
	nni_mtx_init(&s->mtx);
	s->nsock = nsock;
	s->ppipe = NULL;
	s->raw   = 0;
	s->uwq   = nni_sock_sendq(nsock);
	s->urq   = nni_sock_recvq(nsock);
	*sp      = s;
	return (0);
}

static void
pair0_sock_fini(void *arg)
{
	pair0_sock *s = arg;

	nni_mtx_fini(&s->mtx);
	NNI_FREE_STRUCT(s);
}

static int
pair0_pipe_init(void **pp, nni_pipe *npipe, void *psock)
{
	pair0_pipe *p;

	if ((p = NNI_ALLOC_STRUCT(p)) == NULL) {
		return (NNG_ENOMEM);
	}
	nni_aio_init(&p->aio_send, pair0_send_cb, p);
	nni_aio_init(&p->aio_recv, pair0_recv_cb, p);
	nni_aio_init(&p->aio_getq, pair0_getq_cb, p);
	nni_aio_init(&p->aio_putq, pair0_putq_cb, p);

	p->npipe = npipe;
	p->psock = psock;
	*pp      = p;
	return (0);
}

static void
pair0_pipe_fini(void *arg)
{
	pair0_pipe *p = arg;

	nni_aio_fini(&p->aio_send);
	nni_aio_fini(&p->aio_recv);
	nni_aio_fini(&p->aio_putq);
	nni_aio_fini(&p->aio_getq);
	NNI_FREE_STRUCT(p);
}

static int
pair0_pipe_start(void *arg)
{
	pair0_pipe *p = arg;
	pair0_sock *s = p->psock;

	nni_mtx_lock(&s->mtx);
	if (s->ppipe != NULL) {
		nni_mtx_unlock(&s->mtx);
		return (NNG_EBUSY); // Already have a peer, denied.
	}
	s->ppipe = p;
	nni_mtx_unlock(&s->mtx);

	// Schedule a getq on the upper, and a read from the pipe.
	// Each of these also sets up another hold on the pipe itself.
	nni_msgq_aio_get(s->uwq, &p->aio_getq);
	nni_pipe_recv(p->npipe, &p->aio_recv);

	return (0);
}

static void
pair0_pipe_stop(void *arg)
{
	pair0_pipe *p = arg;
	pair0_sock *s = p->psock;

	nni_aio_cancel(&p->aio_send, NNG_ECANCELED);
	nni_aio_cancel(&p->aio_recv, NNG_ECANCELED);
	nni_aio_cancel(&p->aio_putq, NNG_ECANCELED);
	nni_aio_cancel(&p->aio_getq, NNG_ECANCELED);

	nni_mtx_lock(&s->mtx);
	if (s->ppipe == p) {
		s->ppipe = NULL;
	}
	nni_mtx_unlock(&s->mtx);
}

static void
pair0_recv_cb(void *arg)
{
	pair0_pipe *p = arg;
	pair0_sock *s = p->psock;
	nni_msg *   msg;

	if (nni_aio_result(&p->aio_recv) != 0) {
		nni_pipe_stop(p->npipe);
		return;
	}

	msg               = p->aio_recv.a_msg;
	p->aio_putq.a_msg = msg;
	p->aio_recv.a_msg = NULL;

	nni_msg_set_pipe(msg, nni_pipe_id(p->npipe));
	nni_msgq_aio_put(s->urq, &p->aio_putq);
}

static void
pair0_putq_cb(void *arg)
{
	pair0_pipe *p = arg;

	if (nni_aio_result(&p->aio_putq) != 0) {
		nni_msg_free(p->aio_putq.a_msg);
		p->aio_putq.a_msg = NULL;
		nni_pipe_stop(p->npipe);
		return;
	}
	nni_pipe_recv(p->npipe, &p->aio_recv);
}

static void
pair0_getq_cb(void *arg)
{
	pair0_pipe *p = arg;
	pair0_sock *s = p->psock;

	if (nni_aio_result(&p->aio_getq) != 0) {
		nni_pipe_stop(p->npipe);
		return;
	}

	p->aio_send.a_msg = p->aio_getq.a_msg;
	p->aio_getq.a_msg = NULL;
	nni_pipe_send(p->npipe, &p->aio_send);
}

static void
pair0_send_cb(void *arg)
{
	pair0_pipe *p = arg;
	pair0_sock *s = p->psock;

	if (nni_aio_result(&p->aio_send) != 0) {
		nni_msg_free(p->aio_send.a_msg);
		p->aio_send.a_msg = NULL;
		nni_pipe_stop(p->npipe);
		return;
	}

	nni_msgq_aio_get(s->uwq, &p->aio_getq);
}

static void
pair0_sock_open(void *arg)
{
	NNI_ARG_UNUSED(arg);
}

static void
pair0_sock_close(void *arg)
{
	NNI_ARG_UNUSED(arg);
}

static int
pair0_sock_setopt(void *arg, int opt, const void *buf, size_t sz)
{
	pair0_sock *s = arg;
	int         rv;

	if (opt == nng_optid_raw) {
		rv = nni_setopt_int(&s->raw, buf, sz, 0, 1);
	} else {
		rv = NNG_ENOTSUP;
	}
	return (rv);
}

static int
pair0_sock_getopt(void *arg, int opt, void *buf, size_t *szp)
{
	pair0_sock *s = arg;
	int         rv;

	if (opt == nng_optid_raw) {
		rv = nni_getopt_int(&s->raw, buf, szp);
	} else {
		rv = NNG_ENOTSUP;
	}
	return (rv);
}

static nni_proto_pipe_ops pair0_pipe_ops = {
	.pipe_init  = pair0_pipe_init,
	.pipe_fini  = pair0_pipe_fini,
	.pipe_start = pair0_pipe_start,
	.pipe_stop  = pair0_pipe_stop,
};

static nni_proto_sock_ops pair0_sock_ops = {
	.sock_init   = pair0_sock_init,
	.sock_fini   = pair0_sock_fini,
	.sock_open   = pair0_sock_open,
	.sock_close  = pair0_sock_close,
	.sock_setopt = pair0_sock_setopt,
	.sock_getopt = pair0_sock_getopt,
};

// Legacy protocol (v0)
static nni_proto pair0_proto = {
	.proto_version  = NNI_PROTOCOL_VERSION,
	.proto_self     = { NNG_PROTO_PAIR_V0, "pair" },
	.proto_peer     = { NNG_PROTO_PAIR_V0, "pair" },
	.proto_flags    = NNI_PROTO_FLAG_SNDRCV,
	.proto_sock_ops = &pair0_sock_ops,
	.proto_pipe_ops = &pair0_pipe_ops,
};

int
nng_pair0_open(nng_socket *sidp)
{
	return (nni_proto_open(sidp, &pair0_proto));
}
