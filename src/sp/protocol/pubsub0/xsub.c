//
// Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <stdlib.h>

#include "core/nng_impl.h"
#include "nng/protocol/pubsub0/sub.h"

// Subscriber protocol.  The SUB protocol receives messages sent to
// it from publishers, and filters out those it is not interested in,
// only passing up ones that match known subscriptions.

#ifndef NNI_PROTO_SUB_V0
#define NNI_PROTO_SUB_V0 NNI_PROTO(2, 1)
#endif

#ifndef NNI_PROTO_PUB_V0
#define NNI_PROTO_PUB_V0 NNI_PROTO(2, 0)
#endif

typedef struct xsub0_pipe xsub0_pipe;
typedef struct xsub0_sock xsub0_sock;

static void xsub0_recv_cb(void *);
static void xsub0_pipe_fini(void *);

// xsub0_sock is our per-socket protocol private structure.
struct xsub0_sock {
	nni_msgq *urq;
	nni_mtx   lk;
};

// sub0_pipe is our per-pipe protocol private structure.
struct xsub0_pipe {
	nni_pipe *  pipe;
	xsub0_sock *sub;
	nni_aio    aio_recv;
};

static int
xsub0_sock_init(void *arg, nni_sock *sock)
{
	xsub0_sock *s = arg;

	s->urq = nni_sock_recvq(sock);
	return (0);
}

static void
xsub0_sock_fini(void *arg)
{
	xsub0_sock *s = arg;
	nni_mtx_fini(&s->lk);
}

static void
xsub0_sock_open(void *arg)
{
	NNI_ARG_UNUSED(arg);
}

static void
xsub0_sock_close(void *arg)
{
	NNI_ARG_UNUSED(arg);
}

static void
xsub0_pipe_stop(void *arg)
{
	xsub0_pipe *p = arg;

	nni_aio_stop(&p->aio_recv);
}

static void
xsub0_pipe_fini(void *arg)
{
	xsub0_pipe *p = arg;

	nni_aio_fini(&p->aio_recv);
}

static int
xsub0_pipe_init(void *arg, nni_pipe *pipe, void *s)
{
	xsub0_pipe *p = arg;

	nni_aio_init(&p->aio_recv, xsub0_recv_cb, p);

	p->pipe = pipe;
	p->sub  = s;
	return (0);
}

static int
xsub0_pipe_start(void *arg)
{
	xsub0_pipe *p = arg;

	if (nni_pipe_peer(p->pipe) != NNI_PROTO_PUB_V0) {
		// Peer protocol mismatch.
		return (NNG_EPROTO);
	}

	nni_pipe_recv(p->pipe, &p->aio_recv);
	return (0);
}

static void
xsub0_pipe_close(void *arg)
{
	xsub0_pipe *p = arg;

	nni_aio_close(&p->aio_recv);
}

static void
xsub0_recv_cb(void *arg)
{
	xsub0_pipe *p   = arg;
	xsub0_sock *s   = p->sub;
	nni_msgq *  urq = s->urq;
	nni_msg *   msg;

	if (nni_aio_result(&p->aio_recv) != 0) {
		nni_pipe_close(p->pipe);
		return;
	}

	msg = nni_aio_get_msg(&p->aio_recv);
	nni_aio_set_msg(&p->aio_recv, NULL);
	nni_msg_set_pipe(msg, nni_pipe_id(p->pipe));

	if (nni_msgq_tryput(urq, msg) != 0) {
		// This only happens for two reasons.  For flow control,
		// in which case we just want to discard the message and
		// carry on, and for a close of the socket (which is very
		// hard to achieve, since we close the pipes.)  In either
		// case the easiest thing to do is just free the message
		// and try again.
		nni_msg_free(msg);
	}
	nni_pipe_recv(p->pipe, &p->aio_recv);
}

static void
xsub0_sock_send(void *arg, nni_aio *aio)
{
	NNI_ARG_UNUSED(arg);
	nni_aio_finish_error(aio, NNG_ENOTSUP);
}

static void
xsub0_sock_recv(void *arg, nni_aio *aio)
{
	xsub0_sock *s = arg;

	nni_msgq_aio_get(s->urq, aio);
}

// This is the global protocol structure -- our linkage to the core.
// This should be the only global non-static symbol in this file.
static nni_proto_pipe_ops xsub0_pipe_ops = {
	.pipe_size  = sizeof(xsub0_pipe),
	.pipe_init  = xsub0_pipe_init,
	.pipe_fini  = xsub0_pipe_fini,
	.pipe_start = xsub0_pipe_start,
	.pipe_close = xsub0_pipe_close,
	.pipe_stop  = xsub0_pipe_stop,
};

static nni_option xsub0_sock_options[] = {
	// terminate list
	{
	    .o_name = NULL,
	},
};

static nni_proto_sock_ops xsub0_sock_ops = {
	.sock_size    = sizeof(xsub0_sock),
	.sock_init    = xsub0_sock_init,
	.sock_fini    = xsub0_sock_fini,
	.sock_open    = xsub0_sock_open,
	.sock_close   = xsub0_sock_close,
	.sock_send    = xsub0_sock_send,
	.sock_recv    = xsub0_sock_recv,
	.sock_options = xsub0_sock_options,
};

static nni_proto xsub0_proto = {
	.proto_version  = NNI_PROTOCOL_VERSION,
	.proto_self     = { NNI_PROTO_SUB_V0, "sub" },
	.proto_peer     = { NNI_PROTO_PUB_V0, "pub" },
	.proto_flags    = NNI_PROTO_FLAG_RCV | NNI_PROTO_FLAG_RAW,
	.proto_sock_ops = &xsub0_sock_ops,
	.proto_pipe_ops = &xsub0_pipe_ops,
};

int
nng_sub0_open_raw(nng_socket *sidp)
{
	return (nni_proto_open(sidp, &xsub0_proto));
}
