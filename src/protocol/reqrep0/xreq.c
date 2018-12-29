//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/nng_impl.h"
#include "nng/protocol/reqrep0/req.h"

// Request protocol.  The REQ protocol is the "request" side of a
// request-reply pair.  This is useful for building RPC clients, for example.

#ifndef NNI_PROTO_REQ_V0
#define NNI_PROTO_REQ_V0 NNI_PROTO(3, 0)
#endif

#ifndef NNI_PROTO_REP_V0
#define NNI_PROTO_REP_V0 NNI_PROTO(3, 1)
#endif

typedef struct xreq0_pipe xreq0_pipe;
typedef struct xreq0_sock xreq0_sock;

// An xreq0_sock is our per-socket protocol private structure.
struct xreq0_sock {
	nni_msgq *uwq;
	nni_msgq *urq;
	int       ttl;
};

// A req0_pipe is our per-pipe protocol private structure.
struct xreq0_pipe {
	nni_pipe *  pipe;
	xreq0_sock *req;
	nni_aio *   aio_getq;
	nni_aio *   aio_send;
	nni_aio *   aio_recv;
	nni_aio *   aio_putq;
};

static void xreq0_sock_fini(void *);
static void xreq0_getq_cb(void *);
static void xreq0_send_cb(void *);
static void xreq0_recv_cb(void *);
static void xreq0_putq_cb(void *);

static int
xreq0_sock_init(void **sp, nni_sock *sock)
{
	xreq0_sock *s;

	if ((s = NNI_ALLOC_STRUCT(s)) == NULL) {
		return (NNG_ENOMEM);
	}

	s->ttl = 8;
	s->uwq = nni_sock_sendq(sock);
	s->urq = nni_sock_recvq(sock);
	*sp    = s;

	return (0);
}

static void
xreq0_sock_open(void *arg)
{
	NNI_ARG_UNUSED(arg);
}

static void
xreq0_sock_close(void *arg)
{
	NNI_ARG_UNUSED(arg);
}

static void
xreq0_sock_fini(void *arg)
{
	xreq0_sock *s = arg;

	NNI_FREE_STRUCT(s);
}

static void
xreq0_pipe_stop(void *arg)
{
	xreq0_pipe *p = arg;

	nni_aio_stop(p->aio_getq);
	nni_aio_stop(p->aio_putq);
	nni_aio_stop(p->aio_recv);
	nni_aio_stop(p->aio_send);
}

static void
xreq0_pipe_fini(void *arg)
{
	xreq0_pipe *p = arg;

	nni_aio_fini(p->aio_getq);
	nni_aio_fini(p->aio_putq);
	nni_aio_fini(p->aio_recv);
	nni_aio_fini(p->aio_send);
	NNI_FREE_STRUCT(p);
}

static int
xreq0_pipe_init(void **pp, nni_pipe *pipe, void *s)
{
	xreq0_pipe *p;
	int         rv;

	if ((p = NNI_ALLOC_STRUCT(p)) == NULL) {
		return (NNG_ENOMEM);
	}
	if (((rv = nni_aio_init(&p->aio_getq, xreq0_getq_cb, p)) != 0) ||
	    ((rv = nni_aio_init(&p->aio_putq, xreq0_putq_cb, p)) != 0) ||
	    ((rv = nni_aio_init(&p->aio_recv, xreq0_recv_cb, p)) != 0) ||
	    ((rv = nni_aio_init(&p->aio_send, xreq0_send_cb, p)) != 0)) {
		xreq0_pipe_fini(p);
		return (rv);
	}

	p->pipe = pipe;
	p->req  = s;
	*pp     = p;
	return (0);
}

static int
xreq0_pipe_start(void *arg)
{
	xreq0_pipe *p = arg;
	xreq0_sock *s = p->req;

	if (nni_pipe_peer(p->pipe) != NNI_PROTO_REP_V0) {
		return (NNG_EPROTO);
	}

	nni_msgq_aio_get(s->uwq, p->aio_getq);
	nni_pipe_recv(p->pipe, p->aio_recv);
	return (0);
}

static void
xreq0_pipe_close(void *arg)
{
	xreq0_pipe *p = arg;

	nni_aio_close(p->aio_getq);
	nni_aio_close(p->aio_putq);
	nni_aio_close(p->aio_recv);
	nni_aio_close(p->aio_send);
}

// For raw mode we can just let the pipes "contend" via getq to get a
// message from the upper write queue.  The msgqueue implementation
// actually provides ordering, so load will be spread automatically.
// (NB: We may have to revise this in the future if we want to provide some
// kind of priority.)

static void
xreq0_getq_cb(void *arg)
{
	xreq0_pipe *p = arg;

	if (nni_aio_result(p->aio_getq) != 0) {
		nni_pipe_close(p->pipe);
		return;
	}

	nni_aio_set_msg(p->aio_send, nni_aio_get_msg(p->aio_getq));
	nni_aio_set_msg(p->aio_getq, NULL);

	nni_pipe_send(p->pipe, p->aio_send);
}

static void
xreq0_send_cb(void *arg)
{
	xreq0_pipe *p = arg;

	if (nni_aio_result(p->aio_send) != 0) {
		nni_msg_free(nni_aio_get_msg(p->aio_send));
		nni_aio_set_msg(p->aio_send, NULL);
		nni_pipe_close(p->pipe);
		return;
	}

	// Sent a message so we just need to look for another one.
	nni_msgq_aio_get(p->req->uwq, p->aio_getq);
}

static void
xreq0_putq_cb(void *arg)
{
	xreq0_pipe *p = arg;

	if (nni_aio_result(p->aio_putq) != 0) {
		nni_msg_free(nni_aio_get_msg(p->aio_putq));
		nni_aio_set_msg(p->aio_putq, NULL);
		nni_pipe_close(p->pipe);
		return;
	}
	nni_aio_set_msg(p->aio_putq, NULL);

	nni_pipe_recv(p->pipe, p->aio_recv);
}

static void
xreq0_recv_cb(void *arg)
{
	xreq0_pipe *p    = arg;
	xreq0_sock *sock = p->req;
	nni_msg *   msg;
	uint32_t    id;

	if (nni_aio_result(p->aio_recv) != 0) {
		nni_pipe_close(p->pipe);
		return;
	}

	msg = nni_aio_get_msg(p->aio_recv);
	nni_aio_set_msg(p->aio_recv, NULL);
	nni_msg_set_pipe(msg, nni_pipe_id(p->pipe));

	// We yank 4 bytes from front of body, and move them to the header.
	if (nni_msg_len(msg) < 4) {
		// Peer gave us garbage, so kick it.
		nni_msg_free(msg);
		nni_pipe_close(p->pipe);
		return;
	}
	id = nni_msg_trim_u32(msg);
	if (nni_msg_header_append_u32(msg, id) != 0) {
		// Probably ENOMEM, discard and carry on.
		nni_msg_free(msg);
		nni_pipe_recv(p->pipe, p->aio_recv);
		return;
	}

	nni_aio_set_msg(p->aio_putq, msg);
	nni_msgq_aio_put(sock->urq, p->aio_putq);
}

static void
xreq0_sock_send(void *arg, nni_aio *aio)
{
	xreq0_sock *s = arg;

	nni_msgq_aio_put(s->uwq, aio);
}

static void
xreq0_sock_recv(void *arg, nni_aio *aio)
{
	xreq0_sock *s = arg;

	nni_msgq_aio_get(s->urq, aio);
}

static int
xreq0_sock_set_maxttl(void *arg, const void *buf, size_t sz, nni_opt_type t)
{
	xreq0_sock *s = arg;
	return (nni_copyin_int(&s->ttl, buf, sz, 1, 255, t));
}

static int
xreq0_sock_get_maxttl(void *arg, void *buf, size_t *szp, nni_opt_type t)
{
	xreq0_sock *s = arg;
	return (nni_copyout_int(s->ttl, buf, szp, t));
}

static nni_proto_pipe_ops xreq0_pipe_ops = {
	.pipe_init  = xreq0_pipe_init,
	.pipe_fini  = xreq0_pipe_fini,
	.pipe_start = xreq0_pipe_start,
	.pipe_close = xreq0_pipe_close,
	.pipe_stop  = xreq0_pipe_stop,
};

static nni_option xreq0_sock_options[] = {
	{
	    .o_name = NNG_OPT_MAXTTL,
	    .o_get  = xreq0_sock_get_maxttl,
	    .o_set  = xreq0_sock_set_maxttl,
	},
	// terminate list
	{
	    .o_name = NULL,
	},
};

static nni_proto_sock_ops xreq0_sock_ops = {
	.sock_init    = xreq0_sock_init,
	.sock_fini    = xreq0_sock_fini,
	.sock_open    = xreq0_sock_open,
	.sock_close   = xreq0_sock_close,
	.sock_options = xreq0_sock_options,
	.sock_send    = xreq0_sock_send,
	.sock_recv    = xreq0_sock_recv,
};

static nni_proto xreq0_proto = {
	.proto_version  = NNI_PROTOCOL_VERSION,
	.proto_self     = { NNI_PROTO_REQ_V0, "req" },
	.proto_peer     = { NNI_PROTO_REP_V0, "rep" },
	.proto_flags    = NNI_PROTO_FLAG_SNDRCV | NNI_PROTO_FLAG_RAW,
	.proto_sock_ops = &xreq0_sock_ops,
	.proto_pipe_ops = &xreq0_pipe_ops,
	.proto_ctx_ops  = NULL, // raw mode does not support contexts
};

int
nng_req0_open_raw(nng_socket *sidp)
{
	return (nni_proto_open(sidp, &xreq0_proto));
}
