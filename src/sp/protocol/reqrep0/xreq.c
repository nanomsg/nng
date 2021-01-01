//
// Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <stdio.h>

#include "core/nng_impl.h"
#include "nng/protocol/reqrep0/req.h"

// Request protocol.  The REQ protocol is the "request" side of a
// request-reply pair.  This is useful for building RPC clients, for example.

typedef struct xreq0_pipe xreq0_pipe;
typedef struct xreq0_sock xreq0_sock;

// An xreq0_sock is our per-socket protocol private structure.
struct xreq0_sock {
	nni_msgq *     uwq;
	nni_msgq *     urq;
	nni_atomic_int ttl;
};

// A req0_pipe is our per-pipe protocol private structure.
struct xreq0_pipe {
	nni_pipe *  pipe;
	xreq0_sock *req;
	nni_aio     aio_getq;
	nni_aio     aio_send;
	nni_aio     aio_recv;
	nni_aio     aio_putq;
};

static void xreq0_sock_fini(void *);
static void xreq0_getq_cb(void *);
static void xreq0_send_cb(void *);
static void xreq0_recv_cb(void *);
static void xreq0_putq_cb(void *);

static int
xreq0_sock_init(void *arg, nni_sock *sock)
{
	xreq0_sock *s = arg;

	nni_atomic_init(&s->ttl);
	nni_atomic_set(&s->ttl, 8);
	s->uwq = nni_sock_sendq(sock);
	s->urq = nni_sock_recvq(sock);

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
	NNI_ARG_UNUSED(arg);
}

static void
xreq0_pipe_stop(void *arg)
{
	xreq0_pipe *p = arg;

	nni_aio_stop(&p->aio_getq);
	nni_aio_stop(&p->aio_putq);
	nni_aio_stop(&p->aio_recv);
	nni_aio_stop(&p->aio_send);
}

static void
xreq0_pipe_fini(void *arg)
{
	xreq0_pipe *p = arg;

	nni_aio_fini(&p->aio_getq);
	nni_aio_fini(&p->aio_putq);
	nni_aio_fini(&p->aio_recv);
	nni_aio_fini(&p->aio_send);
}

static int
xreq0_pipe_init(void *arg, nni_pipe *pipe, void *s)
{
	xreq0_pipe *p = arg;

	nni_aio_init(&p->aio_getq, xreq0_getq_cb, p);
	nni_aio_init(&p->aio_putq, xreq0_putq_cb, p);
	nni_aio_init(&p->aio_recv, xreq0_recv_cb, p);
	nni_aio_init(&p->aio_send, xreq0_send_cb, p);

	p->pipe = pipe;
	p->req  = s;
	return (0);
}

static int
xreq0_pipe_start(void *arg)
{
	xreq0_pipe *p = arg;
	xreq0_sock *s = p->req;

	if (nni_pipe_peer(p->pipe) != NNG_REQ0_PEER) {
		return (NNG_EPROTO);
	}

	nni_msgq_aio_get(s->uwq, &p->aio_getq);
	nni_pipe_recv(p->pipe, &p->aio_recv);
	return (0);
}

static void
xreq0_pipe_close(void *arg)
{
	xreq0_pipe *p = arg;

	nni_aio_close(&p->aio_getq);
	nni_aio_close(&p->aio_putq);
	nni_aio_close(&p->aio_recv);
	nni_aio_close(&p->aio_send);
}

// For raw mode we can just let the pipes "contend" via get queue to get a
// message from the upper write queue.  The msg queue implementation
// actually provides ordering, so load will be spread automatically.
// (NB: We may have to revise this in the future if we want to provide some
// kind of priority.)

static void
xreq0_getq_cb(void *arg)
{
	xreq0_pipe *p = arg;

	if (nni_aio_result(&p->aio_getq) != 0) {
		nni_pipe_close(p->pipe);
		return;
	}

	nni_aio_set_msg(&p->aio_send, nni_aio_get_msg(&p->aio_getq));
	nni_aio_set_msg(&p->aio_getq, NULL);

	nni_pipe_send(p->pipe, &p->aio_send);
}

static void
xreq0_send_cb(void *arg)
{
	xreq0_pipe *p = arg;

	if (nni_aio_result(&p->aio_send) != 0) {
		nni_msg_free(nni_aio_get_msg(&p->aio_send));
		nni_aio_set_msg(&p->aio_send, NULL);
		nni_pipe_close(p->pipe);
		return;
	}

	// Sent a message so we just need to look for another one.
	nni_msgq_aio_get(p->req->uwq, &p->aio_getq);
}

static void
xreq0_putq_cb(void *arg)
{
	xreq0_pipe *p = arg;

	if (nni_aio_result(&p->aio_putq) != 0) {
		nni_msg_free(nni_aio_get_msg(&p->aio_putq));
		nni_aio_set_msg(&p->aio_putq, NULL);
		nni_pipe_close(p->pipe);
		return;
	}
	nni_aio_set_msg(&p->aio_putq, NULL);

	nni_pipe_recv(p->pipe, &p->aio_recv);
}

static void
xreq0_recv_cb(void *arg)
{
	xreq0_pipe *p    = arg;
	xreq0_sock *sock = p->req;
	nni_msg *   msg;
	bool        end;

	if (nni_aio_result(&p->aio_recv) != 0) {
		nni_pipe_close(p->pipe);
		return;
	}

	msg = nni_aio_get_msg(&p->aio_recv);
	nni_aio_set_msg(&p->aio_recv, NULL);
	nni_msg_set_pipe(msg, nni_pipe_id(p->pipe));
	end = false;

	while (!end) {
		uint8_t *body;

		if (nni_msg_len(msg) < 4) {
			// Peer gave us garbage, so kick it.
			nni_msg_free(msg);
			nni_pipe_close(p->pipe);
			return;
		}
		body = nni_msg_body(msg);
		end  = ((body[0] & 0x80u) != 0);

		if (nng_msg_header_append(msg, body, sizeof (uint32_t)) != 0) {
			// TODO: bump a no-memory stat
			nni_msg_free(msg);
			// Closing the pipe may release some memory.
			// It at least gives an indication to the peer
			// that we've lost the message.
			nni_pipe_close(p->pipe);
			return;
		}
		nni_msg_trim(msg, sizeof (uint32_t));
	}
	nni_aio_set_msg(&p->aio_putq, msg);
	nni_msgq_aio_put(sock->urq, &p->aio_putq);
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
xreq0_sock_set_max_ttl(void *arg, const void *buf, size_t sz, nni_opt_type t)
{
	xreq0_sock *s = arg;
	int         ttl;
	int         rv;
	if ((rv = nni_copyin_int(&ttl, buf, sz, 1, NNI_MAX_MAX_TTL, t)) == 0) {
		nni_atomic_set(&s->ttl, ttl);
	}
	return (rv);
}

static int
xreq0_sock_get_max_ttl(void *arg, void *buf, size_t *szp, nni_opt_type t)
{
	xreq0_sock *s = arg;
	return (nni_copyout_int(nni_atomic_get(&s->ttl), buf, szp, t));
}

static nni_proto_pipe_ops xreq0_pipe_ops = {
	.pipe_size  = sizeof(xreq0_pipe),
	.pipe_init  = xreq0_pipe_init,
	.pipe_fini  = xreq0_pipe_fini,
	.pipe_start = xreq0_pipe_start,
	.pipe_close = xreq0_pipe_close,
	.pipe_stop  = xreq0_pipe_stop,
};

static nni_option xreq0_sock_options[] = {
	{
	    .o_name = NNG_OPT_MAXTTL,
	    .o_get  = xreq0_sock_get_max_ttl,
	    .o_set  = xreq0_sock_set_max_ttl,
	},
	// terminate list
	{
	    .o_name = NULL,
	},
};

static nni_proto_sock_ops xreq0_sock_ops = {
	.sock_size    = sizeof(xreq0_sock),
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
	.proto_self     = { NNG_REQ0_SELF, NNG_REQ0_SELF_NAME },
	.proto_peer     = { NNG_REQ0_PEER, NNG_REQ0_PEER_NAME },
	.proto_flags    = NNI_PROTO_FLAG_SNDRCV | NNI_PROTO_FLAG_RAW,
	.proto_sock_ops = &xreq0_sock_ops,
	.proto_pipe_ops = &xreq0_pipe_ops,
	.proto_ctx_ops  = NULL, // raw mode does not support contexts
};

int
nng_req0_open_raw(nng_socket *sock)
{
	return (nni_proto_open(sock, &xreq0_proto));
}
