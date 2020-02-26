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
#include "nng/protocol/survey0/respond.h"

// Respondent protocol.  The RESPONDENT protocol is the "replier" side of
// the surveyor pattern.  This is useful for building service discovery, or
// voting algorithms, for example.

#ifndef NNI_PROTO_SURVEYOR_V0
#define NNI_PROTO_SURVEYOR_V0 NNI_PROTO(6, 2)
#endif

#ifndef NNI_PROTO_RESPONDENT_V0
#define NNI_PROTO_RESPONDENT_V0 NNI_PROTO(6, 3)
#endif

typedef struct xresp0_pipe xresp0_pipe;
typedef struct xresp0_sock xresp0_sock;

static void xresp0_recv_cb(void *);
static void xresp0_putq_cb(void *);
static void xresp0_getq_cb(void *);
static void xresp0_send_cb(void *);
static void xresp0_sock_getq_cb(void *);
static void xresp0_pipe_fini(void *);

// resp0_sock is our per-socket protocol private structure.
struct xresp0_sock {
	nni_msgq *     urq;
	nni_msgq *     uwq;
	nni_atomic_int ttl;
	nni_idhash *   pipes;
	nni_aio *      aio_getq;
	nni_mtx        mtx;
};

// resp0_pipe is our per-pipe protocol private structure.
struct xresp0_pipe {
	nni_pipe *   npipe;
	xresp0_sock *psock;
	uint32_t     id;
	nni_msgq *   sendq;
	nni_aio *    aio_getq;
	nni_aio *    aio_putq;
	nni_aio *    aio_send;
	nni_aio *    aio_recv;
};

static void
xresp0_sock_fini(void *arg)
{
	xresp0_sock *s = arg;

	nni_aio_free(s->aio_getq);
	nni_idhash_fini(s->pipes);
	nni_mtx_fini(&s->mtx);
}

static int
xresp0_sock_init(void *arg, nni_sock *nsock)
{
	xresp0_sock *s = arg;
	int          rv;

	nni_mtx_init(&s->mtx);
	nni_atomic_init(&s->ttl);
	nni_atomic_set(&s->ttl, 8); // Per RFC
	if (((rv = nni_idhash_init(&s->pipes)) != 0) ||
	    ((rv = nni_aio_alloc(&s->aio_getq, xresp0_sock_getq_cb, s)) !=
	        0)) {
		xresp0_sock_fini(s);
		return (rv);
	}

	s->urq = nni_sock_recvq(nsock);
	s->uwq = nni_sock_sendq(nsock);

	return (0);
}

static void
xresp0_sock_open(void *arg)
{
	xresp0_sock *s = arg;

	nni_msgq_aio_get(s->uwq, s->aio_getq);
}

static void
xresp0_sock_close(void *arg)
{
	xresp0_sock *s = arg;

	nni_aio_close(s->aio_getq);
}

static void
xresp0_pipe_stop(void *arg)
{
	xresp0_pipe *p = arg;

	nni_aio_stop(p->aio_putq);
	nni_aio_stop(p->aio_getq);
	nni_aio_stop(p->aio_send);
	nni_aio_stop(p->aio_recv);
}

static void
xresp0_pipe_fini(void *arg)
{
	xresp0_pipe *p = arg;

	nni_aio_free(p->aio_putq);
	nni_aio_free(p->aio_getq);
	nni_aio_free(p->aio_send);
	nni_aio_free(p->aio_recv);
	nni_msgq_fini(p->sendq);
}

static int
xresp0_pipe_init(void *arg, nni_pipe *npipe, void *s)
{
	xresp0_pipe *p = arg;
	int          rv;

	if (((rv = nni_msgq_init(&p->sendq, 2)) != 0) ||
	    ((rv = nni_aio_alloc(&p->aio_putq, xresp0_putq_cb, p)) != 0) ||
	    ((rv = nni_aio_alloc(&p->aio_recv, xresp0_recv_cb, p)) != 0) ||
	    ((rv = nni_aio_alloc(&p->aio_getq, xresp0_getq_cb, p)) != 0) ||
	    ((rv = nni_aio_alloc(&p->aio_send, xresp0_send_cb, p)) != 0)) {
		xresp0_pipe_fini(p);
		return (rv);
	}

	p->npipe = npipe;
	p->psock = s;
	return (0);
}

static int
xresp0_pipe_start(void *arg)
{
	xresp0_pipe *p = arg;
	xresp0_sock *s = p->psock;
	int          rv;

	if (nni_pipe_peer(p->npipe) != NNI_PROTO_SURVEYOR_V0) {
		return (NNG_EPROTO);
	}

	p->id = nni_pipe_id(p->npipe);

	nni_mtx_lock(&s->mtx);
	rv = nni_idhash_insert(s->pipes, p->id, p);
	nni_mtx_unlock(&s->mtx);
	if (rv != 0) {
		return (rv);
	}

	nni_pipe_recv(p->npipe, p->aio_recv);
	nni_msgq_aio_get(p->sendq, p->aio_getq);

	return (rv);
}

static void
xresp0_pipe_close(void *arg)
{
	xresp0_pipe *p = arg;
	xresp0_sock *s = p->psock;

	nni_aio_close(p->aio_putq);
	nni_aio_close(p->aio_getq);
	nni_aio_close(p->aio_send);
	nni_aio_close(p->aio_recv);

	nni_msgq_close(p->sendq);

	nni_mtx_lock(&s->mtx);
	nni_idhash_remove(s->pipes, p->id);
	nni_mtx_unlock(&s->mtx);
}

// resp0_sock_send watches for messages from the upper write queue,
// extracts the destination pipe, and forwards it to the appropriate
// destination pipe via a separate queue.  This prevents a single bad
// or slow pipe from gumming up the works for the entire socket.s

void
xresp0_sock_getq_cb(void *arg)
{
	xresp0_sock *s = arg;
	nni_msg *    msg;
	uint32_t     id;
	xresp0_pipe *p;

	if (nni_aio_result(s->aio_getq) != 0) {
		return;
	}
	msg = nni_aio_get_msg(s->aio_getq);
	nni_aio_set_msg(s->aio_getq, NULL);

	// We yank the outgoing pipe id from the header
	if (nni_msg_header_len(msg) < 4) {
		nni_msg_free(msg);
		// We can't really close down the socket, so just keep going.
		nni_msgq_aio_get(s->uwq, s->aio_getq);
		return;
	}
	id = nni_msg_header_trim_u32(msg);

	nni_mtx_lock(&s->mtx);
	// Look for the pipe, and attempt to put the message there
	// (nonblocking) if we can.  If we can't for any reason, then we
	// free the message.
	if (((nni_idhash_find(s->pipes, id, (void **) &p)) != 0) ||
	    (nni_msgq_tryput(p->sendq, msg) != 0)) {
		nni_msg_free(msg);
	}
	nni_mtx_unlock(&s->mtx);
	nni_msgq_aio_get(s->uwq, s->aio_getq);
}

void
xresp0_getq_cb(void *arg)
{
	xresp0_pipe *p = arg;

	if (nni_aio_result(p->aio_getq) != 0) {
		nni_pipe_close(p->npipe);
		return;
	}

	nni_aio_set_msg(p->aio_send, nni_aio_get_msg(p->aio_getq));
	nni_aio_set_msg(p->aio_getq, NULL);

	nni_pipe_send(p->npipe, p->aio_send);
}

void
xresp0_send_cb(void *arg)
{
	xresp0_pipe *p = arg;

	if (nni_aio_result(p->aio_send) != 0) {
		nni_msg_free(nni_aio_get_msg(p->aio_send));
		nni_aio_set_msg(p->aio_send, NULL);
		nni_pipe_close(p->npipe);
		return;
	}

	nni_msgq_aio_get(p->sendq, p->aio_getq);
}

static void
xresp0_recv_cb(void *arg)
{
	xresp0_pipe *p   = arg;
	xresp0_sock *s   = p->psock;
	nni_msgq *   urq = s->urq;
	nni_msg *    msg;
	int          hops;
	int          ttl;

	if (nni_aio_result(p->aio_recv) != 0) {
		nni_pipe_close(p->npipe);
		return;
	}

	ttl = nni_atomic_get(&s->ttl);
	msg = nni_aio_get_msg(p->aio_recv);
	nni_aio_set_msg(p->aio_recv, NULL);
	nni_msg_set_pipe(msg, p->id);

	// Store the pipe id in the header, first thing.
	nni_msg_header_append_u32(msg, p->id);

	// Move backtrace from body to header
	hops = 1;
	for (;;) {
		bool     end;
		uint8_t *body;

		if (hops > ttl) {
			goto drop;
		}
		hops++;
		if (nni_msg_len(msg) < 4) {
			// Peer sent us garbage, so kick it.
			nni_msg_free(msg);
			nni_pipe_close(p->npipe);
			return;
		}
		body = nni_msg_body(msg);
		end  = ((body[0] & 0x80u) != 0);
		if (nni_msg_header_append(msg, body, 4) != 0) {
			goto drop;
		}
		nni_msg_trim(msg, 4);
		if (end) {
			break;
		}
	}

	// Now send it up.
	nni_aio_set_msg(p->aio_putq, msg);
	nni_msgq_aio_put(urq, p->aio_putq);
	return;

drop:
	nni_msg_free(msg);
	nni_pipe_recv(p->npipe, p->aio_recv);
}

static void
xresp0_putq_cb(void *arg)
{
	xresp0_pipe *p = arg;

	if (nni_aio_result(p->aio_putq) != 0) {
		nni_msg_free(nni_aio_get_msg(p->aio_putq));
		nni_aio_set_msg(p->aio_putq, NULL);
		nni_pipe_close(p->npipe);
		return;
	}

	nni_pipe_recv(p->npipe, p->aio_recv);
}

static int
xresp0_sock_set_maxttl(void *arg, const void *buf, size_t sz, nni_opt_type t)
{
	xresp0_sock *s = arg;
	int ttl;
	int rv;
	if ((rv = nni_copyin_int(&ttl, buf, sz, 1, NNI_MAX_MAX_TTL, t)) == 0) {
		nni_atomic_set(&s->ttl, ttl);
	}
	return (rv);
}

static int
xresp0_sock_get_maxttl(void *arg, void *buf, size_t *szp, nni_opt_type t)
{
	xresp0_sock *s = arg;
	return (nni_copyout_int(nni_atomic_get(&s->ttl), buf, szp, t));
}

static void
xresp0_sock_send(void *arg, nni_aio *aio)
{
	xresp0_sock *s = arg;

	nni_msgq_aio_put(s->uwq, aio);
}

static void
xresp0_sock_recv(void *arg, nni_aio *aio)
{
	xresp0_sock *s = arg;

	nni_msgq_aio_get(s->urq, aio);
}

static nni_proto_pipe_ops xresp0_pipe_ops = {
	.pipe_size  = sizeof(xresp0_pipe),
	.pipe_init  = xresp0_pipe_init,
	.pipe_fini  = xresp0_pipe_fini,
	.pipe_start = xresp0_pipe_start,
	.pipe_close = xresp0_pipe_close,
	.pipe_stop  = xresp0_pipe_stop,
};

static nni_option xresp0_sock_options[] = {
	{
	    .o_name = NNG_OPT_MAXTTL,
	    .o_get  = xresp0_sock_get_maxttl,
	    .o_set  = xresp0_sock_set_maxttl,
	},
	// terminate list
	{
	    .o_name = NULL,
	},
};

static nni_proto_sock_ops xresp0_sock_ops = {
	.sock_size    = sizeof(xresp0_sock),
	.sock_init    = xresp0_sock_init,
	.sock_fini    = xresp0_sock_fini,
	.sock_open    = xresp0_sock_open,
	.sock_close   = xresp0_sock_close,
	.sock_send    = xresp0_sock_send,
	.sock_recv    = xresp0_sock_recv,
	.sock_options = xresp0_sock_options,
};

static nni_proto xresp0_proto = {
	.proto_version  = NNI_PROTOCOL_VERSION,
	.proto_self     = { NNI_PROTO_RESPONDENT_V0, "respondent" },
	.proto_peer     = { NNI_PROTO_SURVEYOR_V0, "surveyor" },
	.proto_flags    = NNI_PROTO_FLAG_SNDRCV | NNI_PROTO_FLAG_RAW,
	.proto_sock_ops = &xresp0_sock_ops,
	.proto_pipe_ops = &xresp0_pipe_ops,
};

int
nng_respondent0_open_raw(nng_socket *sidp)
{
	return (nni_proto_open(sidp, &xresp0_proto));
}
