//
// Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <string.h>

#include "core/nng_impl.h"
#include "nng/protocol/reqrep0/rep.h"

// Response protocol.  The REP protocol is the "reply" side of a
// request-reply pair.  This is useful for building RPC servers, for
// example.

typedef struct rep0_pipe rep0_pipe;
typedef struct rep0_sock rep0_sock;
typedef struct rep0_ctx  rep0_ctx;

static void rep0_pipe_send_cb(void *);
static void rep0_pipe_recv_cb(void *);
static void rep0_pipe_fini(void *);

struct rep0_ctx {
	rep0_sock *   sock;
	uint32_t      pipe_id;
	rep0_pipe *   spipe; // send pipe
	nni_aio *     saio;  // send aio
	nni_aio *     raio;  // recv aio
	nni_list_node sqnode;
	nni_list_node rqnode;
	size_t        btrace_len;
	uint32_t      btrace[NNI_MAX_MAX_TTL + 1];
};

// rep0_sock is our per-socket protocol private structure.
struct rep0_sock {
	nni_mtx        lk;
	nni_atomic_int ttl;
	nni_idhash *   pipes;
	nni_list       recvpipes; // list of pipes with data to receive
	nni_list       recvq;
	rep0_ctx       ctx;
	nni_pollable   readable;
	nni_pollable   writable;
};

// rep0_pipe is our per-pipe protocol private structure.
struct rep0_pipe {
	nni_pipe *    pipe;
	rep0_sock *   rep;
	uint32_t      id;
	nni_aio       aio_send;
	nni_aio       aio_recv;
	nni_list_node rnode; // receivable list linkage
	nni_list      sendq; // contexts waiting to send
	bool          busy;
};

static void
rep0_ctx_close(void *arg)
{
	rep0_ctx * ctx = arg;
	rep0_sock *s   = ctx->sock;
	nni_aio *  aio;

	nni_mtx_lock(&s->lk);
	if ((aio = ctx->saio) != NULL) {
		rep0_pipe *pipe = ctx->spipe;
		ctx->saio       = NULL;
		ctx->spipe      = NULL;
		nni_list_remove(&pipe->sendq, ctx);
		nni_aio_finish_error(aio, NNG_ECLOSED);
	}
	if ((aio = ctx->raio) != NULL) {
		nni_list_remove(&s->recvq, ctx);
		ctx->raio = NULL;
		nni_aio_finish_error(aio, NNG_ECLOSED);
	}
	nni_mtx_unlock(&s->lk);
}

static void
rep0_ctx_fini(void *arg)
{
	rep0_ctx *ctx = arg;

	rep0_ctx_close(ctx);
}

static int
rep0_ctx_init(void *carg, void *sarg)
{
	rep0_sock *s   = sarg;
	rep0_ctx * ctx = carg;

	NNI_LIST_NODE_INIT(&ctx->sqnode);
	NNI_LIST_NODE_INIT(&ctx->rqnode);
	ctx->btrace_len = 0;
	ctx->sock       = s;
	ctx->pipe_id    = 0;

	return (0);
}

static void
rep0_ctx_cancel_send(nni_aio *aio, void *arg, int rv)
{
	rep0_ctx * ctx = arg;
	rep0_sock *s   = ctx->sock;

	nni_mtx_lock(&s->lk);
	if (ctx->saio != aio) {
		nni_mtx_unlock(&s->lk);
		return;
	}
	nni_list_node_remove(&ctx->sqnode);
	ctx->saio = NULL;
	nni_mtx_unlock(&s->lk);

	nni_msg_header_clear(nni_aio_get_msg(aio)); // reset the headers
	nni_aio_finish_error(aio, rv);
}

static void
rep0_ctx_send(void *arg, nni_aio *aio)
{
	rep0_ctx * ctx = arg;
	rep0_sock *s   = ctx->sock;
	rep0_pipe *p;
	nni_msg *  msg;
	int        rv;
	size_t     len;
	uint32_t   p_id; // pipe id

	msg = nni_aio_get_msg(aio);
	nni_msg_header_clear(msg);

	if (nni_aio_begin(aio) != 0) {
		return;
	}

	nni_mtx_lock(&s->lk);
	len  = ctx->btrace_len;
	p_id = ctx->pipe_id;

	// Assert "completion" of the previous req request.  This ensures
	// exactly one send for one receive ordering.
	ctx->btrace_len = 0;
	ctx->pipe_id    = 0;

	if (ctx == &s->ctx) {
		// No matter how this goes, we will no longer be able
		// to send on the socket (root context).  That's because
		// we will have finished (successfully or otherwise) the
		// reply for the single request we got.
		nni_pollable_clear(&s->writable);
	}
	if ((rv = nni_aio_schedule(aio, rep0_ctx_cancel_send, ctx)) != 0) {
		nni_mtx_unlock(&s->lk);
		nni_aio_finish_error(aio, rv);
		return;
	}

	if (len == 0) {
		nni_mtx_unlock(&s->lk);
		nni_aio_finish_error(aio, NNG_ESTATE);
		return;
	}
	if ((rv = nni_msg_header_append(msg, ctx->btrace, len)) != 0) {
		nni_mtx_unlock(&s->lk);
		nni_aio_finish_error(aio, rv);
		return;
	}
	if (nni_idhash_find(s->pipes, p_id, (void **) &p) != 0) {
		// Pipe is gone.  Make this look like a good send to avoid
		// disrupting the state machine.  We don't care if the peer
		// lost interest in our reply.
		nni_mtx_unlock(&s->lk);
		nni_aio_set_msg(aio, NULL);
		nni_aio_finish(aio, 0, nni_msg_len(msg));
		nni_msg_free(msg);
		return;
	}
	if (!p->busy) {
		p->busy = true;
		len     = nni_msg_len(msg);
		nni_aio_set_msg(&p->aio_send, msg);
		nni_pipe_send(p->pipe, &p->aio_send);
		nni_mtx_unlock(&s->lk);

		nni_aio_set_msg(aio, NULL);
		nni_aio_finish(aio, 0, len);
		return;
	}

	ctx->saio  = aio;
	ctx->spipe = p;
	nni_list_append(&p->sendq, ctx);
	nni_mtx_unlock(&s->lk);
}

static void
rep0_sock_fini(void *arg)
{
	rep0_sock *s = arg;

	nni_idhash_fini(s->pipes);
	rep0_ctx_fini(&s->ctx);
	nni_pollable_fini(&s->writable);
	nni_pollable_fini(&s->readable);
	nni_mtx_fini(&s->lk);
}

static int
rep0_sock_init(void *arg, nni_sock *sock)
{
	rep0_sock *s = arg;
	int        rv;

	NNI_ARG_UNUSED(sock);

	nni_mtx_init(&s->lk);
	if ((rv = nni_idhash_init(&s->pipes)) != 0) {
		rep0_sock_fini(s);
		return (rv);
	}

	NNI_LIST_INIT(&s->recvq, rep0_ctx, rqnode);
	NNI_LIST_INIT(&s->recvpipes, rep0_pipe, rnode);
	nni_atomic_init(&s->ttl);
	nni_atomic_set(&s->ttl, 8);

	(void) rep0_ctx_init(&s->ctx, s);

	// We start off without being either readable or writable.
	// Readability comes when there is something on the socket.
	nni_pollable_init(&s->writable);
	nni_pollable_init(&s->readable);

	return (0);
}

static void
rep0_sock_open(void *arg)
{
	NNI_ARG_UNUSED(arg);
}

static void
rep0_sock_close(void *arg)
{
	rep0_sock *s = arg;

	rep0_ctx_close(&s->ctx);
}

static void
rep0_pipe_stop(void *arg)
{
	rep0_pipe *p = arg;

	nni_aio_stop(&p->aio_send);
	nni_aio_stop(&p->aio_recv);
}

static void
rep0_pipe_fini(void *arg)
{
	rep0_pipe *p = arg;
	nng_msg *  msg;

	if ((msg = nni_aio_get_msg(&p->aio_recv)) != NULL) {
		nni_aio_set_msg(&p->aio_recv, NULL);
		nni_msg_free(msg);
	}

	nni_aio_fini(&p->aio_send);
	nni_aio_fini(&p->aio_recv);
}

static int
rep0_pipe_init(void *arg, nni_pipe *pipe, void *s)
{
	rep0_pipe *p = arg;

	nni_aio_init(&p->aio_send, rep0_pipe_send_cb, p);
	nni_aio_init(&p->aio_recv, rep0_pipe_recv_cb, p);

	NNI_LIST_INIT(&p->sendq, rep0_ctx, sqnode);

	p->id   = nni_pipe_id(pipe);
	p->pipe = pipe;
	p->rep  = s;
	return (0);
}

static int
rep0_pipe_start(void *arg)
{
	rep0_pipe *p = arg;
	rep0_sock *s = p->rep;
	int        rv;

	if (nni_pipe_peer(p->pipe) != NNG_REP0_PEER) {
		// Peer protocol mismatch.
		return (NNG_EPROTO);
	}

	if ((rv = nni_idhash_insert(s->pipes, nni_pipe_id(p->pipe), p)) != 0) {
		return (rv);
	}
	// By definition, we have not received a request yet on this pipe,
	// so it cannot cause us to become writable.
	nni_pipe_recv(p->pipe, &p->aio_recv);
	return (0);
}

static void
rep0_pipe_close(void *arg)
{
	rep0_pipe *p = arg;
	rep0_sock *s = p->rep;
	rep0_ctx * ctx;

	nni_aio_close(&p->aio_send);
	nni_aio_close(&p->aio_recv);

	nni_mtx_lock(&s->lk);
	if (nni_list_active(&s->recvpipes, p)) {
		// We are no longer "receivable".
		nni_list_remove(&s->recvpipes, p);
	}
	while ((ctx = nni_list_first(&p->sendq)) != NULL) {
		nni_aio *aio;
		nni_msg *msg;
		// Pipe was closed.  To avoid pushing an error back to the
		// entire socket, we pretend we completed this successfully.
		nni_list_remove(&p->sendq, ctx);
		aio       = ctx->saio;
		ctx->saio = NULL;
		msg       = nni_aio_get_msg(aio);
		nni_aio_set_msg(aio, NULL);
		nni_aio_finish(aio, 0, nni_msg_len(msg));
		nni_msg_free(msg);
	}
	if (p->id == s->ctx.pipe_id) {
		// We "can" send.  (Well, not really, but we will happily
		// accept a message and discard it.)
		nni_pollable_raise(&s->writable);
	}
	nni_idhash_remove(s->pipes, nni_pipe_id(p->pipe));
	nni_mtx_unlock(&s->lk);
}

static void
rep0_pipe_send_cb(void *arg)
{
	rep0_pipe *p = arg;
	rep0_sock *s = p->rep;
	rep0_ctx * ctx;
	nni_aio *  aio;
	nni_msg *  msg;
	size_t     len;

	if (nni_aio_result(&p->aio_send) != 0) {
		nni_msg_free(nni_aio_get_msg(&p->aio_send));
		nni_aio_set_msg(&p->aio_send, NULL);
		nni_pipe_close(p->pipe);
		return;
	}
	nni_mtx_lock(&s->lk);
	p->busy = false;
	if ((ctx = nni_list_first(&p->sendq)) == NULL) {
		// Nothing else to send.
		if (p->id == s->ctx.pipe_id) {
			// Mark us ready for the other side to send!
			nni_pollable_raise(&s->writable);
		}
		nni_mtx_unlock(&s->lk);
		return;
	}

	nni_list_remove(&p->sendq, ctx);
	aio        = ctx->saio;
	ctx->saio  = NULL;
	ctx->spipe = NULL;
	p->busy    = true;
	msg        = nni_aio_get_msg(aio);
	len        = nni_msg_len(msg);
	nni_aio_set_msg(aio, NULL);
	nni_aio_set_msg(&p->aio_send, msg);
	nni_pipe_send(p->pipe, &p->aio_send);

	nni_mtx_unlock(&s->lk);

	nni_aio_finish_synch(aio, 0, len);
}

static void
rep0_cancel_recv(nni_aio *aio, void *arg, int rv)
{
	rep0_ctx * ctx = arg;
	rep0_sock *s   = ctx->sock;

	nni_mtx_lock(&s->lk);
	if (ctx->raio == aio) {
		nni_list_remove(&s->recvq, ctx);
		ctx->raio = NULL;
		nni_aio_finish_error(aio, rv);
	}
	nni_mtx_unlock(&s->lk);
}

static void
rep0_ctx_recv(void *arg, nni_aio *aio)
{
	rep0_ctx * ctx = arg;
	rep0_sock *s   = ctx->sock;
	rep0_pipe *p;
	size_t     len;
	nni_msg *  msg;

	if (nni_aio_begin(aio) != 0) {
		return;
	}
	nni_mtx_lock(&s->lk);
	if ((p = nni_list_first(&s->recvpipes)) == NULL) {
		int rv;
		if ((rv = nni_aio_schedule(aio, rep0_cancel_recv, ctx)) != 0) {
			nni_mtx_unlock(&s->lk);
			nni_aio_finish_error(aio, rv);
			return;
		}
		if (ctx->raio != NULL) {
			// Cannot have a second receive operation pending.
			// This could be ESTATE, or we could cancel the first
			// with ECANCELED.  We elect the former.
			nni_mtx_unlock(&s->lk);
			nni_aio_finish_error(aio, NNG_ESTATE);
			return;
		}
		ctx->raio = aio;
		nni_list_append(&s->recvq, ctx);
		nni_mtx_unlock(&s->lk);
		return;
	}
	msg = nni_aio_get_msg(&p->aio_recv);
	nni_aio_set_msg(&p->aio_recv, NULL);
	nni_list_remove(&s->recvpipes, p);
	if (nni_list_empty(&s->recvpipes)) {
		nni_pollable_clear(&s->readable);
	}
	nni_pipe_recv(p->pipe, &p->aio_recv);
	if ((ctx == &s->ctx) && !p->busy) {
		nni_pollable_raise(&s->writable);
	}

	len = nni_msg_header_len(msg);
	memcpy(ctx->btrace, nni_msg_header(msg), len);
	ctx->btrace_len = len;
	ctx->pipe_id    = nni_pipe_id(p->pipe);
	nni_mtx_unlock(&s->lk);

	nni_msg_header_clear(msg);
	nni_aio_set_msg(aio, msg);
	nni_aio_finish(aio, 0, nni_msg_len(msg));
}

static void
rep0_pipe_recv_cb(void *arg)
{
	rep0_pipe *p = arg;
	rep0_sock *s = p->rep;
	rep0_ctx * ctx;
	nni_msg *  msg;
	uint8_t *  body;
	nni_aio *  aio;
	size_t     len;
	int        hops;
	int        ttl;

	if (nni_aio_result(&p->aio_recv) != 0) {
		nni_pipe_close(p->pipe);
		return;
	}

	msg = nni_aio_get_msg(&p->aio_recv);
	ttl = nni_atomic_get(&s->ttl);

	nni_msg_set_pipe(msg, p->id);

	// Move backtrace from body to header
	hops = 1;
	for (;;) {
		bool end;

		if (hops > ttl) {
			// This isn't malformed, but it has gone
			// through too many hops.  Do not disconnect,
			// because we can legitimately receive messages
			// with too many hops from devices, etc.
			goto drop;
		}
		hops++;
		if (nni_msg_len(msg) < 4) {
			// Peer is speaking garbage. Kick it.
			nni_msg_free(msg);
			nni_aio_set_msg(&p->aio_recv, NULL);
			nni_pipe_close(p->pipe);
			return;
		}
		body = nni_msg_body(msg);
		end  = ((body[0] & 0x80u) != 0);
		if (nni_msg_header_append(msg, body, 4) != 0) {
			// Out of memory, so drop it.
			goto drop;
		}
		nni_msg_trim(msg, 4);
		if (end) {
			break;
		}
	}

	len = nni_msg_header_len(msg);

	nni_mtx_lock(&s->lk);

	if ((ctx = nni_list_first(&s->recvq)) == NULL) {
		// No one waiting to receive yet, holding pattern.
		nni_list_append(&s->recvpipes, p);
		nni_pollable_raise(&s->readable);
		nni_mtx_unlock(&s->lk);
		return;
	}

	nni_list_remove(&s->recvq, ctx);
	aio       = ctx->raio;
	ctx->raio = NULL;
	nni_aio_set_msg(&p->aio_recv, NULL);
	if ((ctx == &s->ctx) && !p->busy) {
		nni_pollable_raise(&s->writable);
	}

	// schedule another receive
	nni_pipe_recv(p->pipe, &p->aio_recv);

	ctx->btrace_len = len;
	memcpy(ctx->btrace, nni_msg_header(msg), len);
	nni_msg_header_clear(msg);
	ctx->pipe_id = p->id;

	nni_mtx_unlock(&s->lk);

	nni_aio_set_msg(aio, msg);
	nni_aio_finish_synch(aio, 0, nni_msg_len(msg));
	return;

drop:
	nni_msg_free(msg);
	nni_aio_set_msg(&p->aio_recv, NULL);
	nni_pipe_recv(p->pipe, &p->aio_recv);
}

static int
rep0_sock_set_max_ttl(void *arg, const void *buf, size_t sz, nni_opt_type t)
{
	rep0_sock *s = arg;
	int        ttl;
	int        rv;

	if ((rv = nni_copyin_int(&ttl, buf, sz, 1, NNI_MAX_MAX_TTL, t)) == 0) {
		nni_atomic_set(&s->ttl, ttl);
	}
	return (rv);
}

static int
rep0_sock_get_max_ttl(void *arg, void *buf, size_t *szp, nni_opt_type t)
{
	rep0_sock *s = arg;

	return (nni_copyout_int(nni_atomic_get(&s->ttl), buf, szp, t));
}

static int
rep0_sock_get_sendfd(void *arg, void *buf, size_t *szp, nni_opt_type t)
{
	rep0_sock *s = arg;
	int        rv;
	int        fd;

	if ((rv = nni_pollable_getfd(&s->writable, &fd)) != 0) {
		return (rv);
	}
	return (nni_copyout_int(fd, buf, szp, t));
}

static int
rep0_sock_get_recvfd(void *arg, void *buf, size_t *szp, nni_opt_type t)
{
	rep0_sock *s = arg;
	int        rv;
	int        fd;

	if ((rv = nni_pollable_getfd(&s->readable, &fd)) != 0) {
		return (rv);
	}

	return (nni_copyout_int(fd, buf, szp, t));
}

static void
rep0_sock_send(void *arg, nni_aio *aio)
{
	rep0_sock *s = arg;

	rep0_ctx_send(&s->ctx, aio);
}

static void
rep0_sock_recv(void *arg, nni_aio *aio)
{
	rep0_sock *s = arg;

	rep0_ctx_recv(&s->ctx, aio);
}

// This is the global protocol structure -- our linkage to the core.
// This should be the only global non-static symbol in this file.
static nni_proto_pipe_ops rep0_pipe_ops = {
	.pipe_size  = sizeof(rep0_pipe),
	.pipe_init  = rep0_pipe_init,
	.pipe_fini  = rep0_pipe_fini,
	.pipe_start = rep0_pipe_start,
	.pipe_close = rep0_pipe_close,
	.pipe_stop  = rep0_pipe_stop,
};

static nni_proto_ctx_ops rep0_ctx_ops = {
	.ctx_size = sizeof(rep0_ctx),
	.ctx_init = rep0_ctx_init,
	.ctx_fini = rep0_ctx_fini,
	.ctx_send = rep0_ctx_send,
	.ctx_recv = rep0_ctx_recv,
};

static nni_option rep0_sock_options[] = {
	{
	    .o_name = NNG_OPT_MAXTTL,
	    .o_get  = rep0_sock_get_max_ttl,
	    .o_set  = rep0_sock_set_max_ttl,
	},
	{
	    .o_name = NNG_OPT_RECVFD,
	    .o_get  = rep0_sock_get_recvfd,
	},
	{
	    .o_name = NNG_OPT_SENDFD,
	    .o_get  = rep0_sock_get_sendfd,
	},
	// terminate list
	{
	    .o_name = NULL,
	},
};

static nni_proto_sock_ops rep0_sock_ops = {
	.sock_size    = sizeof(rep0_sock),
	.sock_init    = rep0_sock_init,
	.sock_fini    = rep0_sock_fini,
	.sock_open    = rep0_sock_open,
	.sock_close   = rep0_sock_close,
	.sock_options = rep0_sock_options,
	.sock_send    = rep0_sock_send,
	.sock_recv    = rep0_sock_recv,
};

static nni_proto rep0_proto = {
	.proto_version  = NNI_PROTOCOL_VERSION,
	.proto_self     = { NNG_REP0_SELF, NNG_REP0_SELF_NAME },
	.proto_peer     = { NNG_REP0_PEER, NNG_REP0_PEER_NAME },
	.proto_flags    = NNI_PROTO_FLAG_SNDRCV | NNI_PROTO_FLAG_NOMSGQ,
	.proto_sock_ops = &rep0_sock_ops,
	.proto_pipe_ops = &rep0_pipe_ops,
	.proto_ctx_ops  = &rep0_ctx_ops,
};

int
nng_rep0_open(nng_socket *sidp)
{
	return (nni_proto_open(sidp, &rep0_proto));
}
