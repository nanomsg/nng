//
// Copyright 2019 Staysail Systems, Inc. <info@staysail.tech>
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

typedef struct resp0_pipe resp0_pipe;
typedef struct resp0_sock resp0_sock;
typedef struct resp0_ctx  resp0_ctx;

static void resp0_pipe_send_cb(void *);
static void resp0_pipe_recv_cb(void *);
static void resp0_pipe_fini(void *);

struct resp0_ctx {
	resp0_sock *  sock;
	char *        btrace;
	size_t        btrace_len;
	size_t        btrace_size;
	uint32_t      pipe_id;
	resp0_pipe *  spipe; // send pipe
	nni_aio *     saio;  // send aio
	nni_aio *     raio;  // recv aio
	nni_list_node sqnode;
	nni_list_node rqnode;
};

// resp0_sock is our per-socket protocol private structure.
struct resp0_sock {
	nni_mtx       mtx;
	int           ttl;
	nni_idhash *  pipes;
	resp0_ctx *   ctx;
	nni_list      recvpipes;
	nni_list      recvq;
	nni_pollable *recvable;
	nni_pollable *sendable;
};

// resp0_pipe is our per-pipe protocol private structure.
struct resp0_pipe {
	nni_pipe *    npipe;
	resp0_sock *  psock;
	bool          busy;
	uint32_t      id;
	nni_list      sendq; // contexts waiting to send
	nni_aio *     aio_send;
	nni_aio *     aio_recv;
	nni_list_node rnode; // receivable linkage
};

static void
resp0_ctx_close(void *arg)
{
	resp0_ctx * ctx = arg;
	resp0_sock *s   = ctx->sock;
	nni_aio *   aio;

	// complete any outstanding operations here, cancellation, etc.

	nni_mtx_lock(&s->mtx);
	if ((aio = ctx->saio) != NULL) {
		resp0_pipe *p = ctx->spipe;
		ctx->saio     = NULL;
		ctx->spipe    = NULL;
		nni_list_remove(&p->sendq, ctx);
		nni_aio_finish_error(aio, NNG_ECLOSED);
	}
	if ((aio = ctx->raio) != NULL) {
		ctx->raio = NULL;
		nni_list_remove(&s->recvq, ctx);
		nni_aio_finish_error(aio, NNG_ECLOSED);
	}
	nni_mtx_unlock(&s->mtx);
}

static void
resp0_ctx_fini(void *arg)
{
	resp0_ctx *ctx = arg;

	resp0_ctx_close(ctx);
	nni_free(ctx->btrace, ctx->btrace_size);
	NNI_FREE_STRUCT(ctx);
}

static int
resp0_ctx_init(void **ctxp, void *sarg)
{
	resp0_sock *s = sarg;
	resp0_ctx * ctx;

	if ((ctx = NNI_ALLOC_STRUCT(ctx)) == NULL) {
		return (NNG_ENOMEM);
	}

	// this is 1kB, which covers the worst case.
	ctx->btrace_size = 256 * sizeof(uint32_t);
	if ((ctx->btrace = nni_alloc(ctx->btrace_size)) == NULL) {
		NNI_FREE_STRUCT(ctx);
		return (NNG_ENOMEM);
	}
	NNI_LIST_NODE_INIT(&ctx->sqnode);
	NNI_LIST_NODE_INIT(&ctx->rqnode);
	ctx->btrace_len = 0;
	ctx->sock       = s;
	ctx->pipe_id    = 0;
	*ctxp           = ctx;

	return (0);
}

static void
resp0_ctx_cancel_send(nni_aio *aio, void *arg, int rv)
{
	resp0_ctx * ctx = arg;
	resp0_sock *s   = ctx->sock;

	nni_mtx_lock(&s->mtx);
	if (ctx->saio != aio) {
		nni_mtx_unlock(&s->mtx);
		return;
	}
	nni_list_node_remove(&ctx->sqnode);
	ctx->saio = NULL;
	nni_mtx_unlock(&s->mtx);
	nni_msg_header_clear(nni_aio_get_msg(aio)); // reset the headers
	nni_aio_finish_error(aio, rv);
}

static void
resp0_ctx_send(void *arg, nni_aio *aio)
{
	resp0_ctx * ctx = arg;
	resp0_sock *s   = ctx->sock;
	resp0_pipe *p;
	nni_msg *   msg;
	size_t      len;
	uint32_t    pid;
	int         rv;

	if (nni_aio_begin(aio) != 0) {
		return;
	}
	msg = nni_aio_get_msg(aio);
	nni_msg_header_clear(msg);

	if (ctx == s->ctx) {
		// We can't send anymore, because only one send per request.
		nni_pollable_clear(s->sendable);
	}

	nni_mtx_lock(&s->mtx);

	if ((len = ctx->btrace_len) == 0) {
		nni_mtx_unlock(&s->mtx);
		nni_aio_finish_error(aio, NNG_ESTATE);
		return;
	}
	pid             = ctx->pipe_id;
	ctx->pipe_id    = 0;
	ctx->btrace_len = 0;

	if ((rv = nni_msg_header_append(msg, ctx->btrace, len)) != 0) {
		nni_mtx_unlock(&s->mtx);
		nni_aio_finish_error(aio, rv);
		return;
	}

	if (nni_idhash_find(s->pipes, pid, (void **) &p) != 0) {
		// Surveyor has left the building.  Just discard the reply.
		nni_mtx_unlock(&s->mtx);
		nni_aio_set_msg(aio, NULL);
		nni_aio_finish(aio, 0, nni_msg_len(msg));
		nni_msg_free(msg);
		return;
	}

	if (!p->busy) {
		p->busy = true;
		len     = nni_msg_len(msg);
		nni_aio_set_msg(p->aio_send, msg);
		nni_pipe_send(p->npipe, p->aio_send);
		nni_mtx_unlock(&s->mtx);

		nni_aio_set_msg(aio, NULL);
		nni_aio_finish(aio, 0, len);
		return;
	}

	if ((rv = nni_aio_schedule(aio, resp0_ctx_cancel_send, ctx)) != 0) {
		nni_mtx_unlock(&s->mtx);
		nni_aio_finish_error(aio, rv);
		return;
	}

	ctx->saio  = aio;
	ctx->spipe = p;
	nni_list_append(&p->sendq, ctx);
	nni_mtx_unlock(&s->mtx);
}

static void
resp0_sock_fini(void *arg)
{
	resp0_sock *s = arg;

	nni_idhash_fini(s->pipes);
	if (s->ctx != NULL) {
		resp0_ctx_fini(s->ctx);
	}
	nni_pollable_free(s->sendable);
	nni_pollable_free(s->recvable);
	nni_mtx_fini(&s->mtx);
	NNI_FREE_STRUCT(s);
}

static int
resp0_sock_init(void **sp, nni_sock *nsock)
{
	resp0_sock *s;
	int         rv;

	NNI_ARG_UNUSED(nsock);

	if ((s = NNI_ALLOC_STRUCT(s)) == NULL) {
		return (NNG_ENOMEM);
	}
	nni_mtx_init(&s->mtx);
	if ((rv = nni_idhash_init(&s->pipes)) != 0) {
		resp0_sock_fini(s);
		return (rv);
	}

	NNI_LIST_INIT(&s->recvq, resp0_ctx, rqnode);
	NNI_LIST_INIT(&s->recvpipes, resp0_pipe, rnode);

	s->ttl = 8; // Per RFC

	if ((rv = resp0_ctx_init((void **) &s->ctx, s)) != 0) {
		resp0_ctx_fini(s);
		return (rv);
	}

	// We start off without being either readable or pollable.
	// Readability comes when there is something on the socket.
	if (((rv = nni_pollable_alloc(&s->sendable)) != 0) ||
	    ((rv = nni_pollable_alloc(&s->recvable)) != 0)) {
		resp0_sock_fini(s);
		return (rv);
	}
	*sp = s;
	return (0);
}

static void
resp0_sock_open(void *arg)
{
	NNI_ARG_UNUSED(arg);
}

static void
resp0_sock_close(void *arg)
{
	resp0_sock *s = arg;

	resp0_ctx_close(s->ctx);
}

static void
resp0_pipe_stop(void *arg)
{
	resp0_pipe *p = arg;

	nni_aio_stop(p->aio_send);
	nni_aio_stop(p->aio_recv);
}

static void
resp0_pipe_fini(void *arg)
{
	resp0_pipe *p = arg;
	nng_msg *   msg;

	if ((msg = nni_aio_get_msg(p->aio_recv)) != NULL) {
		nni_aio_set_msg(p->aio_recv, NULL);
		nni_msg_free(msg);
	}
	nni_aio_fini(p->aio_send);
	nni_aio_fini(p->aio_recv);
	NNI_FREE_STRUCT(p);
}

static int
resp0_pipe_init(void **pp, nni_pipe *npipe, void *s)
{
	resp0_pipe *p;
	int         rv;

	if ((p = NNI_ALLOC_STRUCT(p)) == NULL) {
		return (NNG_ENOMEM);
	}
	if (((rv = nni_aio_init(&p->aio_recv, resp0_pipe_recv_cb, p)) != 0) ||
	    ((rv = nni_aio_init(&p->aio_send, resp0_pipe_send_cb, p)) != 0)) {
		resp0_pipe_fini(p);
		return (rv);
	}

	NNI_LIST_INIT(&p->sendq, resp0_ctx, sqnode);

	p->npipe = npipe;
	p->psock = s;
	p->busy  = false;
	p->id    = nni_pipe_id(npipe);

	*pp = p;
	return (0);
}

static int
resp0_pipe_start(void *arg)
{
	resp0_pipe *p = arg;
	resp0_sock *s = p->psock;
	int         rv;

	if (nni_pipe_peer(p->npipe) != NNI_PROTO_SURVEYOR_V0) {
		return (NNG_EPROTO);
	}

	nni_mtx_lock(&s->mtx);
	rv = nni_idhash_insert(s->pipes, p->id, p);
	nni_mtx_unlock(&s->mtx);
	if (rv != 0) {
		return (rv);
	}

	nni_pipe_recv(p->npipe, p->aio_recv);
	return (rv);
}

static void
resp0_pipe_close(void *arg)
{
	resp0_pipe *p = arg;
	resp0_sock *s = p->psock;
	resp0_ctx * ctx;

	nni_aio_close(p->aio_send);
	nni_aio_close(p->aio_recv);

	nni_mtx_lock(&s->mtx);
	while ((ctx = nni_list_first(&p->sendq)) != NULL) {
		nni_aio *aio;
		nni_msg *msg;
		nni_list_remove(&p->sendq, ctx);
		aio       = ctx->saio;
		ctx->saio = NULL;
		msg       = nni_aio_get_msg(aio);
		nni_aio_set_msg(aio, NULL);
		nni_aio_finish(aio, 0, nni_msg_len(msg));
		nni_msg_free(msg);
	}
	if (p->id == s->ctx->pipe_id) {
		// Make sure user space knows they can send a message to us,
		// which we will happily discard.
		nni_pollable_raise(s->sendable);
	}
	nni_idhash_remove(s->pipes, p->id);
	nni_mtx_unlock(&s->mtx);
}

static void
resp0_pipe_send_cb(void *arg)
{
	resp0_pipe *p = arg;
	resp0_sock *s = p->psock;
	resp0_ctx * ctx;
	nni_aio *   aio;
	nni_msg *   msg;
	size_t      len;

	if (nni_aio_result(p->aio_send) != 0) {
		nni_msg_free(nni_aio_get_msg(p->aio_send));
		nni_aio_set_msg(p->aio_send, NULL);
		nni_pipe_close(p->npipe);
		return;
	}
	nni_mtx_lock(&s->mtx);
	p->busy = false;
	if ((ctx = nni_list_first(&p->sendq)) == NULL) {
		// Nothing else to send.
		if (p->id == s->ctx->pipe_id) {
			// Mark us ready for the other side to send!
			nni_pollable_raise(s->sendable);
		}
		nni_mtx_unlock(&s->mtx);
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
	nni_aio_set_msg(p->aio_send, msg);
	nni_pipe_send(p->npipe, p->aio_send);

	nni_mtx_unlock(&s->mtx);

	nni_aio_finish_synch(aio, 0, len);
}

static void
resp0_cancel_recv(nni_aio *aio, void *arg, int rv)
{
	resp0_ctx * ctx = arg;
	resp0_sock *s   = ctx->sock;

	nni_mtx_lock(&s->mtx);
	if (ctx->raio == aio) {
		nni_list_remove(&s->recvq, ctx);
		ctx->raio = NULL;
		nni_aio_finish_error(aio, rv);
	}
	nni_mtx_unlock(&s->mtx);
}

static void
resp0_ctx_recv(void *arg, nni_aio *aio)
{
	resp0_ctx * ctx = arg;
	resp0_sock *s   = ctx->sock;
	resp0_pipe *p;
	size_t      len;
	nni_msg *   msg;

	if (nni_aio_begin(aio) != 0) {
		return;
	}
	nni_mtx_lock(&s->mtx);
	if ((p = nni_list_first(&s->recvpipes)) == NULL) {
		int rv;
		rv = nni_aio_schedule(aio, resp0_cancel_recv, ctx);
		if (rv != 0) {
			nni_mtx_unlock(&s->mtx);
			nni_aio_finish_error(aio, rv);
			return;
		}
		// We cannot have two concurrent receive requests on the same
		// context...
		if (ctx->raio != NULL) {
			nni_mtx_unlock(&s->mtx);
			nni_aio_finish_error(aio, NNG_ESTATE);
			return;
		}
		ctx->raio = aio;
		nni_list_append(&s->recvq, ctx);
		nni_mtx_unlock(&s->mtx);
		return;
	}
	msg = nni_aio_get_msg(p->aio_recv);
	nni_aio_set_msg(p->aio_recv, NULL);
	nni_list_remove(&s->recvpipes, p);
	if (nni_list_empty(&s->recvpipes)) {
		nni_pollable_clear(s->recvable);
	}
	nni_pipe_recv(p->npipe, p->aio_recv);

	len = nni_msg_header_len(msg);
	memcpy(ctx->btrace, nni_msg_header(msg), len);
	ctx->btrace_len = len;
	ctx->pipe_id    = p->id;
	if (ctx == s->ctx) {
		nni_pollable_raise(s->sendable);
	}
	nni_mtx_unlock(&s->mtx);

	nni_msg_header_clear(msg);
	nni_aio_set_msg(aio, msg);
	nni_aio_finish(aio, 0, nni_msg_len(msg));
}

static void
resp0_pipe_recv_cb(void *arg)
{
	resp0_pipe *p = arg;
	resp0_sock *s = p->psock;
	resp0_ctx * ctx;
	nni_msg *   msg;
	nni_aio *   aio;
	int         hops;
	size_t      len;

	if (nni_aio_result(p->aio_recv) != 0) {
		nni_pipe_close(p->npipe);
		return;
	}

	msg = nni_aio_get_msg(p->aio_recv);
	nni_msg_set_pipe(msg, p->id);

	// Move backtrace from body to header
	hops = 1;
	for (;;) {
		bool     end = 0;
		uint8_t *body;

		if (hops > s->ttl) {
			goto drop;
		}
		hops++;
		if (nni_msg_len(msg) < 4) {
			// Peer is speaking garbage, kick it.
			nni_msg_free(msg);
			nni_aio_set_msg(p->aio_recv, NULL);
			nni_pipe_close(p->npipe);
			return;
		}
		body = nni_msg_body(msg);
		end  = ((body[0] & 0x80) != 0);
		if (nni_msg_header_append(msg, body, 4) != 0) {
			goto drop;
		}
		nni_msg_trim(msg, 4);
		if (end) {
			break;
		}
	}

	len = nni_msg_header_len(msg);

	nni_mtx_lock(&s->mtx);
	if ((ctx = nni_list_first(&s->recvq)) == NULL) {
		// No one blocked in recv, stall.
		nni_list_append(&s->recvpipes, p);
		nni_pollable_raise(s->recvable);
		nni_mtx_unlock(&s->mtx);
		return;
	}

	nni_list_remove(&s->recvq, ctx);
	aio       = ctx->raio;
	ctx->raio = NULL;
	nni_aio_set_msg(p->aio_recv, NULL);

	// Start the next receive.
	nni_pipe_recv(p->npipe, p->aio_recv);

	ctx->btrace_len = len;
	memcpy(ctx->btrace, nni_msg_header(msg), len);
	nni_msg_header_clear(msg);
	ctx->pipe_id = p->id;

	if ((ctx == s->ctx) && (!p->busy)) {
		nni_pollable_raise(s->sendable);
	}
	nni_mtx_unlock(&s->mtx);

	nni_aio_set_msg(aio, msg);
	nni_aio_finish_synch(aio, 0, nni_msg_len(msg));
	return;

drop:
	nni_msg_free(msg);
	nni_aio_set_msg(p->aio_recv, NULL);
	nni_pipe_recv(p->npipe, p->aio_recv);
}

static int
resp0_sock_set_maxttl(void *arg, const void *buf, size_t sz, nni_opt_type t)
{
	resp0_sock *s = arg;
	return (nni_copyin_int(&s->ttl, buf, sz, 1, 255, t));
}

static int
resp0_sock_get_maxttl(void *arg, void *buf, size_t *szp, nni_opt_type t)
{
	resp0_sock *s = arg;
	return (nni_copyout_int(s->ttl, buf, szp, t));
}

static int
resp0_sock_get_sendfd(void *arg, void *buf, size_t *szp, nni_opt_type t)
{
	resp0_sock *s = arg;
	int         rv;
	int         fd;

	if ((rv = nni_pollable_getfd(s->sendable, &fd)) != 0) {
		return (rv);
	}
	return (nni_copyout_int(fd, buf, szp, t));
}

static int
resp0_sock_get_recvfd(void *arg, void *buf, size_t *szp, nni_opt_type t)
{
	resp0_sock *s = arg;
	int         rv;
	int         fd;

	if ((rv = nni_pollable_getfd(s->recvable, &fd)) != 0) {
		return (rv);
	}
	return (nni_copyout_int(fd, buf, szp, t));
}

static void
resp0_sock_send(void *arg, nni_aio *aio)
{
	resp0_sock *s = arg;

	resp0_ctx_send(s->ctx, aio);
}

static void
resp0_sock_recv(void *arg, nni_aio *aio)
{
	resp0_sock *s = arg;

	resp0_ctx_recv(s->ctx, aio);
}

static nni_proto_pipe_ops resp0_pipe_ops = {
	.pipe_init  = resp0_pipe_init,
	.pipe_fini  = resp0_pipe_fini,
	.pipe_start = resp0_pipe_start,
	.pipe_close = resp0_pipe_close,
	.pipe_stop  = resp0_pipe_stop,
};

static nni_proto_ctx_ops resp0_ctx_ops = {
	.ctx_init = resp0_ctx_init,
	.ctx_fini = resp0_ctx_fini,
	.ctx_send = resp0_ctx_send,
	.ctx_recv = resp0_ctx_recv,
};

static nni_option resp0_sock_options[] = {
	{
	    .o_name = NNG_OPT_MAXTTL,
	    .o_get  = resp0_sock_get_maxttl,
	    .o_set  = resp0_sock_set_maxttl,
	},
	{
	    .o_name = NNG_OPT_RECVFD,
	    .o_get  = resp0_sock_get_recvfd,
	    .o_set  = NULL,
	},
	{
	    .o_name = NNG_OPT_SENDFD,
	    .o_get  = resp0_sock_get_sendfd,
	    .o_set  = NULL,
	},
	// terminate list
	{
	    .o_name = NULL,
	},
};

static nni_proto_sock_ops resp0_sock_ops = {
	.sock_init    = resp0_sock_init,
	.sock_fini    = resp0_sock_fini,
	.sock_open    = resp0_sock_open,
	.sock_close   = resp0_sock_close,
	.sock_send    = resp0_sock_send,
	.sock_recv    = resp0_sock_recv,
	.sock_options = resp0_sock_options,
};

static nni_proto resp0_proto = {
	.proto_version  = NNI_PROTOCOL_VERSION,
	.proto_self     = { NNI_PROTO_RESPONDENT_V0, "respondent" },
	.proto_peer     = { NNI_PROTO_SURVEYOR_V0, "surveyor" },
	.proto_flags    = NNI_PROTO_FLAG_SNDRCV | NNI_PROTO_FLAG_NOMSGQ,
	.proto_sock_ops = &resp0_sock_ops,
	.proto_pipe_ops = &resp0_pipe_ops,
	.proto_ctx_ops  = &resp0_ctx_ops,
};

int
nng_respondent0_open(nng_socket *sidp)
{
	return (nni_proto_open(sidp, &resp0_proto));
}
