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
#include "nng/protocol/survey0/survey.h"

// Surveyor protocol.  The SURVEYOR protocol is the "survey" side of the
// survey pattern.  This is useful for building service discovery, voting, etc.
// Note that this pattern is not optimized for extreme low latency, as it makes
// multiple use of queues for simplicity.  Typically this is used in cases
// where a few dozen extra microseconds does not matter.

#ifndef NNI_PROTO_SURVEYOR_V0
#define NNI_PROTO_SURVEYOR_V0 NNI_PROTO(6, 2)
#endif

#ifndef NNI_PROTO_RESPONDENT_V0
#define NNI_PROTO_RESPONDENT_V0 NNI_PROTO(6, 3)
#endif

typedef struct surv0_pipe surv0_pipe;
typedef struct surv0_sock surv0_sock;
typedef struct surv0_ctx  surv0_ctx;

static void surv0_pipe_getq_cb(void *);
static void surv0_pipe_send_cb(void *);
static void surv0_pipe_recv_cb(void *);
static void surv0_ctx_timeout(void *);

struct surv0_ctx {
	surv0_sock *   sock;
	uint64_t       survid; // survey id
	nni_timer_node timer;
	nni_time       expire;
	nni_duration   survtime;
	nni_msgq *     rq; // recv message queue
};

// surv0_sock is our per-socket protocol private structure.
struct surv0_sock {
	int           ttl;
	nni_list      pipes;
	nni_mtx       mtx;
	surv0_ctx *   ctx;
	nni_idhash *  surveys;
	nni_pollable *sendable;
};

// surv0_pipe is our per-pipe protocol private structure.
struct surv0_pipe {
	nni_pipe *    npipe;
	surv0_sock *  sock;
	nni_msgq *    sendq;
	nni_list_node node;
	nni_aio *     aio_getq;
	nni_aio *     aio_send;
	nni_aio *     aio_recv;
};

static void
surv0_ctx_fini(void *arg)
{
	surv0_ctx *ctx = arg;

	if (ctx->rq != NULL) {
		nni_msgq_close(ctx->rq);
		nni_msgq_fini(ctx->rq);
	}
	nni_timer_cancel(&ctx->timer);
	NNI_FREE_STRUCT(ctx);
}

static int
surv0_ctx_init(void **ctxp, void *sarg)
{
	surv0_ctx * ctx;
	surv0_sock *sock = sarg;
	int         rv;

	if ((ctx = NNI_ALLOC_STRUCT(ctx)) == NULL) {
		return (NNG_ENOMEM);
	}
	nni_mtx_lock(&sock->mtx);
	if (sock->ctx != NULL) {
		ctx->survtime = sock->ctx->survtime;
	}
	nni_mtx_unlock(&sock->mtx);
	ctx->sock = sock;
	// 126 is a deep enough queue, and leaves 2 extra cells for the
	// pushback bit in msgqs.  This can result in up to 1kB of allocation
	// for the message queue.
	if ((rv = nni_msgq_init(&ctx->rq, 126)) != 0) {
		surv0_ctx_fini(ctx);
		return (rv);
	}

	nni_timer_init(&ctx->timer, surv0_ctx_timeout, ctx);
	*ctxp = ctx;
	return (0);
}

static void
surv0_ctx_recv(void *arg, nni_aio *aio)
{
	surv0_ctx * ctx  = arg;
	surv0_sock *sock = ctx->sock;

	nni_mtx_lock(&sock->mtx);
	if (ctx->survid == 0) {
		nni_mtx_unlock(&sock->mtx);
		nni_aio_finish_error(aio, NNG_ESTATE);
		return;
	}
	nni_msgq_aio_get(ctx->rq, aio);
	nni_mtx_unlock(&sock->mtx);
}

void
surv0_ctx_timeout(void *arg)
{
	surv0_ctx * ctx  = arg;
	surv0_sock *sock = ctx->sock;

	nni_mtx_lock(&sock->mtx);
	if (nni_clock() < ctx->expire) {
		nni_mtx_unlock(&sock->mtx);
		return;
	}
	// Abort any pending receives.
	nni_msgq_set_get_error(ctx->rq, NNG_ETIMEDOUT);
	if (ctx->survid != 0) {
		nni_idhash_remove(sock->surveys, ctx->survid);
		ctx->survid = 0;
	}
	nni_mtx_unlock(&sock->mtx);
}

static void
surv0_ctx_send(void *arg, nni_aio *aio)
{
	surv0_ctx * ctx  = arg;
	surv0_sock *sock = ctx->sock;
	surv0_pipe *pipe;
	nni_msg *   msg = nni_aio_get_msg(aio);
	size_t      len = nni_msg_len(msg);
	nni_time    now = nni_clock();
	int         rv;

	if (nni_aio_begin(aio) != 0) {
		return;
	}

	nni_mtx_lock(&sock->mtx);

	// Abort any pending receives -- this is the same as cancellation.
	nni_msgq_set_get_error(ctx->rq, NNG_ECANCELED);
	nni_msgq_flush(ctx->rq);

	// New survey id will be generated, so unregister the old one.
	if (ctx->survid) {
		nni_idhash_remove(sock->surveys, ctx->survid);
		ctx->survid = 0;
	}
	// Allocate the new ID.
	if ((rv = nni_idhash_alloc(sock->surveys, &ctx->survid, ctx)) != 0) {
		nni_mtx_unlock(&sock->mtx);
		nni_aio_finish_error(aio, rv);
		return;
	}
	// Insert it into the message.  We report an error if one occurs,
	// although arguably at this point we could just discard silently.
	if ((rv = nni_msg_header_append_u32(msg, (uint32_t) ctx->survid)) !=
	    0) {
		nni_idhash_remove(sock->surveys, ctx->survid);
		ctx->survid = 0;
		nni_mtx_unlock(&sock->mtx);
		nni_aio_finish_error(aio, rv);
		return;
	}

	// From this point, we're committed to success.  Note that we send
	// regardless of whether there are any pipes or not.  If no pipes,
	// then it just gets discarded.
	nni_aio_set_msg(aio, NULL);
	NNI_LIST_FOREACH (&sock->pipes, pipe) {
		nni_msg *dmsg;

		if (nni_list_next(&sock->pipes, pipe) != NULL) {
			if (nni_msg_dup(&dmsg, msg) != 0) {
				continue;
			}
		} else {
			dmsg = msg;
			msg  = NULL;
		}
		if (nni_msgq_tryput(pipe->sendq, dmsg) != 0) {
			nni_msg_free(dmsg);
		}
	}

	ctx->expire = now + ctx->survtime;
	nni_timer_schedule(&ctx->timer, ctx->expire);

	// Allow recv to run.
	nni_msgq_set_get_error(ctx->rq, 0);

	nni_mtx_unlock(&sock->mtx);
	if (msg != NULL) {
		nni_msg_free(msg);
	}

	nni_aio_finish(aio, 0, len);
}

static void
surv0_sock_fini(void *arg)
{
	surv0_sock *sock = arg;

	if (sock->ctx != NULL) {
		surv0_ctx_fini(sock->ctx);
	}
	nni_idhash_fini(sock->surveys);
	nni_pollable_free(sock->sendable);
	nni_mtx_fini(&sock->mtx);
	NNI_FREE_STRUCT(sock);
}

static int
surv0_sock_init(void **sp, nni_sock *nsock)
{
	surv0_sock *sock;
	int         rv;

	NNI_ARG_UNUSED(nsock);

	if ((sock = NNI_ALLOC_STRUCT(sock)) == NULL) {
		return (NNG_ENOMEM);
	}
	NNI_LIST_INIT(&sock->pipes, surv0_pipe, node);
	nni_mtx_init(&sock->mtx);

	if (((rv = nni_idhash_init(&sock->surveys)) != 0) ||
	    ((rv = surv0_ctx_init((void **) &sock->ctx, sock)) != 0)) {
		surv0_sock_fini(sock);
		return (rv);
	}

	// Survey IDs are 32 bits, with the high order bit set.
	// We start at a random point, to minimize likelihood of
	// accidental collision across restarts.
	nni_idhash_set_limits(sock->surveys, 0x80000000u, 0xffffffffu,
	    nni_random() | 0x80000000u);

	sock->ctx->survtime = NNI_SECOND;
	sock->ttl           = 8;

	*sp = sock;
	return (0);
}

static void
surv0_sock_open(void *arg)
{
	NNI_ARG_UNUSED(arg);
}

static void
surv0_sock_close(void *arg)
{
	surv0_sock *s = arg;

	nni_msgq_close(s->ctx->rq);
}

static void
surv0_pipe_stop(void *arg)
{
	surv0_pipe *p = arg;

	nni_aio_stop(p->aio_getq);
	nni_aio_stop(p->aio_send);
	nni_aio_stop(p->aio_recv);
}

static void
surv0_pipe_fini(void *arg)
{
	surv0_pipe *p = arg;

	nni_aio_fini(p->aio_getq);
	nni_aio_fini(p->aio_send);
	nni_aio_fini(p->aio_recv);
	nni_msgq_fini(p->sendq);
	NNI_FREE_STRUCT(p);
}

static int
surv0_pipe_init(void **pp, nni_pipe *npipe, void *s)
{
	surv0_pipe *p;
	int         rv;

	if ((p = NNI_ALLOC_STRUCT(p)) == NULL) {
		return (NNG_ENOMEM);
	}
	// This depth could be tunable.  The deeper the queue, the more
	// concurrent surveys that can be delivered.  Having said that, this
	// is best effort, and a deep queue doesn't really do much for us.
	// Note that surveys can be *outstanding*, but not yet put on the wire.
	if (((rv = nni_msgq_init(&p->sendq, 16)) != 0) ||
	    ((rv = nni_aio_init(&p->aio_getq, surv0_pipe_getq_cb, p)) != 0) ||
	    ((rv = nni_aio_init(&p->aio_send, surv0_pipe_send_cb, p)) != 0) ||
	    ((rv = nni_aio_init(&p->aio_recv, surv0_pipe_recv_cb, p)) != 0)) {
		surv0_pipe_fini(p);
		return (rv);
	}

	p->npipe = npipe;
	p->sock  = s;
	*pp      = p;
	return (0);
}

static int
surv0_pipe_start(void *arg)
{
	surv0_pipe *p = arg;
	surv0_sock *s = p->sock;

	if (nni_pipe_peer(p->npipe) != NNI_PROTO_RESPONDENT_V0) {
		return (NNG_EPROTO);
	}

	nni_mtx_lock(&s->mtx);
	nni_list_append(&s->pipes, p);
	nni_mtx_unlock(&s->mtx);

	nni_msgq_aio_get(p->sendq, p->aio_getq);
	nni_pipe_recv(p->npipe, p->aio_recv);
	return (0);
}

static void
surv0_pipe_close(void *arg)
{
	surv0_pipe *p = arg;
	surv0_sock *s = p->sock;

	nni_aio_close(p->aio_getq);
	nni_aio_close(p->aio_send);
	nni_aio_close(p->aio_recv);

	nni_msgq_close(p->sendq);

	nni_mtx_lock(&s->mtx);
	if (nni_list_active(&s->pipes, p)) {
		nni_list_remove(&s->pipes, p);
	}
	nni_mtx_unlock(&s->mtx);
}

static void
surv0_pipe_getq_cb(void *arg)
{
	surv0_pipe *p = arg;

	if (nni_aio_result(p->aio_getq) != 0) {
		nni_pipe_close(p->npipe);
		return;
	}

	nni_aio_set_msg(p->aio_send, nni_aio_get_msg(p->aio_getq));
	nni_aio_set_msg(p->aio_getq, NULL);

	nni_pipe_send(p->npipe, p->aio_send);
}

static void
surv0_pipe_send_cb(void *arg)
{
	surv0_pipe *p = arg;

	if (nni_aio_result(p->aio_send) != 0) {
		nni_msg_free(nni_aio_get_msg(p->aio_send));
		nni_aio_set_msg(p->aio_send, NULL);
		nni_pipe_close(p->npipe);
		return;
	}

	nni_msgq_aio_get(p->sendq, p->aio_getq);
}

static void
surv0_pipe_recv_cb(void *arg)
{
	surv0_pipe *p    = arg;
	surv0_sock *sock = p->sock;
	surv0_ctx * ctx;
	nni_msg *   msg;
	uint32_t    id;

	if (nni_aio_result(p->aio_recv) != 0) {
		nni_pipe_close(p->npipe);
		return;
	}

	msg = nni_aio_get_msg(p->aio_recv);
	nni_aio_set_msg(p->aio_recv, NULL);
	nni_msg_set_pipe(msg, nni_pipe_id(p->npipe));

	// We yank 4 bytes of body, and move them to the header.
	if (nni_msg_len(msg) < 4) {
		// Peer sent us garbage.  Kick it.
		nni_msg_free(msg);
		nni_pipe_close(p->npipe);
		return;
	}
	id = nni_msg_trim_u32(msg);
	if (nni_msg_header_append_u32(msg, id) != 0) {
		// Should be NNG_ENOMEM - discard and try again.
		nni_msg_free(msg);
		nni_pipe_recv(p->npipe, p->aio_recv);
		return;
	}

	nni_mtx_lock(&sock->mtx);

	// Best effort at delivery.  Discard if no context or context is
	// unable to receive it.
	if ((nni_idhash_find(sock->surveys, id, (void **) &ctx) != 0) ||
	    (nni_msgq_tryput(ctx->rq, msg) != 0)) {
		nni_msg_free(msg);
	}

	nni_mtx_unlock(&sock->mtx);

	nni_pipe_recv(p->npipe, p->aio_recv);
}

static int
surv0_ctx_set_surveytime(void *arg, const void *buf, size_t sz, nni_opt_type t)
{
	surv0_ctx *ctx = arg;
	return (nni_copyin_ms(&ctx->survtime, buf, sz, t));
}

static int
surv0_ctx_get_surveytime(void *arg, void *buf, size_t *szp, nni_opt_type t)
{
	surv0_ctx *ctx = arg;
	return (nni_copyout_ms(ctx->survtime, buf, szp, t));
}

static int
surv0_sock_set_maxttl(void *arg, const void *buf, size_t sz, nni_opt_type t)
{
	surv0_sock *s = arg;
	return (nni_copyin_int(&s->ttl, buf, sz, 1, 255, t));
}

static int
surv0_sock_get_maxttl(void *arg, void *buf, size_t *szp, nni_opt_type t)
{
	surv0_sock *s = arg;
	return (nni_copyout_int(s->ttl, buf, szp, t));
}

static int
surv0_sock_set_surveytime(
    void *arg, const void *buf, size_t sz, nni_opt_type t)
{
	surv0_sock *s = arg;
	return (surv0_ctx_set_surveytime(s->ctx, buf, sz, t));
}

static int
surv0_sock_get_surveytime(void *arg, void *buf, size_t *szp, nni_opt_type t)
{
	surv0_sock *s = arg;
	return (surv0_ctx_get_surveytime(s->ctx, buf, szp, t));
}

static int
surv0_sock_get_sendfd(void *arg, void *buf, size_t *szp, nni_opt_type t)
{
	surv0_sock *sock = arg;
	int         rv;
	int         fd;

	nni_mtx_lock(&sock->mtx);
	if (sock->sendable == NULL) {
		if ((rv = nni_pollable_alloc(&sock->sendable)) != 0) {
			nni_mtx_unlock(&sock->mtx);
			return (rv);
		}
		// We are always sendable.
		nni_pollable_raise(sock->sendable);
	}
	nni_mtx_unlock(&sock->mtx);
	if ((rv = nni_pollable_getfd(sock->sendable, &fd)) != 0) {
		return (rv);
	}
	return (nni_copyout_int(fd, buf, szp, t));
}

static int
surv0_sock_get_recvfd(void *arg, void *buf, size_t *szp, nni_opt_type t)
{
	surv0_sock *  sock = arg;
	nni_pollable *recvable;
	int           rv;
	int           fd;

	if (((rv = nni_msgq_get_recvable(sock->ctx->rq, &recvable)) != 0) ||
	    ((rv = nni_pollable_getfd(recvable, &fd)) != 0)) {
		return (rv);
	}
	return (nni_copyout_int(fd, buf, szp, t));
}

static void
surv0_sock_recv(void *arg, nni_aio *aio)
{
	surv0_sock *s = arg;
	surv0_ctx_recv(s->ctx, aio);
}

static void
surv0_sock_send(void *arg, nni_aio *aio)
{
	surv0_sock *s = arg;
	surv0_ctx_send(s->ctx, aio);
}

static nni_proto_pipe_ops surv0_pipe_ops = {
	.pipe_init  = surv0_pipe_init,
	.pipe_fini  = surv0_pipe_fini,
	.pipe_start = surv0_pipe_start,
	.pipe_close = surv0_pipe_close,
	.pipe_stop  = surv0_pipe_stop,
};

static nni_option surv0_ctx_options[] = {
	{
	    .o_name = NNG_OPT_SURVEYOR_SURVEYTIME,
	    .o_get  = surv0_ctx_get_surveytime,
	    .o_set  = surv0_ctx_set_surveytime,
	},
	{
	    .o_name = NULL,
	}
};
static nni_proto_ctx_ops surv0_ctx_ops = {
	.ctx_init    = surv0_ctx_init,
	.ctx_fini    = surv0_ctx_fini,
	.ctx_send    = surv0_ctx_send,
	.ctx_recv    = surv0_ctx_recv,
	.ctx_options = surv0_ctx_options,
};

static nni_option surv0_sock_options[] = {
	{
	    .o_name = NNG_OPT_SURVEYOR_SURVEYTIME,
	    .o_get  = surv0_sock_get_surveytime,
	    .o_set  = surv0_sock_set_surveytime,
	},
	{
	    .o_name = NNG_OPT_MAXTTL,
	    .o_get  = surv0_sock_get_maxttl,
	    .o_set  = surv0_sock_set_maxttl,
	},
	{
	    .o_name = NNG_OPT_RECVFD,
	    .o_get  = surv0_sock_get_recvfd,
	},
	{
	    .o_name = NNG_OPT_SENDFD,
	    .o_get  = surv0_sock_get_sendfd,
	},
	// terminate list
	{
	    .o_name = NULL,
	},
};

static nni_proto_sock_ops surv0_sock_ops = {
	.sock_init    = surv0_sock_init,
	.sock_fini    = surv0_sock_fini,
	.sock_open    = surv0_sock_open,
	.sock_close   = surv0_sock_close,
	.sock_send    = surv0_sock_send,
	.sock_recv    = surv0_sock_recv,
	.sock_options = surv0_sock_options,
};

static nni_proto surv0_proto = {
	.proto_version  = NNI_PROTOCOL_VERSION,
	.proto_self     = { NNI_PROTO_SURVEYOR_V0, "surveyor" },
	.proto_peer     = { NNI_PROTO_RESPONDENT_V0, "respondent" },
	.proto_flags    = NNI_PROTO_FLAG_SNDRCV | NNI_PROTO_FLAG_NOMSGQ,
	.proto_sock_ops = &surv0_sock_ops,
	.proto_pipe_ops = &surv0_pipe_ops,
	.proto_ctx_ops  = &surv0_ctx_ops,
};

int
nng_surveyor0_open(nng_socket *sidp)
{
	return (nni_proto_open(sidp, &surv0_proto));
}
