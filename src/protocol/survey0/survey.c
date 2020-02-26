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
#include "nng/protocol/survey0/survey.h"

// Surveyor protocol.  The SURVEYOR protocol is the "survey" side of the
// survey pattern.  This is useful for building service discovery, voting, etc.
// Note that this pattern is not optimized for extreme low latency, as it makes
// multiple use of queues for simplicity.  Typically this is used in cases
// where a few dozen extra microseconds does not matter.

typedef struct surv0_pipe surv0_pipe;
typedef struct surv0_sock surv0_sock;
typedef struct surv0_ctx  surv0_ctx;

static void surv0_pipe_send_cb(void *);
static void surv0_pipe_recv_cb(void *);
static void surv0_ctx_timeout(void *);

struct surv0_ctx {
	surv0_sock *   sock;
	uint64_t       survey_id; // survey id
	nni_timer_node timer;
	nni_time       expire;
	nni_lmq        recv_lmq;
	nni_list       recv_queue;
	nni_atomic_int recv_buf;
	nni_atomic_int survey_time;
	int            err;
};

// surv0_sock is our per-socket protocol private structure.
struct surv0_sock {
	int            ttl;
	nni_list       pipes;
	nni_mtx        mtx;
	surv0_ctx      ctx;
	nni_idhash *   surveys;
	nni_pollable   writable;
	nni_pollable   readable;
	nni_atomic_int send_buf;
};

// surv0_pipe is our per-pipe protocol private structure.
struct surv0_pipe {
	nni_pipe *    pipe;
	surv0_sock *  sock;
	nni_lmq       send_queue;
	nni_list_node node;
	nni_aio *     aio_send;
	nni_aio *     aio_recv;
	bool          busy;
	bool          closed;
};

static void
surv0_ctx_abort(surv0_ctx *ctx, int err)
{
	nni_aio *   aio;
	surv0_sock *sock = ctx->sock;

	while ((aio = nni_list_first(&ctx->recv_queue)) != NULL) {
		nni_list_remove(&ctx->recv_queue, aio);
		nni_aio_finish_error(aio, err);
	}
	nni_lmq_flush(&ctx->recv_lmq);
	if (ctx->survey_id != 0) {
		nni_idhash_remove(sock->surveys, ctx->survey_id);
		ctx->survey_id = 0;
	}
	if (ctx == &sock->ctx) {
		nni_pollable_clear(&sock->readable);
	}
}

static void
surv0_ctx_close(surv0_ctx *ctx)
{
	surv0_sock *sock = ctx->sock;

	nni_mtx_lock(&sock->mtx);
	surv0_ctx_abort(ctx, NNG_ECLOSED);
	nni_mtx_unlock(&sock->mtx);
}

static void
surv0_ctx_fini(void *arg)
{
	surv0_ctx *ctx = arg;

	surv0_ctx_close(ctx);
	nni_timer_cancel(&ctx->timer);
	nni_lmq_fini(&ctx->recv_lmq);
}

static int
surv0_ctx_init(void *c, void *s)
{
	surv0_ctx *  ctx  = c;
	surv0_sock * sock = s;
	int          rv;
	int          len;
	nng_duration tmo;

	nni_aio_list_init(&ctx->recv_queue);
	nni_atomic_init(&ctx->recv_buf);
	nni_atomic_init(&ctx->survey_time);

	if (ctx == &sock->ctx) {
		len = 128;
		tmo = NNI_SECOND; // survey timeout
	} else {
		len = nni_atomic_get(&sock->ctx.recv_buf);
		tmo = nni_atomic_get(&sock->ctx.survey_time);
	}

	nni_atomic_set(&ctx->recv_buf, len);
	nni_atomic_set(&ctx->survey_time, tmo);

	ctx->sock = sock;

	if ((rv = nni_lmq_init(&ctx->recv_lmq, len)) != 0) {
		surv0_ctx_fini(ctx);
		return (rv);
	}
	nni_timer_init(&ctx->timer, surv0_ctx_timeout, ctx);
	return (0);
}

static void
surv0_ctx_cancel(nni_aio *aio, void *arg, int rv)
{
	surv0_ctx * ctx  = arg;
	surv0_sock *sock = ctx->sock;
	nni_mtx_lock(&sock->mtx);
	if (nni_list_active(&ctx->recv_queue, aio)) {
		nni_list_remove(&ctx->recv_queue, aio);
		nni_aio_finish_error(aio, rv);
	}
	if (ctx->survey_id != 0) {
		nni_idhash_remove(sock->surveys, ctx->survey_id);
		ctx->survey_id = 0;
	}
	nni_mtx_unlock(&sock->mtx);
}

static void
surv0_ctx_recv(void *arg, nni_aio *aio)
{
	surv0_ctx * ctx  = arg;
	surv0_sock *sock = ctx->sock;
	nni_msg *   msg;

	if (nni_aio_begin(aio) != 0) {
		return;
	}

	nni_mtx_lock(&sock->mtx);
	if (ctx->survey_id == 0) {
		nni_mtx_unlock(&sock->mtx);
		nni_aio_finish_error(aio, NNG_ESTATE);
		return;
	}
again:
	if (nni_lmq_getq(&ctx->recv_lmq, &msg) != 0) {
		int rv;
		if ((rv = nni_aio_schedule(aio, &surv0_ctx_cancel, ctx)) !=
		    0) {
			nni_mtx_unlock(&sock->mtx);
			nni_aio_finish_error(aio, rv);
			return;
		}
		nni_list_append(&ctx->recv_queue, aio);
		nni_mtx_unlock(&sock->mtx);
		return;
	}
	if (nni_lmq_empty(&ctx->recv_lmq) && (ctx == &sock->ctx)) {
		nni_pollable_clear(&sock->readable);
	}
	if ((msg = nni_msg_unique(msg)) == NULL) {
		goto again;
	}

	nni_mtx_unlock(&sock->mtx);
	nni_aio_finish_msg(aio, msg);
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
	surv0_ctx_abort(ctx, NNG_ETIMEDOUT);
	nni_mtx_unlock(&sock->mtx);
}

static void
surv0_ctx_send(void *arg, nni_aio *aio)
{
	surv0_ctx *  ctx  = arg;
	surv0_sock * sock = ctx->sock;
	surv0_pipe * pipe;
	nni_msg *    msg = nni_aio_get_msg(aio);
	size_t       len = nni_msg_len(msg);
	nni_time     now = nni_clock();
	nng_duration survey_time;
	int          rv;

	if (nni_aio_begin(aio) != 0) {
		return;
	}

	survey_time = nni_atomic_get(&ctx->survey_time);

	nni_mtx_lock(&sock->mtx);

	// Abort everything outstanding.
	surv0_ctx_abort(ctx, NNG_ECANCELED);
	nni_timer_cancel(&ctx->timer);

	// Allocate the new ID.
	if ((rv = nni_idhash_alloc(sock->surveys, &ctx->survey_id, ctx)) !=
	    0) {
		nni_mtx_unlock(&sock->mtx);
		nni_aio_finish_error(aio, rv);
		return;
	}
	nni_msg_header_clear(msg);
	nni_msg_header_append_u32(msg, (uint32_t) ctx->survey_id);

	// From this point, we're committed to success.  Note that we send
	// regardless of whether there are any pipes or not.  If no pipes,
	// then it just gets discarded.
	nni_aio_set_msg(aio, NULL);
	NNI_LIST_FOREACH (&sock->pipes, pipe) {

		// if the pipe isn't busy, then send this message direct.
		if (!pipe->busy) {
			pipe->busy = true;
			nni_msg_clone(msg);
			nni_aio_set_msg(pipe->aio_send, msg);
			nni_pipe_send(pipe->pipe, pipe->aio_send);
		} else if (!nni_lmq_full(&pipe->send_queue)) {
			nni_msg_clone(msg);
			nni_lmq_putq(&pipe->send_queue, msg);
		}
	}

	ctx->expire = now + survey_time;
	nni_timer_schedule(&ctx->timer, ctx->expire);

	nni_mtx_unlock(&sock->mtx);
	nni_msg_free(msg);

	nni_aio_finish(aio, 0, len);
}

static void
surv0_sock_fini(void *arg)
{
	surv0_sock *sock = arg;

	surv0_ctx_fini(&sock->ctx);
	nni_idhash_fini(sock->surveys);
	nni_pollable_fini(&sock->writable);
	nni_pollable_fini(&sock->readable);
	nni_mtx_fini(&sock->mtx);
}

static int
surv0_sock_init(void *arg, nni_sock *s)
{
	surv0_sock *sock = arg;
	int         rv;

	NNI_ARG_UNUSED(s);

	NNI_LIST_INIT(&sock->pipes, surv0_pipe, node);
	nni_mtx_init(&sock->mtx);
	nni_pollable_init(&sock->readable);
	nni_pollable_init(&sock->writable);
	// We are always writable.
	nni_pollable_raise(&sock->writable);

	// We allow for some buffering on a per pipe basis, to allow for
	// multiple contexts to have surveys outstanding.  It is recommended
	// to increase this if many contexts will want to publish
	// at nearly the same time.
	nni_atomic_init(&sock->send_buf);
	nni_atomic_set(&sock->send_buf, 8);

	if (((rv = nni_idhash_init(&sock->surveys)) != 0) ||
	    ((rv = surv0_ctx_init(&sock->ctx, sock)) != 0)) {
		surv0_sock_fini(sock);
		return (rv);
	}

	// Survey IDs are 32 bits, with the high order bit set.
	// We start at a random point, to minimize likelihood of
	// accidental collision across restarts.
	nni_idhash_set_limits(sock->surveys, 0x80000000u, 0xffffffffu,
	    nni_random() | 0x80000000u);

	sock->ttl = 8;

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

	surv0_ctx_close(&s->ctx);
}

static void
surv0_pipe_stop(void *arg)
{
	surv0_pipe *p = arg;

	nni_aio_stop(p->aio_send);
	nni_aio_stop(p->aio_recv);
}

static void
surv0_pipe_fini(void *arg)
{
	surv0_pipe *p = arg;

	nni_aio_free(p->aio_send);
	nni_aio_free(p->aio_recv);
	nni_lmq_fini(&p->send_queue);
}

static int
surv0_pipe_init(void *arg, nni_pipe *pipe, void *s)
{
	surv0_pipe *p    = arg;
	surv0_sock *sock = s;
	int         rv;
	int         len;

	len = nni_atomic_get(&sock->send_buf);

	// This depth could be tunable.  The deeper the queue, the more
	// concurrent surveys that can be delivered (multiple contexts).
	// Note that surveys can be *outstanding*, but not yet put on the wire.
	if (((rv = nni_lmq_init(&p->send_queue, len)) != 0) ||
	    ((rv = nni_aio_alloc(&p->aio_send, surv0_pipe_send_cb, p)) != 0) ||
	    ((rv = nni_aio_alloc(&p->aio_recv, surv0_pipe_recv_cb, p)) != 0)) {
		surv0_pipe_fini(p);
		return (rv);
	}

	p->pipe = pipe;
	p->sock = sock;
	return (0);
}

static int
surv0_pipe_start(void *arg)
{
	surv0_pipe *p = arg;
	surv0_sock *s = p->sock;

	if (nni_pipe_peer(p->pipe) != NNG_SURVEYOR0_PEER) {
		return (NNG_EPROTO);
	}

	nni_mtx_lock(&s->mtx);
	nni_list_append(&s->pipes, p);
	nni_mtx_unlock(&s->mtx);

	nni_pipe_recv(p->pipe, p->aio_recv);
	return (0);
}

static void
surv0_pipe_close(void *arg)
{
	surv0_pipe *p = arg;
	surv0_sock *s = p->sock;

	nni_aio_close(p->aio_send);
	nni_aio_close(p->aio_recv);

	nni_mtx_lock(&s->mtx);
	p->closed = true;
	nni_lmq_flush(&p->send_queue);
	if (nni_list_active(&s->pipes, p)) {
		nni_list_remove(&s->pipes, p);
	}
	nni_mtx_unlock(&s->mtx);
}

static void
surv0_pipe_send_cb(void *arg)
{
	surv0_pipe *p    = arg;
	surv0_sock *sock = p->sock;
	nni_msg *   msg;

	if (nni_aio_result(p->aio_send) != 0) {
		nni_msg_free(nni_aio_get_msg(p->aio_send));
		nni_aio_set_msg(p->aio_send, NULL);
		nni_pipe_close(p->pipe);
		return;
	}

	nni_mtx_lock(&sock->mtx);
	if (p->closed) {
		nni_mtx_unlock(&sock->mtx);
		return;
	}
	if (nni_lmq_getq(&p->send_queue, &msg) == 0) {
		nni_aio_set_msg(p->aio_send, msg);
		nni_pipe_send(p->pipe, p->aio_send);
	} else {
		p->busy = false;
	}
	nni_mtx_unlock(&sock->mtx);
}

static void
surv0_pipe_recv_cb(void *arg)
{
	surv0_pipe *p    = arg;
	surv0_sock *sock = p->sock;
	surv0_ctx * ctx;
	nni_msg *   msg;
	uint32_t    id;
	nni_aio *   aio;

	if (nni_aio_result(p->aio_recv) != 0) {
		nni_pipe_close(p->pipe);
		return;
	}

	msg = nni_aio_get_msg(p->aio_recv);
	nni_aio_set_msg(p->aio_recv, NULL);
	nni_msg_set_pipe(msg, nni_pipe_id(p->pipe));

	// We yank 4 bytes of body, and move them to the header.
	if (nni_msg_len(msg) < 4) {
		// Peer sent us garbage.  Kick it.
		nni_msg_free(msg);
		nni_pipe_close(p->pipe);
		return;
	}
	id = nni_msg_trim_u32(msg);
	nni_msg_header_append_u32(msg, id);

	nni_mtx_lock(&sock->mtx);
	// Best effort at delivery.  Discard if no context or context is
	// unable to receive it.
	if ((nni_idhash_find(sock->surveys, id, (void **) &ctx) != 0) ||
	    (nni_lmq_full(&ctx->recv_lmq))) {
		nni_msg_free(msg);
	} else if ((aio = nni_list_first(&ctx->recv_queue)) != NULL) {
		nni_list_remove(&ctx->recv_queue, aio);
		nni_aio_finish_msg(aio, msg);
	} else {
		nni_lmq_putq(&ctx->recv_lmq, msg);
		if (ctx == &sock->ctx) {
			nni_pollable_raise(&sock->readable);
		}
	}
	nni_mtx_unlock(&sock->mtx);

	nni_pipe_recv(p->pipe, p->aio_recv);
}

static int
surv0_ctx_set_survey_time(
    void *arg, const void *buf, size_t sz, nni_opt_type t)
{
	surv0_ctx *  ctx = arg;
	nng_duration expire;
	int          rv;
	if ((rv = nni_copyin_ms(&expire, buf, sz, t)) == 0) {
		nni_atomic_set(&ctx->survey_time, expire);
	}
	return (rv);
}

static int
surv0_ctx_get_survey_time(void *arg, void *buf, size_t *szp, nni_opt_type t)
{
	surv0_ctx *ctx = arg;
	return (
	    nni_copyout_ms(nni_atomic_get(&ctx->survey_time), buf, szp, t));
}

static int
surv0_sock_set_max_ttl(void *arg, const void *buf, size_t sz, nni_opt_type t)
{
	surv0_sock *s = arg;
	return (nni_copyin_int(&s->ttl, buf, sz, 1, NNI_MAX_MAX_TTL, t));
}

static int
surv0_sock_get_max_ttl(void *arg, void *buf, size_t *szp, nni_opt_type t)
{
	surv0_sock *s = arg;
	return (nni_copyout_int(s->ttl, buf, szp, t));
}

static int
surv0_sock_set_survey_time(
    void *arg, const void *buf, size_t sz, nni_opt_type t)
{
	surv0_sock *s = arg;
	return (surv0_ctx_set_survey_time(&s->ctx, buf, sz, t));
}

static int
surv0_sock_get_survey_time(void *arg, void *buf, size_t *szp, nni_opt_type t)
{
	surv0_sock *s = arg;
	return (surv0_ctx_get_survey_time(&s->ctx, buf, szp, t));
}

static int
surv0_sock_get_send_fd(void *arg, void *buf, size_t *szp, nni_opt_type t)
{
	surv0_sock *sock = arg;
	int         rv;
	int         fd;

	if ((rv = nni_pollable_getfd(&sock->writable, &fd)) != 0) {
		return (rv);
	}
	return (nni_copyout_int(fd, buf, szp, t));
}

static int
surv0_sock_get_recv_fd(void *arg, void *buf, size_t *szp, nni_opt_type t)
{
	surv0_sock *sock = arg;
	int         rv;
	int         fd;

	if ((rv = nni_pollable_getfd(&sock->readable, &fd)) != 0) {
		return (rv);
	}
	return (nni_copyout_int(fd, buf, szp, t));
}

static void
surv0_sock_recv(void *arg, nni_aio *aio)
{
	surv0_sock *s = arg;
	surv0_ctx_recv(&s->ctx, aio);
}

static void
surv0_sock_send(void *arg, nni_aio *aio)
{
	surv0_sock *s = arg;
	surv0_ctx_send(&s->ctx, aio);
}

static nni_proto_pipe_ops surv0_pipe_ops = {
	.pipe_size  = sizeof(surv0_pipe),
	.pipe_init  = surv0_pipe_init,
	.pipe_fini  = surv0_pipe_fini,
	.pipe_start = surv0_pipe_start,
	.pipe_close = surv0_pipe_close,
	.pipe_stop  = surv0_pipe_stop,
};

static nni_option surv0_ctx_options[] = {
	{
	    .o_name = NNG_OPT_SURVEYOR_SURVEYTIME,
	    .o_get  = surv0_ctx_get_survey_time,
	    .o_set  = surv0_ctx_set_survey_time,
	},
	{
	    .o_name = NULL,
	}
};
static nni_proto_ctx_ops surv0_ctx_ops = {
	.ctx_size    = sizeof(surv0_ctx),
	.ctx_init    = surv0_ctx_init,
	.ctx_fini    = surv0_ctx_fini,
	.ctx_send    = surv0_ctx_send,
	.ctx_recv    = surv0_ctx_recv,
	.ctx_options = surv0_ctx_options,
};

static nni_option surv0_sock_options[] = {
	{
	    .o_name = NNG_OPT_SURVEYOR_SURVEYTIME,
	    .o_get  = surv0_sock_get_survey_time,
	    .o_set  = surv0_sock_set_survey_time,
	},
	{
	    .o_name = NNG_OPT_MAXTTL,
	    .o_get  = surv0_sock_get_max_ttl,
	    .o_set  = surv0_sock_set_max_ttl,
	},
	{
	    .o_name = NNG_OPT_RECVFD,
	    .o_get  = surv0_sock_get_recv_fd,
	},
	{
	    .o_name = NNG_OPT_SENDFD,
	    .o_get  = surv0_sock_get_send_fd,
	},
	// terminate list
	{
	    .o_name = NULL,
	},
};

static nni_proto_sock_ops surv0_sock_ops = {
	.sock_size    = sizeof(surv0_sock),
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
	.proto_self     = { NNG_SURVEYOR0_SELF, NNG_SURVEYOR0_SELF_NAME },
	.proto_peer     = { NNG_SURVEYOR0_PEER, NNG_SURVEYOR0_PEER_NAME },
	.proto_flags    = NNI_PROTO_FLAG_SNDRCV | NNI_PROTO_FLAG_NOMSGQ,
	.proto_sock_ops = &surv0_sock_ops,
	.proto_pipe_ops = &surv0_pipe_ops,
	.proto_ctx_ops  = &surv0_ctx_ops,
};

int
nng_surveyor0_open(nng_socket *sock)
{
	return (nni_proto_open(sock, &surv0_proto));
}
