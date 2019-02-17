//
// Copyright 2019 Staysail Systems, Inc. <info@staysail.tech>
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

typedef struct req0_pipe req0_pipe;
typedef struct req0_sock req0_sock;
typedef struct req0_ctx  req0_ctx;

static void req0_run_sendq(req0_sock *, nni_list *);
static void req0_ctx_reset(req0_ctx *);
static void req0_ctx_timeout(void *);
static void req0_pipe_fini(void *);
static void req0_ctx_fini(void *);
static int  req0_ctx_init(void **, void *);

// A req0_ctx is a "context" for the request.  It uses most of the
// socket, but keeps track of its own outstanding replays, the request ID,
// and so forth.
struct req0_ctx {
	nni_list_node  snode;
	nni_list_node  sqnode; // node on the sendq
	nni_list_node  pnode;  // node on the pipe list
	uint32_t       reqid;
	req0_sock *    sock;
	nni_aio *      raio; // user aio waiting to receive - only one!
	nni_aio *      saio;
	nng_msg *      reqmsg; // request message
	size_t         reqlen;
	nng_msg *      repmsg; // reply message
	nni_timer_node timer;
	nni_duration   retry;
};

// A req0_sock is our per-socket protocol private structure.
struct req0_sock {
	nni_sock *   nsock;
	nni_duration retry;
	bool         closed;
	int          ttl;

	req0_ctx *ctx; // base socket ctx

	nni_list readypipes;
	nni_list busypipes;
	nni_list stoppipes;
	nni_list ctxs;

	nni_list      sendq;  // contexts waiting to send.
	nni_idhash *  reqids; // contexts by request ID
	nni_pollable *recvable;
	nni_pollable *sendable;

	nni_mtx mtx;
};

// A req0_pipe is our per-pipe protocol private structure.
struct req0_pipe {
	nni_pipe *    pipe;
	req0_sock *   req;
	nni_list_node node;
	nni_list      ctxs; // ctxs with pending traffic
	bool          closed;
	nni_aio *     aio_send;
	nni_aio *     aio_recv;
};

static void req0_sock_fini(void *);
static void req0_send_cb(void *);
static void req0_recv_cb(void *);

static int
req0_sock_init(void **sp, nni_sock *sock)
{
	req0_sock *s;
	int        rv;

	if ((s = NNI_ALLOC_STRUCT(s)) == NULL) {
		return (NNG_ENOMEM);
	}
	if ((rv = nni_idhash_init(&s->reqids)) != 0) {
		NNI_FREE_STRUCT(s);
		return (rv);
	}

	// Request IDs are 32 bits, with the high order bit set.
	// We start at a random point, to minimize likelihood of
	// accidental collision across restarts.
	nni_idhash_set_limits(
	    s->reqids, 0x80000000u, 0xffffffffu, nni_random() | 0x80000000u);

	nni_mtx_init(&s->mtx);

	NNI_LIST_INIT(&s->readypipes, req0_pipe, node);
	NNI_LIST_INIT(&s->busypipes, req0_pipe, node);
	NNI_LIST_INIT(&s->stoppipes, req0_pipe, node);
	NNI_LIST_INIT(&s->sendq, req0_ctx, sqnode);
	NNI_LIST_INIT(&s->ctxs, req0_ctx, snode);

	// this is "semi random" start for request IDs.
	s->nsock = sock;
	s->retry = NNI_SECOND * 60;

	if ((rv = req0_ctx_init((void **) &s->ctx, s)) != 0) {
		req0_sock_fini(s);
		return (rv);
	}
	if (((rv = nni_pollable_alloc(&s->sendable)) != 0) ||
	    ((rv = nni_pollable_alloc(&s->recvable)) != 0)) {
		req0_sock_fini(s);
		return (rv);
	}

	s->ttl = 8;
	*sp    = s;

	return (0);
}

static void
req0_sock_open(void *arg)
{
	NNI_ARG_UNUSED(arg);
}

static void
req0_sock_close(void *arg)
{
	req0_sock *s = arg;
	req0_ctx * ctx;

	nni_mtx_lock(&s->mtx);
	s->closed = true;
	NNI_LIST_FOREACH (&s->ctxs, ctx) {
		if (ctx->raio != NULL) {
			nni_aio_finish_error(ctx->raio, NNG_ECLOSED);
			ctx->raio = NULL;
			req0_ctx_reset(ctx);
		}
	}
	nni_mtx_unlock(&s->mtx);
}

static void
req0_sock_fini(void *arg)
{
	req0_sock *s = arg;

	nni_mtx_lock(&s->mtx);
	NNI_ASSERT(nni_list_empty(&s->busypipes));
	NNI_ASSERT(nni_list_empty(&s->stoppipes));
	NNI_ASSERT(nni_list_empty(&s->readypipes));
	nni_mtx_unlock(&s->mtx);
	if (s->ctx) {
		req0_ctx_fini(s->ctx);
	}
	nni_pollable_free(s->recvable);
	nni_pollable_free(s->sendable);
	nni_idhash_fini(s->reqids);
	nni_mtx_fini(&s->mtx);
	NNI_FREE_STRUCT(s);
}

static void
req0_pipe_stop(void *arg)
{
	req0_pipe *p = arg;
	req0_sock *s = p->req;

	nni_aio_stop(p->aio_recv);
	nni_aio_stop(p->aio_send);
	nni_mtx_lock(&s->mtx);
	nni_list_node_remove(&p->node);
	nni_mtx_unlock(&s->mtx);
}

static void
req0_pipe_fini(void *arg)
{
	req0_pipe *p = arg;

	nni_aio_fini(p->aio_recv);
	nni_aio_fini(p->aio_send);
	NNI_FREE_STRUCT(p);
}

static int
req0_pipe_init(void **pp, nni_pipe *pipe, void *s)
{
	req0_pipe *p;
	int        rv;

	if ((p = NNI_ALLOC_STRUCT(p)) == NULL) {
		return (NNG_ENOMEM);
	}
	if (((rv = nni_aio_init(&p->aio_recv, req0_recv_cb, p)) != 0) ||
	    ((rv = nni_aio_init(&p->aio_send, req0_send_cb, p)) != 0)) {
		req0_pipe_fini(p);
		return (rv);
	}

	NNI_LIST_NODE_INIT(&p->node);
	NNI_LIST_INIT(&p->ctxs, req0_ctx, pnode);
	p->pipe = pipe;
	p->req  = s;
	*pp     = p;
	return (0);
}

static int
req0_pipe_start(void *arg)
{
	req0_pipe *p = arg;
	req0_sock *s = p->req;

	if (nni_pipe_peer(p->pipe) != NNI_PROTO_REP_V0) {
		return (NNG_EPROTO);
	}

	nni_mtx_lock(&s->mtx);
	if (s->closed || p->closed) {
		nni_mtx_unlock(&s->mtx);
		return (NNG_ECLOSED);
	}
	nni_list_append(&s->readypipes, p);
	nni_pollable_raise(s->sendable);
	req0_run_sendq(s, NULL);
	nni_mtx_unlock(&s->mtx);

	nni_pipe_recv(p->pipe, p->aio_recv);
	return (0);
}

static void
req0_pipe_close(void *arg)
{
	req0_pipe *p = arg;
	req0_sock *s = p->req;
	req0_ctx * ctx;

	nni_aio_close(p->aio_recv);
	nni_aio_close(p->aio_send);

	nni_mtx_lock(&s->mtx);
	// This removes the node from either busypipes or readypipes.
	// It doesn't much matter which.  We stick the pipe on the stop
	// list, so that we can wait for that to close down safely.
	p->closed = true;
	nni_list_node_remove(&p->node);
	nni_list_append(&s->stoppipes, p);
	if (nni_list_empty(&s->readypipes)) {
		nni_pollable_clear(s->sendable);
	}

	while ((ctx = nni_list_first(&p->ctxs)) != NULL) {
		nni_list_remove(&p->ctxs, ctx);
		// Reset the timer on this so it expires immediately.
		// This is actually easier than canceling the timer and
		// running the sendq separately.  (In particular, it avoids
		// a potential deadlock on cancelling the timer.)
		nni_timer_schedule(&ctx->timer, NNI_TIME_ZERO);
	}
	nni_mtx_unlock(&s->mtx);
}

// For cooked mode, we use a context, and send out that way.  This
// completely bypasses the upper write queue.  Each context keeps one
// message pending; these are "scheduled" via the sendq.  The sendq
// is ordered, so FIFO ordering between contexts is provided for.

static void
req0_send_cb(void *arg)
{
	req0_pipe *p = arg;
	req0_sock *s = p->req;
	nni_aio *  aio;
	nni_list   aios;

	nni_aio_list_init(&aios);
	if (nni_aio_result(p->aio_send) != 0) {
		// We failed to send... clean up and deal with it.
		nni_msg_free(nni_aio_get_msg(p->aio_send));
		nni_aio_set_msg(p->aio_send, NULL);
		nni_pipe_close(p->pipe);
		return;
	}

	// We completed a cooked send, so we need to reinsert ourselves
	// in the ready list, and re-run the sendq.

	nni_mtx_lock(&s->mtx);
	if (p->closed || s->closed) {
		// This occurs if the req0_pipe_close has been called.
		// In that case we don't want any more processing.
		nni_mtx_unlock(&s->mtx);
		return;
	}
	nni_list_remove(&s->busypipes, p);
	nni_list_append(&s->readypipes, p);
	if (nni_list_empty(&s->sendq)) {
		nni_pollable_raise(s->sendable);
	}
	req0_run_sendq(s, &aios);
	nni_mtx_unlock(&s->mtx);

	while ((aio = nni_list_first(&aios)) != NULL) {
		nni_list_remove(&aios, aio);
		nni_aio_finish_synch(aio, 0, 0);
	}
}

static void
req0_recv_cb(void *arg)
{
	req0_pipe *p = arg;
	req0_sock *s = p->req;
	req0_ctx * ctx;
	nni_msg *  msg;
	nni_aio *  aio;
	uint32_t   id;

	if (nni_aio_result(p->aio_recv) != 0) {
		nni_pipe_close(p->pipe);
		return;
	}

	msg = nni_aio_get_msg(p->aio_recv);
	nni_aio_set_msg(p->aio_recv, NULL);
	nni_msg_set_pipe(msg, nni_pipe_id(p->pipe));

	// We yank 4 bytes from front of body, and move them to the header.
	if (nni_msg_len(msg) < 4) {
		// Malformed message.
		goto malformed;
	}
	id = nni_msg_trim_u32(msg);
	if (nni_msg_header_append_u32(msg, id) != 0) {
		// Arguably we could just discard and carry on.  But
		// dropping the connection is probably more helpful since
		// it lets the other side see that a problem occurred.
		// Plus it gives us a chance to reclaim some memory.
		goto malformed;
	}

	// Schedule another receive while we are processing this.
	nni_mtx_lock(&s->mtx);
	nni_pipe_recv(p->pipe, p->aio_recv);

	// Look for a context to receive it.
	if ((nni_idhash_find(s->reqids, id, (void **) &ctx) != 0) ||
	    (ctx->saio != NULL) || (ctx->repmsg != NULL)) {
		nni_mtx_unlock(&s->mtx);
		// No waiting context, we have not sent the request out to
		// the wire yet, or context already has a reply ready.
		// Discard the message.
		nni_msg_free(msg);
		return;
	}

	// We have our match, so we can remove this.
	nni_list_node_remove(&ctx->sqnode);
	nni_idhash_remove(s->reqids, id);
	ctx->reqid = 0;
	if (ctx->reqmsg != NULL) {
		nni_msg_free(ctx->reqmsg);
		ctx->reqmsg = NULL;
	}

	// Is there an aio waiting for us?
	if ((aio = ctx->raio) != NULL) {
		ctx->raio = NULL;
		nni_mtx_unlock(&s->mtx);
		nni_aio_set_msg(aio, msg);
		nni_aio_finish_synch(aio, 0, nni_msg_len(msg));
	} else {
		// No AIO, so stash msg.  Receive will pick it up later.
		ctx->repmsg = msg;
		if (ctx == s->ctx) {
			nni_pollable_raise(s->recvable);
		}
		nni_mtx_unlock(&s->mtx);
	}
	return;

malformed:
	nni_msg_free(msg);
	nni_pipe_close(p->pipe);
}

static void
req0_ctx_timeout(void *arg)
{
	req0_ctx * ctx = arg;
	req0_sock *s   = ctx->sock;

	nni_mtx_lock(&s->mtx);
	if ((ctx->reqmsg != NULL) && (!s->closed)) {
		if (!nni_list_node_active(&ctx->sqnode)) {
			nni_list_append(&s->sendq, ctx);
		}
		req0_run_sendq(s, NULL);
	}
	nni_mtx_unlock(&s->mtx);
}

static int
req0_ctx_init(void **cpp, void *sarg)
{
	req0_sock *s = sarg;
	req0_ctx * ctx;

	if ((ctx = NNI_ALLOC_STRUCT(ctx)) == NULL) {
		return (NNG_ENOMEM);
	}

	nni_timer_init(&ctx->timer, req0_ctx_timeout, ctx);

	nni_mtx_lock(&s->mtx);
	ctx->sock  = s;
	ctx->raio  = NULL;
	ctx->retry = s->retry;
	nni_list_append(&s->ctxs, ctx);
	nni_mtx_unlock(&s->mtx);

	*cpp = ctx;
	return (0);
}

static void
req0_ctx_fini(void *arg)
{
	req0_ctx * ctx = arg;
	req0_sock *s   = ctx->sock;
	nni_aio *  aio;

	nni_mtx_lock(&s->mtx);
	if ((aio = ctx->raio) != NULL) {
		ctx->raio = NULL;
		nni_aio_finish_error(aio, NNG_ECLOSED);
	}
	if ((aio = ctx->saio) != NULL) {
		ctx->saio = NULL;
		nni_aio_set_msg(aio, ctx->reqmsg);
		ctx->reqmsg = NULL;
		nni_aio_finish_error(aio, NNG_ECLOSED);
	}
	req0_ctx_reset(ctx);
	nni_list_remove(&s->ctxs, ctx);
	nni_mtx_unlock(&s->mtx);

	nni_timer_cancel(&ctx->timer);
	nni_timer_fini(&ctx->timer);

	NNI_FREE_STRUCT(ctx);
}

static int
req0_ctx_set_resendtime(void *arg, const void *buf, size_t sz, nni_opt_type t)
{
	req0_ctx *ctx = arg;
	return (nni_copyin_ms(&ctx->retry, buf, sz, t));
}

static int
req0_ctx_get_resendtime(void *arg, void *buf, size_t *szp, nni_opt_type t)
{
	req0_ctx *ctx = arg;
	return (nni_copyout_ms(ctx->retry, buf, szp, t));
}

static void
req0_run_sendq(req0_sock *s, nni_list *aiolist)
{
	req0_ctx *ctx;
	nni_aio * aio;

	// Note: This routine should be called with the socket lock held.
	while ((ctx = nni_list_first(&s->sendq)) != NULL) {
		nni_msg *  msg;
		req0_pipe *p;

		if ((p = nni_list_first(&s->readypipes)) == NULL) {
			return;
		}

		// We have a place to send it, so do the send.
		// If a sending error occurs that causes the message to
		// be dropped, we rely on the resend timer to pick it up.
		// We also notify the completion callback if this is the
		// first send attempt.
		nni_list_remove(&s->sendq, ctx);

		// Schedule a resubmit timer.  We only do this if we got
		// a pipe to send to.  Otherwise, we should get handled
		// the next time that the sendq is run.  We don't do this
		// if the retry is "disabled" with NNG_DURATION_INFINITE.
		if (ctx->retry > 0) {
			nni_timer_schedule(
			    &ctx->timer, nni_clock() + ctx->retry);
		}

		if (nni_msg_dup(&msg, ctx->reqmsg) != 0) {
			// Oops.  Well, keep trying each context; maybe
			// one of them will get lucky.
			continue;
		}

		// Put us on the pipe list of active contexts.
		// This gives the pipe a chance to kick a resubmit
		// if the pipe is removed.
		nni_list_node_remove(&ctx->pnode);
		nni_list_append(&p->ctxs, ctx);

		nni_list_remove(&s->readypipes, p);
		nni_list_append(&s->busypipes, p);

		if ((aio = ctx->saio) != NULL) {
			ctx->saio = NULL;
			nni_aio_bump_count(aio, ctx->reqlen);
			// If the list was passed in, we want to do a
			// synchronous completion later.
			if (aiolist != NULL) {
				nni_list_append(aiolist, aio);
			} else {
				nni_aio_finish(aio, 0, 0);
			}
			if (ctx == s->ctx) {
				if (nni_list_empty(&s->readypipes)) {
					nni_pollable_clear(s->sendable);
				} else {
					nni_pollable_raise(s->sendable);
				}
			}
		}

		nni_aio_set_msg(p->aio_send, msg);
		nni_pipe_send(p->pipe, p->aio_send);
	}
}

void
req0_ctx_reset(req0_ctx *ctx)
{
	req0_sock *s = ctx->sock;
	// Call with sock lock held!

	// We cannot safely "wait" using nni_timer_cancel, but this removes
	// any scheduled timer activation.  If the timeout is already running
	// concurrently, it will still run.  It should do nothing, because
	// we toss the reqmsg.  There is still a very narrow race if the
	// timeout fires, but doesn't actually start running before we
	// both finish this function, *and* manage to reschedule another
	// request.  The consequence of that occurring is that the request
	// will be emitted on the wire twice.  This is not actually tragic.
	nni_timer_schedule(&ctx->timer, NNI_TIME_NEVER);

	nni_list_node_remove(&ctx->pnode);
	nni_list_node_remove(&ctx->sqnode);
	if (ctx->reqid != 0) {
		nni_idhash_remove(s->reqids, ctx->reqid);
		ctx->reqid = 0;
	}
	if (ctx->reqmsg != NULL) {
		nni_msg_free(ctx->reqmsg);
		ctx->reqmsg = NULL;
	}
	if (ctx->repmsg != NULL) {
		nni_msg_free(ctx->repmsg);
		ctx->repmsg = NULL;
	}
}

static void
req0_ctx_cancel_recv(nni_aio *aio, void *arg, int rv)
{
	req0_ctx * ctx = arg;
	req0_sock *s   = ctx->sock;

	nni_mtx_lock(&s->mtx);
	if (ctx->raio != aio) {
		// already completed, ignore this.
		nni_mtx_unlock(&s->mtx);
		return;
	}
	ctx->raio = NULL;

	// Cancellation of a pending receive is treated as aborting the
	// entire state machine.  This allows us to preserve the semantic of
	// exactly one receive operation per send operation, and should
	// be the least surprising for users.  The main consequence is that
	// if a receive operation is completed (in error or otherwise), the
	// user must submit a new send operation to restart the state machine.
	req0_ctx_reset(ctx);

	nni_aio_finish_error(aio, rv);
	nni_mtx_unlock(&s->mtx);
}

static void
req0_ctx_recv(void *arg, nni_aio *aio)
{
	req0_ctx * ctx = arg;
	req0_sock *s   = ctx->sock;
	nni_msg *  msg;

	if (nni_aio_begin(aio) != 0) {
		return;
	}
	nni_mtx_lock(&s->mtx);
	if (s->closed) {
		nni_mtx_unlock(&s->mtx);
		nni_aio_finish_error(aio, NNG_ECLOSED);
		return;
	}
	if ((ctx->raio != NULL) ||
	    ((ctx->reqmsg == NULL) && (ctx->repmsg == NULL))) {
		// We have already got a pending receive or have not
		// tried to send a request yet.
		// Either of these violate our basic state assumptions.
		nni_mtx_unlock(&s->mtx);
		nni_aio_finish_error(aio, NNG_ESTATE);
		return;
	}

	if ((msg = ctx->repmsg) == NULL) {
		int rv;
		rv = nni_aio_schedule(aio, req0_ctx_cancel_recv, ctx);
		if (rv != 0) {
			nni_mtx_unlock(&s->mtx);
			nni_aio_finish_error(aio, rv);
			return;
		}
		ctx->raio = aio;
		nni_mtx_unlock(&s->mtx);
		return;
	}

	ctx->repmsg = NULL;

	// We have got a message to pass up, yay!
	nni_aio_set_msg(aio, msg);
	if (ctx == s->ctx) {
		nni_pollable_clear(s->recvable);
	}
	nni_mtx_unlock(&s->mtx);
	nni_aio_finish(aio, 0, nni_msg_len(msg));
}

static void
req0_ctx_cancel_send(nni_aio *aio, void *arg, int rv)
{
	req0_ctx * ctx = arg;
	req0_sock *s   = ctx->sock;

	nni_mtx_lock(&s->mtx);
	if (ctx->saio != aio) {
		// already completed, ignore this.
		nni_mtx_unlock(&s->mtx);
		return;
	}

	// There should not be a pending reply, because we canceled
	// it while we were waiting.
	NNI_ASSERT(ctx->raio == NULL);
	ctx->saio = NULL;
	// Restore the message back to the aio.
	nni_aio_set_msg(aio, ctx->reqmsg);
	nni_msg_header_clear(ctx->reqmsg);
	ctx->reqmsg = NULL;

	// Cancellation of a pending receive is treated as aborting the
	// entire state machine.  This allows us to preserve the semantic of
	// exactly one receive operation per send operation, and should
	// be the least surprising for users.  The main consequence is that
	// if a receive operation is completed (in error or otherwise), the
	// user must submit a new send operation to restart the state machine.
	req0_ctx_reset(ctx);

	nni_aio_finish_error(aio, rv);
	nni_mtx_unlock(&s->mtx);
}

static void
req0_ctx_send(void *arg, nni_aio *aio)
{
	req0_ctx * ctx = arg;
	req0_sock *s   = ctx->sock;
	nng_msg *  msg = nni_aio_get_msg(aio);
	uint64_t   id;
	int        rv;

	if (nni_aio_begin(aio) != 0) {
		return;
	}
	nni_mtx_lock(&s->mtx);
	if (s->closed) {
		nni_mtx_unlock(&s->mtx);
		nni_aio_finish_error(aio, NNG_ECLOSED);
		return;
	}
	// Sending a new request cancels the old one, including any
	// outstanding reply.
	if (ctx->raio != NULL) {
		nni_aio_finish_error(ctx->raio, NNG_ECANCELED);
		ctx->raio = NULL;
	}
	if (ctx->saio != NULL) {
		nni_aio_set_msg(ctx->saio, ctx->reqmsg);
		nni_msg_header_clear(ctx->reqmsg);
		ctx->reqmsg = NULL;
		nni_aio_finish_error(ctx->saio, NNG_ECANCELED);
		ctx->saio = NULL;
		nni_list_remove(&s->sendq, ctx);
	}

	// This resets the entire state machine.
	req0_ctx_reset(ctx);

	// Insert us on the per ID hash list, so that receives can find us.
	if ((rv = nni_idhash_alloc(s->reqids, &id, ctx)) != 0) {
		nni_mtx_unlock(&s->mtx);
		nni_aio_finish_error(aio, rv);
		return;
	}
	ctx->reqid = (uint32_t) id;
	if ((rv = nni_msg_header_append_u32(msg, ctx->reqid)) != 0) {
		nni_idhash_remove(s->reqids, id);
		nni_mtx_unlock(&s->mtx);
		nni_aio_finish_error(aio, rv);
		return;
	}
	// If no pipes are ready, and the request was a poll (no background
	// schedule), then fail it.  Should be NNG_TIMEDOUT.
	rv = nni_aio_schedule(aio, req0_ctx_cancel_send, ctx);
	if ((rv != 0) && (nni_list_empty(&s->readypipes))) {
		nni_idhash_remove(s->reqids, id);
		nni_mtx_unlock(&s->mtx);
		nni_aio_finish_error(aio, rv);
		return;
	}
	ctx->reqlen = nni_msg_len(msg);
	ctx->reqmsg = msg;
	ctx->saio   = aio;
	nni_aio_set_msg(aio, NULL);

	// Stick us on the sendq list.
	nni_list_append(&s->sendq, ctx);

	// Note that this will be synchronous if the readypipes list was
	// not empty.
	req0_run_sendq(s, NULL);
	nni_mtx_unlock(&s->mtx);
}

static void
req0_sock_send(void *arg, nni_aio *aio)
{
	req0_sock *s = arg;
	req0_ctx_send(s->ctx, aio);
}

static void
req0_sock_recv(void *arg, nni_aio *aio)
{
	req0_sock *s = arg;
	req0_ctx_recv(s->ctx, aio);
}

static int
req0_sock_set_maxttl(void *arg, const void *buf, size_t sz, nni_opt_type t)
{
	req0_sock *s = arg;
	return (nni_copyin_int(&s->ttl, buf, sz, 1, 255, t));
}

static int
req0_sock_get_maxttl(void *arg, void *buf, size_t *szp, nni_opt_type t)
{
	req0_sock *s = arg;
	return (nni_copyout_int(s->ttl, buf, szp, t));
}

static int
req0_sock_set_resendtime(void *arg, const void *buf, size_t sz, nni_opt_type t)
{
	req0_sock *s = arg;
	int        rv;
	rv       = req0_ctx_set_resendtime(s->ctx, buf, sz, t);
	s->retry = s->ctx->retry;
	return (rv);
}

static int
req0_sock_get_resendtime(void *arg, void *buf, size_t *szp, nni_opt_type t)
{
	req0_sock *s = arg;
	return (req0_ctx_get_resendtime(s->ctx, buf, szp, t));
}

static int
req0_sock_get_sendfd(void *arg, void *buf, size_t *szp, nni_opt_type t)
{
	req0_sock *s = arg;
	int        rv;
	int        fd;

	if ((rv = nni_pollable_getfd(s->sendable, &fd)) != 0) {
		return (rv);
	}
	return (nni_copyout_int(fd, buf, szp, t));
}

static int
req0_sock_get_recvfd(void *arg, void *buf, size_t *szp, nni_opt_type t)
{
	req0_sock *s = arg;
	int        rv;
	int        fd;

	if ((rv = nni_pollable_getfd(s->recvable, &fd)) != 0) {
		return (rv);
	}

	return (nni_copyout_int(fd, buf, szp, t));
}

static nni_proto_pipe_ops req0_pipe_ops = {
	.pipe_init  = req0_pipe_init,
	.pipe_fini  = req0_pipe_fini,
	.pipe_start = req0_pipe_start,
	.pipe_close = req0_pipe_close,
	.pipe_stop  = req0_pipe_stop,
};

static nni_option req0_ctx_options[] = {
	{
	    .o_name = NNG_OPT_REQ_RESENDTIME,
	    .o_get  = req0_ctx_get_resendtime,
	    .o_set  = req0_ctx_set_resendtime,
	},
	{
	    .o_name = NULL,
	},
};

static nni_proto_ctx_ops req0_ctx_ops = {
	.ctx_init    = req0_ctx_init,
	.ctx_fini    = req0_ctx_fini,
	.ctx_recv    = req0_ctx_recv,
	.ctx_send    = req0_ctx_send,
	.ctx_options = req0_ctx_options,
};

static nni_option req0_sock_options[] = {
	{
	    .o_name = NNG_OPT_MAXTTL,
	    .o_get  = req0_sock_get_maxttl,
	    .o_set  = req0_sock_set_maxttl,
	},
	{
	    .o_name = NNG_OPT_REQ_RESENDTIME,
	    .o_get  = req0_sock_get_resendtime,
	    .o_set  = req0_sock_set_resendtime,
	},
	{
	    .o_name = NNG_OPT_RECVFD,
	    .o_get  = req0_sock_get_recvfd,
	},
	{
	    .o_name = NNG_OPT_SENDFD,
	    .o_get  = req0_sock_get_sendfd,
	},
	// terminate list
	{
	    .o_name = NULL,
	},
};

static nni_proto_sock_ops req0_sock_ops = {
	.sock_init    = req0_sock_init,
	.sock_fini    = req0_sock_fini,
	.sock_open    = req0_sock_open,
	.sock_close   = req0_sock_close,
	.sock_options = req0_sock_options,
	.sock_send    = req0_sock_send,
	.sock_recv    = req0_sock_recv,
};

static nni_proto req0_proto = {
	.proto_version  = NNI_PROTOCOL_VERSION,
	.proto_self     = { NNI_PROTO_REQ_V0, "req" },
	.proto_peer     = { NNI_PROTO_REP_V0, "rep" },
	.proto_flags    = NNI_PROTO_FLAG_SNDRCV | NNI_PROTO_FLAG_NOMSGQ,
	.proto_sock_ops = &req0_sock_ops,
	.proto_pipe_ops = &req0_pipe_ops,
	.proto_ctx_ops  = &req0_ctx_ops,
};

int
nng_req0_open(nng_socket *sidp)
{
	return (nni_proto_open(sidp, &req0_proto));
}
