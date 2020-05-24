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

typedef struct req0_pipe req0_pipe;
typedef struct req0_sock req0_sock;
typedef struct req0_ctx  req0_ctx;

static void req0_run_send_queue(req0_sock *, nni_list *);
static void req0_ctx_reset(req0_ctx *);
static void req0_ctx_timeout(void *);
static void req0_pipe_fini(void *);
static void req0_ctx_fini(void *);
static int  req0_ctx_init(void *, void *);

// A req0_ctx is a "context" for the request.  It uses most of the
// socket, but keeps track of its own outstanding replays, the request ID,
// and so forth.
struct req0_ctx {
	req0_sock *    sock;
	nni_list_node  sock_node;  // node on the socket context list
	nni_list_node  send_node;  // node on the send_queue
	nni_list_node  pipe_node;  // node on the pipe list
	uint32_t       request_id; // request ID, without high bit set
	nni_aio *      recv_aio;   // user aio waiting to recv - only one!
	nni_aio *      send_aio;   // user aio waiting to send
	nng_msg *      req_msg;    // request message (owned by protocol)
	size_t         req_len;    // length of request message (for stats)
	nng_msg *      rep_msg;    // reply message
	nni_timer_node timer;
	nni_duration   retry;
};

// A req0_sock is our per-socket protocol private structure.
struct req0_sock {
	nni_duration   retry;
	bool           closed;
	nni_atomic_int ttl;
	req0_ctx       master; // base socket master
	nni_list       ready_pipes;
	nni_list       busy_pipes;
	nni_list       stop_pipes;
	nni_list       contexts;
	nni_list       send_queue; // contexts waiting to send.
	nni_idhash *   requests;   // contexts by request ID
	nni_pollable   readable;
	nni_pollable   writable;
	nni_mtx        mtx;
};

// A req0_pipe is our per-pipe protocol private structure.
struct req0_pipe {
	nni_pipe *    pipe;
	req0_sock *   req;
	nni_list_node node;
	nni_list      contexts; // contexts with pending traffic
	bool          closed;
	nni_aio       aio_send;
	nni_aio       aio_recv;
};

static void req0_sock_fini(void *);
static void req0_send_cb(void *);
static void req0_recv_cb(void *);

static int
req0_sock_init(void *arg, nni_sock *sock)
{
	req0_sock *s = arg;
	int        rv;

	NNI_ARG_UNUSED(sock);

	if ((rv = nni_idhash_init(&s->requests)) != 0) {
		return (rv);
	}

	// Request IDs are 32 bits, with the high order bit set.
	// We start at a random point, to minimize likelihood of
	// accidental collision across restarts.
	nni_idhash_set_limits(
	    s->requests, 0x80000000u, 0xffffffffu, nni_random() | 0x80000000u);

	nni_mtx_init(&s->mtx);

	NNI_LIST_INIT(&s->ready_pipes, req0_pipe, node);
	NNI_LIST_INIT(&s->busy_pipes, req0_pipe, node);
	NNI_LIST_INIT(&s->stop_pipes, req0_pipe, node);
	NNI_LIST_INIT(&s->send_queue, req0_ctx, send_node);
	NNI_LIST_INIT(&s->contexts, req0_ctx, sock_node);

	// this is "semi random" start for request IDs.
	s->retry = NNI_SECOND * 60;

	(void) req0_ctx_init(&s->master, s);

	nni_pollable_init(&s->writable);
	nni_pollable_init(&s->readable);

	nni_atomic_init(&s->ttl);
	nni_atomic_set(&s->ttl, 8);
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

	nni_mtx_lock(&s->mtx);
	s->closed = true;
	nni_mtx_unlock(&s->mtx);
}

static void
req0_sock_fini(void *arg)
{
	req0_sock *s = arg;

	nni_mtx_lock(&s->mtx);
	NNI_ASSERT(nni_list_empty(&s->busy_pipes));
	NNI_ASSERT(nni_list_empty(&s->stop_pipes));
	NNI_ASSERT(nni_list_empty(&s->ready_pipes));
	nni_mtx_unlock(&s->mtx);

	req0_ctx_fini(&s->master);
	nni_pollable_fini(&s->readable);
	nni_pollable_fini(&s->writable);
	nni_idhash_fini(s->requests);
	nni_mtx_fini(&s->mtx);
}

static void
req0_pipe_stop(void *arg)
{
	req0_pipe *p = arg;
	req0_sock *s = p->req;

	nni_aio_stop(&p->aio_recv);
	nni_aio_stop(&p->aio_send);
	nni_mtx_lock(&s->mtx);
	nni_list_node_remove(&p->node);
	nni_mtx_unlock(&s->mtx);
}

static void
req0_pipe_fini(void *arg)
{
	req0_pipe *p = arg;

	nni_aio_fini(&p->aio_recv);
	nni_aio_fini(&p->aio_send);
}

static int
req0_pipe_init(void *arg, nni_pipe *pipe, void *s)
{
	req0_pipe *p = arg;

	nni_aio_init(&p->aio_recv, req0_recv_cb, p);
	nni_aio_init(&p->aio_send, req0_send_cb, p);
	NNI_LIST_NODE_INIT(&p->node);
	NNI_LIST_INIT(&p->contexts, req0_ctx, pipe_node);
	p->pipe = pipe;
	p->req  = s;
	return (0);
}

static int
req0_pipe_start(void *arg)
{
	req0_pipe *p = arg;
	req0_sock *s = p->req;

	if (nni_pipe_peer(p->pipe) != NNG_REQ0_PEER) {
		return (NNG_EPROTO);
	}

	nni_mtx_lock(&s->mtx);
	nni_list_append(&s->ready_pipes, p);
	nni_pollable_raise(&s->writable);
	req0_run_send_queue(s, NULL);
	nni_mtx_unlock(&s->mtx);

	nni_pipe_recv(p->pipe, &p->aio_recv);
	return (0);
}

static void
req0_pipe_close(void *arg)
{
	req0_pipe *p = arg;
	req0_sock *s = p->req;
	req0_ctx * ctx;

	nni_aio_close(&p->aio_recv);
	nni_aio_close(&p->aio_send);

	nni_mtx_lock(&s->mtx);
	// This removes the node from either busy_pipes or ready_pipes.
	// It doesn't much matter which.  We stick the pipe on the stop
	// list, so that we can wait for that to close down safely.
	p->closed = true;
	nni_list_node_remove(&p->node);
	nni_list_append(&s->stop_pipes, p);
	if (nni_list_empty(&s->ready_pipes)) {
		nni_pollable_clear(&s->writable);
	}

	while ((ctx = nni_list_first(&p->contexts)) != NULL) {
		nni_list_remove(&p->contexts, ctx);
		// Reset the timer on this so it expires immediately.
		// This is actually easier than canceling the timer and
		// running the send_queue separately.  (In particular, it
		// avoids a potential deadlock on cancelling the timer.)
		nni_timer_schedule(&ctx->timer, NNI_TIME_ZERO);
	}
	nni_mtx_unlock(&s->mtx);
}

// For cooked mode, we use a context, and send out that way.  This
// completely bypasses the upper write queue.  Each context keeps one
// message pending; these are "scheduled" via the send_queue.  The send_queue
// is ordered, so FIFO ordering between contexts is provided for.

static void
req0_send_cb(void *arg)
{
	req0_pipe *p = arg;
	req0_sock *s = p->req;
	nni_aio *  aio;
	nni_list   sent_list;

	nni_aio_list_init(&sent_list);
	if (nni_aio_result(&p->aio_send) != 0) {
		// We failed to send... clean up and deal with it.
		nni_msg_free(nni_aio_get_msg(&p->aio_send));
		nni_aio_set_msg(&p->aio_send, NULL);
		nni_pipe_close(p->pipe);
		return;
	}

	// We completed a cooked send, so we need to reinsert ourselves
	// in the ready list, and re-run the send_queue.

	nni_mtx_lock(&s->mtx);
	if (p->closed || s->closed) {
		// This occurs if the req0_pipe_close has been called.
		// In that case we don't want any more processing.
		nni_mtx_unlock(&s->mtx);
		return;
	}
	nni_list_remove(&s->busy_pipes, p);
	nni_list_append(&s->ready_pipes, p);
	if (nni_list_empty(&s->send_queue)) {
		nni_pollable_raise(&s->writable);
	}
	req0_run_send_queue(s, &sent_list);
	nni_mtx_unlock(&s->mtx);

	while ((aio = nni_list_first(&sent_list)) != NULL) {
		nni_list_remove(&sent_list, aio);
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

	if (nni_aio_result(&p->aio_recv) != 0) {
		nni_pipe_close(p->pipe);
		return;
	}

	msg = nni_aio_get_msg(&p->aio_recv);
	nni_aio_set_msg(&p->aio_recv, NULL);
	nni_msg_set_pipe(msg, nni_pipe_id(p->pipe));

	// We yank 4 bytes from front of body, and move them to the header.
	if (nni_msg_len(msg) < 4) {
		// Malformed message.
		goto malformed;
	}
	id = nni_msg_trim_u32(msg);

	// Schedule another receive while we are processing this.
	nni_mtx_lock(&s->mtx);

	// NB: If close was called, then this will just abort.
	nni_pipe_recv(p->pipe, &p->aio_recv);

	// Look for a context to receive it.
	if ((nni_idhash_find(s->requests, id, (void **) &ctx) != 0) ||
	    (ctx->send_aio != NULL) || (ctx->rep_msg != NULL)) {
		nni_mtx_unlock(&s->mtx);
		// No waiting context, we have not sent the request out to
		// the wire yet, or context already has a reply ready.
		// Discard the message.
		nni_msg_free(msg);
		return;
	}

	// We have our match, so we can remove this.
	nni_list_node_remove(&ctx->send_node);
	nni_idhash_remove(s->requests, id);
	ctx->request_id = 0;
	if (ctx->req_msg != NULL) {
		nni_msg_free(ctx->req_msg);
		ctx->req_msg = NULL;
	}

	// Is there an aio waiting for us?
	if ((aio = ctx->recv_aio) != NULL) {
		ctx->recv_aio = NULL;
		nni_mtx_unlock(&s->mtx);
		nni_aio_set_msg(aio, msg);
		nni_aio_finish_synch(aio, 0, nni_msg_len(msg));
	} else {
		// No AIO, so stash msg.  Receive will pick it up later.
		ctx->rep_msg = msg;
		if (ctx == &s->master) {
			nni_pollable_raise(&s->readable);
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
	if ((ctx->req_msg != NULL) && (!s->closed)) {
		if (!nni_list_node_active(&ctx->send_node)) {
			nni_list_append(&s->send_queue, ctx);
		}
		req0_run_send_queue(s, NULL);
	}
	nni_mtx_unlock(&s->mtx);
}

static int
req0_ctx_init(void *arg, void *sock)
{
	req0_sock *s   = sock;
	req0_ctx * ctx = arg;

	nni_timer_init(&ctx->timer, req0_ctx_timeout, ctx);

	nni_mtx_lock(&s->mtx);
	ctx->sock     = s;
	ctx->recv_aio = NULL;
	ctx->retry    = s->retry;
	nni_list_append(&s->contexts, ctx);
	nni_mtx_unlock(&s->mtx);

	return (0);
}

static void
req0_ctx_fini(void *arg)
{
	req0_ctx * ctx = arg;
	req0_sock *s   = ctx->sock;
	nni_aio *  aio;

	nni_mtx_lock(&s->mtx);
	if ((aio = ctx->recv_aio) != NULL) {
		ctx->recv_aio = NULL;
		nni_aio_finish_error(aio, NNG_ECLOSED);
	}
	if ((aio = ctx->send_aio) != NULL) {
		ctx->send_aio = NULL;
		nni_aio_set_msg(aio, ctx->req_msg);
		ctx->req_msg = NULL;
		nni_aio_finish_error(aio, NNG_ECLOSED);
	}
	req0_ctx_reset(ctx);
	nni_list_remove(&s->contexts, ctx);
	nni_mtx_unlock(&s->mtx);

	nni_timer_cancel(&ctx->timer);
	nni_timer_fini(&ctx->timer);
}

static int
req0_ctx_set_resend_time(void *arg, const void *buf, size_t sz, nni_opt_type t)
{
	req0_ctx *ctx = arg;
	return (nni_copyin_ms(&ctx->retry, buf, sz, t));
}

static int
req0_ctx_get_resend_time(void *arg, void *buf, size_t *szp, nni_opt_type t)
{
	req0_ctx *ctx = arg;
	return (nni_copyout_ms(ctx->retry, buf, szp, t));
}

static void
req0_run_send_queue(req0_sock *s, nni_list *sent_list)
{
	req0_ctx *ctx;
	nni_aio * aio;

	// Note: This routine should be called with the socket lock held.
	while ((ctx = nni_list_first(&s->send_queue)) != NULL) {
		req0_pipe *p;

		if ((p = nni_list_first(&s->ready_pipes)) == NULL) {
			return;
		}

		// We have a place to send it, so do the send.
		// If a sending error occurs that causes the message to
		// be dropped, we rely on the resend timer to pick it up.
		// We also notify the completion callback if this is the
		// first send attempt.
		nni_list_remove(&s->send_queue, ctx);

		// Schedule a resubmit timer.  We only do this if we got
		// a pipe to send to.  Otherwise, we should get handled
		// the next time that the send_queue is run.  We don't do this
		// if the retry is "disabled" with NNG_DURATION_INFINITE.
		if (ctx->retry > 0) {
			nni_timer_schedule(
			    &ctx->timer, nni_clock() + ctx->retry);
		}

		// Put us on the pipe list of active contexts.
		// This gives the pipe a chance to kick a resubmit
		// if the pipe is removed.
		nni_list_node_remove(&ctx->pipe_node);
		nni_list_append(&p->contexts, ctx);

		nni_list_remove(&s->ready_pipes, p);
		nni_list_append(&s->busy_pipes, p);
		if (nni_list_empty(&s->ready_pipes)) {
			nni_pollable_clear(&s->writable);
		}

		if ((aio = ctx->send_aio) != NULL) {
			ctx->send_aio = NULL;
			nni_aio_bump_count(aio, ctx->req_len);
			// If the list was passed in, we want to do a
			// synchronous completion later.
			if (sent_list != NULL) {
				nni_list_append(sent_list, aio);
			} else {
				nni_aio_finish(aio, 0, 0);
			}
		}

		// At this point, we will never give this message back to
		// to the user, so we don't have to worry about making it
		// unique.  We can freely clone it.
		nni_msg_clone(ctx->req_msg);
		nni_aio_set_msg(&p->aio_send, ctx->req_msg);
		nni_pipe_send(p->pipe, &p->aio_send);
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
	// we toss the request.  There is still a very narrow race if the
	// timeout fires, but doesn't actually start running before we
	// both finish this function, *and* manage to reschedule another
	// request.  The consequence of that occurring is that the request
	// will be emitted on the wire twice.  This is not actually tragic.
	nni_timer_schedule(&ctx->timer, NNI_TIME_NEVER);

	nni_list_node_remove(&ctx->pipe_node);
	nni_list_node_remove(&ctx->send_node);
	if (ctx->request_id != 0) {
		nni_idhash_remove(s->requests, ctx->request_id);
		ctx->request_id = 0;
	}
	if (ctx->req_msg != NULL) {
		nni_msg_free(ctx->req_msg);
		ctx->req_msg = NULL;
	}
	if (ctx->rep_msg != NULL) {
		nni_msg_free(ctx->rep_msg);
		ctx->rep_msg = NULL;
	}
}

static void
req0_ctx_cancel_recv(nni_aio *aio, void *arg, int rv)
{
	req0_ctx * ctx = arg;
	req0_sock *s   = ctx->sock;

	nni_mtx_lock(&s->mtx);
	if (ctx->recv_aio == aio) {
		ctx->recv_aio = NULL;

		// Cancellation of a pending receive is treated as aborting the
		// entire state machine.  This allows us to preserve the
		// semantic of exactly one receive operation per send
		// operation, and should be the least surprising for users. The
		// main consequence is that if a receive operation is completed
		// (in error or otherwise), the user must submit a new send
		// operation to restart the state machine.
		req0_ctx_reset(ctx);

		nni_aio_finish_error(aio, rv);
	}
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
	if ((ctx->recv_aio != NULL) ||
	    ((ctx->req_msg == NULL) && (ctx->rep_msg == NULL))) {
		// We have already got a pending receive or have not
		// tried to send a request yet.
		// Either of these violate our basic state assumptions.
		nni_mtx_unlock(&s->mtx);
		nni_aio_finish_error(aio, NNG_ESTATE);
		return;
	}

	if ((msg = ctx->rep_msg) == NULL) {
		int rv;
		rv = nni_aio_schedule(aio, req0_ctx_cancel_recv, ctx);
		if (rv != 0) {
			nni_mtx_unlock(&s->mtx);
			nni_aio_finish_error(aio, rv);
			return;
		}
		ctx->recv_aio = aio;
		nni_mtx_unlock(&s->mtx);
		return;
	}

	ctx->rep_msg = NULL;

	// We have got a message to pass up, yay!
	nni_aio_set_msg(aio, msg);
	if (ctx == &s->master) {
		nni_pollable_clear(&s->readable);
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
	if (ctx->send_aio == aio) {
		// There should not be a pending reply, because we canceled
		// it while we were waiting.
		NNI_ASSERT(ctx->recv_aio == NULL);
		ctx->send_aio = NULL;
		// Restore the message back to the aio.
		nni_aio_set_msg(aio, ctx->req_msg);
		nni_msg_header_clear(ctx->req_msg);
		ctx->req_msg = NULL;

		// Cancellation of a pending receive is treated as aborting the
		// entire state machine.  This allows us to preserve the
		// semantic of exactly one receive operation per send
		// operation, and should be the least surprising for users. The
		// main consequence is that if a receive operation is completed
		// (in error or otherwise), the user must submit a new send
		// operation to restart the state machine.
		req0_ctx_reset(ctx);

		nni_aio_finish_error(aio, rv);
	}
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
	if (ctx->recv_aio != NULL) {
		nni_aio_finish_error(ctx->recv_aio, NNG_ECANCELED);
		ctx->recv_aio = NULL;
	}
	if (ctx->send_aio != NULL) {
		nni_aio_set_msg(ctx->send_aio, ctx->req_msg);
		nni_msg_header_clear(ctx->req_msg);
		ctx->req_msg = NULL;
		nni_aio_finish_error(ctx->send_aio, NNG_ECANCELED);
		ctx->send_aio = NULL;
		nni_list_remove(&s->send_queue, ctx);
	}

	// This resets the entire state machine.
	req0_ctx_reset(ctx);

	// Insert us on the per ID hash list, so that receives can find us.
	if ((rv = nni_idhash_alloc(s->requests, &id, ctx)) != 0) {
		nni_mtx_unlock(&s->mtx);
		nni_aio_finish_error(aio, rv);
		return;
	}
	ctx->request_id = (uint32_t) id;
	nni_msg_header_clear(msg);
	nni_msg_header_append_u32(msg, ctx->request_id);

	// If no pipes are ready, and the request was a poll (no background
	// schedule), then fail it.  Should be NNG_ETIMEDOUT.
	rv = nni_aio_schedule(aio, req0_ctx_cancel_send, ctx);
	if ((rv != 0) && (nni_list_empty(&s->ready_pipes))) {
		nni_idhash_remove(s->requests, id);
		nni_mtx_unlock(&s->mtx);
		nni_aio_finish_error(aio, rv);
		return;
	}
	ctx->req_len  = nni_msg_len(msg);
	ctx->req_msg  = msg;
	ctx->send_aio = aio;
	nni_aio_set_msg(aio, NULL);

	// Stick us on the send_queue list.
	nni_list_append(&s->send_queue, ctx);

	req0_run_send_queue(s, NULL);
	nni_mtx_unlock(&s->mtx);
}

static void
req0_sock_send(void *arg, nni_aio *aio)
{
	req0_sock *s = arg;
	req0_ctx_send(&s->master, aio);
}

static void
req0_sock_recv(void *arg, nni_aio *aio)
{
	req0_sock *s = arg;
	req0_ctx_recv(&s->master, aio);
}

static int
req0_sock_set_max_ttl(void *arg, const void *buf, size_t sz, nni_opt_type t)
{
	req0_sock *s = arg;
	int        ttl;
	int        rv;
	if ((rv = nni_copyin_int(&ttl, buf, sz, 1, NNI_MAX_MAX_TTL, t)) == 0) {
		nni_atomic_set(&s->ttl, ttl);
	}
	return (rv);
}

static int
req0_sock_get_max_ttl(void *arg, void *buf, size_t *szp, nni_opt_type t)
{
	req0_sock *s = arg;
	return (nni_copyout_int(nni_atomic_get(&s->ttl), buf, szp, t));
}

static int
req0_sock_set_resend_time(
    void *arg, const void *buf, size_t sz, nni_opt_type t)
{
	req0_sock *s = arg;
	int        rv;
	rv       = req0_ctx_set_resend_time(&s->master, buf, sz, t);
	s->retry = s->master.retry;
	return (rv);
}

static int
req0_sock_get_resend_time(void *arg, void *buf, size_t *szp, nni_opt_type t)
{
	req0_sock *s = arg;
	return (req0_ctx_get_resend_time(&s->master, buf, szp, t));
}

static int
req0_sock_get_send_fd(void *arg, void *buf, size_t *szp, nni_opt_type t)
{
	req0_sock *s = arg;
	int        rv;
	int        fd;

	if ((rv = nni_pollable_getfd(&s->writable, &fd)) != 0) {
		return (rv);
	}
	return (nni_copyout_int(fd, buf, szp, t));
}

static int
req0_sock_get_recv_fd(void *arg, void *buf, size_t *szp, nni_opt_type t)
{
	req0_sock *s = arg;
	int        rv;
	int        fd;

	if ((rv = nni_pollable_getfd(&s->readable, &fd)) != 0) {
		return (rv);
	}

	return (nni_copyout_int(fd, buf, szp, t));
}

static nni_proto_pipe_ops req0_pipe_ops = {
	.pipe_size  = sizeof(req0_pipe),
	.pipe_init  = req0_pipe_init,
	.pipe_fini  = req0_pipe_fini,
	.pipe_start = req0_pipe_start,
	.pipe_close = req0_pipe_close,
	.pipe_stop  = req0_pipe_stop,
};

static nni_option req0_ctx_options[] = {
	{
	    .o_name = NNG_OPT_REQ_RESENDTIME,
	    .o_get  = req0_ctx_get_resend_time,
	    .o_set  = req0_ctx_set_resend_time,
	},
	{
	    .o_name = NULL,
	},
};

static nni_proto_ctx_ops req0_ctx_ops = {
	.ctx_size    = sizeof(req0_ctx),
	.ctx_init    = req0_ctx_init,
	.ctx_fini    = req0_ctx_fini,
	.ctx_recv    = req0_ctx_recv,
	.ctx_send    = req0_ctx_send,
	.ctx_options = req0_ctx_options,
};

static nni_option req0_sock_options[] = {
	{
	    .o_name = NNG_OPT_MAXTTL,
	    .o_get  = req0_sock_get_max_ttl,
	    .o_set  = req0_sock_set_max_ttl,
	},
	{
	    .o_name = NNG_OPT_REQ_RESENDTIME,
	    .o_get  = req0_sock_get_resend_time,
	    .o_set  = req0_sock_set_resend_time,
	},
	{
	    .o_name = NNG_OPT_RECVFD,
	    .o_get  = req0_sock_get_recv_fd,
	},
	{
	    .o_name = NNG_OPT_SENDFD,
	    .o_get  = req0_sock_get_send_fd,
	},
	// terminate list
	{
	    .o_name = NULL,
	},
};

static nni_proto_sock_ops req0_sock_ops = {
	.sock_size    = sizeof(req0_sock),
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
	.proto_self     = { NNG_REQ0_SELF, NNG_REQ0_SELF_NAME },
	.proto_peer     = { NNG_REQ0_PEER, NNG_REQ0_PEER_NAME },
	.proto_flags    = NNI_PROTO_FLAG_SNDRCV | NNI_PROTO_FLAG_NOMSGQ,
	.proto_sock_ops = &req0_sock_ops,
	.proto_pipe_ops = &req0_pipe_ops,
	.proto_ctx_ops  = &req0_ctx_ops,
};

int
nng_req0_open(nng_socket *sock)
{
	return (nni_proto_open(sock, &req0_proto));
}
