//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "core/nng_impl.h"

// Request protocol.  The REQ protocol is the "request" side of a
// request-reply pair.  This is useful for building RPC clients, for
// example.

typedef struct nni_req_pipe	nni_req_pipe;
typedef struct nni_req_sock	nni_req_sock;

static void nni_req_resend(nni_req_sock *);
static void nni_req_timeout(void *);
static void nni_req_pipe_fini(void *);

// An nni_req_sock is our per-socket protocol private structure.
struct nni_req_sock {
	nni_sock *	sock;
	nni_msgq *	uwq;
	nni_msgq *	urq;
	nni_duration	retry;
	nni_time	resend;
	int		raw;
	int		wantw;
	nni_msg *	reqmsg;

	nni_req_pipe *	pendpipe;

	nni_list	readypipes;
	nni_list	busypipes;

	nni_timer_node	timer;

	uint32_t	nextid;         // next id
	uint8_t		reqid[4];       // outstanding request ID (big endian)
	nni_mtx		mtx;
};

// An nni_req_pipe is our per-pipe protocol private structure.
struct nni_req_pipe {
	nni_pipe *	pipe;
	nni_req_sock *	req;
	nni_list_node	node;
	nni_aio		aio_getq;               // raw mode only
	nni_aio		aio_sendraw;            // raw mode only
	nni_aio		aio_sendcooked;         // cooked mode only
	nni_aio		aio_recv;
	nni_aio		aio_putq;
	nni_mtx		mtx;
};

static void nni_req_resender(void *);
static void nni_req_getq_cb(void *);
static void nni_req_sendraw_cb(void *);
static void nni_req_sendcooked_cb(void *);
static void nni_req_recv_cb(void *);
static void nni_req_putq_cb(void *);

static int
nni_req_sock_init(void **reqp, nni_sock *sock)
{
	nni_req_sock *req;
	int rv;

	if ((req = NNI_ALLOC_STRUCT(req)) == NULL) {
		return (NNG_ENOMEM);
	}
	if ((rv = nni_mtx_init(&req->mtx)) != 0) {
		NNI_FREE_STRUCT(req);
		return (rv);
	}

	NNI_LIST_INIT(&req->readypipes, nni_req_pipe, node);
	NNI_LIST_INIT(&req->busypipes, nni_req_pipe, node);
	nni_timer_init(&req->timer, nni_req_timeout, req);

	// this is "semi random" start for request IDs.
	req->nextid = nni_random();

	req->retry = NNI_SECOND * 60;
	req->sock = sock;
	req->reqmsg = NULL;
	req->raw = 0;
	req->wantw = 0;
	req->resend = NNI_TIME_ZERO;

	req->uwq = nni_sock_sendq(sock);
	req->urq = nni_sock_recvq(sock);
	*reqp = req;
	nni_sock_recverr(sock, NNG_ESTATE);
	return (0);
}


static void
nni_req_sock_close(void *arg)
{
	nni_req_sock *req = arg;

	nni_timer_cancel(&req->timer);
}


static void
nni_req_sock_fini(void *arg)
{
	nni_req_sock *req = arg;

	nni_mtx_lock(&req->mtx);
	if (req->reqmsg != NULL) {
		nni_msg_free(req->reqmsg);
	}
	nni_mtx_unlock(&req->mtx);
	nni_mtx_fini(&req->mtx);
	NNI_FREE_STRUCT(req);
}


static int
nni_req_pipe_init(void **rpp, nni_pipe *pipe, void *rsock)
{
	nni_req_pipe *rp;
	int rv;

	if ((rp = NNI_ALLOC_STRUCT(rp)) == NULL) {
		return (NNG_ENOMEM);
	}
	if ((rv = nni_mtx_init(&rp->mtx)) != 0) {
		goto failed;
	}
	if ((rv = nni_aio_init(&rp->aio_getq, nni_req_getq_cb, rp)) != 0) {
		goto failed;
	}
	if ((rv = nni_aio_init(&rp->aio_putq, nni_req_putq_cb, rp)) != 0) {
		goto failed;
	}
	if ((rv = nni_aio_init(&rp->aio_recv, nni_req_recv_cb, rp)) != 0) {
		goto failed;
	}
	rv = nni_aio_init(&rp->aio_sendraw, nni_req_sendraw_cb, rp);
	if (rv != 0) {
		goto failed;
	}
	rv = nni_aio_init(&rp->aio_sendcooked, nni_req_sendcooked_cb, rp);
	if (rv != 0) {
		goto failed;
	}

	NNI_LIST_NODE_INIT(&rp->node);
	rp->pipe = pipe;
	rp->req = rsock;
	*rpp = rp;
	return (0);

failed:
	nni_req_pipe_fini(rp);
	return (rv);
}


static void
nni_req_pipe_fini(void *arg)
{
	nni_req_pipe *rp = arg;

	if (rp != NULL) {
		nni_aio_fini(&rp->aio_getq);
		nni_aio_fini(&rp->aio_putq);
		nni_aio_fini(&rp->aio_recv);
		nni_aio_fini(&rp->aio_sendcooked);
		nni_aio_fini(&rp->aio_sendraw);
		nni_mtx_fini(&rp->mtx);
		NNI_FREE_STRUCT(rp);
	}
}


static int
nni_req_pipe_start(void *arg)
{
	nni_req_pipe *rp = arg;
	nni_req_sock *req = rp->req;

	if (nni_pipe_peer(rp->pipe) != NNG_PROTO_REP) {
		return (NNG_EPROTO);
	}

	nni_mtx_lock(&req->mtx);
	nni_list_append(&req->readypipes, rp);
	if (req->wantw) {
		nni_req_resend(req);
	}
	nni_mtx_unlock(&req->mtx);


	nni_msgq_aio_get(req->uwq, &rp->aio_getq);
	nni_pipe_aio_recv(rp->pipe, &rp->aio_recv);
	return (0);
}


static void
nni_req_pipe_stop(void *arg)
{
	nni_req_pipe *rp = arg;
	nni_req_sock *req = rp->req;

	nni_aio_stop(&rp->aio_getq);
	nni_aio_stop(&rp->aio_putq);
	nni_aio_stop(&rp->aio_recv);
	nni_aio_stop(&rp->aio_sendcooked);
	nni_aio_stop(&rp->aio_sendraw);

	// At this point there should not be any further AIOs running.
	// Further, any completion tasks have completed.

	nni_mtx_lock(&req->mtx);
	// This removes the node from either busypipes or readypipes.
	// It doesn't much matter which.
	if (nni_list_active(&req->readypipes, rp)) {
		nni_list_remove(&req->readypipes, rp);
	}

	if ((rp == req->pendpipe) && (req->reqmsg != NULL)) {
		// removing the pipe we sent the last request on...
		// schedule immediate resend.
		req->pendpipe = NULL;
		req->resend = NNI_TIME_ZERO;
		req->wantw = 1;
		nni_req_resend(req);
	}
	nni_mtx_unlock(&req->mtx);
}


static int
nni_req_sock_setopt(void *arg, int opt, const void *buf, size_t sz)
{
	nni_req_sock *req = arg;
	int rv;

	switch (opt) {
	case NNG_OPT_RESENDTIME:
		rv = nni_setopt_duration(&req->retry, buf, sz);
		break;
	case NNG_OPT_RAW:
		rv = nni_setopt_int(&req->raw, buf, sz, 0, 1);
		break;
	default:
		rv = NNG_ENOTSUP;
	}
	return (rv);
}


static int
nni_req_sock_getopt(void *arg, int opt, void *buf, size_t *szp)
{
	nni_req_sock *req = arg;
	int rv;

	switch (opt) {
	case NNG_OPT_RESENDTIME:
		rv = nni_getopt_duration(&req->retry, buf, szp);
		break;
	case NNG_OPT_RAW:
		rv = nni_getopt_int(&req->raw, buf, szp);
		break;
	default:
		rv = NNG_ENOTSUP;
	}
	return (rv);
}


// Raw and cooked mode differ in the way they send messages out.
//
// For cooked mdes, we have a getq callback on the upper write queue, which
// when it finds a message, cancels any current processing, and saves a copy
// of the message, and then tries to "resend" the message, looking for a
// suitable available outgoing pipe.  If no suitable pipe is available,
// a flag is set, so that as soon as such a pipe is available we trigger
// a resend attempt.  We also trigger the attempt on either timeout, or if
// the underlying pipe we chose disconnects.
//
// For raw mode we can just let the pipes "contend" via getq to get a
// message from the upper write queue.  The msgqueue implementation
// actually provides ordering, so load will be spread automatically.
// (NB: We may have to revise this in the future if we want to provide some
// kind of priority.)

static void
nni_req_getq_cb(void *arg)
{
	nni_req_pipe *rp = arg;
	nni_req_sock *req = rp->req;

	// We should be in RAW mode.  Cooked mode traffic bypasses
	// the upper write queue entirely, and should never end up here.
	// If the mode changes, we may briefly deliver a message, but
	// that's ok (there's an inherent race anyway).  (One minor
	// exception: we wind up here in error state when the uwq is closed.)

	if (nni_aio_result(&rp->aio_getq) != 0) {
		nni_pipe_stop(rp->pipe);
		return;
	}

	rp->aio_sendraw.a_msg = rp->aio_getq.a_msg;
	rp->aio_getq.a_msg = NULL;

	// Send the message, but use the raw mode aio.
	nni_pipe_aio_send(rp->pipe, &rp->aio_sendraw);
}


static void
nni_req_sendraw_cb(void *arg)
{
	nni_req_pipe *rp = arg;
	nni_msg *msg;

	if (nni_aio_result(&rp->aio_sendraw) != 0) {
		nni_msg_free(rp->aio_sendraw.a_msg);
		rp->aio_sendraw.a_msg = NULL;
		nni_pipe_stop(rp->pipe);
		return;
	}

	// Sent a message so we just need to look for another one.
	nni_msgq_aio_get(rp->req->uwq, &rp->aio_getq);
}


static void
nni_req_sendcooked_cb(void *arg)
{
	nni_req_pipe *rp = arg;
	nni_req_sock *req = rp->req;

	if (nni_aio_result(&rp->aio_sendcooked) != 0) {
		// We failed to send... clean up and deal with it.
		// We leave ourselves on the busy list for now, which
		// means no new asynchronous traffic can occur here.
		nni_msg_free(rp->aio_sendcooked.a_msg);
		rp->aio_sendcooked.a_msg = NULL;
		nni_pipe_stop(rp->pipe);
		return;
	}

	// Cooked mode.  We completed a cooked send, so we need to
	// reinsert ourselves in the ready list, and possibly schedule
	// a resend.

	nni_mtx_lock(&req->mtx);
	if (nni_list_active(&req->busypipes, rp)) {
		nni_list_remove(&req->busypipes, rp);
		nni_list_append(&req->readypipes, rp);
		nni_req_resend(req);
	} else {
		// We wind up here if stop was called from the reader
		// side while we were waiting to be scheduled to run for the
		// writer side.  In this case we can't complete the operation,
		// and we have to abort.
		nni_pipe_stop(rp->pipe);
	}
	nni_mtx_unlock(&req->mtx);
}


static void
nni_req_putq_cb(void *arg)
{
	nni_req_pipe *rp = arg;

	if (nni_aio_result(&rp->aio_putq) != 0) {
		nni_msg_free(rp->aio_putq.a_msg);
		nni_pipe_stop(rp->pipe);
		return;
	}
	rp->aio_putq.a_msg = NULL;

	nni_pipe_aio_recv(rp->pipe, &rp->aio_recv);
}


static void
nni_req_recv_cb(void *arg)
{
	nni_req_pipe *rp = arg;
	nni_msg *msg;

	if (nni_aio_result(&rp->aio_recv) != 0) {
		nni_pipe_stop(rp->pipe);
		return;
	}

	msg = rp->aio_recv.a_msg;
	rp->aio_recv.a_msg = NULL;

	// We yank 4 bytes of body, and move them to the header.
	if (nni_msg_len(msg) < 4) {
		// Malformed message.
		goto malformed;
	}
	if (nni_msg_append_header(msg, nni_msg_body(msg), 4) != 0) {
		// Arguably we could just discard and carry on.  But
		// dropping the connection is probably more helpful since
		// it lets the other side see that a problem occurred.
		// Plus it gives us a chance to reclaim some memory.
		goto malformed;
	}
	if (nni_msg_trim(msg, 4) != 0) {
		// This should never happen - could be an assert.
		nni_panic("Failed to trim REQ header from body");
	}

	rp->aio_putq.a_msg = msg;
	nni_msgq_aio_put(rp->req->urq, &rp->aio_putq);
	return;

malformed:
	nni_msg_free(msg);
	nni_pipe_stop(rp->pipe);
}


static void
nni_req_timeout(void *arg)
{
	nni_req_sock *req = arg;

	nni_mtx_lock(&req->mtx);
	if (req->reqmsg != NULL) {
		req->wantw = 1;
		nni_req_resend(req);
	}
	nni_mtx_unlock(&req->mtx);
}


static void
nni_req_resend(nni_req_sock *req)
{
	nni_req_pipe *rp;
	nni_msg *msg;
	int i;

	// Note: This routine should be called with the socket lock held.
	// Also, this should only be called while handling cooked mode
	// requests.
	if (req->reqmsg == NULL) {
		return;
	}

	if (req->wantw) {
		req->wantw = 0;

		if (nni_msg_dup(&msg, req->reqmsg) != 0) {
			// Failed to alloc message, reschedule it. Also,
			// mark that we have a message we want to resend,
			// in case something comes available.
			req->wantw = 1;
			nni_timer_schedule(&req->timer,
			    nni_clock() + req->retry);
			return;
		}

		// Now we iterate across all possible outpipes, until
		// one accepts it.
		rp = nni_list_first(&req->readypipes);
		if (rp == NULL) {
			// No pipes ready to process us.  Note that we have
			// something to send, and schedule it.
			nni_msg_free(msg);
			req->wantw = 1;
			return;
		}

		nni_list_remove(&req->readypipes, rp);
		nni_list_append(&req->busypipes, rp);

		req->pendpipe = rp;
		req->resend = nni_clock() + req->retry;
		rp->aio_sendcooked.a_msg = msg;

		// Note that because we were ready rather than busy, we
		// should not have any I/O oustanding and hence the aio
		// object will be available for our use.
		nni_pipe_aio_send(rp->pipe, &rp->aio_sendcooked);
		nni_timer_schedule(&req->timer, req->resend);
	}
}


static nni_msg *
nni_req_sock_sfilter(void *arg, nni_msg *msg)
{
	nni_req_sock *req = arg;
	uint32_t id;

	if (req->raw) {
		// No automatic retry, and the request ID must
		// be in the header coming down.
		return (msg);
	}

	// Generate a new request ID.  We always set the high
	// order bit so that the peer can locate the end of the
	// backtrace.  (Pipe IDs have the high order bit clear.)
	id = (req->nextid++) | 0x80000000u;

	// Request ID is in big endian format.
	NNI_PUT32(req->reqid, id);

	if (nni_msg_append_header(msg, req->reqid, 4) != 0) {
		// Should be ENOMEM.
		nni_msg_free(msg);
		return (NULL);
	}

	// NB: The socket lock is also held, so this is always self-serialized.
	// But we have to serialize against other async callbacks.
	nni_mtx_lock(&req->mtx);

	// If another message is there, this cancels it.
	if (req->reqmsg != NULL) {
		nni_msg_free(req->reqmsg);
		req->reqmsg = NULL;
	}

	// Make a duplicate message... for retries.
	req->reqmsg = msg;
	// Schedule for immediate send
	req->resend = NNI_TIME_ZERO;
	req->wantw = 1;

	nni_req_resend(req);
	nni_mtx_unlock(&req->mtx);

	// Clear the error condition.
	nni_sock_recverr(req->sock, 0);

	return (NULL);
}


static nni_msg *
nni_req_sock_rfilter(void *arg, nni_msg *msg)
{
	nni_req_sock *req = arg;
	nni_msg *rmsg;

	if (req->raw) {
		// Pass it unmolested
		return (msg);
	}

	if (nni_msg_header_len(msg) < 4) {
		nni_msg_free(msg);
		return (NULL);
	}

	nni_mtx_lock(&req->mtx);

	if ((rmsg = req->reqmsg) == NULL) {
		// We had no outstanding request.
		nni_mtx_unlock(&req->mtx);
		nni_msg_free(msg);
		return (NULL);
	}
	if (memcmp(nni_msg_header(msg), req->reqid, 4) != 0) {
		// Wrong request id
		nni_mtx_unlock(&req->mtx);
		nni_msg_free(msg);
		return (NULL);
	}

	req->reqmsg = NULL;
	req->pendpipe = NULL;
	nni_mtx_unlock(&req->mtx);

	nni_sock_recverr(req->sock, NNG_ESTATE);
	nni_msg_free(rmsg);

	return (msg);
}


// This is the global protocol structure -- our linkage to the core.
// This should be the only global non-static symbol in this file.
static nni_proto_pipe_ops nni_req_pipe_ops = {
	.pipe_init	= nni_req_pipe_init,
	.pipe_fini	= nni_req_pipe_fini,
	.pipe_start	= nni_req_pipe_start,
	.pipe_stop	= nni_req_pipe_stop,
};

static nni_proto_sock_ops nni_req_sock_ops = {
	.sock_init	= nni_req_sock_init,
	.sock_fini	= nni_req_sock_fini,
	.sock_close	= nni_req_sock_close,
	.sock_setopt	= nni_req_sock_setopt,
	.sock_getopt	= nni_req_sock_getopt,
	.sock_rfilter	= nni_req_sock_rfilter,
	.sock_sfilter	= nni_req_sock_sfilter,
};

nni_proto nni_req_proto = {
	.proto_self	= NNG_PROTO_REQ,
	.proto_peer	= NNG_PROTO_REP,
	.proto_name	= "req",
	.proto_flags	= NNI_PROTO_FLAG_SNDRCV,
	.proto_sock_ops = &nni_req_sock_ops,
	.proto_pipe_ops = &nni_req_pipe_ops,
};
