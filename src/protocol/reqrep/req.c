//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
// Copyright 2017 Capitar IT Group BV <info@capitar.com>
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

// Request protocol.  The REQ protocol is the "request" side of a
// request-reply pair.  This is useful for building RPC clients, for
// example.

typedef struct req_pipe req_pipe;
typedef struct req_sock req_sock;

static void req_resend(req_sock *);
static void req_timeout(void *);
static void req_pipe_fini(void *);

// A req_sock is our per-socket protocol private structure.
struct req_sock {
	nni_sock *   sock;
	nni_msgq *   uwq;
	nni_msgq *   urq;
	nni_duration retry;
	nni_time     resend;
	int          raw;
	int          wantw;
	int          closed;
	int          ttl;
	nni_msg *    reqmsg;

	req_pipe *pendpipe;

	nni_list readypipes;
	nni_list busypipes;

	nni_timer_node timer;

	uint32_t nextid;   // next id
	uint8_t  reqid[4]; // outstanding request ID (big endian)
	nni_mtx  mtx;
	nni_cv   cv;
};

// A req_pipe is our per-pipe protocol private structure.
struct req_pipe {
	nni_pipe *    pipe;
	req_sock *    req;
	nni_list_node node;
	nni_aio *     aio_getq;       // raw mode only
	nni_aio *     aio_sendraw;    // raw mode only
	nni_aio *     aio_sendcooked; // cooked mode only
	nni_aio *     aio_recv;
	nni_aio *     aio_putq;
	nni_mtx       mtx;
};

static void req_resender(void *);
static void req_getq_cb(void *);
static void req_sendraw_cb(void *);
static void req_sendcooked_cb(void *);
static void req_recv_cb(void *);
static void req_putq_cb(void *);

static int
req_sock_init(void **sp, nni_sock *sock)
{
	req_sock *s;

	if ((s = NNI_ALLOC_STRUCT(s)) == NULL) {
		return (NNG_ENOMEM);
	}
	nni_mtx_init(&s->mtx);
	nni_cv_init(&s->cv, &s->mtx);

	NNI_LIST_INIT(&s->readypipes, req_pipe, node);
	NNI_LIST_INIT(&s->busypipes, req_pipe, node);
	nni_timer_init(&s->timer, req_timeout, s);

	// this is "semi random" start for request IDs.
	s->nextid = nni_random();
	s->retry  = NNI_SECOND * 60;
	s->sock   = sock;
	s->reqmsg = NULL;
	s->raw    = 0;
	s->wantw  = 0;
	s->resend = NNI_TIME_ZERO;
	s->ttl    = 8;
	s->uwq    = nni_sock_sendq(sock);
	s->urq    = nni_sock_recvq(sock);
	*sp       = s;
	nni_sock_recverr(sock, NNG_ESTATE);
	return (0);
}

static void
req_sock_open(void *arg)
{
	NNI_ARG_UNUSED(arg);
}

static void
req_sock_close(void *arg)
{
	req_sock *s = arg;

	nni_mtx_lock(&s->mtx);
	s->closed = 1;
	nni_mtx_unlock(&s->mtx);

	nni_timer_cancel(&s->timer);
}

static void
req_sock_fini(void *arg)
{
	req_sock *s = arg;

	nni_mtx_lock(&s->mtx);
	while ((!nni_list_empty(&s->readypipes)) ||
	    (!nni_list_empty(&s->busypipes))) {
		nni_cv_wait(&s->cv);
	}
	if (s->reqmsg != NULL) {
		nni_msg_free(s->reqmsg);
	}
	nni_mtx_unlock(&s->mtx);
	nni_cv_fini(&s->cv);
	nni_mtx_fini(&s->mtx);
	NNI_FREE_STRUCT(s);
}

static void
req_pipe_fini(void *arg)
{
	req_pipe *p = arg;

	nni_aio_fini(p->aio_getq);
	nni_aio_fini(p->aio_putq);
	nni_aio_fini(p->aio_recv);
	nni_aio_fini(p->aio_sendcooked);
	nni_aio_fini(p->aio_sendraw);
	nni_mtx_fini(&p->mtx);
	NNI_FREE_STRUCT(p);
}

static int
req_pipe_init(void **pp, nni_pipe *pipe, void *s)
{
	req_pipe *p;
	int       rv;

	if ((p = NNI_ALLOC_STRUCT(p)) == NULL) {
		return (NNG_ENOMEM);
	}
	nni_mtx_init(&p->mtx);
	if (((rv = nni_aio_init(&p->aio_getq, req_getq_cb, p)) != 0) ||
	    ((rv = nni_aio_init(&p->aio_putq, req_putq_cb, p)) != 0) ||
	    ((rv = nni_aio_init(&p->aio_recv, req_recv_cb, p)) != 0) ||
	    ((rv = nni_aio_init(&p->aio_sendraw, req_sendraw_cb, p)) != 0) ||
	    ((rv = nni_aio_init(&p->aio_sendcooked, req_sendcooked_cb, p)) !=
	        0)) {
		req_pipe_fini(p);
		return (rv);
	}

	NNI_LIST_NODE_INIT(&p->node);
	p->pipe = pipe;
	p->req  = s;
	*pp     = p;
	return (0);
}

static int
req_pipe_start(void *arg)
{
	req_pipe *p = arg;
	req_sock *s = p->req;

	if (nni_pipe_peer(p->pipe) != NNG_PROTO_REP) {
		return (NNG_EPROTO);
	}

	nni_mtx_lock(&s->mtx);
	if (s->closed) {
		nni_mtx_unlock(&s->mtx);
		return (NNG_ECLOSED);
	}
	nni_list_append(&s->readypipes, p);
	// If sock was waiting for somewhere to send data, go ahead and
	// send it to this pipe.
	if (s->wantw) {
		req_resend(s);
	}
	nni_mtx_unlock(&s->mtx);

	nni_msgq_aio_get(s->uwq, p->aio_getq);
	nni_pipe_recv(p->pipe, p->aio_recv);
	return (0);
}

static void
req_pipe_stop(void *arg)
{
	req_pipe *p = arg;
	req_sock *s = p->req;

	nni_aio_stop(p->aio_getq);
	nni_aio_stop(p->aio_putq);
	nni_aio_stop(p->aio_recv);
	nni_aio_stop(p->aio_sendcooked);
	nni_aio_stop(p->aio_sendraw);

	// At this point there should not be any further AIOs running.
	// Further, any completion tasks have completed.

	nni_mtx_lock(&s->mtx);
	// This removes the node from either busypipes or readypipes.
	// It doesn't much matter which.
	if (nni_list_node_active(&p->node)) {
		nni_list_node_remove(&p->node);
		if (s->closed) {
			nni_cv_wake(&s->cv);
		}
	}

	if ((p == s->pendpipe) && (s->reqmsg != NULL)) {
		// removing the pipe we sent the last request on...
		// schedule immediate resend.
		s->pendpipe = NULL;
		s->resend   = NNI_TIME_ZERO;
		s->wantw    = 1;
		req_resend(s);
	}
	nni_mtx_unlock(&s->mtx);
}

static int
req_sock_setopt(void *arg, int opt, const void *buf, size_t sz)
{
	req_sock *s  = arg;
	int       rv = NNG_ENOTSUP;

	if (opt == nng_optid_req_resendtime) {
		rv = nni_setopt_usec(&s->retry, buf, sz);

	} else if (opt == nng_optid_raw) {
		rv = nni_setopt_int(&s->raw, buf, sz, 0, 1);
		if (rv == 0) {
			nni_sock_recverr(s->sock, s->raw ? 0 : NNG_ESTATE);
		}

	} else if (opt == nng_optid_maxttl) {
		rv = nni_setopt_int(&s->ttl, buf, sz, 1, 255);
	}

	return (rv);
}

static int
req_sock_getopt(void *arg, int opt, void *buf, size_t *szp)
{
	req_sock *s  = arg;
	int       rv = NNG_ENOTSUP;

	if (opt == nng_optid_req_resendtime) {
		rv = nni_getopt_usec(&s->retry, buf, szp);

	} else if (opt == nng_optid_raw) {
		rv = nni_getopt_int(&s->raw, buf, szp);

	} else if (opt == nng_optid_maxttl) {
		rv = nni_getopt_int(&s->ttl, buf, szp);
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
req_getq_cb(void *arg)
{
	req_pipe *p = arg;
	req_sock *s = p->req;

	// We should be in RAW mode.  Cooked mode traffic bypasses
	// the upper write queue entirely, and should never end up here.
	// If the mode changes, we may briefly deliver a message, but
	// that's ok (there's an inherent race anyway).  (One minor
	// exception: we wind up here in error state when the uwq is closed.)

	if (nni_aio_result(p->aio_getq) != 0) {
		nni_pipe_stop(p->pipe);
		return;
	}

	nni_aio_set_msg(p->aio_sendraw, nni_aio_get_msg(p->aio_getq));
	nni_aio_set_msg(p->aio_getq, NULL);

	// Send the message, but use the raw mode aio.
	nni_pipe_send(p->pipe, p->aio_sendraw);
}

static void
req_sendraw_cb(void *arg)
{
	req_pipe *p = arg;

	if (nni_aio_result(p->aio_sendraw) != 0) {
		nni_msg_free(nni_aio_get_msg(p->aio_sendraw));
		nni_aio_set_msg(p->aio_sendraw, NULL);
		nni_pipe_stop(p->pipe);
		return;
	}

	// Sent a message so we just need to look for another one.
	nni_msgq_aio_get(p->req->uwq, p->aio_getq);
}

static void
req_sendcooked_cb(void *arg)
{
	req_pipe *p = arg;
	req_sock *s = p->req;

	if (nni_aio_result(p->aio_sendcooked) != 0) {
		// We failed to send... clean up and deal with it.
		// We leave ourselves on the busy list for now, which
		// means no new asynchronous traffic can occur here.
		nni_msg_free(nni_aio_get_msg(p->aio_sendcooked));
		nni_aio_set_msg(p->aio_sendcooked, NULL);
		nni_pipe_stop(p->pipe);
		return;
	}

	// Cooked mode.  We completed a cooked send, so we need to
	// reinsert ourselves in the ready list, and possibly schedule
	// a resend.

	nni_mtx_lock(&s->mtx);
	if (nni_list_active(&s->busypipes, p)) {
		nni_list_remove(&s->busypipes, p);
		nni_list_append(&s->readypipes, p);
		req_resend(s);
	} else {
		// We wind up here if stop was called from the reader
		// side while we were waiting to be scheduled to run for the
		// writer side.  In this case we can't complete the operation,
		// and we have to abort.
		nni_pipe_stop(p->pipe);
	}
	nni_mtx_unlock(&s->mtx);
}

static void
req_putq_cb(void *arg)
{
	req_pipe *p = arg;

	if (nni_aio_result(p->aio_putq) != 0) {
		nni_msg_free(nni_aio_get_msg(p->aio_putq));
		nni_aio_set_msg(p->aio_putq, NULL);
		nni_pipe_stop(p->pipe);
		return;
	}
	nni_aio_set_msg(p->aio_putq, NULL);

	nni_pipe_recv(p->pipe, p->aio_recv);
}

static void
req_recv_cb(void *arg)
{
	req_pipe *p = arg;
	nni_msg * msg;

	if (nni_aio_result(p->aio_recv) != 0) {
		nni_pipe_stop(p->pipe);
		return;
	}

	msg = nni_aio_get_msg(p->aio_recv);
	nni_aio_set_msg(p->aio_recv, NULL);

	// We yank 4 bytes of body, and move them to the header.
	if (nni_msg_len(msg) < 4) {
		// Malformed message.
		goto malformed;
	}
	if (nni_msg_header_append(msg, nni_msg_body(msg), 4) != 0) {
		// Arguably we could just discard and carry on.  But
		// dropping the connection is probably more helpful since
		// it lets the other side see that a problem occurred.
		// Plus it gives us a chance to reclaim some memory.
		goto malformed;
	}
	(void) nni_msg_trim(msg, 4); // Cannot fail

	nni_aio_set_msg(p->aio_putq, msg);
	nni_msgq_aio_put(p->req->urq, p->aio_putq);
	return;

malformed:
	nni_msg_free(msg);
	nni_pipe_stop(p->pipe);
}

static void
req_timeout(void *arg)
{
	req_sock *s = arg;

	nni_mtx_lock(&s->mtx);
	if (s->reqmsg != NULL) {
		s->wantw = 1;
		req_resend(s);
	}
	nni_mtx_unlock(&s->mtx);
}

static void
req_resend(req_sock *s)
{
	req_pipe *p;
	nni_msg * msg;

	// Note: This routine should be called with the socket lock held.
	// Also, this should only be called while handling cooked mode
	// requests.
	if ((msg = s->reqmsg) == NULL) {
		return;
	}

	if (s->closed) {
		s->reqmsg = NULL;
		nni_msg_free(msg);
	}

	if (s->wantw) {
		s->wantw = 0;

		if (nni_msg_dup(&msg, s->reqmsg) != 0) {
			// Failed to alloc message, reschedule it. Also,
			// mark that we have a message we want to resend,
			// in case something comes available.
			s->wantw = 1;
			nni_timer_schedule(&s->timer, nni_clock() + s->retry);
			return;
		}

		// Now we iterate across all possible outpipes, until
		// one accepts it.
		if ((p = nni_list_first(&s->readypipes)) == NULL) {
			// No pipes ready to process us.  Note that we have
			// something to send, and schedule it.
			nni_msg_free(msg);
			s->wantw = 1;
			return;
		}

		nni_list_remove(&s->readypipes, p);
		nni_list_append(&s->busypipes, p);

		s->pendpipe = p;
		s->resend   = nni_clock() + s->retry;
		nni_aio_set_msg(p->aio_sendcooked, msg);

		// Note that because we were ready rather than busy, we
		// should not have any I/O oustanding and hence the aio
		// object will be available for our use.
		nni_pipe_send(p->pipe, p->aio_sendcooked);
		nni_timer_schedule(&s->timer, s->resend);
	}
}

static nni_msg *
req_sock_sfilter(void *arg, nni_msg *msg)
{
	req_sock *s = arg;
	uint32_t  id;

	if (s->raw) {
		// No automatic retry, and the request ID must
		// be in the header coming down.
		return (msg);
	}

	// Generate a new request ID.  We always set the high
	// order bit so that the peer can locate the end of the
	// backtrace.  (Pipe IDs have the high order bit clear.)
	id = (s->nextid++) | 0x80000000u;

	// Request ID is in big endian format.
	NNI_PUT32(s->reqid, id);

	if (nni_msg_header_append(msg, s->reqid, 4) != 0) {
		// Should be ENOMEM.
		nni_msg_free(msg);
		return (NULL);
	}

	// NB: The socket lock is also held, so this is always self-serialized.
	// But we have to serialize against other async callbacks.
	nni_mtx_lock(&s->mtx);

	// If another message is there, this cancels it.
	if (s->reqmsg != NULL) {
		nni_msg_free(s->reqmsg);
		s->reqmsg = NULL;
	}

	// Make a duplicate message... for retries.
	s->reqmsg = msg;
	// Schedule for immediate send
	s->resend = NNI_TIME_ZERO;
	s->wantw  = 1;

	req_resend(s);
	nni_mtx_unlock(&s->mtx);

	// Clear the error condition.
	nni_sock_recverr(s->sock, 0);

	return (NULL);
}

static nni_msg *
req_sock_rfilter(void *arg, nni_msg *msg)
{
	req_sock *s = arg;
	nni_msg * rmsg;

	if (s->raw) {
		// Pass it unmolested
		return (msg);
	}

	if (nni_msg_header_len(msg) < 4) {
		nni_msg_free(msg);
		return (NULL);
	}

	nni_mtx_lock(&s->mtx);

	if ((rmsg = s->reqmsg) == NULL) {
		// We had no outstanding request.
		nni_mtx_unlock(&s->mtx);
		nni_msg_free(msg);
		return (NULL);
	}
	if (memcmp(nni_msg_header(msg), s->reqid, 4) != 0) {
		// Wrong request id
		nni_mtx_unlock(&s->mtx);
		nni_msg_free(msg);
		return (NULL);
	}

	s->reqmsg   = NULL;
	s->pendpipe = NULL;
	nni_mtx_unlock(&s->mtx);

	nni_sock_recverr(s->sock, NNG_ESTATE);
	nni_msg_free(rmsg);

	return (msg);
}

static nni_proto_pipe_ops req_pipe_ops = {
	.pipe_init  = req_pipe_init,
	.pipe_fini  = req_pipe_fini,
	.pipe_start = req_pipe_start,
	.pipe_stop  = req_pipe_stop,
};

static nni_proto_sock_ops req_sock_ops = {
	.sock_init    = req_sock_init,
	.sock_fini    = req_sock_fini,
	.sock_open    = req_sock_open,
	.sock_close   = req_sock_close,
	.sock_setopt  = req_sock_setopt,
	.sock_getopt  = req_sock_getopt,
	.sock_rfilter = req_sock_rfilter,
	.sock_sfilter = req_sock_sfilter,
};

static nni_proto req_proto = {
	.proto_version  = NNI_PROTOCOL_VERSION,
	.proto_self     = { NNG_PROTO_REQ_V0, "req" },
	.proto_peer     = { NNG_PROTO_REP_V0, "rep" },
	.proto_flags    = NNI_PROTO_FLAG_SNDRCV,
	.proto_sock_ops = &req_sock_ops,
	.proto_pipe_ops = &req_pipe_ops,
};

int
nng_req0_open(nng_socket *sidp)
{
	return (nni_proto_open(sidp, &req_proto));
}
