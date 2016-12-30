//
// Copyright 2016 Garrett D'Amore <garrett@damore.org>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <stdlib.h>
#include <string.h>

#include "core/nng_impl.h"

// Request protocol.  The REQ protocol is the "request" side of a
// request-reply pair.  This is useful for bulding RPC clients, for
// example.

typedef struct nni_req_pipe	nni_req_pipe;
typedef struct nni_req_sock	nni_req_sock;

// An nni_req_sock is our per-socket protocol private structure.
struct nni_req_sock {
	nni_socket *	sock;
	nni_mutex	mx;
	nni_cond	cv;
	nni_msgqueue *	uwq;
	nni_msgqueue *	urq;
	nni_duration	retry;
	nni_time	resend;
	nni_thread *	resender;
	int		raw;
	nni_list	pipes;
	nni_msg *	reqmsg;
	uint32_t	nextid;         // next id
	uint8_t		reqid[4];       // outstanding request ID (big endian)
};

// An nni_req_pipe is our per-pipe protocol private structure.
struct nni_req_pipe {
	nni_pipe *	pipe;
	nni_req_sock *	req;
	int		good;
	nni_thread *	sthr;
	nni_thread *	rthr;
	int		sigclose;
	nni_list_node	node;
};

static void nni_req_receiver(void *);
static void nni_req_sender(void *);
static void nni_req_resender(void *);

static int
nni_req_create(void **reqp, nni_socket *sock)
{
	nni_req_sock *req;
	int rv;

	if ((req = nni_alloc(sizeof (*req))) == NULL) {
		return (NNG_ENOMEM);
	}
	if ((rv = nni_mutex_init(&req->mx)) != 0) {
		nni_free(req, sizeof (*req));
		return (rv);
	}
	if ((rv = nni_cond_init(&req->cv, &req->mx)) != 0) {
		nni_mutex_fini(&req->mx);
		nni_free(req, sizeof (*req));
		return (rv);
	}
	// this is "semi random" start for request IDs.
	req->nextid = (nni_clock() >> 32) ^ (nni_clock() & 0xffffffff);
	req->retry = NNI_SECOND * 60;
	req->sock = sock;
	req->reqmsg = NULL;
	req->raw = 0;
	req->resend = NNI_TIME_ZERO;
	NNI_LIST_INIT(&req->pipes, nni_req_pipe, node);

	req->uwq = nni_socket_sendq(sock);
	req->urq = nni_socket_recvq(sock);
	*reqp = req;
	nni_socket_recverr(sock, NNG_ESTATE);
	rv = nni_thread_create(&req->resender, nni_req_resender, req);
	if (rv != 0) {
		nni_cond_fini(&req->cv);
		nni_mutex_fini(&req->mx);
		nni_free(req, sizeof (*req));
		return (rv);
	}
	return (0);
}


static void
nni_req_destroy(void *arg)
{
	nni_req_sock *req = arg;
	nni_thread *resender;

	// Shut down the resender.  We request it to exit by clearing
	// its old value, then kick it.
	nni_mutex_enter(&req->mx);
	resender = req->resender;
	req->resender = NULL;
	nni_cond_broadcast(&req->cv);
	nni_mutex_exit(&req->mx);

	nni_thread_reap(resender);
	nni_cond_fini(&req->cv);
	nni_mutex_fini(&req->mx);
	nni_free(req, sizeof (*req));
}


static int
nni_req_add_pipe(void *arg, nni_pipe *pipe, void **datap)
{
	nni_req_sock *req = arg;
	nni_req_pipe *rp;
	int rv;

	if ((rp = nni_alloc(sizeof (*rp))) == NULL) {
		return (NNG_ENOMEM);
	}
	rp->pipe = pipe;
	rp->good = 0;
	rp->sigclose = 0;
	rp->sthr = NULL;
	rp->rthr = NULL;
	rp->req = req;

	nni_mutex_enter(&req->mx);
	if ((rv = nni_thread_create(&rp->rthr, nni_req_receiver, rp)) != 0) {
		goto fail;
	}
	if ((rv = nni_thread_create(&rp->sthr, nni_req_sender, rp)) != 0) {
		goto fail;
	}
	rp->good = 1;
	nni_list_append(&req->pipes, rp);
	*datap = rp;
	nni_mutex_exit(&req->mx);
	return (0);
fail:
	nni_mutex_exit(&req->mx);
	if (rp->rthr) {
		nni_thread_reap(rp->rthr);
	}
	if (rp->sthr) {
		nni_thread_reap(rp->sthr);
	}
	nni_free(rp, sizeof (*rp));
	return (rv);
}


static void
nni_req_rem_pipe(void *arg, void *data)
{
	nni_req_sock *req = arg;
	nni_req_pipe *rp = data;

	nni_mutex_enter(&req->mx);
	nni_list_remove(&req->pipes, rp);
	nni_mutex_exit(&req->mx);

	if (rp->sthr != NULL) {
		(void) nni_thread_reap(rp->sthr);
	}
	if (rp->rthr != NULL) {
		(void) nni_thread_reap(rp->rthr);
	}
}


static void
nni_req_sender(void *arg)
{
	nni_req_pipe *rp = arg;
	nni_req_sock *req = rp->req;
	nni_msgqueue *uwq = req->uwq;
	nni_msgqueue *urq = req->urq;
	nni_pipe *pipe = rp->pipe;
	nni_msg *msg;
	int rv;

	nni_mutex_enter(&req->mx);
	if (!rp->good) {
		nni_mutex_exit(&req->mx);
		return;
	}
	nni_mutex_exit(&req->mx);

	for (;;) {
		rv = nni_msgqueue_get_sig(uwq, &msg, &rp->sigclose);
		if (rv != 0) {
			break;
		}
		rv = nni_pipe_send(pipe, msg);
		if (rv != 0) {
			nni_msg_free(msg);
			break;
		}
	}
	nni_msgqueue_signal(urq, &rp->sigclose);
	nni_pipe_close(pipe);
}


static void
nni_req_receiver(void *arg)
{
	nni_req_pipe *rp = arg;
	nni_req_sock *req = rp->req;
	nni_msgqueue *urq = req->urq;
	nni_msgqueue *uwq = req->uwq;
	nni_pipe *pipe = rp->pipe;
	nni_msg *msg;
	int rv;

	nni_mutex_enter(&req->mx);
	if (!rp->good) {
		nni_mutex_exit(&req->mx);
		return;
	}
	nni_mutex_exit(&req->mx);
	for (;;) {
		size_t len;
		char *body;
		rv = nni_pipe_recv(pipe, &msg);
		if (rv != 0) {
			break;
		}
		// We yank 4 bytes of body, and move them to the header.
		body = nni_msg_body(msg, &len);
		if (len < 4) {
			// Not enough data, just toss it.
			nni_msg_free(msg);
			continue;
		}
		if (nni_msg_append_header(msg, body, 4) != 0) {
			// Should be NNG_ENOMEM
			nni_msg_free(msg);
			continue;
		}
		if (nni_msg_trim(msg, 4) != 0) {
			// This should never happen - could be an assert.
			nni_panic("Failed to trim REQ header from body");
		}
		rv = nni_msgqueue_put_sig(urq, msg, &rp->sigclose);
		if (rv != 0) {
			nni_msg_free(msg);
			break;
		}
	}
	nni_msgqueue_signal(uwq, &rp->sigclose);
	nni_pipe_close(pipe);
}


static int
nni_req_setopt(void *arg, int opt, const void *buf, size_t sz)
{
	nni_req_sock *req = arg;
	int rv;

	switch (opt) {
	case NNG_OPT_RESENDTIME:
		nni_mutex_enter(&req->mx);
		rv = nni_setopt_duration(&req->retry, buf, sz);
		nni_mutex_exit(&req->mx);
		break;
	case NNG_OPT_RAW:
		nni_mutex_enter(&req->mx);
		rv = nni_setopt_int(&req->raw, buf, sz, 0, 1);
		nni_mutex_exit(&req->mx);
		break;
	default:
		rv = NNG_ENOTSUP;
	}
	return (rv);
}


static int
nni_req_getopt(void *arg, int opt, void *buf, size_t *szp)
{
	nni_req_sock *req = arg;
	int rv;

	switch (opt) {
	case NNG_OPT_RESENDTIME:
		nni_mutex_enter(&req->mx);
		rv = nni_getopt_duration(&req->retry, buf, szp);
		nni_mutex_exit(&req->mx);
		break;
	case NNG_OPT_RAW:
		nni_mutex_enter(&req->mx);
		rv = nni_getopt_int(&req->raw, buf, szp);
		nni_mutex_exit(&req->mx);
		break;
	default:
		rv = NNG_ENOTSUP;
	}
	return (rv);
}


static void
nni_req_resender(void *arg)
{
	nni_req_sock *req = arg;
	int rv;

	for (;;) {
		nni_mutex_enter(&req->mx);
		if (req->resender == NULL) {
			nni_mutex_exit(&req->mx);
			return;
		}
		if (req->reqmsg == NULL) {
			nni_cond_wait(&req->cv);
			nni_mutex_exit(&req->mx);
			continue;
		}
		rv = nni_cond_waituntil(&req->cv, req->resend);
		if ((rv == NNG_ETIMEDOUT) && (req->reqmsg != NULL)) {
			nni_msg *dup;
			// XXX: check for final timeout on this?
			if (nni_msg_dup(&dup, req->reqmsg) != 0) {
				if (nni_msgqueue_putback(req->uwq, dup) != 0) {
					nni_msg_free(dup);
				}
			}
			req->resend = nni_clock() + req->retry;
		}
		nni_mutex_exit(&req->mx);
	}
}


static nni_msg *
nni_req_sendfilter(void *arg, nni_msg *msg)
{
	nni_req_sock *req = arg;
	uint32_t id;
	uint8_t buf[4];

	nni_mutex_enter(&req->mx);
	if (req->raw) {
		// No automatic retry, and the request ID must
		// be in the header coming down.
		nni_mutex_exit(&req->mx);
		return (msg);
	}

	// Generate a new request ID.  We always set the high
	// order bit so that the peer can locate the end of the
	// backtrace.  (Pipe IDs have the high order bit clear.)
	id = (req->nextid++) | 0x80000000u;

	// Request ID is in big endian format.
	req->reqid[0] = (uint8_t) (id >> 24);
	req->reqid[1] = (uint8_t) (id >> 16);
	req->reqid[2] = (uint8_t) (id >> 8);
	req->reqid[3] = (uint8_t) (id);

	if (nni_msg_append_header(msg, buf, 4) != 0) {
		// Should be ENOMEM.
		nni_mutex_exit(&req->mx);
		nni_msg_free(msg);
		return (NULL);
	}

	// If another message is there, this cancels it.
	if (req->reqmsg != NULL) {
		nni_msg_free(req->reqmsg);
		req->reqmsg = NULL;
	}

	// Make a duplicate message... for retries.
	if (nni_msg_dup(&req->reqmsg, msg) != 0) {
		nni_mutex_exit(&req->mx);
		nni_msg_free(msg);
		return (NULL);
	}

	// Schedule the next retry
	req->resend = nni_clock() + req->retry;
	nni_cond_signal(&req->cv);

	// Clear the error condition.
	nni_socket_recverr(req->sock, 0);
	nni_mutex_exit(&req->mx);

	return (msg);
}


static nni_msg *
nni_req_recvfilter(void *arg, nni_msg *msg)
{
	nni_req_sock *req = arg;
	char *header;
	size_t len;

	nni_mutex_enter(&req->mx);
	if (req->raw) {
		// Pass it unmolested
		nni_mutex_exit(&req->mx);
		return (msg);
	}

	header = nni_msg_header(msg, &len);
	if (len < 4) {
		nni_mutex_exit(&req->mx);
		nni_msg_free(msg);
		return (NULL);
	}

	if (req->reqmsg == NULL) {
		// We had no outstanding request.
		nni_mutex_exit(&req->mx);
		nni_msg_free(msg);
		return (NULL);
	}
	if (memcmp(header, req->reqid, 4) != 0) {
		// Wrong request id
		nni_mutex_exit(&req->mx);
		nni_msg_free(msg);
		return (NULL);
	}

	nni_socket_recverr(req->sock, NNG_ESTATE);
	nni_msg_free(req->reqmsg);
	req->reqmsg = NULL;
	nni_cond_signal(&req->cv);
	nni_mutex_exit(&req->mx);
	return (msg);
}


// This is the global protocol structure -- our linkage to the core.
// This should be the only global non-static symbol in this file.
struct nni_protocol nni_req_protocol = {
	.proto_self		= NNG_PROTO_REQ,
	.proto_peer		= NNG_PROTO_REP,
	.proto_name		= "req",
	.proto_create		= nni_req_create,
	.proto_destroy		= nni_req_destroy,
	.proto_add_pipe		= nni_req_add_pipe,
	.proto_rem_pipe		= nni_req_rem_pipe,
	.proto_setopt		= nni_req_setopt,
	.proto_getopt		= nni_req_getopt,
	.proto_recv_filter	= nni_req_recvfilter,
	.proto_send_filter	= nni_req_sendfilter,
};
