//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
// Copyright 2017 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <stdlib.h>
#include <string.h>

#include "core/nng_impl.h"

// Response protocol.  The REP protocol is the "reply" side of a
// request-reply pair.  This is useful for building RPC servers, for
// example.

typedef struct nni_rep_pipe nni_rep_pipe;
typedef struct nni_rep_sock nni_rep_sock;

static void nni_rep_sock_getq_cb(void *);
static void nni_rep_pipe_getq_cb(void *);
static void nni_rep_pipe_putq_cb(void *);
static void nni_rep_pipe_send_cb(void *);
static void nni_rep_pipe_recv_cb(void *);
static void nni_rep_pipe_fini(void *);

// An nni_rep_sock is our per-socket protocol private structure.
struct nni_rep_sock {
	nni_sock *  sock;
	nni_msgq *  uwq;
	nni_msgq *  urq;
	int         raw;
	int         ttl;
	nni_idhash *pipes;
	char *      btrace;
	size_t      btrace_len;
	nni_aio     aio_getq;
};

// An nni_rep_pipe is our per-pipe protocol private structure.
struct nni_rep_pipe {
	nni_pipe *    pipe;
	nni_rep_sock *rep;
	nni_msgq *    sendq;
	nni_aio       aio_getq;
	nni_aio       aio_send;
	nni_aio       aio_recv;
	nni_aio       aio_putq;
};

static void
nni_rep_sock_fini(void *arg)
{
	nni_rep_sock *rep = arg;

	nni_aio_stop(&rep->aio_getq);
	nni_aio_fini(&rep->aio_getq);
	nni_idhash_fini(rep->pipes);
	if (rep->btrace != NULL) {
		nni_free(rep->btrace, rep->btrace_len);
	}
	NNI_FREE_STRUCT(rep);
}

static int
nni_rep_sock_init(void **repp, nni_sock *sock)
{
	nni_rep_sock *rep;
	int           rv;

	if ((rep = NNI_ALLOC_STRUCT(rep)) == NULL) {
		return (NNG_ENOMEM);
	}
	if ((rv = nni_idhash_init(&rep->pipes)) != 0) {
		NNI_FREE_STRUCT(rep);
		return (rv);
	}

	rep->ttl        = 8; // Per RFC
	rep->sock       = sock;
	rep->raw        = 0;
	rep->btrace     = NULL;
	rep->btrace_len = 0;

	nni_aio_init(&rep->aio_getq, nni_rep_sock_getq_cb, rep);

	rep->uwq = nni_sock_sendq(sock);
	rep->urq = nni_sock_recvq(sock);

	*repp = rep;
	nni_sock_senderr(sock, NNG_ESTATE);

	return (0);
}

static void
nni_rep_sock_open(void *arg)
{
	nni_rep_sock *rep = arg;

	nni_msgq_aio_get(rep->uwq, &rep->aio_getq);
}

static void
nni_rep_sock_close(void *arg)
{
	nni_rep_sock *rep = arg;

	nni_aio_cancel(&rep->aio_getq, NNG_ECLOSED);
}

static int
nni_rep_pipe_init(void **rpp, nni_pipe *pipe, void *rsock)
{
	nni_rep_pipe *rp;
	int           rv;

	if ((rp = NNI_ALLOC_STRUCT(rp)) == NULL) {
		return (NNG_ENOMEM);
	}
	if ((rv = nni_msgq_init(&rp->sendq, 2)) != 0) {
		NNI_FREE_STRUCT(rp);
		return (rv);
	}
	nni_aio_init(&rp->aio_getq, nni_rep_pipe_getq_cb, rp);
	nni_aio_init(&rp->aio_send, nni_rep_pipe_send_cb, rp);
	nni_aio_init(&rp->aio_recv, nni_rep_pipe_recv_cb, rp);
	nni_aio_init(&rp->aio_putq, nni_rep_pipe_putq_cb, rp);

	rp->pipe = pipe;
	rp->rep  = rsock;
	*rpp     = rp;
	return (0);
}

static void
nni_rep_pipe_fini(void *arg)
{
	nni_rep_pipe *rp = arg;

	nni_aio_fini(&rp->aio_getq);
	nni_aio_fini(&rp->aio_send);
	nni_aio_fini(&rp->aio_recv);
	nni_aio_fini(&rp->aio_putq);
	nni_msgq_fini(rp->sendq);
	NNI_FREE_STRUCT(rp);
}

static int
nni_rep_pipe_start(void *arg)
{
	nni_rep_pipe *rp  = arg;
	nni_rep_sock *rep = rp->rep;
	int           rv;

	rv = nni_idhash_insert(rep->pipes, nni_pipe_id(rp->pipe), rp);
	if (rv != 0) {
		return (rv);
	}

	nni_msgq_aio_get(rp->sendq, &rp->aio_getq);
	nni_pipe_recv(rp->pipe, &rp->aio_recv);
	return (0);
}

static void
nni_rep_pipe_stop(void *arg)
{
	nni_rep_pipe *rp  = arg;
	nni_rep_sock *rep = rp->rep;

	nni_msgq_close(rp->sendq);
	nni_aio_stop(&rp->aio_getq);
	nni_aio_stop(&rp->aio_send);
	nni_aio_stop(&rp->aio_recv);
	nni_aio_stop(&rp->aio_putq);

	nni_idhash_remove(rep->pipes, nni_pipe_id(rp->pipe));
}

static void
nni_rep_sock_getq_cb(void *arg)
{
	nni_rep_sock *rep = arg;
	nni_msgq *    uwq = rep->uwq;
	nni_msg *     msg;
	uint32_t      id;
	nni_rep_pipe *rp;
	int           rv;

	// This watches for messages from the upper write queue,
	// extracts the destination pipe, and forwards it to the appropriate
	// destination pipe via a separate queue.  This prevents a single bad
	// or slow pipe from gumming up the works for the entire socket.

	if (nni_aio_result(&rep->aio_getq) != 0) {
		// Closed socket?
		return;
	}

	msg                 = rep->aio_getq.a_msg;
	rep->aio_getq.a_msg = NULL;

	// We yank the outgoing pipe id from the header
	if (nni_msg_header_len(msg) < 4) {
		nni_msg_free(msg);

		// Look for another message on the upper write queue.
		nni_msgq_aio_get(uwq, &rep->aio_getq);
		return;
	}

	id = nni_msg_header_trim_u32(msg);

	// Look for the pipe, and attempt to put the message there
	// (nonblocking) if we can.  If we can't for any reason, then we
	// free the message.
	rv = nni_idhash_find(rep->pipes, id, (void **) &rp);
	if (rv == 0) {
		rv = nni_msgq_tryput(rp->sendq, msg);
	}
	if (rv != 0) {
		nni_msg_free(msg);
	}

	// Now look for another message on the upper write queue.
	nni_msgq_aio_get(uwq, &rep->aio_getq);
}

static void
nni_rep_pipe_getq_cb(void *arg)
{
	nni_rep_pipe *rp = arg;

	if (nni_aio_result(&rp->aio_getq) != 0) {
		nni_pipe_stop(rp->pipe);
		return;
	}

	rp->aio_send.a_msg = rp->aio_getq.a_msg;
	rp->aio_getq.a_msg = NULL;

	nni_pipe_send(rp->pipe, &rp->aio_send);
}

static void
nni_rep_pipe_send_cb(void *arg)
{
	nni_rep_pipe *rp = arg;

	if (nni_aio_result(&rp->aio_send) != 0) {
		nni_msg_free(rp->aio_send.a_msg);
		rp->aio_send.a_msg = NULL;
		nni_pipe_stop(rp->pipe);
		return;
	}

	nni_msgq_aio_get(rp->sendq, &rp->aio_getq);
}

static void
nni_rep_pipe_recv_cb(void *arg)
{
	nni_rep_pipe *rp  = arg;
	nni_rep_sock *rep = rp->rep;
	nni_msg *     msg;
	int           rv;
	uint8_t *     body;
	int           hops;

	if (nni_aio_result(&rp->aio_recv) != 0) {
		nni_pipe_stop(rp->pipe);
		return;
	}

	msg                = rp->aio_recv.a_msg;
	rp->aio_recv.a_msg = NULL;

	// Store the pipe id in the header, first thing.
	rv = nni_msg_header_append_u32(msg, nni_pipe_id(rp->pipe));
	if (rv != 0) {
		// Failure here causes us to drop the message.
		goto drop;
	}

	// Move backtrace from body to header
	hops = 1;
	for (;;) {
		int end = 0;
		if (hops >= rep->ttl) {
			// This isn't malformed, but it has gone through
			// too many hops.  Do not disconnect, because we
			// can legitimately receive messages with too many
			// hops from devices, etc.
			goto drop;
		}
		if (nni_msg_len(msg) < 4) {
			// Peer is speaking garbage. Kick it.
			nni_msg_free(msg);
			nni_pipe_stop(rp->pipe);
			return;
		}
		body = nni_msg_body(msg);
		end  = (body[0] & 0x80) ? 1 : 0;
		rv   = nni_msg_header_append(msg, body, 4);
		if (rv != 0) {
			// Presumably this is due to out of memory.
			// We could just discard and try again, but we
			// just toss the connection for now.  Given the
			// out of memory situation, this is not unreasonable.
			goto drop;
		}
		nni_msg_trim(msg, 4);
		if (end) {
			break;
		}
	}

	// Go ahead and send it up.
	rp->aio_putq.a_msg = msg;
	nni_msgq_aio_put(rp->rep->urq, &rp->aio_putq);
	return;

drop:
	nni_msg_free(msg);
	nni_pipe_recv(rp->pipe, &rp->aio_recv);
}

static void
nni_rep_pipe_putq_cb(void *arg)
{
	nni_rep_pipe *rp = arg;

	if (nni_aio_result(&rp->aio_putq) != 0) {
		nni_msg_free(rp->aio_putq.a_msg);
		rp->aio_putq.a_msg = NULL;
		nni_pipe_stop(rp->pipe);
		return;
	}

	nni_pipe_recv(rp->pipe, &rp->aio_recv);
}

static int
nni_rep_sock_setopt(void *arg, int opt, const void *buf, size_t sz)
{
	nni_rep_sock *rep = arg;
	int           rv;

	switch (opt) {
	case NNG_OPT_MAXTTL:
		rv = nni_setopt_int(&rep->ttl, buf, sz, 1, 255);
		break;
	case NNG_OPT_RAW:
		rv = nni_setopt_int(&rep->raw, buf, sz, 0, 1);
		nni_sock_senderr(rep->sock, rep->raw ? 0 : NNG_ESTATE);
		break;
	default:
		rv = NNG_ENOTSUP;
	}
	return (rv);
}

static int
nni_rep_sock_getopt(void *arg, int opt, void *buf, size_t *szp)
{
	nni_rep_sock *rep = arg;
	int           rv;

	switch (opt) {
	case NNG_OPT_MAXTTL:
		rv = nni_getopt_int(&rep->ttl, buf, szp);
		break;
	case NNG_OPT_RAW:
		rv = nni_getopt_int(&rep->raw, buf, szp);
		break;
	default:
		rv = NNG_ENOTSUP;
	}
	return (rv);
}

static nni_msg *
nni_rep_sock_sfilter(void *arg, nni_msg *msg)
{
	nni_rep_sock *rep = arg;

	if (rep->raw) {
		return (msg);
	}

	// Cannot send again until a receive is done...
	nni_sock_senderr(rep->sock, NNG_ESTATE);

	// If we have a stored backtrace, append it to the header...
	// if we don't have a backtrace, discard the message.
	if (rep->btrace == NULL) {
		nni_msg_free(msg);
		return (NULL);
	}

	// drop anything else in the header...
	nni_msg_header_clear(msg);

	if (nni_msg_header_append(msg, rep->btrace, rep->btrace_len) != 0) {
		nni_free(rep->btrace, rep->btrace_len);
		rep->btrace     = NULL;
		rep->btrace_len = 0;
		nni_msg_free(msg);
		return (NULL);
	}

	nni_free(rep->btrace, rep->btrace_len);
	rep->btrace     = NULL;
	rep->btrace_len = 0;
	return (msg);
}

static nni_msg *
nni_rep_sock_rfilter(void *arg, nni_msg *msg)
{
	nni_rep_sock *rep = arg;
	char *        header;
	size_t        len;

	if (rep->raw) {
		return (msg);
	}

	nni_sock_senderr(rep->sock, 0);
	len    = nni_msg_header_len(msg);
	header = nni_msg_header(msg);
	if (rep->btrace != NULL) {
		nni_free(rep->btrace, rep->btrace_len);
		rep->btrace     = NULL;
		rep->btrace_len = 0;
	}
	if ((rep->btrace = nni_alloc(len)) == NULL) {
		nni_msg_free(msg);
		return (NULL);
	}
	rep->btrace_len = len;
	memcpy(rep->btrace, header, len);
	nni_msg_header_clear(msg);
	return (msg);
}

// This is the global protocol structure -- our linkage to the core.
// This should be the only global non-static symbol in this file.
static nni_proto_pipe_ops nni_rep_pipe_ops = {
	.pipe_init  = nni_rep_pipe_init,
	.pipe_fini  = nni_rep_pipe_fini,
	.pipe_start = nni_rep_pipe_start,
	.pipe_stop  = nni_rep_pipe_stop,
};

static nni_proto_sock_ops nni_rep_sock_ops = {
	.sock_init    = nni_rep_sock_init,
	.sock_fini    = nni_rep_sock_fini,
	.sock_open    = nni_rep_sock_open,
	.sock_close   = nni_rep_sock_close,
	.sock_setopt  = nni_rep_sock_setopt,
	.sock_getopt  = nni_rep_sock_getopt,
	.sock_rfilter = nni_rep_sock_rfilter,
	.sock_sfilter = nni_rep_sock_sfilter,
};

nni_proto nni_rep_proto = {
	.proto_version  = NNI_PROTOCOL_VERSION,
	.proto_self     = { NNG_PROTO_REP_V0, "rep" },
	.proto_peer     = { NNG_PROTO_REQ_V0, "req" },
	.proto_flags    = NNI_PROTO_FLAG_SNDRCV,
	.proto_sock_ops = &nni_rep_sock_ops,
	.proto_pipe_ops = &nni_rep_pipe_ops,
};

int
nng_rep0_open(nng_socket *sidp)
{
	return (nni_proto_open(sidp, &nni_rep_proto));
}
