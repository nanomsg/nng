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

#include "core/nng_impl.h"

// Response protocol.  The REP protocol is the "reply" side of a
// request-reply pair.  This is useful for building RPC servers, for
// example.

typedef struct nni_rep_pipe	nni_rep_pipe;
typedef struct nni_rep_sock	nni_rep_sock;

// An nni_rep_sock is our per-socket protocol private structure.
struct nni_rep_sock {
	nni_sock *	sock;
	nni_msgq *	uwq;
	nni_msgq *	urq;
	int		raw;
	int		ttl;
	nni_idhash	pipes;
	char *		btrace;
	size_t		btrace_len;
};

// An nni_rep_pipe is our per-pipe protocol private structure.
struct nni_rep_pipe {
	nni_pipe *	pipe;
	nni_rep_sock *	rep;
	nni_msgq *	sendq;
	int		sigclose;
};

static int
nni_rep_sock_init(void **repp, nni_sock *sock)
{
	nni_rep_sock *rep;
	int rv;

	if ((rep = NNI_ALLOC_STRUCT(rep)) == NULL) {
		return (NNG_ENOMEM);
	}
	rep->ttl = 8;   // Per RFC
	rep->sock = sock;
	rep->raw = 0;
	rep->btrace = NULL;
	rep->btrace_len = 0;
	if ((rv = nni_idhash_init(&rep->pipes)) != 0) {
		NNI_FREE_STRUCT(rep);
		return (rv);
	}

	rep->uwq = nni_sock_sendq(sock);
	rep->urq = nni_sock_recvq(sock);

	*repp = rep;
	nni_sock_senderr(sock, NNG_ESTATE);
	return (0);
}


static void
nni_rep_sock_fini(void *arg)
{
	nni_rep_sock *rep = arg;

	if (rep != NULL) {
		nni_idhash_fini(&rep->pipes);
		if (rep->btrace != NULL) {
			nni_free(rep->btrace, rep->btrace_len);
		}
		NNI_FREE_STRUCT(rep);
	}
}


static int
nni_rep_pipe_init(void **rpp, nni_pipe *pipe, void *rsock)
{
	nni_rep_pipe *rp;
	int rv;

	if ((rp = NNI_ALLOC_STRUCT(rp)) == NULL) {
		return (NNG_ENOMEM);
	}
	if ((rv = nni_msgq_init(&rp->sendq, 2)) != 0) {
		NNI_FREE_STRUCT(rp);
		return (rv);
	}
	rp->pipe = pipe;
	rp->rep = rsock;
	rp->sigclose = 0;
	*rpp = rp;
	return (0);
}


static void
nni_rep_pipe_fini(void *arg)
{
	nni_rep_pipe *rp = arg;

	if (rp != NULL) {
		nni_msgq_fini(rp->sendq);
		NNI_FREE_STRUCT(rp);
	}
}


static int
nni_rep_pipe_add(void *arg)
{
	nni_rep_pipe *rp = arg;
	nni_rep_sock *rep = rp->rep;

	return (nni_idhash_insert(&rep->pipes, nni_pipe_id(rp->pipe), rp));
}


static void
nni_rep_pipe_rem(void *arg)
{
	nni_rep_pipe *rp = arg;
	nni_rep_sock *rep = rp->rep;

	nni_idhash_remove(&rep->pipes, nni_pipe_id(rp->pipe));
}


// nni_rep_sock_send watches for messages from the upper write queue,
// extracts the destination pipe, and forwards it to the appropriate
// destination pipe via a separate queue.  This prevents a single bad
// or slow pipe from gumming up the works for the entire socket.
static void
nni_rep_sock_send(void *arg)
{
	nni_rep_sock *rep = arg;
	nni_msgq *uwq = rep->uwq;
	nni_mtx *mx = nni_sock_mtx(rep->sock);
	nni_msg *msg;

	for (;;) {
		uint8_t *header;
		uint32_t id;
		nni_rep_pipe *rp;
		int rv;

		if ((rv = nni_msgq_get(uwq, &msg)) != 0) {
			break;
		}
		// We yank the outgoing pipe id from the header
		if (nni_msg_header_len(msg) < 4) {
			nni_msg_free(msg);
			continue;
		}
		header = nni_msg_header(msg);
		NNI_GET32(header, id);
		nni_msg_trim_header(msg, 4);

		nni_mtx_lock(mx);
		if (nni_idhash_find(&rep->pipes, id, (void **) &rp) != 0) {
			nni_mtx_unlock(mx);
			nni_msg_free(msg);
			continue;
		}
		// Try a non-blocking put to the lower writer.
		rv = nni_msgq_put_until(rp->sendq, msg, NNI_TIME_ZERO);
		if (rv != 0) {
			// message queue is full, we have no choice but
			// to drop it.  This should not happen under normal
			// circumstances.
			nni_msg_free(msg);
		}
		nni_mtx_unlock(mx);
	}
}


static void
nni_rep_pipe_send(void *arg)
{
	nni_rep_pipe *rp = arg;
	nni_rep_sock *rep = rp->rep;
	nni_msgq *urq = rep->urq;
	nni_msgq *wq = rp->sendq;
	nni_pipe *pipe = rp->pipe;
	nni_msg *msg;
	int rv;

	for (;;) {
		rv = nni_msgq_get_sig(wq, &msg, &rp->sigclose);
		if (rv != 0) {
			break;
		}

		rv = nni_pipe_send(pipe, msg);
		if (rv != 0) {
			nni_msg_free(msg);
			break;
		}
	}
	nni_msgq_signal(urq, &rp->sigclose);
	nni_pipe_close(pipe);
}


static void
nni_rep_pipe_recv(void *arg)
{
	nni_rep_pipe *rp = arg;
	nni_rep_sock *rep = rp->rep;
	nni_msgq *urq = rep->urq;
	nni_msgq *uwq = rep->uwq;
	nni_pipe *pipe = rp->pipe;
	nni_msg *msg;
	int rv;
	uint8_t idbuf[4];
	uint32_t id = nni_pipe_id(pipe);

	NNI_PUT32(idbuf, id);

	for (;;) {
		uint8_t *body;
		int hops;

again:
		rv = nni_pipe_recv(pipe, &msg);
		if (rv != 0) {
			break;
		}

		// Store the pipe id in the header, first thing.
		rv = nni_msg_append_header(msg, idbuf, 4);
		if (rv != 0) {
			nni_msg_free(msg);
			continue;
		}

		// Move backtrace from body to header
		hops = 0;
		for (;;) {
			int end = 0;
			if (hops >= rep->ttl) {
				nni_msg_free(msg);
				goto again;
			}
			if (nni_msg_len(msg) < 4) {
				nni_msg_free(msg);
				goto again;
			}
			body = nni_msg_body(msg);
			end = (body[0] & 0x80) ? 1 : 0;
			rv = nni_msg_append_header(msg, body, 4);
			if (rv != 0) {
				nni_msg_free(msg);
				goto again;
			}
			nni_msg_trim(msg, 4);
			if (end) {
				break;
			}
		}

		// Now send it up.
		rv = nni_msgq_put_sig(urq, msg, &rp->sigclose);
		if (rv != 0) {
			nni_msg_free(msg);
			break;
		}
	}
	nni_msgq_signal(uwq, &rp->sigclose);
	nni_msgq_signal(rp->sendq, &rp->sigclose);
	nni_pipe_close(pipe);
}


static int
nni_rep_sock_setopt(void *arg, int opt, const void *buf, size_t sz)
{
	nni_rep_sock *rep = arg;
	int rv;

	switch (opt) {
	case NNG_OPT_MAXTTL:
		rv = nni_setopt_int(&rep->ttl, buf, sz, 1, 255);
		break;
	case NNG_OPT_RAW:
		rv = nni_setopt_int(&rep->raw, buf, sz, 0, 1);
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
	int rv;

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
	nni_msg_trunc_header(msg, nni_msg_header_len(msg));

	if (nni_msg_append_header(msg, rep->btrace, rep->btrace_len) != 0) {
		nni_free(rep->btrace, rep->btrace_len);
		rep->btrace = NULL;
		rep->btrace_len = 0;
		nni_msg_free(msg);
		return (NULL);
	}

	nni_free(rep->btrace, rep->btrace_len);
	rep->btrace = NULL;
	rep->btrace_len = 0;
	return (msg);
}


static nni_msg *
nni_rep_sock_rfilter(void *arg, nni_msg *msg)
{
	nni_rep_sock *rep = arg;
	char *header;
	size_t len;

	if (rep->raw) {
		return (msg);
	}

	nni_sock_senderr(rep->sock, 0);
	len = nni_msg_header_len(msg);
	header = nni_msg_header(msg);
	if (rep->btrace != NULL) {
		nni_free(rep->btrace, rep->btrace_len);
		rep->btrace = NULL;
		rep->btrace_len = 0;
	}
	if ((rep->btrace = nni_alloc(len)) == NULL) {
		nni_msg_free(msg);
		return (NULL);
	}
	rep->btrace_len = len;
	memcpy(rep->btrace, header, len);
	nni_msg_trunc_header(msg, len);
	return (msg);
}


// This is the global protocol structure -- our linkage to the core.
// This should be the only global non-static symbol in this file.
static nni_proto_pipe_ops nni_rep_pipe_ops = {
	.pipe_init	= nni_rep_pipe_init,
	.pipe_fini	= nni_rep_pipe_fini,
	.pipe_add	= nni_rep_pipe_add,
	.pipe_rem	= nni_rep_pipe_rem,
	.pipe_worker	= { nni_rep_pipe_send,
			    nni_rep_pipe_recv },
};

static nni_proto_sock_ops nni_rep_sock_ops = {
	.sock_init	= nni_rep_sock_init,
	.sock_fini	= nni_rep_sock_fini,
	.sock_setopt	= nni_rep_sock_setopt,
	.sock_getopt	= nni_rep_sock_getopt,
	.sock_rfilter	= nni_rep_sock_rfilter,
	.sock_sfilter	= nni_rep_sock_sfilter,
	.sock_worker	= { nni_rep_sock_send },
};

nni_proto nni_rep_proto = {
	.proto_self	= NNG_PROTO_REP,
	.proto_peer	= NNG_PROTO_REQ,
	.proto_name	= "rep",
	.proto_sock_ops = &nni_rep_sock_ops,
	.proto_pipe_ops = &nni_rep_pipe_ops,
};
