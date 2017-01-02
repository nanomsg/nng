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

// Response protocol.  The REP protocol is the "reply" side of a
// request-reply pair.  This is useful for bulding RPC servers, for
// example.

typedef struct nni_rep_pipe	nni_rep_pipe;
typedef struct nni_rep_sock	nni_rep_sock;

// An nni_rep_sock is our per-socket protocol private structure.
struct nni_rep_sock {
	nni_sock *	sock;
	nni_mtx		mx;
	nni_msgq *	uwq;
	nni_msgq *	urq;
	int		raw;
	int		ttl;
	nni_thr		sender;
	nni_idhash *	pipes;
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

static void nni_rep_topsender(void *);

static int
nni_rep_init(void **repp, nni_sock *sock)
{
	nni_rep_sock *rep;
	int rv;

	if ((rep = NNI_ALLOC_STRUCT(rep)) == NULL) {
		return (NNG_ENOMEM);
	}
	if ((rv = nni_mtx_init(&rep->mx)) != 0) {
		NNI_FREE_STRUCT(rep);
		return (rv);
	}
	rep->ttl = 8;   // Per RFC
	rep->sock = sock;
	rep->raw = 0;
	rep->btrace = NULL;
	rep->btrace_len = 0;
	if ((rv = nni_idhash_create(&rep->pipes)) != 0) {
		nni_mtx_fini(&rep->mx);
		NNI_FREE_STRUCT(rep);
		return (rv);
	}

	rep->uwq = nni_sock_sendq(sock);
	rep->urq = nni_sock_recvq(sock);

	rv = nni_thr_init(&rep->sender, nni_rep_topsender, rep);
	if (rv != 0) {
		nni_idhash_destroy(rep->pipes);
		nni_mtx_fini(&rep->mx);
		NNI_FREE_STRUCT(rep);
		return (rv);
	}
	*repp = rep;
	nni_sock_senderr(sock, NNG_ESTATE);
	nni_thr_run(&rep->sender);
	return (0);
}


static void
nni_rep_fini(void *arg)
{
	nni_rep_sock *rep = arg;

	nni_thr_fini(&rep->sender);
	nni_idhash_destroy(rep->pipes);
	nni_mtx_fini(&rep->mx);
	if (rep->btrace != NULL) {
		nni_free(rep->btrace, rep->btrace_len);
	}
	NNI_FREE_STRUCT(rep);
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

	nni_msgq_fini(rp->sendq);
	NNI_FREE_STRUCT(rp);
}


static int
nni_rep_pipe_add(void *arg)
{
	nni_rep_pipe *rp = arg;
	nni_rep_sock *rep = rp->rep;
	int rv;

	nni_mtx_lock(&rep->mx);
	rv = nni_idhash_insert(rep->pipes, nni_pipe_id(rp->pipe), rp);
	nni_mtx_unlock(&rep->mx);

	return (rv);
}


static void
nni_rep_pipe_rem(void *arg)
{
	nni_rep_pipe *rp = arg;
	nni_rep_sock *rep = rp->rep;

	nni_mtx_lock(&rep->mx);
	nni_idhash_remove(rep->pipes, nni_pipe_id(rp->pipe));
	nni_mtx_unlock(&rep->mx);
}


// nni_rep_topsender watches for messages from the upper write queue,
// extracts the destination pipe, and forwards it to the appropriate
// destination pipe via a separate queue.  This prevents a single bad
// or slow pipe from gumming up the works for the entire socket.
static void
nni_rep_topsender(void *arg)
{
	nni_rep_sock *rep = arg;
	nni_msgq *uwq = rep->uwq;
	nni_msgq *urq = rep->urq;
	nni_msg *msg;

	for (;;) {
		uint8_t *header;
		size_t size;
		uint32_t id;
		nni_rep_pipe *rp;
		int rv;

		if ((rv = nni_msgq_get(uwq, &msg)) != 0) {
			break;
		}
		// We yank the outgoing pipe id from the header
		header = nni_msg_header(msg, &size);
		if (size < 4) {
			nni_msg_free(msg);
			continue;
		}
		id = header[0];
		id <<= 8;
		id += header[1];
		id <<= 8;
		id += header[2];
		id <<= 8;
		id += header[3];
		nni_msg_trim_header(msg, 4);

		nni_mtx_lock(&rep->mx);
		if (nni_idhash_find(rep->pipes, id, (void **) &rp) != 0) {
			nni_mtx_unlock(&rep->mx);
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
		nni_mtx_unlock(&rep->mx);
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
	uint8_t *body;
	size_t size;
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

	idbuf[0] = (uint8_t) (id >> 24);
	idbuf[1] = (uint8_t) (id >> 16);
	idbuf[2] = (uint8_t) (id >> 8);
	idbuf[3] = (uint8_t) (id);

	for (;;) {
		size_t len;
		char *body;
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
			body = nni_msg_body(msg, &len);
			if (len < 4) {
				nni_msg_free(msg);
				goto again;
			}
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
	nni_pipe_close(pipe);
}


static int
nni_rep_setopt(void *arg, int opt, const void *buf, size_t sz)
{
	nni_rep_sock *rep = arg;
	int rv;

	switch (opt) {
	case NNG_OPT_MAXTTL:
		nni_mtx_lock(&rep->mx);
		rv = nni_setopt_int(&rep->ttl, buf, sz, 1, 255);
		nni_mtx_unlock(&rep->mx);
		break;
	case NNG_OPT_RAW:
		nni_mtx_lock(&rep->mx);
		rv = nni_setopt_int(&rep->raw, buf, sz, 0, 1);
		nni_mtx_unlock(&rep->mx);
		break;
	default:
		rv = NNG_ENOTSUP;
	}
	return (rv);
}


static int
nni_rep_getopt(void *arg, int opt, void *buf, size_t *szp)
{
	nni_rep_sock *rep = arg;
	int rv;

	switch (opt) {
	case NNG_OPT_MAXTTL:
		nni_mtx_lock(&rep->mx);
		rv = nni_getopt_int(&rep->ttl, buf, szp);
		nni_mtx_unlock(&rep->mx);
		break;
	case NNG_OPT_RAW:
		nni_mtx_lock(&rep->mx);
		rv = nni_getopt_int(&rep->raw, buf, szp);
		nni_mtx_unlock(&rep->mx);
		break;
	default:
		rv = NNG_ENOTSUP;
	}
	return (rv);
}


static nni_msg *
nni_rep_sendfilter(void *arg, nni_msg *msg)
{
	nni_rep_sock *rep = arg;
	size_t len;

	nni_mtx_lock(&rep->mx);
	if (rep->raw) {
		nni_mtx_unlock(&rep->mx);
		return (msg);
	}

	// Cannot send again until a receive is done...
	nni_sock_senderr(rep->sock, NNG_ESTATE);

	// If we have a stored backtrace, append it to the header...
	// if we don't have a backtrace, discard the message.
	if (rep->btrace == NULL) {
		nni_mtx_unlock(&rep->mx);
		nni_msg_free(msg);
		return (NULL);
	}

	// drop anything else in the header...
	(void) nni_msg_header(msg, &len);
	nni_msg_trim_header(msg, len);

	if (nni_msg_append_header(msg, rep->btrace, rep->btrace_len) != 0) {
		nni_free(rep->btrace, rep->btrace_len);
		rep->btrace = NULL;
		rep->btrace_len = 0;
		nni_mtx_unlock(&rep->mx);
		nni_msg_free(msg);
		return (NULL);
	}

	nni_free(rep->btrace, rep->btrace_len);
	rep->btrace = NULL;
	rep->btrace_len = 0;
	nni_mtx_unlock(&rep->mx);
	return (msg);
}


static nni_msg *
nni_rep_recvfilter(void *arg, nni_msg *msg)
{
	nni_rep_sock *rep = arg;
	char *header;
	size_t len;

	nni_mtx_lock(&rep->mx);
	if (rep->raw) {
		nni_mtx_unlock(&rep->mx);
		return (msg);
	}

	nni_sock_senderr(rep->sock, 0);
	header = nni_msg_header(msg, &len);
	if (rep->btrace != NULL) {
		nni_free(rep->btrace, rep->btrace_len);
		rep->btrace = NULL;
		rep->btrace_len = 0;
	}
	if ((rep->btrace = nni_alloc(len)) == NULL) {
		nni_mtx_unlock(&rep->mx);
		nni_msg_free(msg);
		return (NULL);
	}
	rep->btrace_len = len;
	memcpy(rep->btrace, header, len);
	nni_msg_trim_header(msg, len);
	nni_mtx_unlock(&rep->mx);
	return (msg);
}


// This is the global protocol structure -- our linkage to the core.
// This should be the only global non-static symbol in this file.
static nni_proto_pipe nni_rep_proto_pipe = {
	.pipe_init	= nni_rep_pipe_init,
	.pipe_fini	= nni_rep_pipe_fini,
	.pipe_add	= nni_rep_pipe_add,
	.pipe_rem	= nni_rep_pipe_rem,
	.pipe_send	= nni_rep_pipe_send,
	.pipe_recv	= nni_rep_pipe_recv,
};

nni_proto nni_rep_protocol = {
	.proto_self		= NNG_PROTO_REP,
	.proto_peer		= NNG_PROTO_REQ,
	.proto_name		= "rep",
	.proto_pipe		= &nni_rep_proto_pipe,
	.proto_init		= nni_rep_init,
	.proto_fini		= nni_rep_fini,
	.proto_setopt		= nni_rep_setopt,
	.proto_getopt		= nni_rep_getopt,
	.proto_recv_filter	= nni_rep_recvfilter,
	.proto_send_filter	= nni_rep_sendfilter,
};
