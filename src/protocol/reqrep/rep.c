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

typedef struct rep_pipe rep_pipe;
typedef struct rep_sock rep_sock;

static void rep_sock_getq_cb(void *);
static void rep_pipe_getq_cb(void *);
static void rep_pipe_putq_cb(void *);
static void rep_pipe_send_cb(void *);
static void rep_pipe_recv_cb(void *);
static void rep_pipe_fini(void *);

// A rep_sock is our per-socket protocol private structure.
struct rep_sock {
	nni_sock *  sock;
	nni_msgq *  uwq;
	nni_msgq *  urq;
	int         raw;
	int         ttl;
	nni_idhash *pipes;
	char *      btrace;
	size_t      btrace_len;
	nni_aio *   aio_getq;
};

// A rep_pipe is our per-pipe protocol private structure.
struct rep_pipe {
	nni_pipe *pipe;
	rep_sock *rep;
	nni_msgq *sendq;
	nni_aio * aio_getq;
	nni_aio * aio_send;
	nni_aio * aio_recv;
	nni_aio * aio_putq;
};

static void
rep_sock_fini(void *arg)
{
	rep_sock *s = arg;

	nni_aio_stop(s->aio_getq);
	nni_aio_fini(s->aio_getq);
	nni_idhash_fini(s->pipes);
	if (s->btrace != NULL) {
		nni_free(s->btrace, s->btrace_len);
	}
	NNI_FREE_STRUCT(s);
}

static int
rep_sock_init(void **sp, nni_sock *sock)
{
	rep_sock *s;
	int       rv;

	if ((s = NNI_ALLOC_STRUCT(s)) == NULL) {
		return (NNG_ENOMEM);
	}
	if (((rv = nni_idhash_init(&s->pipes)) != 0) ||
	    ((rv = nni_aio_init(&s->aio_getq, rep_sock_getq_cb, s)) != 0)) {
		rep_sock_fini(s);
		return (rv);
	}

	s->ttl        = 8; // Per RFC
	s->sock       = sock;
	s->raw        = 0;
	s->btrace     = NULL;
	s->btrace_len = 0;
	s->uwq        = nni_sock_sendq(sock);
	s->urq        = nni_sock_recvq(sock);

	*sp = s;
	nni_sock_senderr(sock, NNG_ESTATE);

	return (0);
}

static void
rep_sock_open(void *arg)
{
	rep_sock *s = arg;

	nni_msgq_aio_get(s->uwq, s->aio_getq);
}

static void
rep_sock_close(void *arg)
{
	rep_sock *s = arg;

	nni_aio_cancel(s->aio_getq, NNG_ECLOSED);
}

static void
rep_pipe_fini(void *arg)
{
	rep_pipe *p = arg;

	nni_aio_fini(p->aio_getq);
	nni_aio_fini(p->aio_send);
	nni_aio_fini(p->aio_recv);
	nni_aio_fini(p->aio_putq);
	nni_msgq_fini(p->sendq);
	NNI_FREE_STRUCT(p);
}

static int
rep_pipe_init(void **pp, nni_pipe *pipe, void *s)
{
	rep_pipe *p;
	int       rv;

	if ((p = NNI_ALLOC_STRUCT(p)) == NULL) {
		return (NNG_ENOMEM);
	}
	if (((rv = nni_msgq_init(&p->sendq, 2)) != 0) ||
	    ((rv = nni_aio_init(&p->aio_getq, rep_pipe_getq_cb, p)) != 0) ||
	    ((rv = nni_aio_init(&p->aio_send, rep_pipe_send_cb, p)) != 0) ||
	    ((rv = nni_aio_init(&p->aio_recv, rep_pipe_recv_cb, p)) != 0) ||
	    ((rv = nni_aio_init(&p->aio_putq, rep_pipe_putq_cb, p)) != 0)) {
		rep_pipe_fini(p);
		return (rv);
	}

	p->pipe = pipe;
	p->rep  = s;
	*pp     = p;
	return (0);
}

static int
rep_pipe_start(void *arg)
{
	rep_pipe *p = arg;
	rep_sock *s = p->rep;
	int       rv;

	if ((rv = nni_idhash_insert(s->pipes, nni_pipe_id(p->pipe), p)) != 0) {
		return (rv);
	}

	nni_msgq_aio_get(p->sendq, p->aio_getq);
	nni_pipe_recv(p->pipe, p->aio_recv);
	return (0);
}

static void
rep_pipe_stop(void *arg)
{
	rep_pipe *p = arg;
	rep_sock *s = p->rep;

	nni_msgq_close(p->sendq);
	nni_aio_stop(p->aio_getq);
	nni_aio_stop(p->aio_send);
	nni_aio_stop(p->aio_recv);
	nni_aio_stop(p->aio_putq);

	nni_idhash_remove(s->pipes, nni_pipe_id(p->pipe));
}

static void
rep_sock_getq_cb(void *arg)
{
	rep_sock *s   = arg;
	nni_msgq *uwq = s->uwq;
	nni_msg * msg;
	uint32_t  id;
	rep_pipe *p;
	int       rv;

	// This watches for messages from the upper write queue,
	// extracts the destination pipe, and forwards it to the appropriate
	// destination pipe via a separate queue.  This prevents a single bad
	// or slow pipe from gumming up the works for the entire socket.

	if (nni_aio_result(s->aio_getq) != 0) {
		// Closed socket?
		return;
	}

	msg = nni_aio_get_msg(s->aio_getq);
	nni_aio_set_msg(s->aio_getq, NULL);

	// We yank the outgoing pipe id from the header
	if (nni_msg_header_len(msg) < 4) {
		nni_msg_free(msg);

		// Look for another message on the upper write queue.
		nni_msgq_aio_get(uwq, s->aio_getq);
		return;
	}

	id = nni_msg_header_trim_u32(msg);

	// Look for the pipe, and attempt to put the message there
	// (nonblocking) if we can.  If we can't for any reason, then we
	// free the message.
	if ((rv = nni_idhash_find(s->pipes, id, (void **) &p)) == 0) {
		rv = nni_msgq_tryput(p->sendq, msg);
	}
	if (rv != 0) {
		nni_msg_free(msg);
	}

	// Now look for another message on the upper write queue.
	nni_msgq_aio_get(uwq, s->aio_getq);
}

static void
rep_pipe_getq_cb(void *arg)
{
	rep_pipe *p = arg;

	if (nni_aio_result(p->aio_getq) != 0) {
		nni_pipe_stop(p->pipe);
		return;
	}

	nni_aio_set_msg(p->aio_send, nni_aio_get_msg(p->aio_getq));
	nni_aio_set_msg(p->aio_getq, NULL);

	nni_pipe_send(p->pipe, p->aio_send);
}

static void
rep_pipe_send_cb(void *arg)
{
	rep_pipe *p = arg;

	if (nni_aio_result(p->aio_send) != 0) {
		nni_msg_free(nni_aio_get_msg(p->aio_send));
		nni_aio_set_msg(p->aio_send, NULL);
		nni_pipe_stop(p->pipe);
		return;
	}

	nni_msgq_aio_get(p->sendq, p->aio_getq);
}

static void
rep_pipe_recv_cb(void *arg)
{
	rep_pipe *p = arg;
	rep_sock *s = p->rep;
	nni_msg * msg;
	int       rv;
	uint8_t * body;
	int       hops;

	if (nni_aio_result(p->aio_recv) != 0) {
		nni_pipe_stop(p->pipe);
		return;
	}

	msg = nni_aio_get_msg(p->aio_recv);
	nni_aio_set_msg(p->aio_recv, NULL);

	// Store the pipe id in the header, first thing.
	rv = nni_msg_header_append_u32(msg, nni_pipe_id(p->pipe));
	if (rv != 0) {
		// Failure here causes us to drop the message.
		goto drop;
	}

	// Move backtrace from body to header
	hops = 1;
	for (;;) {
		int end = 0;
		if (hops >= s->ttl) {
			// This isn't malformed, but it has gone through
			// too many hops.  Do not disconnect, because we
			// can legitimately receive messages with too many
			// hops from devices, etc.
			goto drop;
		}
		if (nni_msg_len(msg) < 4) {
			// Peer is speaking garbage. Kick it.
			nni_msg_free(msg);
			nni_pipe_stop(p->pipe);
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
	nni_aio_set_msg(p->aio_putq, msg);
	nni_msgq_aio_put(s->urq, p->aio_putq);
	return;

drop:
	nni_msg_free(msg);
	nni_pipe_recv(p->pipe, p->aio_recv);
}

static void
rep_pipe_putq_cb(void *arg)
{
	rep_pipe *p = arg;

	if (nni_aio_result(p->aio_putq) != 0) {
		nni_msg_free(nni_aio_get_msg(p->aio_putq));
		nni_aio_set_msg(p->aio_putq, NULL);
		nni_pipe_stop(p->pipe);
		return;
	}

	nni_pipe_recv(p->pipe, p->aio_recv);
}

static int
rep_sock_setopt(void *arg, int opt, const void *buf, size_t sz)
{
	rep_sock *s  = arg;
	int       rv = NNG_ENOTSUP;

	if (opt == nng_optid_maxttl) {
		rv = nni_setopt_int(&s->ttl, buf, sz, 1, 255);
	} else if (opt == nng_optid_raw) {
		rv = nni_setopt_int(&s->raw, buf, sz, 0, 1);
		nni_sock_senderr(s->sock, s->raw ? 0 : NNG_ESTATE);
	}
	return (rv);
}

static int
rep_sock_getopt(void *arg, int opt, void *buf, size_t *szp)
{
	rep_sock *s  = arg;
	int       rv = NNG_ENOTSUP;

	if (opt == nng_optid_maxttl) {
		rv = nni_getopt_int(&s->ttl, buf, szp);
	} else if (opt == nng_optid_raw) {
		rv = nni_getopt_int(&s->raw, buf, szp);
	}
	return (rv);
}

static nni_msg *
rep_sock_sfilter(void *arg, nni_msg *msg)
{
	rep_sock *s = arg;

	if (s->raw) {
		return (msg);
	}

	// Cannot send again until a receive is done...
	nni_sock_senderr(s->sock, NNG_ESTATE);

	// If we have a stored backtrace, append it to the header...
	// if we don't have a backtrace, discard the message.
	if (s->btrace == NULL) {
		nni_msg_free(msg);
		return (NULL);
	}

	// drop anything else in the header...
	nni_msg_header_clear(msg);

	if (nni_msg_header_append(msg, s->btrace, s->btrace_len) != 0) {
		nni_free(s->btrace, s->btrace_len);
		s->btrace     = NULL;
		s->btrace_len = 0;
		nni_msg_free(msg);
		return (NULL);
	}

	nni_free(s->btrace, s->btrace_len);
	s->btrace     = NULL;
	s->btrace_len = 0;
	return (msg);
}

static nni_msg *
rep_sock_rfilter(void *arg, nni_msg *msg)
{
	rep_sock *s = arg;
	char *    header;
	size_t    len;

	if (s->raw) {
		return (msg);
	}

	nni_sock_senderr(s->sock, 0);
	len    = nni_msg_header_len(msg);
	header = nni_msg_header(msg);
	if (s->btrace != NULL) {
		nni_free(s->btrace, s->btrace_len);
		s->btrace     = NULL;
		s->btrace_len = 0;
	}
	if ((s->btrace = nni_alloc(len)) == NULL) {
		nni_msg_free(msg);
		return (NULL);
	}
	s->btrace_len = len;
	memcpy(s->btrace, header, len);
	nni_msg_header_clear(msg);
	return (msg);
}

// This is the global protocol structure -- our linkage to the core.
// This should be the only global non-static symbol in this file.
static nni_proto_pipe_ops rep_pipe_ops = {
	.pipe_init  = rep_pipe_init,
	.pipe_fini  = rep_pipe_fini,
	.pipe_start = rep_pipe_start,
	.pipe_stop  = rep_pipe_stop,
};

static nni_proto_sock_ops rep_sock_ops = {
	.sock_init    = rep_sock_init,
	.sock_fini    = rep_sock_fini,
	.sock_open    = rep_sock_open,
	.sock_close   = rep_sock_close,
	.sock_setopt  = rep_sock_setopt,
	.sock_getopt  = rep_sock_getopt,
	.sock_rfilter = rep_sock_rfilter,
	.sock_sfilter = rep_sock_sfilter,
};

static nni_proto nni_rep_proto = {
	.proto_version  = NNI_PROTOCOL_VERSION,
	.proto_self     = { NNG_PROTO_REP_V0, "rep" },
	.proto_peer     = { NNG_PROTO_REQ_V0, "req" },
	.proto_flags    = NNI_PROTO_FLAG_SNDRCV,
	.proto_sock_ops = &rep_sock_ops,
	.proto_pipe_ops = &rep_pipe_ops,
};

int
nng_rep0_open(nng_socket *sidp)
{
	return (nni_proto_open(sidp, &nni_rep_proto));
}
