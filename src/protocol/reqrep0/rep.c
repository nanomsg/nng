//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <stdlib.h>
#include <string.h>

#include "core/nng_impl.h"
#include "protocol/reqrep0/rep.h"

// Response protocol.  The REP protocol is the "reply" side of a
// request-reply pair.  This is useful for building RPC servers, for
// example.

#ifndef NNI_PROTO_REQ_V0
#define NNI_PROTO_REQ_V0 NNI_PROTO(3, 0)
#endif

#ifndef NNI_PROTO_REP_V0
#define NNI_PROTO_REP_V0 NNI_PROTO(3, 1)
#endif

typedef struct rep0_pipe rep0_pipe;
typedef struct rep0_sock rep0_sock;

static void rep0_sock_getq_cb(void *);
static void rep0_pipe_getq_cb(void *);
static void rep0_pipe_putq_cb(void *);
static void rep0_pipe_send_cb(void *);
static void rep0_pipe_recv_cb(void *);
static void rep0_pipe_fini(void *);

// rep0_sock is our per-socket protocol private structure.
struct rep0_sock {
	nni_msgq *  uwq;
	nni_msgq *  urq;
	nni_mtx     lk;
	int         ttl;
	nni_idhash *pipes;
	char *      btrace;
	size_t      btrace_len;
	nni_aio *   aio_getq;
};

// rep0_pipe is our per-pipe protocol private structure.
struct rep0_pipe {
	nni_pipe * pipe;
	rep0_sock *rep;
	nni_msgq * sendq;
	nni_aio *  aio_getq;
	nni_aio *  aio_send;
	nni_aio *  aio_recv;
	nni_aio *  aio_putq;
};

static void
rep0_sock_fini(void *arg)
{
	rep0_sock *s = arg;

	nni_aio_stop(s->aio_getq);
	nni_aio_fini(s->aio_getq);
	nni_idhash_fini(s->pipes);
	if (s->btrace != NULL) {
		nni_free(s->btrace, s->btrace_len);
	}
	nni_mtx_fini(&s->lk);
	NNI_FREE_STRUCT(s);
}

static int
rep0_sock_init(void **sp, nni_sock *sock)
{
	rep0_sock *s;
	int        rv;

	if ((s = NNI_ALLOC_STRUCT(s)) == NULL) {
		return (NNG_ENOMEM);
	}
	nni_mtx_init(&s->lk);
	if (((rv = nni_idhash_init(&s->pipes)) != 0) ||
	    ((rv = nni_aio_init(&s->aio_getq, rep0_sock_getq_cb, s)) != 0)) {
		rep0_sock_fini(s);
		return (rv);
	}

	s->ttl        = 8; // Per RFC
	s->btrace     = NULL;
	s->btrace_len = 0;
	s->uwq        = nni_sock_sendq(sock);
	s->urq        = nni_sock_recvq(sock);

	*sp = s;

	return (0);
}

static void
rep0_sock_open(void *arg)
{
	rep0_sock *s = arg;

	nni_msgq_aio_get(s->uwq, s->aio_getq);
}

static void
rep0_sock_close(void *arg)
{
	rep0_sock *s = arg;

	nni_aio_abort(s->aio_getq, NNG_ECLOSED);
}

static void
rep0_pipe_fini(void *arg)
{
	rep0_pipe *p = arg;

	nni_aio_fini(p->aio_getq);
	nni_aio_fini(p->aio_send);
	nni_aio_fini(p->aio_recv);
	nni_aio_fini(p->aio_putq);
	nni_msgq_fini(p->sendq);
	NNI_FREE_STRUCT(p);
}

static int
rep0_pipe_init(void **pp, nni_pipe *pipe, void *s)
{
	rep0_pipe *p;
	int        rv;

	if ((p = NNI_ALLOC_STRUCT(p)) == NULL) {
		return (NNG_ENOMEM);
	}
	if (((rv = nni_msgq_init(&p->sendq, 2)) != 0) ||
	    ((rv = nni_aio_init(&p->aio_getq, rep0_pipe_getq_cb, p)) != 0) ||
	    ((rv = nni_aio_init(&p->aio_send, rep0_pipe_send_cb, p)) != 0) ||
	    ((rv = nni_aio_init(&p->aio_recv, rep0_pipe_recv_cb, p)) != 0) ||
	    ((rv = nni_aio_init(&p->aio_putq, rep0_pipe_putq_cb, p)) != 0)) {
		rep0_pipe_fini(p);
		return (rv);
	}

	p->pipe = pipe;
	p->rep  = s;
	*pp     = p;
	return (0);
}

static int
rep0_pipe_start(void *arg)
{
	rep0_pipe *p = arg;
	rep0_sock *s = p->rep;
	int        rv;

	if ((rv = nni_idhash_insert(s->pipes, nni_pipe_id(p->pipe), p)) != 0) {
		return (rv);
	}

	nni_msgq_aio_get(p->sendq, p->aio_getq);
	nni_pipe_recv(p->pipe, p->aio_recv);
	return (0);
}

static void
rep0_pipe_stop(void *arg)
{
	rep0_pipe *p = arg;
	rep0_sock *s = p->rep;

	nni_msgq_close(p->sendq);
	nni_aio_stop(p->aio_getq);
	nni_aio_stop(p->aio_send);
	nni_aio_stop(p->aio_recv);
	nni_aio_stop(p->aio_putq);

	nni_idhash_remove(s->pipes, nni_pipe_id(p->pipe));
}

static void
rep0_sock_getq_cb(void *arg)
{
	rep0_sock *s   = arg;
	nni_msgq * uwq = s->uwq;
	nni_msg *  msg;
	uint32_t   id;
	rep0_pipe *p;
	int        rv;

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
	// XXX: LOCKING?!?!
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
rep0_pipe_getq_cb(void *arg)
{
	rep0_pipe *p = arg;

	if (nni_aio_result(p->aio_getq) != 0) {
		nni_pipe_stop(p->pipe);
		return;
	}

	nni_aio_set_msg(p->aio_send, nni_aio_get_msg(p->aio_getq));
	nni_aio_set_msg(p->aio_getq, NULL);

	nni_pipe_send(p->pipe, p->aio_send);
}

static void
rep0_pipe_send_cb(void *arg)
{
	rep0_pipe *p = arg;

	if (nni_aio_result(p->aio_send) != 0) {
		nni_msg_free(nni_aio_get_msg(p->aio_send));
		nni_aio_set_msg(p->aio_send, NULL);
		nni_pipe_stop(p->pipe);
		return;
	}

	nni_msgq_aio_get(p->sendq, p->aio_getq);
}

static void
rep0_pipe_recv_cb(void *arg)
{
	rep0_pipe *p = arg;
	rep0_sock *s = p->rep;
	nni_msg *  msg;
	int        rv;
	uint8_t *  body;
	int        hops;

	if (nni_aio_result(p->aio_recv) != 0) {
		nni_pipe_stop(p->pipe);
		return;
	}

	msg = nni_aio_get_msg(p->aio_recv);
	nni_aio_set_msg(p->aio_recv, NULL);

	nni_msg_set_pipe(msg, nni_pipe_id(p->pipe));

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
rep0_pipe_putq_cb(void *arg)
{
	rep0_pipe *p = arg;

	if (nni_aio_result(p->aio_putq) != 0) {
		nni_msg_free(nni_aio_get_msg(p->aio_putq));
		nni_aio_set_msg(p->aio_putq, NULL);
		nni_pipe_stop(p->pipe);
		return;
	}

	nni_pipe_recv(p->pipe, p->aio_recv);
}

static int
rep0_sock_setopt_maxttl(void *arg, const void *buf, size_t sz, int typ)
{
	rep0_sock *s = arg;
	return (nni_copyin_int(&s->ttl, buf, sz, 1, 255, typ));
}

static int
rep0_sock_getopt_maxttl(void *arg, void *buf, size_t *szp, int typ)
{
	rep0_sock *s = arg;
	return (nni_copyout_int(s->ttl, buf, szp, typ));
}

static nni_msg *
rep0_sock_filter(void *arg, nni_msg *msg)
{
	rep0_sock *s = arg;
	char *     header;
	size_t     len;

	nni_mtx_lock(&s->lk);

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
	nni_mtx_unlock(&s->lk);
	return (msg);
}

static void
rep0_sock_send_raw(void *arg, nni_aio *aio)
{
	rep0_sock *s = arg;
	nni_msgq_aio_put(s->uwq, aio);
}

static void
rep0_sock_send(void *arg, nni_aio *aio)
{
	rep0_sock *s = arg;
	int        rv;
	nni_msg *  msg;

	nni_mtx_lock(&s->lk);
	if (s->btrace == NULL) {
		nni_mtx_unlock(&s->lk);
		nni_aio_finish_error(aio, NNG_ESTATE);
		return;
	}

	msg = nni_aio_get_msg(aio);

	// drop anything else in the header...  (it should already be
	// empty, but there can be stale backtrace info there.)
	nni_msg_header_clear(msg);

	if ((rv = nni_msg_header_append(msg, s->btrace, s->btrace_len)) != 0) {
		nni_mtx_unlock(&s->lk);
		nni_aio_finish_error(aio, rv);
		return;
	}

	nni_free(s->btrace, s->btrace_len);
	s->btrace     = NULL;
	s->btrace_len = 0;

	nni_mtx_unlock(&s->lk);
	nni_msgq_aio_put(s->uwq, aio);
}

static void
rep0_sock_recv(void *arg, nni_aio *aio)
{
	rep0_sock *s = arg;

	nni_msgq_aio_get(s->urq, aio);
}

// This is the global protocol structure -- our linkage to the core.
// This should be the only global non-static symbol in this file.
static nni_proto_pipe_ops rep0_pipe_ops = {
	.pipe_init  = rep0_pipe_init,
	.pipe_fini  = rep0_pipe_fini,
	.pipe_start = rep0_pipe_start,
	.pipe_stop  = rep0_pipe_stop,
};

static nni_proto_sock_option rep0_sock_options[] = {
	{
	    .pso_name   = NNG_OPT_MAXTTL,
	    .pso_type   = NNI_TYPE_INT32,
	    .pso_getopt = rep0_sock_getopt_maxttl,
	    .pso_setopt = rep0_sock_setopt_maxttl,
	},
	// terminate list
	{
	    .pso_name = NULL,
	},
};

static nni_proto_sock_ops rep0_sock_ops = {
	.sock_init    = rep0_sock_init,
	.sock_fini    = rep0_sock_fini,
	.sock_open    = rep0_sock_open,
	.sock_close   = rep0_sock_close,
	.sock_options = rep0_sock_options,
	.sock_filter  = rep0_sock_filter,
	.sock_send    = rep0_sock_send,
	.sock_recv    = rep0_sock_recv,
};

static nni_proto_sock_ops rep0_sock_ops_raw = {
	.sock_init    = rep0_sock_init,
	.sock_fini    = rep0_sock_fini,
	.sock_open    = rep0_sock_open,
	.sock_close   = rep0_sock_close,
	.sock_options = rep0_sock_options,
	.sock_filter  = NULL, // No filtering for raw mode
	.sock_send    = rep0_sock_send_raw,
	.sock_recv    = rep0_sock_recv,
};

static nni_proto rep0_proto = {
	.proto_version  = NNI_PROTOCOL_VERSION,
	.proto_self     = { NNI_PROTO_REP_V0, "rep" },
	.proto_peer     = { NNI_PROTO_REQ_V0, "req" },
	.proto_flags    = NNI_PROTO_FLAG_SNDRCV,
	.proto_sock_ops = &rep0_sock_ops,
	.proto_pipe_ops = &rep0_pipe_ops,
};

static nni_proto rep0_proto_raw = {
	.proto_version  = NNI_PROTOCOL_VERSION,
	.proto_self     = { NNI_PROTO_REP_V0, "rep" },
	.proto_peer     = { NNI_PROTO_REQ_V0, "req" },
	.proto_flags    = NNI_PROTO_FLAG_SNDRCV | NNI_PROTO_FLAG_RAW,
	.proto_sock_ops = &rep0_sock_ops_raw,
	.proto_pipe_ops = &rep0_pipe_ops,
};

int
nng_rep0_open(nng_socket *sidp)
{
	return (nni_proto_open(sidp, &rep0_proto));
}

int
nng_rep0_open_raw(nng_socket *sidp)
{
	return (nni_proto_open(sidp, &rep0_proto_raw));
}
