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

// Respondent protocol.  The RESPONDENT protocol is the "replier" side of
// the surveyor pattern.  This is useful for building service discovery, or
// voting algorithsm, for example.

typedef struct resp_pipe resp_pipe;
typedef struct resp_sock resp_sock;

static void resp_recv_cb(void *);
static void resp_putq_cb(void *);
static void resp_getq_cb(void *);
static void resp_send_cb(void *);
static void resp_sock_getq_cb(void *);
static void resp_pipe_fini(void *);

// A resp_sock is our per-socket protocol private structure.
struct resp_sock {
	nni_sock *  nsock;
	nni_msgq *  urq;
	nni_msgq *  uwq;
	int         raw;
	int         ttl;
	nni_idhash *pipes;
	char *      btrace;
	size_t      btrace_len;
	nni_aio *   aio_getq;
	nni_mtx     mtx;
};

// A resp_pipe is our per-pipe protocol private structure.
struct resp_pipe {
	nni_pipe * npipe;
	resp_sock *psock;
	uint32_t   id;
	nni_msgq * sendq;
	nni_aio *  aio_getq;
	nni_aio *  aio_putq;
	nni_aio *  aio_send;
	nni_aio *  aio_recv;
};

static void
resp_sock_fini(void *arg)
{
	resp_sock *s = arg;

	nni_aio_stop(s->aio_getq);
	nni_aio_fini(s->aio_getq);
	nni_idhash_fini(s->pipes);
	if (s->btrace != NULL) {
		nni_free(s->btrace, s->btrace_len);
	}
	nni_mtx_fini(&s->mtx);
	NNI_FREE_STRUCT(s);
}

static int
resp_sock_init(void **sp, nni_sock *nsock)
{
	resp_sock *s;
	int        rv;

	if ((s = NNI_ALLOC_STRUCT(s)) == NULL) {
		return (NNG_ENOMEM);
	}
	nni_mtx_init(&s->mtx);
	if (((rv = nni_idhash_init(&s->pipes)) != 0) ||
	    ((rv = nni_aio_init(&s->aio_getq, resp_sock_getq_cb, s)) != 0)) {
		resp_sock_fini(s);
		return (rv);
	}

	s->ttl        = 8; // Per RFC
	s->nsock      = nsock;
	s->raw        = 0;
	s->btrace     = NULL;
	s->btrace_len = 0;
	s->urq        = nni_sock_recvq(nsock);
	s->uwq        = nni_sock_sendq(nsock);

	*sp = s;
	return (0);
}

static void
resp_sock_open(void *arg)
{
	resp_sock *s = arg;

	nni_msgq_aio_get(s->uwq, s->aio_getq);
}

static void
resp_sock_close(void *arg)
{
	resp_sock *s = arg;

	nni_aio_cancel(s->aio_getq, NNG_ECLOSED);
}

static void
resp_pipe_fini(void *arg)
{
	resp_pipe *p = arg;

	nni_aio_fini(p->aio_putq);
	nni_aio_fini(p->aio_getq);
	nni_aio_fini(p->aio_send);
	nni_aio_fini(p->aio_recv);
	nni_msgq_fini(p->sendq);
	NNI_FREE_STRUCT(p);
}

static int
resp_pipe_init(void **pp, nni_pipe *npipe, void *s)
{
	resp_pipe *p;
	int        rv;

	if ((p = NNI_ALLOC_STRUCT(p)) == NULL) {
		return (NNG_ENOMEM);
	}
	if (((rv = nni_msgq_init(&p->sendq, 2)) != 0) ||
	    ((rv = nni_aio_init(&p->aio_putq, resp_putq_cb, p)) != 0) ||
	    ((rv = nni_aio_init(&p->aio_recv, resp_recv_cb, p)) != 0) ||
	    ((rv = nni_aio_init(&p->aio_getq, resp_getq_cb, p)) != 0) ||
	    ((rv = nni_aio_init(&p->aio_send, resp_send_cb, p)) != 0)) {
		resp_pipe_fini(p);
		return (rv);
	}

	p->npipe = npipe;
	p->psock = s;
	*pp      = p;
	return (0);
}

static int
resp_pipe_start(void *arg)
{
	resp_pipe *p = arg;
	resp_sock *s = p->psock;
	int        rv;

	p->id = nni_pipe_id(p->npipe);

	nni_mtx_lock(&s->mtx);
	rv = nni_idhash_insert(s->pipes, p->id, p);
	nni_mtx_unlock(&s->mtx);
	if (rv != 0) {
		return (rv);
	}

	nni_pipe_recv(p->npipe, p->aio_recv);
	nni_msgq_aio_get(p->sendq, p->aio_getq);

	return (rv);
}

static void
resp_pipe_stop(void *arg)
{
	resp_pipe *p = arg;
	resp_sock *s = p->psock;

	nni_msgq_close(p->sendq);
	nni_aio_stop(p->aio_putq);
	nni_aio_stop(p->aio_getq);
	nni_aio_stop(p->aio_send);
	nni_aio_stop(p->aio_recv);

	if (p->id != 0) {
		nni_mtx_lock(&s->mtx);
		nni_idhash_remove(s->pipes, p->id);
		nni_mtx_unlock(&s->mtx);
		p->id = 0;
	}
}

// resp_sock_send watches for messages from the upper write queue,
// extracts the destination pipe, and forwards it to the appropriate
// destination pipe via a separate queue.  This prevents a single bad
// or slow pipe from gumming up the works for the entire socket.s

void
resp_sock_getq_cb(void *arg)
{
	resp_sock *s = arg;
	nni_msg *  msg;
	uint32_t   id;
	resp_pipe *p;
	int        rv;

	if (nni_aio_result(s->aio_getq) != 0) {
		return;
	}
	msg = nni_aio_get_msg(s->aio_getq);
	nni_aio_set_msg(s->aio_getq, NULL);

	// We yank the outgoing pipe id from the header
	if (nni_msg_header_len(msg) < 4) {
		nni_msg_free(msg);
		// We can't really close down the socket, so just keep going.
		nni_msgq_aio_get(s->uwq, s->aio_getq);
		return;
	}
	id = nni_msg_header_trim_u32(msg);

	nni_mtx_lock(&s->mtx);
	if ((rv = nni_idhash_find(s->pipes, id, (void **) &p)) != 0) {
		// Destination pipe not present.
		nni_msg_free(msg);
	} else {
		// Non-blocking put.
		if (nni_msgq_tryput(p->sendq, msg) != 0) {
			nni_msg_free(msg);
		}
	}
	nni_msgq_aio_get(s->uwq, s->aio_getq);
	nni_mtx_unlock(&s->mtx);
}

void
resp_getq_cb(void *arg)
{
	resp_pipe *p = arg;

	if (nni_aio_result(p->aio_getq) != 0) {
		nni_pipe_stop(p->npipe);
		return;
	}

	nni_aio_set_msg(p->aio_send, nni_aio_get_msg(p->aio_getq));
	nni_aio_set_msg(p->aio_getq, NULL);

	nni_pipe_send(p->npipe, p->aio_send);
}

void
resp_send_cb(void *arg)
{
	resp_pipe *p = arg;

	if (nni_aio_result(p->aio_send) != 0) {
		nni_msg_free(nni_aio_get_msg(p->aio_send));
		nni_aio_set_msg(p->aio_send, NULL);
		nni_pipe_stop(p->npipe);
		return;
	}

	nni_msgq_aio_get(p->sendq, p->aio_getq);
}

static void
resp_recv_cb(void *arg)
{
	resp_pipe *p = arg;
	resp_sock *s = p->psock;
	nni_msgq * urq;
	nni_msg *  msg;
	int        hops;
	int        rv;

	if (nni_aio_result(p->aio_recv) != 0) {
		goto error;
	}

	urq = nni_sock_recvq(s->nsock);

	msg = nni_aio_get_msg(p->aio_recv);
	nni_aio_set_msg(p->aio_recv, NULL);
	nni_msg_set_pipe(msg, p->id);

	// Store the pipe id in the header, first thing.
	if (nni_msg_header_append_u32(msg, p->id) != 0) {
		nni_msg_free(msg);
		goto error;
	}

	// Move backtrace from body to header
	hops = 0;
	for (;;) {
		int      end = 0;
		uint8_t *body;

		if (hops >= s->ttl) {
			nni_msg_free(msg);
			goto error;
		}
		if (nni_msg_len(msg) < 4) {
			nni_msg_free(msg);
			goto error;
		}
		body = nni_msg_body(msg);
		end  = (body[0] & 0x80) ? 1 : 0;
		rv   = nni_msg_header_append(msg, body, 4);
		if (rv != 0) {
			nni_msg_free(msg);
			goto error;
		}
		nni_msg_trim(msg, 4);
		if (end) {
			break;
		}
	}

	// Now send it up.
	nni_aio_set_msg(p->aio_putq, msg);
	nni_msgq_aio_put(urq, p->aio_putq);
	return;

error:
	nni_pipe_stop(p->npipe);
}

static void
resp_putq_cb(void *arg)
{
	resp_pipe *p = arg;

	if (nni_aio_result(p->aio_putq) != 0) {
		nni_msg_free(nni_aio_get_msg(p->aio_putq));
		nni_aio_set_msg(p->aio_putq, NULL);
		nni_pipe_stop(p->npipe);
	}

	nni_pipe_recv(p->npipe, p->aio_recv);
}

static int
resp_sock_setopt_raw(void *arg, const void *buf, size_t sz)
{
	resp_sock *s = arg;
	int        rv;

	nni_mtx_lock(&s->mtx);
	rv = nni_setopt_int(&s->raw, buf, sz, 0, 1);
	nni_mtx_unlock(&s->mtx);
	return (rv);
}

static int
resp_sock_getopt_raw(void *arg, void *buf, size_t *szp)
{
	resp_sock *s = arg;
	return (nni_getopt_int(s->raw, buf, szp));
}

static int
resp_sock_setopt_maxttl(void *arg, const void *buf, size_t sz)
{
	resp_sock *s = arg;
	return (nni_setopt_int(&s->ttl, buf, sz, 1, 255));
}

static int
resp_sock_getopt_maxttl(void *arg, void *buf, size_t *szp)
{
	resp_sock *s = arg;
	return (nni_getopt_int(s->ttl, buf, szp));
}

static void
resp_sock_send(void *arg, nni_aio *aio)
{
	resp_sock *s = arg;
	nni_msg *  msg;
	int        rv;

	nni_mtx_lock(&s->mtx);
	if (s->raw) {
		nni_mtx_unlock(&s->mtx);
		nni_sock_send_pending(s->nsock);
		nni_msgq_aio_put(s->uwq, aio);
		return;
	}

	msg = nni_aio_get_msg(aio);

	// If we have a stored backtrace, append it to the header...
	// if we don't have a backtrace, discard the message.
	if (s->btrace == NULL) {
		nni_mtx_unlock(&s->mtx);
		nni_aio_finish_error(aio, NNG_ESTATE);
		return;
	}

	// drop anything else in the header...
	nni_msg_header_clear(msg);

	if ((rv = nni_msg_header_append(msg, s->btrace, s->btrace_len)) != 0) {
		nni_mtx_unlock(&s->mtx);
		nni_aio_finish_error(aio, rv);
		return;
	}

	nni_free(s->btrace, s->btrace_len);
	s->btrace     = NULL;
	s->btrace_len = 0;

	nni_mtx_unlock(&s->mtx);
	nni_sock_send_pending(s->nsock);
	nni_msgq_aio_put(s->uwq, aio);
}

static nni_msg *
resp_sock_filter(void *arg, nni_msg *msg)
{
	resp_sock *s = arg;
	char *     header;
	size_t     len;

	nni_mtx_lock(&s->mtx);
	if (s->raw) {
		nni_mtx_unlock(&s->mtx);
		return (msg);
	}

	len    = nni_msg_header_len(msg);
	header = nni_msg_header(msg);
	if (s->btrace != NULL) {
		nni_free(s->btrace, s->btrace_len);
		s->btrace     = NULL;
		s->btrace_len = 0;
	}
	if ((s->btrace = nni_alloc(len)) == NULL) {
		nni_mtx_unlock(&s->mtx);
		nni_msg_free(msg);
		return (NULL);
	}
	s->btrace_len = len;
	memcpy(s->btrace, header, len);
	nni_msg_header_clear(msg);
	nni_mtx_unlock(&s->mtx);
	return (msg);
}

static void
resp_sock_recv(void *arg, nni_aio *aio)
{
	resp_sock *s = arg;

	nni_sock_recv_pending(s->nsock);
	nni_msgq_aio_get(s->urq, aio);
}

static nni_proto_pipe_ops resp_pipe_ops = {
	.pipe_init  = resp_pipe_init,
	.pipe_fini  = resp_pipe_fini,
	.pipe_start = resp_pipe_start,
	.pipe_stop  = resp_pipe_stop,
};

static nni_proto_sock_option resp_sock_options[] = {
	{
	    .pso_name   = NNG_OPT_RAW,
	    .pso_getopt = resp_sock_getopt_raw,
	    .pso_setopt = resp_sock_setopt_raw,
	},
	{
	    .pso_name   = NNG_OPT_MAXTTL,
	    .pso_getopt = resp_sock_getopt_maxttl,
	    .pso_setopt = resp_sock_setopt_maxttl,
	},
	// terminate list
	{ NULL, NULL, NULL },
};

static nni_proto_sock_ops resp_sock_ops = {
	.sock_init    = resp_sock_init,
	.sock_fini    = resp_sock_fini,
	.sock_open    = resp_sock_open,
	.sock_close   = resp_sock_close,
	.sock_filter  = resp_sock_filter,
	.sock_send    = resp_sock_send,
	.sock_recv    = resp_sock_recv,
	.sock_options = resp_sock_options,
};

static nni_proto resp_proto = {
	.proto_version  = NNI_PROTOCOL_VERSION,
	.proto_self     = { NNG_PROTO_RESPONDENT_V0, "respondent" },
	.proto_peer     = { NNG_PROTO_SURVEYOR_V0, "surveyor" },
	.proto_flags    = NNI_PROTO_FLAG_SNDRCV,
	.proto_sock_ops = &resp_sock_ops,
	.proto_pipe_ops = &resp_pipe_ops,
};

int
nng_respondent0_open(nng_socket *sidp)
{
	return (nni_proto_open(sidp, &resp_proto));
}
