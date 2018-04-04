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
#include "protocol/survey0/respond.h"

// Respondent protocol.  The RESPONDENT protocol is the "replier" side of
// the surveyor pattern.  This is useful for building service discovery, or
// voting algorithms, for example.

#ifndef NNI_PROTO_SURVEYOR_V0
#define NNI_PROTO_SURVEYOR_V0 NNI_PROTO(6, 2)
#endif

#ifndef NNI_PROTO_RESPONDENT_V0
#define NNI_PROTO_RESPONDENT_V0 NNI_PROTO(6, 3)
#endif

typedef struct resp0_pipe resp0_pipe;
typedef struct resp0_sock resp0_sock;

static void resp0_recv_cb(void *);
static void resp0_putq_cb(void *);
static void resp0_getq_cb(void *);
static void resp0_send_cb(void *);
static void resp0_sock_getq_cb(void *);
static void resp0_pipe_fini(void *);

// resp0_sock is our per-socket protocol private structure.
struct resp0_sock {
	nni_msgq *  urq;
	nni_msgq *  uwq;
	int         ttl;
	nni_idhash *pipes;
	char *      btrace;
	size_t      btrace_len;
	nni_aio *   aio_getq;
	nni_mtx     mtx;
};

// resp0_pipe is our per-pipe protocol private structure.
struct resp0_pipe {
	nni_pipe *  npipe;
	resp0_sock *psock;
	uint32_t    id;
	nni_msgq *  sendq;
	nni_aio *   aio_getq;
	nni_aio *   aio_putq;
	nni_aio *   aio_send;
	nni_aio *   aio_recv;
};

static void
resp0_sock_fini(void *arg)
{
	resp0_sock *s = arg;

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
resp0_sock_init(void **sp, nni_sock *nsock)
{
	resp0_sock *s;
	int         rv;

	if ((s = NNI_ALLOC_STRUCT(s)) == NULL) {
		return (NNG_ENOMEM);
	}
	nni_mtx_init(&s->mtx);
	if (((rv = nni_idhash_init(&s->pipes)) != 0) ||
	    ((rv = nni_aio_init(&s->aio_getq, resp0_sock_getq_cb, s)) != 0)) {
		resp0_sock_fini(s);
		return (rv);
	}

	s->ttl        = 8; // Per RFC
	s->btrace     = NULL;
	s->btrace_len = 0;
	s->urq        = nni_sock_recvq(nsock);
	s->uwq        = nni_sock_sendq(nsock);

	*sp = s;
	return (0);
}

static void
resp0_sock_open(void *arg)
{
	resp0_sock *s = arg;

	nni_msgq_aio_get(s->uwq, s->aio_getq);
}

static void
resp0_sock_close(void *arg)
{
	resp0_sock *s = arg;

	nni_aio_abort(s->aio_getq, NNG_ECLOSED);
}

static void
resp0_pipe_fini(void *arg)
{
	resp0_pipe *p = arg;

	nni_aio_fini(p->aio_putq);
	nni_aio_fini(p->aio_getq);
	nni_aio_fini(p->aio_send);
	nni_aio_fini(p->aio_recv);
	nni_msgq_fini(p->sendq);
	NNI_FREE_STRUCT(p);
}

static int
resp0_pipe_init(void **pp, nni_pipe *npipe, void *s)
{
	resp0_pipe *p;
	int         rv;

	if ((p = NNI_ALLOC_STRUCT(p)) == NULL) {
		return (NNG_ENOMEM);
	}
	if (((rv = nni_msgq_init(&p->sendq, 2)) != 0) ||
	    ((rv = nni_aio_init(&p->aio_putq, resp0_putq_cb, p)) != 0) ||
	    ((rv = nni_aio_init(&p->aio_recv, resp0_recv_cb, p)) != 0) ||
	    ((rv = nni_aio_init(&p->aio_getq, resp0_getq_cb, p)) != 0) ||
	    ((rv = nni_aio_init(&p->aio_send, resp0_send_cb, p)) != 0)) {
		resp0_pipe_fini(p);
		return (rv);
	}

	p->npipe = npipe;
	p->psock = s;
	*pp      = p;
	return (0);
}

static int
resp0_pipe_start(void *arg)
{
	resp0_pipe *p = arg;
	resp0_sock *s = p->psock;
	int         rv;

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
resp0_pipe_stop(void *arg)
{
	resp0_pipe *p = arg;
	resp0_sock *s = p->psock;

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

// resp0_sock_send watches for messages from the upper write queue,
// extracts the destination pipe, and forwards it to the appropriate
// destination pipe via a separate queue.  This prevents a single bad
// or slow pipe from gumming up the works for the entire socket.s

void
resp0_sock_getq_cb(void *arg)
{
	resp0_sock *s = arg;
	nni_msg *   msg;
	uint32_t    id;
	resp0_pipe *p;
	int         rv;

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
resp0_getq_cb(void *arg)
{
	resp0_pipe *p = arg;

	if (nni_aio_result(p->aio_getq) != 0) {
		nni_pipe_stop(p->npipe);
		return;
	}

	nni_aio_set_msg(p->aio_send, nni_aio_get_msg(p->aio_getq));
	nni_aio_set_msg(p->aio_getq, NULL);

	nni_pipe_send(p->npipe, p->aio_send);
}

void
resp0_send_cb(void *arg)
{
	resp0_pipe *p = arg;

	if (nni_aio_result(p->aio_send) != 0) {
		nni_msg_free(nni_aio_get_msg(p->aio_send));
		nni_aio_set_msg(p->aio_send, NULL);
		nni_pipe_stop(p->npipe);
		return;
	}

	nni_msgq_aio_get(p->sendq, p->aio_getq);
}

static void
resp0_recv_cb(void *arg)
{
	resp0_pipe *p   = arg;
	resp0_sock *s   = p->psock;
	nni_msgq *  urq = s->urq;
	nni_msg *   msg;
	int         hops;
	int         rv;

	if (nni_aio_result(p->aio_recv) != 0) {
		goto error;
	}

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
resp0_putq_cb(void *arg)
{
	resp0_pipe *p = arg;

	if (nni_aio_result(p->aio_putq) != 0) {
		nni_msg_free(nni_aio_get_msg(p->aio_putq));
		nni_aio_set_msg(p->aio_putq, NULL);
		nni_pipe_stop(p->npipe);
	}

	nni_pipe_recv(p->npipe, p->aio_recv);
}

static int
resp0_sock_setopt_maxttl(void *arg, const void *buf, size_t sz, int typ)
{
	resp0_sock *s = arg;
	return (nni_copyin_int(&s->ttl, buf, sz, 1, 255, typ));
}

static int
resp0_sock_getopt_maxttl(void *arg, void *buf, size_t *szp, int typ)
{
	resp0_sock *s = arg;
	return (nni_copyout_int(s->ttl, buf, szp, typ));
}

static void
resp0_sock_send_raw(void *arg, nni_aio *aio)
{
	resp0_sock *s = arg;

	nni_msgq_aio_put(s->uwq, aio);
}

static void
resp0_sock_send(void *arg, nni_aio *aio)
{
	resp0_sock *s = arg;
	nni_msg *   msg;
	int         rv;

	nni_mtx_lock(&s->mtx);

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
	nni_msgq_aio_put(s->uwq, aio);
}

static nni_msg *
resp0_sock_filter(void *arg, nni_msg *msg)
{
	resp0_sock *s = arg;
	char *      header;
	size_t      len;

	nni_mtx_lock(&s->mtx);

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
resp0_sock_recv(void *arg, nni_aio *aio)
{
	resp0_sock *s = arg;

	nni_msgq_aio_get(s->urq, aio);
}

static nni_proto_pipe_ops resp0_pipe_ops = {
	.pipe_init  = resp0_pipe_init,
	.pipe_fini  = resp0_pipe_fini,
	.pipe_start = resp0_pipe_start,
	.pipe_stop  = resp0_pipe_stop,
};

static nni_proto_sock_option resp0_sock_options[] = {
	{
	    .pso_name   = NNG_OPT_MAXTTL,
	    .pso_type   = NNI_TYPE_INT32,
	    .pso_getopt = resp0_sock_getopt_maxttl,
	    .pso_setopt = resp0_sock_setopt_maxttl,
	},
	// terminate list
	{
	    .pso_name = NULL,
	},
};

static nni_proto_sock_ops resp0_sock_ops = {
	.sock_init    = resp0_sock_init,
	.sock_fini    = resp0_sock_fini,
	.sock_open    = resp0_sock_open,
	.sock_close   = resp0_sock_close,
	.sock_filter  = resp0_sock_filter,
	.sock_send    = resp0_sock_send,
	.sock_recv    = resp0_sock_recv,
	.sock_options = resp0_sock_options,
};

static nni_proto_sock_ops resp0_sock_ops_raw = {
	.sock_init    = resp0_sock_init,
	.sock_fini    = resp0_sock_fini,
	.sock_open    = resp0_sock_open,
	.sock_close   = resp0_sock_close,
	.sock_filter  = NULL, // no filter for raw
	.sock_send    = resp0_sock_send_raw,
	.sock_recv    = resp0_sock_recv,
	.sock_options = resp0_sock_options,
};

static nni_proto resp0_proto = {
	.proto_version  = NNI_PROTOCOL_VERSION,
	.proto_self     = { NNI_PROTO_RESPONDENT_V0, "respondent" },
	.proto_peer     = { NNI_PROTO_SURVEYOR_V0, "surveyor" },
	.proto_flags    = NNI_PROTO_FLAG_SNDRCV,
	.proto_sock_ops = &resp0_sock_ops,
	.proto_pipe_ops = &resp0_pipe_ops,
};

static nni_proto resp0_proto_raw = {
	.proto_version  = NNI_PROTOCOL_VERSION,
	.proto_self     = { NNI_PROTO_RESPONDENT_V0, "respondent" },
	.proto_peer     = { NNI_PROTO_SURVEYOR_V0, "surveyor" },
	.proto_flags    = NNI_PROTO_FLAG_SNDRCV | NNI_PROTO_FLAG_RAW,
	.proto_sock_ops = &resp0_sock_ops_raw,
	.proto_pipe_ops = &resp0_pipe_ops,
};

int
nng_respondent0_open(nng_socket *sidp)
{
	return (nni_proto_open(sidp, &resp0_proto));
}

int
nng_respondent0_open_raw(nng_socket *sidp)
{
	return (nni_proto_open(sidp, &resp0_proto_raw));
}
