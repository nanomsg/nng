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
#include "nng/protocol/survey0/survey.h"

// Surveyor protocol.  The SURVEYOR protocol is the "survey" side of the
// survey pattern.  This is useful for building service discovery, voting, etc.

#ifndef NNI_PROTO_SURVEYOR_V0
#define NNI_PROTO_SURVEYOR_V0 NNI_PROTO(6, 2)
#endif

#ifndef NNI_PROTO_RESPONDENT_V0
#define NNI_PROTO_RESPONDENT_V0 NNI_PROTO(6, 3)
#endif

typedef struct xsurv0_pipe xsurv0_pipe;
typedef struct xsurv0_sock xsurv0_sock;

static void xsurv0_sock_getq_cb(void *);
static void xsurv0_getq_cb(void *);
static void xsurv0_putq_cb(void *);
static void xsurv0_send_cb(void *);
static void xsurv0_recv_cb(void *);

// surv0_sock is our per-socket protocol private structure.
struct xsurv0_sock {
	int       ttl;
	nni_list  pipes;
	nni_aio * aio_getq;
	nni_msgq *uwq;
	nni_msgq *urq;
	nni_mtx   mtx;
};

// surv0_pipe is our per-pipe protocol private structure.
struct xsurv0_pipe {
	nni_pipe *    npipe;
	xsurv0_sock * psock;
	nni_msgq *    sendq;
	nni_list_node node;
	nni_aio *     aio_getq;
	nni_aio *     aio_putq;
	nni_aio *     aio_send;
	nni_aio *     aio_recv;
};

static void
xsurv0_sock_fini(void *arg)
{
	xsurv0_sock *s = arg;

	nni_aio_fini(s->aio_getq);
	nni_mtx_fini(&s->mtx);
	NNI_FREE_STRUCT(s);
}

static int
xsurv0_sock_init(void **sp, nni_sock *nsock)
{
	xsurv0_sock *s;
	int          rv;

	if ((s = NNI_ALLOC_STRUCT(s)) == NULL) {
		return (NNG_ENOMEM);
	}
	if ((rv = nni_aio_init(&s->aio_getq, xsurv0_sock_getq_cb, s)) != 0) {
		xsurv0_sock_fini(s);
		return (rv);
	}
	NNI_LIST_INIT(&s->pipes, xsurv0_pipe, node);
	nni_mtx_init(&s->mtx);

	s->uwq = nni_sock_sendq(nsock);
	s->urq = nni_sock_recvq(nsock);
	s->ttl = 8;

	*sp = s;
	return (0);
}

static void
xsurv0_sock_open(void *arg)
{
	xsurv0_sock *s = arg;

	nni_msgq_aio_get(s->uwq, s->aio_getq);
}

static void
xsurv0_sock_close(void *arg)
{
	xsurv0_sock *s = arg;

	nni_aio_close(s->aio_getq);
}

static void
xsurv0_pipe_stop(void *arg)
{
	xsurv0_pipe *p = arg;

	nni_aio_stop(p->aio_getq);
	nni_aio_stop(p->aio_send);
	nni_aio_stop(p->aio_recv);
	nni_aio_stop(p->aio_putq);
}

static void
xsurv0_pipe_fini(void *arg)
{
	xsurv0_pipe *p = arg;

	nni_aio_fini(p->aio_getq);
	nni_aio_fini(p->aio_send);
	nni_aio_fini(p->aio_recv);
	nni_aio_fini(p->aio_putq);
	nni_msgq_fini(p->sendq);
	NNI_FREE_STRUCT(p);
}

static int
xsurv0_pipe_init(void **pp, nni_pipe *npipe, void *s)
{
	xsurv0_pipe *p;
	int          rv;

	if ((p = NNI_ALLOC_STRUCT(p)) == NULL) {
		return (NNG_ENOMEM);
	}
	// This depth could be tunable.  The queue exists so that if we
	// have multiple requests coming in faster than we can deliver them,
	// we try to avoid dropping them.  We don't really have a solution
	// for applying backpressure.  It would be nice if surveys carried
	// an expiration with them, so that we could discard any that are
	// not delivered before their expiration date.
	if (((rv = nni_msgq_init(&p->sendq, 16)) != 0) ||
	    ((rv = nni_aio_init(&p->aio_getq, xsurv0_getq_cb, p)) != 0) ||
	    ((rv = nni_aio_init(&p->aio_putq, xsurv0_putq_cb, p)) != 0) ||
	    ((rv = nni_aio_init(&p->aio_send, xsurv0_send_cb, p)) != 0) ||
	    ((rv = nni_aio_init(&p->aio_recv, xsurv0_recv_cb, p)) != 0)) {
		xsurv0_pipe_fini(p);
		return (rv);
	}

	p->npipe = npipe;
	p->psock = s;
	*pp      = p;
	return (0);
}

static int
xsurv0_pipe_start(void *arg)
{
	xsurv0_pipe *p = arg;
	xsurv0_sock *s = p->psock;

	if (nni_pipe_peer(p->npipe) != NNI_PROTO_RESPONDENT_V0) {
		return (NNG_EPROTO);
	}

	nni_mtx_lock(&s->mtx);
	nni_list_append(&s->pipes, p);
	nni_mtx_unlock(&s->mtx);

	nni_msgq_aio_get(p->sendq, p->aio_getq);
	nni_pipe_recv(p->npipe, p->aio_recv);
	return (0);
}

static void
xsurv0_pipe_close(void *arg)
{
	xsurv0_pipe *p = arg;
	xsurv0_sock *s = p->psock;

	nni_aio_close(p->aio_getq);
	nni_aio_close(p->aio_send);
	nni_aio_close(p->aio_recv);
	nni_aio_close(p->aio_putq);

	nni_msgq_close(p->sendq);

	nni_mtx_lock(&s->mtx);
	if (nni_list_active(&s->pipes, p)) {
		nni_list_remove(&s->pipes, p);
	}
	nni_mtx_unlock(&s->mtx);
}

static void
xsurv0_getq_cb(void *arg)
{
	xsurv0_pipe *p = arg;

	if (nni_aio_result(p->aio_getq) != 0) {
		nni_pipe_close(p->npipe);
		return;
	}

	nni_aio_set_msg(p->aio_send, nni_aio_get_msg(p->aio_getq));
	nni_aio_set_msg(p->aio_getq, NULL);

	nni_pipe_send(p->npipe, p->aio_send);
}

static void
xsurv0_send_cb(void *arg)
{
	xsurv0_pipe *p = arg;

	if (nni_aio_result(p->aio_send) != 0) {
		nni_msg_free(nni_aio_get_msg(p->aio_send));
		nni_aio_set_msg(p->aio_send, NULL);
		nni_pipe_close(p->npipe);
		return;
	}

	nni_msgq_aio_get(p->sendq, p->aio_getq);
}

static void
xsurv0_putq_cb(void *arg)
{
	xsurv0_pipe *p = arg;

	if (nni_aio_result(p->aio_putq) != 0) {
		nni_msg_free(nni_aio_get_msg(p->aio_putq));
		nni_aio_set_msg(p->aio_putq, NULL);
		nni_pipe_close(p->npipe);
		return;
	}

	nni_pipe_recv(p->npipe, p->aio_recv);
}

static void
xsurv0_recv_cb(void *arg)
{
	xsurv0_pipe *p = arg;
	nni_msg *    msg;

	if (nni_aio_result(p->aio_recv) != 0) {
		nni_pipe_close(p->npipe);
		return;
	}

	msg = nni_aio_get_msg(p->aio_recv);
	nni_aio_set_msg(p->aio_recv, NULL);
	nni_msg_set_pipe(msg, nni_pipe_id(p->npipe));

	// We yank 4 bytes of body, and move them to the header.
	if (nni_msg_len(msg) < 4) {
		// Peer gave us garbage, so kick it.
		nni_msg_free(msg);
		nni_pipe_close(p->npipe);
		return;
	}
	if (nni_msg_header_append(msg, nni_msg_body(msg), 4) != 0) {
		// Probably ENOMEM, discard and keep going.
		nni_msg_free(msg);
		nni_pipe_recv(p->npipe, p->aio_recv);
		return;
	}
	(void) nni_msg_trim(msg, 4);

	nni_aio_set_msg(p->aio_putq, msg);
	nni_msgq_aio_put(p->psock->urq, p->aio_putq);
}

static int
xsurv0_sock_set_maxttl(void *arg, const void *buf, size_t sz, nni_opt_type t)
{
	xsurv0_sock *s = arg;
	return (nni_copyin_int(&s->ttl, buf, sz, 1, 255, t));
}

static int
xsurv0_sock_get_maxttl(void *arg, void *buf, size_t *szp, nni_opt_type t)
{
	xsurv0_sock *s = arg;
	return (nni_copyout_int(s->ttl, buf, szp, t));
}

static void
xsurv0_sock_getq_cb(void *arg)
{
	xsurv0_sock *s = arg;
	xsurv0_pipe *p;
	xsurv0_pipe *last;
	nni_msg *    msg, *dup;

	if (nni_aio_result(s->aio_getq) != 0) {
		// Should be NNG_ECLOSED.
		return;
	}
	msg = nni_aio_get_msg(s->aio_getq);
	nni_aio_set_msg(s->aio_getq, NULL);

	nni_mtx_lock(&s->mtx);
	last = nni_list_last(&s->pipes);
	NNI_LIST_FOREACH (&s->pipes, p) {
		if (p != last) {
			if (nni_msg_dup(&dup, msg) != 0) {
				continue;
			}
		} else {
			dup = msg;
		}
		if (nni_msgq_tryput(p->sendq, dup) != 0) {
			nni_msg_free(dup);
		}
	}

	nni_msgq_aio_get(s->uwq, s->aio_getq);
	nni_mtx_unlock(&s->mtx);

	if (last == NULL) {
		// If there were no pipes to send on, just toss the message.
		nni_msg_free(msg);
	}
}

static void
xsurv0_sock_recv(void *arg, nni_aio *aio)
{
	xsurv0_sock *s = arg;

	nni_msgq_aio_get(s->urq, aio);
}

static void
xsurv0_sock_send(void *arg, nni_aio *aio)
{
	xsurv0_sock *s = arg;

	nni_msgq_aio_put(s->uwq, aio);
}

static nni_proto_pipe_ops xsurv0_pipe_ops = {
	.pipe_init  = xsurv0_pipe_init,
	.pipe_fini  = xsurv0_pipe_fini,
	.pipe_start = xsurv0_pipe_start,
	.pipe_close = xsurv0_pipe_close,
	.pipe_stop  = xsurv0_pipe_stop,
};

static nni_option xsurv0_sock_options[] = {
	{
	    .o_name = NNG_OPT_MAXTTL,
	    .o_get  = xsurv0_sock_get_maxttl,
	    .o_set  = xsurv0_sock_set_maxttl,
	},
	// terminate list
	{
	    .o_name = NULL,
	},
};

static nni_proto_sock_ops xsurv0_sock_ops = {
	.sock_init    = xsurv0_sock_init,
	.sock_fini    = xsurv0_sock_fini,
	.sock_open    = xsurv0_sock_open,
	.sock_close   = xsurv0_sock_close,
	.sock_send    = xsurv0_sock_send,
	.sock_recv    = xsurv0_sock_recv,
	.sock_options = xsurv0_sock_options,
};

static nni_proto xsurv0_proto = {
	.proto_version  = NNI_PROTOCOL_VERSION,
	.proto_self     = { NNI_PROTO_SURVEYOR_V0, "surveyor" },
	.proto_peer     = { NNI_PROTO_RESPONDENT_V0, "respondent" },
	.proto_flags    = NNI_PROTO_FLAG_SNDRCV | NNI_PROTO_FLAG_RAW,
	.proto_sock_ops = &xsurv0_sock_ops,
	.proto_pipe_ops = &xsurv0_pipe_ops,
};

int
nng_surveyor0_open_raw(nng_socket *sidp)
{
	return (nni_proto_open(sidp, &xsurv0_proto));
}
