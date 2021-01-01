//
// Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/nng_impl.h"
#include "nng/protocol/survey0/survey.h"

// Surveyor protocol.  The SURVEYOR protocol is the "survey" side of the
// survey pattern.  This is useful for building service discovery, voting, etc.

typedef struct xsurv0_pipe xsurv0_pipe;
typedef struct xsurv0_sock xsurv0_sock;

static void xsurv0_sock_getq_cb(void *);
static void xsurv0_getq_cb(void *);
static void xsurv0_putq_cb(void *);
static void xsurv0_send_cb(void *);
static void xsurv0_recv_cb(void *);

// surv0_sock is our per-socket protocol private structure.
struct xsurv0_sock {
	nni_list       pipes;
	nni_aio        aio_getq;
	nni_msgq *     uwq;
	nni_msgq *     urq;
	nni_mtx        mtx;
	nni_atomic_int ttl;
};

// surv0_pipe is our per-pipe protocol private structure.
struct xsurv0_pipe {
	nni_pipe *    npipe;
	xsurv0_sock * psock;
	nni_msgq *    sendq;
	nni_list_node node;
	nni_aio       aio_getq;
	nni_aio       aio_putq;
	nni_aio       aio_send;
	nni_aio       aio_recv;
};

static void
xsurv0_sock_fini(void *arg)
{
	xsurv0_sock *s = arg;

	nni_aio_fini(&s->aio_getq);
	nni_mtx_fini(&s->mtx);
}

static int
xsurv0_sock_init(void *arg, nni_sock *nsock)
{
	xsurv0_sock *s = arg;

	nni_aio_init(&s->aio_getq, xsurv0_sock_getq_cb, s);
	NNI_LIST_INIT(&s->pipes, xsurv0_pipe, node);
	nni_mtx_init(&s->mtx);

	s->uwq = nni_sock_sendq(nsock);
	s->urq = nni_sock_recvq(nsock);
	nni_atomic_init(&s->ttl);
	nni_atomic_set(&s->ttl, 8);

	return (0);
}

static void
xsurv0_sock_open(void *arg)
{
	xsurv0_sock *s = arg;

	nni_msgq_aio_get(s->uwq, &s->aio_getq);
}

static void
xsurv0_sock_close(void *arg)
{
	xsurv0_sock *s = arg;

	nni_aio_close(&s->aio_getq);
}

static void
xsurv0_pipe_stop(void *arg)
{
	xsurv0_pipe *p = arg;

	nni_aio_stop(&p->aio_getq);
	nni_aio_stop(&p->aio_send);
	nni_aio_stop(&p->aio_recv);
	nni_aio_stop(&p->aio_putq);
}

static void
xsurv0_pipe_fini(void *arg)
{
	xsurv0_pipe *p = arg;

	nni_aio_fini(&p->aio_getq);
	nni_aio_fini(&p->aio_send);
	nni_aio_fini(&p->aio_recv);
	nni_aio_fini(&p->aio_putq);
	nni_msgq_fini(p->sendq);
}

static int
xsurv0_pipe_init(void *arg, nni_pipe *npipe, void *s)
{
	xsurv0_pipe *p = arg;
	int          rv;

	nni_aio_init(&p->aio_getq, xsurv0_getq_cb, p);
	nni_aio_init(&p->aio_putq, xsurv0_putq_cb, p);
	nni_aio_init(&p->aio_send, xsurv0_send_cb, p);
	nni_aio_init(&p->aio_recv, xsurv0_recv_cb, p);

	// This depth could be tunable.  The queue exists so that if we
	// have multiple requests coming in faster than we can deliver them,
	// we try to avoid dropping them.  We don't really have a solution
	// for applying back pressure.  It would be nice if surveys carried
	// an expiration with them, so that we could discard any that are
	// not delivered before their expiration date.
	if ((rv = nni_msgq_init(&p->sendq, 16)) != 0) {
		xsurv0_pipe_fini(p);
		return (rv);
	}

	p->npipe = npipe;
	p->psock = s;
	return (0);
}

static int
xsurv0_pipe_start(void *arg)
{
	xsurv0_pipe *p = arg;
	xsurv0_sock *s = p->psock;

	if (nni_pipe_peer(p->npipe) != NNG_SURVEYOR0_PEER) {
		return (NNG_EPROTO);
	}

	nni_mtx_lock(&s->mtx);
	nni_list_append(&s->pipes, p);
	nni_mtx_unlock(&s->mtx);

	nni_msgq_aio_get(p->sendq, &p->aio_getq);
	nni_pipe_recv(p->npipe, &p->aio_recv);
	return (0);
}

static void
xsurv0_pipe_close(void *arg)
{
	xsurv0_pipe *p = arg;
	xsurv0_sock *s = p->psock;

	nni_aio_close(&p->aio_getq);
	nni_aio_close(&p->aio_send);
	nni_aio_close(&p->aio_recv);
	nni_aio_close(&p->aio_putq);

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

	if (nni_aio_result(&p->aio_getq) != 0) {
		nni_pipe_close(p->npipe);
		return;
	}

	nni_aio_set_msg(&p->aio_send, nni_aio_get_msg(&p->aio_getq));
	nni_aio_set_msg(&p->aio_getq, NULL);

	nni_pipe_send(p->npipe, &p->aio_send);
}

static void
xsurv0_send_cb(void *arg)
{
	xsurv0_pipe *p = arg;

	if (nni_aio_result(&p->aio_send) != 0) {
		nni_msg_free(nni_aio_get_msg(&p->aio_send));
		nni_aio_set_msg(&p->aio_send, NULL);
		nni_pipe_close(p->npipe);
		return;
	}

	nni_msgq_aio_get(p->sendq, &p->aio_getq);
}

static void
xsurv0_putq_cb(void *arg)
{
	xsurv0_pipe *p = arg;

	if (nni_aio_result(&p->aio_putq) != 0) {
		nni_msg_free(nni_aio_get_msg(&p->aio_putq));
		nni_aio_set_msg(&p->aio_putq, NULL);
		nni_pipe_close(p->npipe);
		return;
	}

	nni_pipe_recv(p->npipe, &p->aio_recv);
}

static void
xsurv0_recv_cb(void *arg)
{
	xsurv0_pipe *p = arg;
	nni_msg *    msg;
	bool         end;

	if (nni_aio_result(&p->aio_recv) != 0) {
		nni_pipe_close(p->npipe);
		return;
	}

	msg = nni_aio_get_msg(&p->aio_recv);
	nni_aio_set_msg(&p->aio_recv, NULL);
	nni_msg_set_pipe(msg, nni_pipe_id(p->npipe));
	end = false;

	while (!end) {
		uint8_t *body;

		if (nni_msg_len(msg) < 4) {
			// Peer gave us garbage, so kick it.
			nni_msg_free(msg);
			nni_pipe_close(p->npipe);
			return;
		}
		body = nni_msg_body(msg);
		end  = ((body[0] & 0x80u) != 0);

		if (nni_msg_header_append(msg, body, sizeof(uint32_t)) != 0) {
			// TODO: bump a no-memory stat
			nni_msg_free(msg);
			// Closing the pipe may release some memory.
			// It at least gives an indication to the peer
			// that we've lost the message.
			nni_pipe_close(p->npipe);
			return;
		}
		nni_msg_trim(msg, sizeof(uint32_t));
	}

	nni_aio_set_msg(&p->aio_putq, msg);
	nni_msgq_aio_put(p->psock->urq, &p->aio_putq);
}

static int
xsurv0_sock_set_max_ttl(void *arg, const void *buf, size_t sz, nni_opt_type t)
{
	xsurv0_sock *s = arg;
	int          ttl;
	int          rv;
	if ((rv = nni_copyin_int(&ttl, buf, sz, 1, NNI_MAX_MAX_TTL, t)) == 0) {
		nni_atomic_set(&s->ttl, ttl);
	}
	return (rv);
}

static int
xsurv0_sock_get_max_ttl(void *arg, void *buf, size_t *szp, nni_opt_type t)
{
	xsurv0_sock *s = arg;
	return (nni_copyout_int(nni_atomic_get(&s->ttl), buf, szp, t));
}

static void
xsurv0_sock_getq_cb(void *arg)
{
	xsurv0_sock *s = arg;
	xsurv0_pipe *p;
	nni_msg *    msg;

	if (nni_aio_result(&s->aio_getq) != 0) {
		// Should be NNG_ECLOSED.
		return;
	}
	msg = nni_aio_get_msg(&s->aio_getq);
	nni_aio_set_msg(&s->aio_getq, NULL);

	nni_mtx_lock(&s->mtx);
	NNI_LIST_FOREACH (&s->pipes, p) {
		nni_msg_clone(msg);
		if (nni_msgq_tryput(p->sendq, msg) != 0) {
			nni_msg_free(msg);
		}
	}

	nni_msgq_aio_get(s->uwq, &s->aio_getq);
	nni_mtx_unlock(&s->mtx);

	// If there were no pipes to send on, just toss the message.
	nni_msg_free(msg);
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
	.pipe_size  = sizeof(xsurv0_pipe),
	.pipe_init  = xsurv0_pipe_init,
	.pipe_fini  = xsurv0_pipe_fini,
	.pipe_start = xsurv0_pipe_start,
	.pipe_close = xsurv0_pipe_close,
	.pipe_stop  = xsurv0_pipe_stop,
};

static nni_option xsurv0_sock_options[] = {
	{
	    .o_name = NNG_OPT_MAXTTL,
	    .o_get  = xsurv0_sock_get_max_ttl,
	    .o_set  = xsurv0_sock_set_max_ttl,
	},
	// terminate list
	{
	    .o_name = NULL,
	},
};

static nni_proto_sock_ops xsurv0_sock_ops = {
	.sock_size    = sizeof(xsurv0_sock),
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
	.proto_self     = { NNG_SURVEYOR0_SELF, NNG_SURVEYOR0_SELF_NAME },
	.proto_peer     = { NNG_SURVEYOR0_PEER, NNG_SURVEYOR0_PEER_NAME },
	.proto_flags    = NNI_PROTO_FLAG_SNDRCV | NNI_PROTO_FLAG_RAW,
	.proto_sock_ops = &xsurv0_sock_ops,
	.proto_pipe_ops = &xsurv0_pipe_ops,
};

int
nng_surveyor0_open_raw(nng_socket *sidp)
{
	return (nni_proto_open(sidp, &xsurv0_proto));
}
