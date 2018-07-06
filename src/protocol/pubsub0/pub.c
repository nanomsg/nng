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
#include "protocol/pubsub0/pub.h"

// Publish protocol.  The PUB protocol simply sends messages out, as
// a broadcast.  It has nothing more sophisticated because it does not
// perform sender-side filtering.  Its best effort delivery, so anything
// that can't receive the message won't get one.

#ifndef NNI_PROTO_SUB_V0
#define NNI_PROTO_SUB_V0 NNI_PROTO(2, 1)
#endif

#ifndef NNI_PROTO_PUB_V0
#define NNI_PROTO_PUB_V0 NNI_PROTO(2, 0)
#endif

typedef struct pub0_pipe pub0_pipe;
typedef struct pub0_sock pub0_sock;

static void pub0_pipe_recv_cb(void *);
static void pub0_pipe_send_cb(void *);
static void pub0_pipe_getq_cb(void *);
static void pub0_sock_getq_cb(void *);
static void pub0_sock_fini(void *);
static void pub0_pipe_fini(void *);

// pub0_sock is our per-socket protocol private structure.
struct pub0_sock {
	nni_msgq *uwq;
	nni_aio * aio_getq;
	nni_list  pipes;
	nni_mtx   mtx;
};

// pub0_pipe is our per-pipe protocol private structure.
struct pub0_pipe {
	nni_pipe *    pipe;
	pub0_sock *   pub;
	nni_msgq *    sendq;
	nni_aio *     aio_getq;
	nni_aio *     aio_send;
	nni_aio *     aio_recv;
	nni_list_node node;
};

static void
pub0_sock_fini(void *arg)
{
	pub0_sock *s = arg;

	nni_aio_fini(s->aio_getq);
	nni_mtx_fini(&s->mtx);
	NNI_FREE_STRUCT(s);
}

static int
pub0_sock_init(void **sp, nni_sock *sock)
{
	pub0_sock *s;
	int        rv;

	if ((s = NNI_ALLOC_STRUCT(s)) == NULL) {
		return (NNG_ENOMEM);
	}
	nni_mtx_init(&s->mtx);
	if ((rv = nni_aio_init(&s->aio_getq, pub0_sock_getq_cb, s)) != 0) {
		pub0_sock_fini(s);
		return (rv);
	}

	NNI_LIST_INIT(&s->pipes, pub0_pipe, node);

	s->uwq = nni_sock_sendq(sock);

	*sp = s;
	return (0);
}

static void
pub0_sock_open(void *arg)
{
	pub0_sock *s = arg;

	nni_msgq_aio_get(s->uwq, s->aio_getq);
}

static void
pub0_sock_close(void *arg)
{
	pub0_sock *s = arg;

	nni_aio_close(s->aio_getq);
}

static void
pub0_pipe_stop(void *arg)
{
	pub0_pipe *p = arg;

	nni_aio_stop(p->aio_getq);
	nni_aio_stop(p->aio_send);
	nni_aio_stop(p->aio_recv);
}

static void
pub0_pipe_fini(void *arg)
{
	pub0_pipe *p = arg;

	nni_aio_fini(p->aio_getq);
	nni_aio_fini(p->aio_send);
	nni_aio_fini(p->aio_recv);
	nni_msgq_fini(p->sendq);
	NNI_FREE_STRUCT(p);
}

static int
pub0_pipe_init(void **pp, nni_pipe *pipe, void *s)
{
	pub0_pipe *p;
	int        rv;

	if ((p = NNI_ALLOC_STRUCT(p)) == NULL) {
		return (NNG_ENOMEM);
	}

	// XXX: consider making this depth tunable
	if (((rv = nni_msgq_init(&p->sendq, 16)) != 0) ||
	    ((rv = nni_aio_init(&p->aio_getq, pub0_pipe_getq_cb, p)) != 0) ||
	    ((rv = nni_aio_init(&p->aio_send, pub0_pipe_send_cb, p)) != 0) ||
	    ((rv = nni_aio_init(&p->aio_recv, pub0_pipe_recv_cb, p)) != 0)) {

		pub0_pipe_fini(p);
		return (rv);
	}

	p->pipe = pipe;
	p->pub  = s;
	*pp     = p;
	return (0);
}

static int
pub0_pipe_start(void *arg)
{
	pub0_pipe *p = arg;
	pub0_sock *s = p->pub;

	if (nni_pipe_peer(p->pipe) != NNI_PROTO_SUB_V0) {
		return (NNG_EPROTO);
	}
	nni_mtx_lock(&s->mtx);
	nni_list_append(&s->pipes, p);
	nni_mtx_unlock(&s->mtx);

	// Start the receiver and the queue reader.
	nni_pipe_recv(p->pipe, p->aio_recv);
	nni_msgq_aio_get(p->sendq, p->aio_getq);

	return (0);
}

static void
pub0_pipe_close(void *arg)
{
	pub0_pipe *p = arg;
	pub0_sock *s = p->pub;

	nni_aio_close(p->aio_getq);
	nni_aio_close(p->aio_send);
	nni_aio_close(p->aio_recv);

	nni_msgq_close(p->sendq);

	nni_mtx_lock(&s->mtx);
	if (nni_list_active(&s->pipes, p)) {
		nni_list_remove(&s->pipes, p);
	}
	nni_mtx_unlock(&s->mtx);
}

static void
pub0_sock_getq_cb(void *arg)
{
	pub0_sock *s   = arg;
	nni_msgq * uwq = s->uwq;
	nni_msg *  msg, *dup;

	pub0_pipe *p;
	pub0_pipe *last;
	int        rv;

	if (nni_aio_result(s->aio_getq) != 0) {
		return;
	}

	msg = nni_aio_get_msg(s->aio_getq);
	nni_aio_set_msg(s->aio_getq, NULL);

	nni_mtx_lock(&s->mtx);
	last = nni_list_last(&s->pipes);
	NNI_LIST_FOREACH (&s->pipes, p) {
		if (p != last) {
			rv = nni_msg_dup(&dup, msg);
			if (rv != 0) {
				continue;
			}
		} else {
			dup = msg;
		}
		if ((rv = nni_msgq_tryput(p->sendq, dup)) != 0) {
			nni_msg_free(dup);
		}
	}
	nni_mtx_unlock(&s->mtx);

	if (last == NULL) {
		nni_msg_free(msg);
	}

	nni_msgq_aio_get(uwq, s->aio_getq);
}

static void
pub0_pipe_recv_cb(void *arg)
{
	pub0_pipe *p = arg;

	if (nni_aio_result(p->aio_recv) != 0) {
		nni_pipe_close(p->pipe);
		return;
	}

	nni_msg_free(nni_aio_get_msg(p->aio_recv));
	nni_aio_set_msg(p->aio_recv, NULL);
	nni_pipe_recv(p->pipe, p->aio_recv);
}

static void
pub0_pipe_getq_cb(void *arg)
{
	pub0_pipe *p = arg;

	if (nni_aio_result(p->aio_getq) != 0) {
		nni_pipe_close(p->pipe);
		return;
	}

	nni_aio_set_msg(p->aio_send, nni_aio_get_msg(p->aio_getq));
	nni_aio_set_msg(p->aio_getq, NULL);

	nni_pipe_send(p->pipe, p->aio_send);
}

static void
pub0_pipe_send_cb(void *arg)
{
	pub0_pipe *p = arg;

	if (nni_aio_result(p->aio_send) != 0) {
		nni_msg_free(nni_aio_get_msg(p->aio_send));
		nni_aio_set_msg(p->aio_send, NULL);
		nni_pipe_close(p->pipe);
		return;
	}

	nni_aio_set_msg(p->aio_send, NULL);
	nni_msgq_aio_get(p->sendq, p->aio_getq);
}

static void
pub0_sock_recv(void *arg, nni_aio *aio)
{
	NNI_ARG_UNUSED(arg);
	nni_aio_finish_error(aio, NNG_ENOTSUP);
}

static void
pub0_sock_send(void *arg, nni_aio *aio)
{
	pub0_sock *s = arg;

	nni_msgq_aio_put(s->uwq, aio);
}

static nni_proto_pipe_ops pub0_pipe_ops = {
	.pipe_init  = pub0_pipe_init,
	.pipe_fini  = pub0_pipe_fini,
	.pipe_start = pub0_pipe_start,
	.pipe_close = pub0_pipe_close,
	.pipe_stop  = pub0_pipe_stop,
};

static nni_proto_option pub0_sock_options[] = {
	// terminate list
	{
	    .o_name = NULL,
	},
};

static nni_proto_sock_ops pub0_sock_ops = {
	.sock_init    = pub0_sock_init,
	.sock_fini    = pub0_sock_fini,
	.sock_open    = pub0_sock_open,
	.sock_close   = pub0_sock_close,
	.sock_send    = pub0_sock_send,
	.sock_recv    = pub0_sock_recv,
	.sock_options = pub0_sock_options,
};

static nni_proto pub0_proto = {
	.proto_version  = NNI_PROTOCOL_VERSION,
	.proto_self     = { NNI_PROTO_PUB_V0, "pub" },
	.proto_peer     = { NNI_PROTO_SUB_V0, "sub" },
	.proto_flags    = NNI_PROTO_FLAG_SND,
	.proto_sock_ops = &pub0_sock_ops,
	.proto_pipe_ops = &pub0_pipe_ops,
};

static nni_proto pub0_proto_raw = {
	.proto_version  = NNI_PROTOCOL_VERSION,
	.proto_self     = { NNI_PROTO_PUB_V0, "pub" },
	.proto_peer     = { NNI_PROTO_SUB_V0, "sub" },
	.proto_flags    = NNI_PROTO_FLAG_SND | NNI_PROTO_FLAG_RAW,
	.proto_sock_ops = &pub0_sock_ops,
	.proto_pipe_ops = &pub0_pipe_ops,
};

int
nng_pub0_open(nng_socket *sidp)
{
	return (nni_proto_open(sidp, &pub0_proto));
}

int
nng_pub0_open_raw(nng_socket *sidp)
{
	return (nni_proto_open(sidp, &pub0_proto_raw));
}
