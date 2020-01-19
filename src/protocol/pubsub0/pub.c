//
// Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <string.h>

#include "core/nng_impl.h"
#include "nng/protocol/pubsub0/pub.h"

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
static void pub0_sock_fini(void *);
static void pub0_pipe_fini(void *);

// pub0_sock is our per-socket protocol private structure.
struct pub0_sock {
	nni_list      pipes;
	nni_mtx       mtx;
	bool          closed;
	size_t        sendbuf;
	nni_pollable *sendable;
};

// pub0_pipe is our per-pipe protocol private structure.
struct pub0_pipe {
	nni_pipe *    pipe;
	pub0_sock *   pub;
	nni_lmq       sendq;
	bool          closed;
	bool          busy;
	nni_aio *     aio_send;
	nni_aio *     aio_recv;
	nni_list_node node;
};

static void
pub0_sock_fini(void *arg)
{
	pub0_sock *s = arg;

	nni_pollable_free(s->sendable);
	nni_mtx_fini(&s->mtx);
}

static int
pub0_sock_init(void *arg, nni_sock *nsock)
{
	pub0_sock *sock = arg;
	int        rv;
	NNI_ARG_UNUSED(nsock);

	if ((rv = nni_pollable_alloc(&sock->sendable)) != 0) {
		return (rv);
	}
	nni_mtx_init(&sock->mtx);
	NNI_LIST_INIT(&sock->pipes, pub0_pipe, node);
	sock->sendbuf = 16; // fairly arbitrary
	return (0);
}

static void
pub0_sock_open(void *arg)
{
	NNI_ARG_UNUSED(arg);
}

static void
pub0_sock_close(void *arg)
{
	NNI_ARG_UNUSED(arg);
}

static void
pub0_pipe_stop(void *arg)
{
	pub0_pipe *p = arg;

	nni_aio_stop(p->aio_send);
	nni_aio_stop(p->aio_recv);
}

static void
pub0_pipe_fini(void *arg)
{
	pub0_pipe *p = arg;

	nni_aio_free(p->aio_send);
	nni_aio_free(p->aio_recv);
	nni_lmq_fini(&p->sendq);
}

static int
pub0_pipe_init(void *arg, nni_pipe *pipe, void *s)
{
	pub0_pipe *p    = arg;
	pub0_sock *sock = s;
	int        rv;
	size_t     len;

	nni_mtx_lock(&sock->mtx);
	len = sock->sendbuf;
	nni_mtx_unlock(&sock->mtx);

	// XXX: consider making this depth tunable
	if (((rv = nni_lmq_init(&p->sendq, len)) != 0) ||
	    ((rv = nni_aio_alloc(&p->aio_send, pub0_pipe_send_cb, p)) != 0) ||
	    ((rv = nni_aio_alloc(&p->aio_recv, pub0_pipe_recv_cb, p)) != 0)) {

		pub0_pipe_fini(p);
		return (rv);
	}

	p->busy = false;
	p->pipe = pipe;
	p->pub  = s;
	return (0);
}

static int
pub0_pipe_start(void *arg)
{
	pub0_pipe *p    = arg;
	pub0_sock *sock = p->pub;

	if (nni_pipe_peer(p->pipe) != NNI_PROTO_SUB_V0) {
		return (NNG_EPROTO);
	}
	nni_mtx_lock(&sock->mtx);
	nni_list_append(&sock->pipes, p);
	nni_mtx_unlock(&sock->mtx);

	// Start the receiver.
	nni_pipe_recv(p->pipe, p->aio_recv);

	return (0);
}

static void
pub0_pipe_close(void *arg)
{
	pub0_pipe *p    = arg;
	pub0_sock *sock = p->pub;

	nni_aio_close(p->aio_send);
	nni_aio_close(p->aio_recv);

	nni_mtx_lock(&sock->mtx);
	p->closed = true;
	nni_lmq_flush(&p->sendq);

	if (nni_list_active(&sock->pipes, p)) {
		nni_list_remove(&sock->pipes, p);
	}
	nni_mtx_unlock(&sock->mtx);
}

static void
pub0_pipe_recv_cb(void *arg)
{
	pub0_pipe *p = arg;

	// We should never receive a message -- the only valid reason for us to
	// be here is on pipe close.
	if (nni_aio_result(p->aio_recv) == 0) {
		nni_msg_free(nni_aio_get_msg(p->aio_recv));
	}
	nni_pipe_close(p->pipe);
}

static void
pub0_pipe_send_cb(void *arg)
{
	pub0_pipe *p    = arg;
	pub0_sock *sock = p->pub;
	nni_msg *  msg;

	if (nni_aio_result(p->aio_send) != 0) {
		nni_msg_free(nni_aio_get_msg(p->aio_send));
		nni_aio_set_msg(p->aio_send, NULL);
		nni_pipe_close(p->pipe);
		return;
	}

	nni_mtx_lock(&sock->mtx);
	if (p->closed) {
		nni_mtx_unlock(&sock->mtx);
		return;
	}
	if (nni_lmq_getq(&p->sendq, &msg) == 0) {
		nni_aio_set_msg(p->aio_send, msg);
		nni_pipe_send(p->pipe, p->aio_send);
	} else {
		p->busy = false;
	}
	nni_mtx_unlock(&sock->mtx);
}

static void
pub0_sock_recv(void *arg, nni_aio *aio)
{
	NNI_ARG_UNUSED(arg);
	if (nni_aio_begin(aio) == 0) {
		nni_aio_finish_error(aio, NNG_ENOTSUP);
	}
}

static void
pub0_sock_send(void *arg, nni_aio *aio)
{
	pub0_sock *sock = arg;
	pub0_pipe *p;
	nng_msg *  msg;
	size_t     len;

	msg = nni_aio_get_msg(aio);
	len = nni_msg_len(msg);
	nni_mtx_lock(&sock->mtx);
	NNI_LIST_FOREACH (&sock->pipes, p) {

		nni_msg_clone(msg);
		if (p->busy) {
			if (nni_lmq_full(&p->sendq)) {
				// Make space for the new message.
				nni_msg *old;
				(void) nni_lmq_getq(&p->sendq, &old);
				nni_msg_free(old);
			}
			nni_lmq_putq(&p->sendq, msg);
		} else {
			p->busy = true;
			nni_aio_set_msg(p->aio_send, msg);
			nni_pipe_send(p->pipe, p->aio_send);
		}
	}
	nni_mtx_unlock(&sock->mtx);
	nng_msg_free(msg);
	nni_aio_finish(aio, 0, len);
}

static int
pub0_sock_get_sendfd(void *arg, void *buf, size_t *szp, nni_type t)
{
	pub0_sock *sock = arg;
	int        fd;
	int        rv;
	nni_mtx_lock(&sock->mtx);
	// PUB sockets are *always* writable.
	nni_pollable_raise(sock->sendable);
	rv = nni_pollable_getfd(sock->sendable, &fd);
	nni_mtx_unlock(&sock->mtx);

	if (rv == 0) {
		rv = nni_copyout_int(fd, buf, szp, t);
	}
	return (rv);
}

static int
pub0_sock_set_sendbuf(void *arg, const void *buf, size_t sz, nni_type t)
{
	pub0_sock *sock = arg;
	pub0_pipe *p;
	int        val;
	int        rv;

	if ((rv = nni_copyin_int(&val, buf, sz, 1, 8192, t)) != 0) {
		return (rv);
	}

	nni_mtx_lock(&sock->mtx);
	sock->sendbuf = (size_t) val;
	NNI_LIST_FOREACH (&sock->pipes, p) {
		// If we fail part way thru (should only be ENOMEM), we
		// stop short.  The others would likely fail for ENOMEM as
		// well anyway.  There is a weird effect here where the
		// buffers may have been set for *some* of the pipes, but
		// we have no way to correct partial failure.
		if ((rv = nni_lmq_resize(&p->sendq, (size_t) val)) != 0) {
			break;
		}
	}
	nni_mtx_unlock(&sock->mtx);
	return (rv);
}

static int
pub0_sock_get_sendbuf(void *arg, void *buf, size_t *szp, nni_type t)
{
	pub0_sock *sock = arg;
	int        val;
	nni_mtx_lock(&sock->mtx);
	val = (int) sock->sendbuf;
	nni_mtx_unlock(&sock->mtx);
	return (nni_copyout_int(val, buf, szp, t));
}

static nni_proto_pipe_ops pub0_pipe_ops = {
	.pipe_size  = sizeof(pub0_pipe),
	.pipe_init  = pub0_pipe_init,
	.pipe_fini  = pub0_pipe_fini,
	.pipe_start = pub0_pipe_start,
	.pipe_close = pub0_pipe_close,
	.pipe_stop  = pub0_pipe_stop,
};

static nni_option pub0_sock_options[] = {
	// terminate list
	{
	    .o_name = NNG_OPT_SENDFD,
	    .o_get  = pub0_sock_get_sendfd,
	},
	{
	    .o_name = NNG_OPT_SENDBUF,
	    .o_get  = pub0_sock_get_sendbuf,
	    .o_set  = pub0_sock_set_sendbuf,
	},
	{
	    .o_name = NULL,
	},
};

static nni_proto_sock_ops pub0_sock_ops = {
	.sock_size    = sizeof(pub0_sock),
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
	.proto_flags    = NNI_PROTO_FLAG_SND | NNI_PROTO_FLAG_NOMSGQ,
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
