//
// Copyright 2025 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <string.h>

#include "core/nng_impl.h"

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
	nni_sock    *sock;
	nni_list     pipes;
	nni_mtx      mtx;
	bool         closed;
	size_t       sendbuf;
	nni_pollable sendable;

#ifdef NNG_ENABLE_STATS
	nni_stat_item stat_tx_direct;
	nni_stat_item stat_tx_discard;
	nni_stat_item stat_tx_queued;
	nni_stat_item stat_tx_bufsz;
#endif
};

// pub0_pipe is our per-pipe protocol private structure.
struct pub0_pipe {
	nni_pipe     *pipe;
	pub0_sock    *pub;
	nni_lmq       sendq;
	bool          closed;
	bool          busy;
	nni_aio       aio_send;
	nni_aio       aio_recv;
	nni_list_node node;
};

static void
pub0_sock_fini(void *arg)
{
	pub0_sock *s = arg;

	nni_pollable_fini(&s->sendable);
	nni_mtx_fini(&s->mtx);
}

static void
pub0_sock_init(void *arg, nni_sock *ns)
{
	pub0_sock *sock = arg;
	NNI_ARG_UNUSED(ns);

	nni_pollable_init(&sock->sendable);
	nni_mtx_init(&sock->mtx);
	NNI_LIST_INIT(&sock->pipes, pub0_pipe, node);
	sock->sendbuf = 16; // fairly arbitrary
	sock->sock    = ns;

#if NNG_ENABLE_STATS
	static const nni_stat_info tx_direct_info = {
		.si_name = "tx_direct",
		.si_desc = "messages sent without queueing (per pipe)",
		.si_type = NNG_STAT_COUNTER,
		.si_unit = NNG_UNIT_MESSAGES,
	};
	static const nni_stat_info tx_discard_info = {
		.si_name = "tx_discard",
		.si_desc = "messages dropped (once per pipe)",
		.si_type = NNG_STAT_COUNTER,
		.si_unit = NNG_UNIT_MESSAGES,
	};
	static const nni_stat_info tx_queued_info = {
		.si_name = "tx_queued",
		.si_desc = "messages queued (once per pipe)",
		.si_type = NNG_STAT_COUNTER,
		.si_unit = NNG_UNIT_MESSAGES,
	};
	static const nni_stat_info tx_bufsz_info = {
		.si_name = "tx_buf_size",
		.si_desc = "pipe buffer size for queued messages",
		.si_type = NNG_STAT_LEVEL,
		.si_unit = NNG_UNIT_MESSAGES,
	};

	nni_stat_init(&sock->stat_tx_direct, &tx_direct_info);
	nni_stat_init(&sock->stat_tx_discard, &tx_discard_info);
	nni_stat_init(&sock->stat_tx_queued, &tx_queued_info);
	nni_stat_init(&sock->stat_tx_bufsz, &tx_bufsz_info);
	nni_sock_add_stat(ns, &sock->stat_tx_direct);
	nni_sock_add_stat(ns, &sock->stat_tx_discard);
	nni_sock_add_stat(ns, &sock->stat_tx_queued);
	nni_sock_add_stat(ns, &sock->stat_tx_bufsz);
	nni_stat_set_value(&sock->stat_tx_bufsz, sock->sendbuf);
#endif
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

	nni_aio_stop(&p->aio_send);
	nni_aio_stop(&p->aio_recv);
}

static void
pub0_pipe_fini(void *arg)
{
	pub0_pipe *p = arg;

	nni_aio_fini(&p->aio_send);
	nni_aio_fini(&p->aio_recv);
	nni_lmq_fini(&p->sendq);
}

static int
pub0_pipe_init(void *arg, nni_pipe *pipe, void *s)
{
	pub0_pipe *p    = arg;
	pub0_sock *sock = s;
	size_t     len;

	nni_mtx_lock(&sock->mtx);
	len = sock->sendbuf;
	nni_mtx_unlock(&sock->mtx);

	nni_lmq_init(&p->sendq, len);
	nni_aio_init(&p->aio_send, pub0_pipe_send_cb, p);
	nni_aio_init(&p->aio_recv, pub0_pipe_recv_cb, p);

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
		nng_log_warn("NNG-PEER-MISMATCH",
		    "Peer protocol mismatch: %d != %d, rejected.",
		    nni_pipe_peer(p->pipe), NNI_PROTO_SUB_V0);
		return (NNG_EPROTO);
	}
	nni_mtx_lock(&sock->mtx);
	nni_list_append(&sock->pipes, p);
	nni_mtx_unlock(&sock->mtx);

	// Start the receiver.
	nni_pipe_recv(p->pipe, &p->aio_recv);

	return (0);
}

static void
pub0_pipe_close(void *arg)
{
	pub0_pipe *p    = arg;
	pub0_sock *sock = p->pub;

	nni_aio_close(&p->aio_send);
	nni_aio_close(&p->aio_recv);

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
	if (nni_aio_result(&p->aio_recv) == 0) {
		nni_msg_free(nni_aio_get_msg(&p->aio_recv));
	}
	nni_pipe_close(p->pipe);
}

static void
pub0_pipe_send_cb(void *arg)
{
	pub0_pipe *p    = arg;
	pub0_sock *sock = p->pub;
	nni_msg   *msg;

	if (nni_aio_result(&p->aio_send) != 0) {
		nni_msg_free(nni_aio_get_msg(&p->aio_send));
		nni_aio_set_msg(&p->aio_send, NULL);
		nni_pipe_close(p->pipe);
		return;
	}

	nni_mtx_lock(&sock->mtx);
	if (p->closed) {
		nni_mtx_unlock(&sock->mtx);
		return;
	}
	if (nni_lmq_get(&p->sendq, &msg) == 0) {
		nni_aio_set_msg(&p->aio_send, msg);
		nni_pipe_send(p->pipe, &p->aio_send);
	} else {
		p->busy = false;
	}
	nni_mtx_unlock(&sock->mtx);
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
	pub0_sock *sock = arg;
	pub0_pipe *p;
	nng_msg   *msg;
	size_t     len;

	msg = nni_aio_get_msg(aio);
	len = nni_msg_len(msg);
	nni_mtx_lock(&sock->mtx);
#ifdef NNG_ENABLE_STATS
	int dropped = 0;
	int direct  = 0;
	int queued  = 0;
#endif
	NNI_LIST_FOREACH (&sock->pipes, p) {

		nni_msg_clone(msg);
		if (p->busy) {
			if (nni_lmq_full(&p->sendq)) {
				// Make space for the new message.
				nni_msg *old;
				(void) nni_lmq_get(&p->sendq, &old);
				nni_msg_free(old);
#ifdef NNG_ENABLE_STATS
				dropped++;
#endif
			}
#ifdef NNG_ENABLE_STATS
			queued++;
#endif

			nni_lmq_put(&p->sendq, msg);
		} else {
			p->busy = true;
			nni_aio_set_msg(&p->aio_send, msg);
			nni_pipe_send(p->pipe, &p->aio_send);
#ifdef NNG_ENABLE_STATS
			direct++;
#endif
		}
	}
#ifdef NNG_ENABLE_STATS
	if (direct == 0 && queued == 0) {
		dropped++; // we didn't find a pipe to send it to!
	}
	nni_sock_bump_tx(sock->sock, len);
	nni_stat_inc(&sock->stat_tx_discard, dropped);
	nni_stat_inc(&sock->stat_tx_queued, queued);
	nni_stat_inc(&sock->stat_tx_direct, direct);
#endif
	nni_mtx_unlock(&sock->mtx);
	nng_msg_free(msg);
	nni_aio_finish(aio, 0, len);
}

static nng_err
pub0_sock_get_sendfd(void *arg, int *fdp)
{
	pub0_sock *sock = arg;

	// PUB sockets are *always* writable.
	nni_pollable_raise(&sock->sendable);
	return (nni_pollable_getfd(&sock->sendable, fdp));
}

static nng_err
pub0_sock_set_sendbuf(void *arg, const void *buf, size_t sz, nni_type t)
{
	pub0_sock *sock = arg;
	pub0_pipe *p;
	int        val;
	nng_err    rv;

	if ((rv = nni_copyin_int(&val, buf, sz, 1, 8192, t)) != NNG_OK) {
		return (rv);
	}

	nni_mtx_lock(&sock->mtx);
	sock->sendbuf = (size_t) val;
#ifdef NNG_ENABLE_STATS
	nni_stat_set_value(&sock->stat_tx_bufsz, sock->sendbuf);
#endif
	NNI_LIST_FOREACH (&sock->pipes, p) {
		// If we fail part way through (should only be ENOMEM), we
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

static nng_err
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
	    .o_name = NNG_OPT_SENDBUF,
	    .o_get  = pub0_sock_get_sendbuf,
	    .o_set  = pub0_sock_set_sendbuf,
	},
	{
	    .o_name = NULL,
	},
};

static nni_proto_sock_ops pub0_sock_ops = {
	.sock_size         = sizeof(pub0_sock),
	.sock_init         = pub0_sock_init,
	.sock_fini         = pub0_sock_fini,
	.sock_open         = pub0_sock_open,
	.sock_close        = pub0_sock_close,
	.sock_send         = pub0_sock_send,
	.sock_recv         = pub0_sock_recv,
	.sock_send_poll_fd = pub0_sock_get_sendfd,
	.sock_options      = pub0_sock_options,
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
nng_pub0_open(nng_socket *id)
{
	return (nni_proto_open(id, &pub0_proto));
}

int
nng_pub0_open_raw(nng_socket *id)
{
	return (nni_proto_open(id, &pub0_proto_raw));
}
