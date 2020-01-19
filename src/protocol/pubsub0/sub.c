//
// Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
// Copyright 2019 Nathan Kent <nate@nkent.net>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <stdbool.h>
#include <string.h>

#include "core/nng_impl.h"
#include "nng/protocol/pubsub0/sub.h"

// Subscriber protocol.  The SUB protocol receives messages sent to
// it from publishers, and filters out those it is not interested in,
// only passing up ones that match known subscriptions.

#ifndef NNI_PROTO_SUB_V0
#define NNI_PROTO_SUB_V0 NNI_PROTO(2, 1)
#endif

#ifndef NNI_PROTO_PUB_V0
#define NNI_PROTO_PUB_V0 NNI_PROTO(2, 0)
#endif

// By default we accept 128 messages.
#define SUB0_DEFAULT_RECV_BUF_LEN 128

// By default, prefer new messages when the queue is full.
#define SUB0_DEFAULT_PREFER_NEW true

typedef struct sub0_pipe  sub0_pipe;
typedef struct sub0_sock  sub0_sock;
typedef struct sub0_ctx   sub0_ctx;
typedef struct sub0_topic sub0_topic;

static void sub0_recv_cb(void *);
static void sub0_pipe_fini(void *);

struct sub0_topic {
	nni_list_node node;
	size_t        len;
	void *        buf;
};

// sub0_ctx is a context for a SUB socket.  The advantage of contexts is
// that different contexts can maintain different subscriptions.
struct sub0_ctx {
	nni_list_node node;
	sub0_sock *   sock;
	nni_list      topics;     // TODO: Consider patricia trie
	nni_list      recv_queue; // can have multiple pending receives
	nni_lmq       lmq;
	bool          prefer_new;
};

// sub0_sock is our per-socket protocol private structure.
struct sub0_sock {
	nni_pollable readable;
	sub0_ctx     master;   // default context
	nni_list     contexts; // all contexts
	size_t       recv_buf_len;
	bool         prefer_new;
	nni_mtx      lk;
};

// sub0_pipe is our per-pipe protocol private structure.
struct sub0_pipe {
	nni_pipe * pipe;
	sub0_sock *sub;
	nni_aio    aio_recv;
};

static void
sub0_ctx_cancel(nng_aio *aio, void *arg, int rv)
{
	sub0_ctx * ctx  = arg;
	sub0_sock *sock = ctx->sock;
	nni_mtx_lock(&sock->lk);
	if (nni_list_active(&ctx->recv_queue, aio)) {
		nni_list_remove(&ctx->recv_queue, aio);
		nni_aio_finish_error(aio, rv);
	}
	nni_mtx_unlock(&sock->lk);
}

static void
sub0_ctx_recv(void *arg, nni_aio *aio)
{
	sub0_ctx * ctx  = arg;
	sub0_sock *sock = ctx->sock;
	nni_msg *  msg;

	if (nni_aio_begin(aio) != 0) {
		return;
	}

	nni_mtx_lock(&sock->lk);

again:
	if (nni_lmq_empty(&ctx->lmq)) {
		int rv;
		if ((rv = nni_aio_schedule(aio, sub0_ctx_cancel, ctx)) != 0) {
			nni_mtx_unlock(&sock->lk);
			nni_aio_finish_error(aio, rv);
			return;
		}
		nni_list_append(&ctx->recv_queue, aio);
		nni_mtx_unlock(&sock->lk);
		return;
	}

	(void) nni_lmq_getq(&ctx->lmq, &msg);

	if (nni_lmq_empty(&ctx->lmq) && (ctx == &sock->master)) {
		nni_pollable_clear(&sock->readable);
	}
	if ((msg = nni_msg_unique(msg)) == NULL) {
		goto again;
	}
	nni_aio_set_msg(aio, msg);
	nni_mtx_unlock(&sock->lk);
	nni_aio_finish(aio, 0, nni_msg_len(msg));
}

static void
sub0_ctx_send(void *arg, nni_aio *aio)
{
	NNI_ARG_UNUSED(arg);
	if (nni_aio_begin(aio) == 0) {
		nni_aio_finish_error(aio, NNG_ENOTSUP);
	}
}

static void
sub0_ctx_close(void *arg)
{
	sub0_ctx * ctx  = arg;
	sub0_sock *sock = ctx->sock;
	nni_aio *  aio;

	nni_mtx_lock(&sock->lk);
	while ((aio = nni_list_first(&ctx->recv_queue)) != NULL) {
		nni_list_remove(&ctx->recv_queue, aio);
		nni_aio_finish_error(aio, NNG_ECLOSED);
	}
	nni_mtx_unlock(&sock->lk);
}

static void
sub0_ctx_fini(void *arg)
{
	sub0_ctx *  ctx  = arg;
	sub0_sock * sock = ctx->sock;
	sub0_topic *topic;

	sub0_ctx_close(ctx);

	nni_mtx_lock(&sock->lk);
	nni_list_remove(&sock->contexts, ctx);
	nni_mtx_unlock(&sock->lk);

	while ((topic = nni_list_first(&ctx->topics)) != 0) {
		nni_list_remove(&ctx->topics, topic);
		nni_free(topic->buf, topic->len);
		NNI_FREE_STRUCT(topic);
	}

	nni_lmq_fini(&ctx->lmq);
}

static int
sub0_ctx_init(void *ctx_arg, void *sock_arg)
{
	sub0_sock *sock = sock_arg;
	sub0_ctx * ctx  = ctx_arg;
	size_t     len;
	bool       prefer_new;
	int        rv;

	nni_mtx_lock(&sock->lk);
	len        = sock->recv_buf_len;
	prefer_new = sock->prefer_new;

	if ((rv = nni_lmq_init(&ctx->lmq, len)) != 0) {
		return (rv);
	}
	ctx->prefer_new = prefer_new;

	nni_aio_list_init(&ctx->recv_queue);
	NNI_LIST_INIT(&ctx->topics, sub0_topic, node);

	ctx->sock = sock;

	nni_list_append(&sock->contexts, ctx);
	nni_mtx_unlock(&sock->lk);

	return (0);
}

static void
sub0_sock_fini(void *arg)
{
	sub0_sock *sock = arg;

	sub0_ctx_fini(&sock->master);
	nni_pollable_fini(&sock->readable);
	nni_mtx_fini(&sock->lk);
}

static int
sub0_sock_init(void *arg, nni_sock *unused)
{
	sub0_sock *sock = arg;
	int        rv;

	NNI_ARG_UNUSED(unused);

	NNI_LIST_INIT(&sock->contexts, sub0_ctx, node);
	nni_mtx_init(&sock->lk);
	sock->recv_buf_len = SUB0_DEFAULT_RECV_BUF_LEN;
	sock->prefer_new   = SUB0_DEFAULT_PREFER_NEW;
	nni_pollable_init(&sock->readable);

	if ((rv = sub0_ctx_init(&sock->master, sock)) != 0) {
		sub0_sock_fini(sock);
		return (rv);
	}

	return (0);
}

static void
sub0_sock_open(void *arg)
{
	NNI_ARG_UNUSED(arg);
}

static void
sub0_sock_close(void *arg)
{
	sub0_sock *sock = arg;
	sub0_ctx_close(&sock->master);
}

static void
sub0_pipe_stop(void *arg)
{
	sub0_pipe *p = arg;

	nni_aio_stop(&p->aio_recv);
}

static void
sub0_pipe_fini(void *arg)
{
	sub0_pipe *p = arg;

	nni_aio_fini(&p->aio_recv);
}

static int
sub0_pipe_init(void *arg, nni_pipe *pipe, void *s)
{
	sub0_pipe *p = arg;

	nni_aio_init(&p->aio_recv, sub0_recv_cb, p);

	p->pipe = pipe;
	p->sub  = s;
	return (0);
}

static int
sub0_pipe_start(void *arg)
{
	sub0_pipe *p = arg;

	if (nni_pipe_peer(p->pipe) != NNI_PROTO_PUB_V0) {
		// Peer protocol mismatch.
		return (NNG_EPROTO);
	}

	nni_pipe_recv(p->pipe, &p->aio_recv);
	return (0);
}

static void
sub0_pipe_close(void *arg)
{
	sub0_pipe *p = arg;

	nni_aio_close(&p->aio_recv);
}

static bool
sub0_matches(sub0_ctx *ctx, uint8_t *body, size_t len)
{
	sub0_topic *topic;

	// This is a naive and trivial matcher.  Replace with a real
	// patricia trie later.
	NNI_LIST_FOREACH (&ctx->topics, topic) {
		if (len < topic->len) {
			continue;
		}
		if ((topic->len == 0) ||
		    (memcmp(topic->buf, body, topic->len) == 0)) {
			return (true);
		}
	}
	return (false);
}

static void
sub0_recv_cb(void *arg)
{
	sub0_pipe *p    = arg;
	sub0_sock *sock = p->sub;
	sub0_ctx * ctx;
	nni_msg *  msg;
	size_t     len;
	uint8_t *  body;
	nni_list   finish;
	nng_aio *  aio;
	bool       submatch;

	if (nni_aio_result(&p->aio_recv) != 0) {
		nni_pipe_close(p->pipe);
		return;
	}

	nni_aio_list_init(&finish);

	msg = nni_aio_get_msg(&p->aio_recv);
	nni_aio_set_msg(&p->aio_recv, NULL);
	nni_msg_set_pipe(msg, nni_pipe_id(p->pipe));

	body     = nni_msg_body(msg);
	len      = nni_msg_len(msg);
	submatch = false;

	nni_mtx_lock(&sock->lk);
	// Go through all contexts.  We will try to send up.
	NNI_LIST_FOREACH (&sock->contexts, ctx) {

		if (nni_lmq_full(&ctx->lmq) && !ctx->prefer_new) {
			// Cannot deliver here, as receive buffer is full.
			continue;
		}

		if (!sub0_matches(ctx, body, len)) {
			continue;
		}

		nni_msg_clone(msg);

		// If we got to this point, we are capable of receiving this
		// message and it is intended for us.
		submatch = true;

		if (!nni_list_empty(&ctx->recv_queue)) {
			aio = nni_list_first(&ctx->recv_queue);
			nni_list_remove(&ctx->recv_queue, aio);
			nni_aio_set_msg(aio, msg);

			// Save for synchronous completion
			nni_list_append(&finish, aio);
		} else if (nni_lmq_full(&ctx->lmq)) {
			// Make space for the new message.
			nni_msg *old;
			(void) nni_lmq_getq(&ctx->lmq, &old);
			nni_msg_free(old);

			(void) nni_lmq_putq(&ctx->lmq, msg);
		} else {
			(void) nni_lmq_putq(&ctx->lmq, msg);
		}
	}
	nni_mtx_unlock(&sock->lk);

	// Drop the first reference we inherited.  Any we passed are
	// accounted for in the clones we made.
	nni_msg_free(msg);

	while ((aio = nni_list_first(&finish)) != NULL) {
		nni_list_remove(&finish, aio);
		nni_aio_finish_synch(aio, 0, len);
	}

	if (submatch) {
		nni_pollable_raise(&sock->readable);
	}

	nni_pipe_recv(p->pipe, &p->aio_recv);
}

static int
sub0_ctx_get_recv_buf_len(void *arg, void *buf, size_t *szp, nni_type t)
{
	sub0_ctx * ctx  = arg;
	sub0_sock *sock = ctx->sock;
	int        val;
	nni_mtx_lock(&sock->lk);
	val = (int) nni_lmq_cap(&ctx->lmq);
	nni_mtx_unlock(&sock->lk);

	return (nni_copyout_int(val, buf, szp, t));
}

static int
sub0_ctx_set_recv_buf_len(void *arg, const void *buf, size_t sz, nni_type t)
{
	sub0_ctx * ctx  = arg;
	sub0_sock *sock = ctx->sock;
	int        val;
	int        rv;

	if ((rv = nni_copyin_int(&val, buf, sz, 1, 8192, t)) != 0) {
		return (rv);
	}
	nni_mtx_lock(&sock->lk);
	if ((rv = nni_lmq_resize(&ctx->lmq, (size_t) val)) != 0) {
		nni_mtx_unlock(&sock->lk);
		return (rv);
	}

	// If we change the socket, then this will change the queue for
	// any new contexts. (Previously constructed contexts are unaffected.)
	if (&sock->master == ctx) {
		sock->recv_buf_len = (size_t) val;
	}
	nni_mtx_unlock(&sock->lk);
	return (0);
}

// For now we maintain subscriptions on a sorted linked list.  As we do not
// expect to have huge numbers of subscriptions, and as the operation is
// really O(n), we think this is acceptable.  In the future we might decide
// to replace this with a patricia trie, like old nanomsg had.

static int
sub0_ctx_subscribe(void *arg, const void *buf, size_t sz, nni_type t)
{
	sub0_ctx *  ctx  = arg;
	sub0_sock * sock = ctx->sock;
	sub0_topic *topic;
	sub0_topic *new_topic;
	NNI_ARG_UNUSED(t);

	nni_mtx_lock(&sock->lk);
	NNI_LIST_FOREACH (&ctx->topics, topic) {
		if (topic->len != sz) {
			continue;
		}
		if (memcmp(topic->buf, buf, sz) == 0) {
			// Already have it.
			nni_mtx_unlock(&sock->lk);
			return (0);
		}
	}
	if ((new_topic = NNI_ALLOC_STRUCT(new_topic)) == NULL) {
		nni_mtx_unlock(&sock->lk);
		return (NNG_ENOMEM);
	}
	if ((sz > 0) && ((new_topic->buf = nni_alloc(sz)) == NULL)) {
		nni_mtx_unlock(&sock->lk);
		NNI_FREE_STRUCT(new_topic);
		return (NNG_ENOMEM);
	}
	memcpy(new_topic->buf, buf, sz);
	new_topic->len = sz;
	nni_list_append(&ctx->topics, new_topic);
	nni_mtx_unlock(&sock->lk);
	return (0);
}

static int
sub0_ctx_unsubscribe(void *arg, const void *buf, size_t sz, nni_type t)
{
	sub0_ctx *  ctx  = arg;
	sub0_sock * sock = ctx->sock;
	sub0_topic *topic;
	size_t      len;
	NNI_ARG_UNUSED(t);

	nni_mtx_lock(&sock->lk);
	NNI_LIST_FOREACH (&ctx->topics, topic) {
		if (topic->len != sz) {
			continue;
		}
		if (memcmp(topic->buf, buf, sz) == 0) {
			// Matched!
			break;
		}
	}
	if (topic == NULL) {
		nni_mtx_unlock(&sock->lk);
		return (NNG_ENOENT);
	}
	nni_list_remove(&ctx->topics, topic);

	// Now we need to make sure that any messages that are waiting still
	// match the subscription.  We basically just run through the queue
	// and requeue those messages we need.
	len = nni_lmq_len(&ctx->lmq);
	for (size_t i = 0; i < len; i++) {
		nni_msg *msg;

		(void) nni_lmq_getq(&ctx->lmq, &msg);
		if (sub0_matches(ctx, nni_msg_body(msg), nni_msg_len(msg))) {
			(void) nni_lmq_putq(&ctx->lmq, msg);
		} else {
			nni_msg_free(msg);
		}
	}
	nni_mtx_unlock(&sock->lk);

	nni_free(topic->buf, topic->len);
	NNI_FREE_STRUCT(topic);
	return (0);
}

static int
sub0_ctx_get_prefer_new(void *arg, void *buf, size_t *szp, nni_type t)
{
	sub0_ctx * ctx  = arg;
	sub0_sock *sock = ctx->sock;
	bool       val;

	nni_mtx_lock(&sock->lk);
	val = ctx->prefer_new;
	nni_mtx_unlock(&sock->lk);

	return (nni_copyout_bool(val, buf, szp, t));
}

static int
sub0_ctx_set_prefer_new(void *arg, const void *buf, size_t sz, nni_type t)
{
	sub0_ctx * ctx  = arg;
	sub0_sock *sock = ctx->sock;
	bool       val;
	int        rv;

	if ((rv = nni_copyin_bool(&val, buf, sz, t)) != 0) {
		return (rv);
	}

	nni_mtx_lock(&sock->lk);
	ctx->prefer_new = val;
	if (&sock->master == ctx) {
		sock->prefer_new = val;
	}
	nni_mtx_unlock(&sock->lk);

	return (0);
}

static nni_option sub0_ctx_options[] = {
	{
	    .o_name = NNG_OPT_RECVBUF,
	    .o_get  = sub0_ctx_get_recv_buf_len,
	    .o_set  = sub0_ctx_set_recv_buf_len,
	},
	{
	    .o_name = NNG_OPT_SUB_SUBSCRIBE,
	    .o_set  = sub0_ctx_subscribe,
	},
	{
	    .o_name = NNG_OPT_SUB_UNSUBSCRIBE,
	    .o_set  = sub0_ctx_unsubscribe,
	},
	{
	    .o_name = NNG_OPT_SUB_PREFNEW,
	    .o_get  = sub0_ctx_get_prefer_new,
	    .o_set  = sub0_ctx_set_prefer_new,
	},
	{
	    .o_name = NULL,
	},
};

static void
sub0_sock_send(void *arg, nni_aio *aio)
{
	NNI_ARG_UNUSED(arg);
	if (nni_aio_begin(aio) == 0) {
		nni_aio_finish_error(aio, NNG_ENOTSUP);
	}
}

static void
sub0_sock_recv(void *arg, nni_aio *aio)
{
	sub0_sock *sock = arg;

	sub0_ctx_recv(&sock->master, aio);
}

static int
sub0_sock_get_recv_fd(void *arg, void *buf, size_t *szp, nni_opt_type t)
{
	sub0_sock *sock = arg;
	int        rv;
	int        fd;

	if ((rv = nni_pollable_getfd(&sock->readable, &fd)) != 0) {
		return (rv);
	}
	return (nni_copyout_int(fd, buf, szp, t));
}

static int
sub0_sock_get_recv_buf_len(void *arg, void *buf, size_t *szp, nni_type t)
{
	sub0_sock *sock = arg;
	return (sub0_ctx_get_recv_buf_len(&sock->master, buf, szp, t));
}

static int
sub0_sock_set_recv_buf_len(void *arg, const void *buf, size_t sz, nni_type t)
{
	sub0_sock *sock = arg;
	return (sub0_ctx_set_recv_buf_len(&sock->master, buf, sz, t));
}

static int
sub0_sock_subscribe(void *arg, const void *buf, size_t sz, nni_type t)
{
	sub0_sock *sock = arg;
	return (sub0_ctx_subscribe(&sock->master, buf, sz, t));
}

static int
sub0_sock_unsubscribe(void *arg, const void *buf, size_t sz, nni_type t)
{
	sub0_sock *sock = arg;
	return (sub0_ctx_unsubscribe(&sock->master, buf, sz, t));
}

static int
sub0_sock_get_prefer_new(void *arg, void *buf, size_t *szp, nni_type t)
{
	sub0_sock *sock = arg;
	return (sub0_ctx_get_prefer_new(&sock->master, buf, szp, t));
}

static int
sub0_sock_set_prefer_new(void *arg, const void *buf, size_t sz, nni_type t)
{
	sub0_sock *sock = arg;
	return (sub0_ctx_set_prefer_new(&sock->master, buf, sz, t));
}

// This is the global protocol structure -- our linkage to the core.
// This should be the only global non-static symbol in this file.
static nni_proto_pipe_ops sub0_pipe_ops = {
	.pipe_size  = sizeof(sub0_pipe),
	.pipe_init  = sub0_pipe_init,
	.pipe_fini  = sub0_pipe_fini,
	.pipe_start = sub0_pipe_start,
	.pipe_close = sub0_pipe_close,
	.pipe_stop  = sub0_pipe_stop,
};

static nni_proto_ctx_ops sub0_ctx_ops = {
	.ctx_size    = sizeof(sub0_ctx),
	.ctx_init    = sub0_ctx_init,
	.ctx_fini    = sub0_ctx_fini,
	.ctx_send    = sub0_ctx_send,
	.ctx_recv    = sub0_ctx_recv,
	.ctx_options = sub0_ctx_options,
};

static nni_option sub0_sock_options[] = {
	{
	    .o_name = NNG_OPT_SUB_SUBSCRIBE,
	    .o_set  = sub0_sock_subscribe,
	},
	{
	    .o_name = NNG_OPT_SUB_UNSUBSCRIBE,
	    .o_set  = sub0_sock_unsubscribe,
	},
	{
	    .o_name = NNG_OPT_RECVFD,
	    .o_get  = sub0_sock_get_recv_fd,
	},
	{
	    .o_name = NNG_OPT_RECVBUF,
	    .o_get  = sub0_sock_get_recv_buf_len,
	    .o_set  = sub0_sock_set_recv_buf_len,
	},
	{
	    .o_name = NNG_OPT_SUB_PREFNEW,
	    .o_get  = sub0_sock_get_prefer_new,
	    .o_set  = sub0_sock_set_prefer_new,
	},
	// terminate list
	{
	    .o_name = NULL,
	},
};

static nni_proto_sock_ops sub0_sock_ops = {
	.sock_size    = sizeof(sub0_sock),
	.sock_init    = sub0_sock_init,
	.sock_fini    = sub0_sock_fini,
	.sock_open    = sub0_sock_open,
	.sock_close   = sub0_sock_close,
	.sock_send    = sub0_sock_send,
	.sock_recv    = sub0_sock_recv,
	.sock_options = sub0_sock_options,
};

static nni_proto sub0_proto = {
	.proto_version  = NNI_PROTOCOL_VERSION,
	.proto_self     = { NNI_PROTO_SUB_V0, "sub" },
	.proto_peer     = { NNI_PROTO_PUB_V0, "pub" },
	.proto_flags    = NNI_PROTO_FLAG_RCV | NNI_PROTO_FLAG_NOMSGQ,
	.proto_sock_ops = &sub0_sock_ops,
	.proto_pipe_ops = &sub0_pipe_ops,
	.proto_ctx_ops  = &sub0_ctx_ops,
};

int
nng_sub0_open(nng_socket *sock)
{
	return (nni_proto_open(sock, &sub0_proto));
}
