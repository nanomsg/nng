//
// Copyright 2021 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <stdlib.h>

#include "core/nng_impl.h"
#include "nng/protocol/pipeline0/push.h"

// Push protocol.  The PUSH protocol is the "write" side of a pipeline.
// Push distributes fairly, or tries to, by giving messages in round-robin
// order.

#ifndef NNI_PROTO_PULL_V0
#define NNI_PROTO_PULL_V0 NNI_PROTO(5, 1)
#endif

#ifndef NNI_PROTO_PUSH_V0
#define NNI_PROTO_PUSH_V0 NNI_PROTO(5, 0)
#endif

typedef struct push0_pipe push0_pipe;
typedef struct push0_sock push0_sock;

static void push0_send_cb(void *);
static void push0_recv_cb(void *);
static void push0_pipe_ready(push0_pipe *);

// push0_sock is our per-socket protocol private structure.
struct push0_sock {
	nni_lmq      wq; // list of messages queued
	nni_list     aq; // list of aio senders waiting
	nni_list     pl; // list of pipes ready to send
	nni_pollable writable;
	nni_mtx      m;
};

// push0_pipe is our per-pipe protocol private structure.
struct push0_pipe {
	nni_pipe     *pipe;
	push0_sock   *push;
	nni_list_node node;

	nni_aio aio_recv;
	nni_aio aio_send;
};

static int
push0_sock_init(void *arg, nni_sock *sock)
{
	push0_sock *s = arg;
	NNI_ARG_UNUSED(sock);

	nni_mtx_init(&s->m);
	nni_aio_list_init(&s->aq);
	NNI_LIST_INIT(&s->pl, push0_pipe, node);
	nni_lmq_init(&s->wq, 0); // initially we start unbuffered.
	nni_pollable_init(&s->writable);

	return (0);
}

static void
push0_sock_fini(void *arg)
{
	push0_sock *s = arg;
	nni_pollable_fini(&s->writable);
	nni_lmq_fini(&s->wq);
	nni_mtx_fini(&s->m);
}

static void
push0_sock_open(void *arg)
{
	NNI_ARG_UNUSED(arg);
}

static void
push0_sock_close(void *arg)
{
	push0_sock *s = arg;
	nni_aio    *a;
	nni_mtx_lock(&s->m);
	while ((a = nni_list_first(&s->aq)) != NULL) {
		nni_aio_list_remove(a);
		nni_aio_finish_error(a, NNG_ECLOSED);
	}
	nni_mtx_unlock(&s->m);
}

static void
push0_pipe_stop(void *arg)
{
	push0_pipe *p = arg;

	nni_aio_stop(&p->aio_recv);
	nni_aio_stop(&p->aio_send);
}

static void
push0_pipe_fini(void *arg)
{
	push0_pipe *p = arg;

	nni_aio_fini(&p->aio_recv);
	nni_aio_fini(&p->aio_send);
}

static int
push0_pipe_init(void *arg, nni_pipe *pipe, void *s)
{
	push0_pipe *p = arg;

	nni_aio_init(&p->aio_recv, push0_recv_cb, p);
	nni_aio_init(&p->aio_send, push0_send_cb, p);
	NNI_LIST_NODE_INIT(&p->node);
	p->pipe = pipe;
	p->push = s;
	return (0);
}

static int
push0_pipe_start(void *arg)
{
	push0_pipe *p = arg;

	if (nni_pipe_peer(p->pipe) != NNI_PROTO_PULL_V0) {
		return (NNG_EPROTO);
	}

	// Schedule a receiver.  This is mostly so that we can detect
	// a closed transport pipe.
	nni_pipe_recv(p->pipe, &p->aio_recv);
	push0_pipe_ready(p);

	return (0);
}

static void
push0_pipe_close(void *arg)
{
	push0_pipe *p = arg;
	push0_sock *s = p->push;

	nni_aio_close(&p->aio_recv);
	nni_aio_close(&p->aio_send);

	nni_mtx_lock(&s->m);
	if (nni_list_node_active(&p->node)) {
		nni_list_node_remove(&p->node);

		if (nni_list_empty(&s->pl) && nni_lmq_full(&s->wq)) {
			nni_pollable_clear(&s->writable);
		}
	}
	nni_mtx_unlock(&s->m);
}

static void
push0_recv_cb(void *arg)
{
	push0_pipe *p = arg;

	// We normally expect to receive an error.  If a pipe actually
	// sends us data, we just discard it.
	if (nni_aio_result(&p->aio_recv) != 0) {
		nni_pipe_close(p->pipe);
		return;
	}
	nni_msg_free(nni_aio_get_msg(&p->aio_recv));
	nni_aio_set_msg(&p->aio_recv, NULL);
	nni_pipe_recv(p->pipe, &p->aio_recv);
}

static void
push0_pipe_ready(push0_pipe *p)
{
	push0_sock *s = p->push;
	nni_msg    *m;
	nni_aio    *a = NULL;
	size_t      l;
	bool        blocked;

	nni_mtx_lock(&s->m);

	blocked = nni_lmq_full(&s->wq) && nni_list_empty(&s->pl);

	// if  message is waiting in the buffered queue
	// then we prefer that.
	if (nni_lmq_get(&s->wq, &m) == 0) {
		nni_aio_set_msg(&p->aio_send, m);
		nni_pipe_send(p->pipe, &p->aio_send);

		if ((a = nni_list_first(&s->aq)) != NULL) {
			nni_aio_list_remove(a);
			m = nni_aio_get_msg(a);
			l = nni_msg_len(m);
			nni_lmq_put(&s->wq, m);
		}

	} else if ((a = nni_list_first(&s->aq)) != NULL) {
		// Looks like we had the unbuffered case, but
		// someone was waiting.
		nni_aio_list_remove(a);
		m = nni_aio_get_msg(a);
		l = nni_msg_len(m);

		nni_aio_set_msg(&p->aio_send, m);
		nni_pipe_send(p->pipe, &p->aio_send);
	} else {
		// We had nothing to send.  Just put us in the ready list.
		nni_list_append(&s->pl, p);
	}

	if (blocked) {
		// if we blocked, then toggle the status.
		if ((!nni_lmq_full(&s->wq)) || (!nni_list_empty(&s->pl))) {
			nni_pollable_raise(&s->writable);
		}
	}

	nni_mtx_unlock(&s->m);

	if (a != NULL) {
		nni_aio_set_msg(a, NULL);
		nni_aio_finish_sync(a, 0, l);
	}
}

static void
push0_send_cb(void *arg)
{
	push0_pipe *p = arg;

	if (nni_aio_result(&p->aio_send) != 0) {
		nni_msg_free(nni_aio_get_msg(&p->aio_send));
		nni_aio_set_msg(&p->aio_send, NULL);
		nni_pipe_close(p->pipe);
		return;
	}

	push0_pipe_ready(p);
}

static void
push0_cancel(nni_aio *aio, void *arg, int rv)
{
	push0_sock *s = arg;

	nni_mtx_lock(&s->m);
	if (nni_aio_list_active(aio)) {
		nni_aio_list_remove(aio);
		nni_aio_finish_error(aio, rv);
	}
	nni_mtx_unlock(&s->m);
}

static void
push0_sock_send(void *arg, nni_aio *aio)
{
	push0_sock *s = arg;
	push0_pipe *p;
	nni_msg    *m;
	size_t      l;
	int         rv;

	if (nni_aio_begin(aio) != 0) {
		return;
	}

	m = nni_aio_get_msg(aio);
	l = nni_msg_len(m);

	nni_mtx_lock(&s->m);

	// First we want to see if we can send it right now.
	// Note that we don't block the sender until the read is complete,
	// only until we have committed to send it.
	if ((p = nni_list_first(&s->pl)) != NULL) {
		nni_list_remove(&s->pl, p);
		// NB: We won't have had any waiters in the message queue
		// or the aio queue, because we would not put the pipe
		// in the ready list in that case.  Note though that the
		// wq may be "full" if we are unbuffered.
		if (nni_list_empty(&s->pl) && (nni_lmq_full(&s->wq))) {
			nni_pollable_clear(&s->writable);
		}
		nni_aio_set_msg(aio, NULL);
		nni_aio_finish(aio, 0, l);
		nni_aio_set_msg(&p->aio_send, m);
		nni_pipe_send(p->pipe, &p->aio_send);
		nni_mtx_unlock(&s->m);
		return;
	}

	// Can we maybe queue it.
	if (nni_lmq_put(&s->wq, m) == 0) {
		// Yay, we can.  So we're done.
		nni_aio_set_msg(aio, NULL);
		nni_aio_finish(aio, 0, l);
		if (nni_lmq_full(&s->wq)) {
			nni_pollable_clear(&s->writable);
		}
		nni_mtx_unlock(&s->m);
		return;
	}

	if ((rv = nni_aio_schedule(aio, push0_cancel, s)) != 0) {
		nni_aio_finish_error(aio, rv);
		nni_mtx_unlock(&s->m);
		return;
	}
	nni_aio_list_append(&s->aq, aio);
	nni_mtx_unlock(&s->m);
}

static void
push0_sock_recv(void *arg, nni_aio *aio)
{
	NNI_ARG_UNUSED(arg);
	nni_aio_finish_error(aio, NNG_ENOTSUP);
}

static int
push0_set_send_buf_len(void *arg, const void *buf, size_t sz, nni_type t)
{
	push0_sock *s = arg;
	int         val;
	int         rv;

	if ((rv = nni_copyin_int(&val, buf, sz, 0, 8192, t)) != 0) {
		return (rv);
	}
	nni_mtx_lock(&s->m);
	rv = nni_lmq_resize(&s->wq, (size_t) val);
	// Changing the size of the queue can affect our readiness.
	if (!nni_lmq_full(&s->wq)) {
		nni_pollable_raise(&s->writable);
	} else if (nni_list_empty(&s->pl)) {
		nni_pollable_clear(&s->writable);
	}
	nni_mtx_unlock(&s->m);
	return (rv);
}

static int
push0_get_send_buf_len(void *arg, void *buf, size_t *szp, nni_opt_type t)
{
	push0_sock *s = arg;
	int         val;

	nni_mtx_lock(&s->m);
	val = (int) nni_lmq_cap(&s->wq);
	nni_mtx_unlock(&s->m);

	return (nni_copyout_int(val, buf, szp, t));
}

static int
push0_sock_get_send_fd(void *arg, void *buf, size_t *szp, nni_opt_type t)
{
	push0_sock *s = arg;
	int         rv;
	int         fd;

	if ((rv = nni_pollable_getfd(&s->writable, &fd)) != 0) {
		return (rv);
	}
	return (nni_copyout_int(fd, buf, szp, t));
}

static nni_proto_pipe_ops push0_pipe_ops = {
	.pipe_size  = sizeof(push0_pipe),
	.pipe_init  = push0_pipe_init,
	.pipe_fini  = push0_pipe_fini,
	.pipe_start = push0_pipe_start,
	.pipe_close = push0_pipe_close,
	.pipe_stop  = push0_pipe_stop,
};

static nni_option push0_sock_options[] = {
	{
	    .o_name = NNG_OPT_SENDFD,
	    .o_get  = push0_sock_get_send_fd,
	},
	{
	    .o_name = NNG_OPT_SENDBUF,
	    .o_get  = push0_get_send_buf_len,
	    .o_set  = push0_set_send_buf_len,
	},
	// terminate list
	{
	    .o_name = NULL,
	},
};

static nni_proto_sock_ops push0_sock_ops = {
	.sock_size    = sizeof(push0_sock),
	.sock_init    = push0_sock_init,
	.sock_fini    = push0_sock_fini,
	.sock_open    = push0_sock_open,
	.sock_close   = push0_sock_close,
	.sock_options = push0_sock_options,
	.sock_send    = push0_sock_send,
	.sock_recv    = push0_sock_recv,
};

static nni_proto push0_proto = {
	.proto_version  = NNI_PROTOCOL_VERSION,
	.proto_self     = { NNI_PROTO_PUSH_V0, "push" },
	.proto_peer     = { NNI_PROTO_PULL_V0, "pull" },
	.proto_flags    = NNI_PROTO_FLAG_SND,
	.proto_pipe_ops = &push0_pipe_ops,
	.proto_sock_ops = &push0_sock_ops,
};

static nni_proto push0_proto_raw = {
	.proto_version  = NNI_PROTOCOL_VERSION,
	.proto_self     = { NNI_PROTO_PUSH_V0, "push" },
	.proto_peer     = { NNI_PROTO_PULL_V0, "pull" },
	.proto_flags    = NNI_PROTO_FLAG_SND | NNI_PROTO_FLAG_RAW,
	.proto_pipe_ops = &push0_pipe_ops,
	.proto_sock_ops = &push0_sock_ops,
};

int
nng_push0_open(nng_socket *s)
{
	return (nni_proto_open(s, &push0_proto));
}

int
nng_push0_open_raw(nng_socket *s)
{
	return (nni_proto_open(s, &push0_proto_raw));
}
