//
// Copyright 2022 Cogent Embedded, Inc.
// Copyright 2021 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//
#include <stdbool.h>
#include <stdlib.h>

#include "core/nng_impl.h"
#include "nng/protocol/hub0/hub.h"
#include <stdio.h>

#ifndef NNI_PROTO_HUB_V0
#define NNI_PROTO_HUB_V0 NNI_PROTO(1, 0)
#endif

typedef struct hub0_pipe hub0_pipe;
typedef struct hub0_sock hub0_sock;

static void hub0_sock_send(void *, nni_aio *);
static void hub0_sock_recv(void *, nni_aio *);

static void hub0_pipe_recv(hub0_pipe *);

static void hub0_pipe_send_cb(void *);
static void hub0_pipe_recv_cb(void *);

// hub0_sock is our per-socket protocol private structure.
struct hub0_sock {
	nni_list     pipes;
	nni_mtx      mtx;
	nni_pollable can_send;
	nni_pollable can_recv;
	nni_lmq      recv_msgs;
	nni_list     recv_wait;
	int          send_buf;
	nni_list     waq;
};

// hub0_pipe is our per-pipe protocol private structure.
struct hub0_pipe {
	nni_pipe       *pipe;
	hub0_sock      *hub;
	nni_lmq         send_queue;
	nni_list_node   node;
	bool            busy;
	bool            read_ready;
	nni_aio         aio_recv;
	nni_aio         aio_send;
};

static void
hub0_sock_fini(void *arg)
{
	hub0_sock *s = arg;

	nni_mtx_fini(&s->mtx);
	nni_pollable_fini(&s->can_send);
	nni_pollable_fini(&s->can_recv);
	nni_lmq_fini(&s->recv_msgs);
}

static void
hub0_sock_init(void *arg, nni_sock *ns)
{
	hub0_sock *s = arg;

	NNI_ARG_UNUSED(ns);

	NNI_LIST_INIT(&s->pipes, hub0_pipe, node);
	nni_mtx_init(&s->mtx);
	nni_aio_list_init(&s->recv_wait);
	nni_pollable_init(&s->can_send);
	nni_pollable_init(&s->can_recv);
	nni_lmq_init(&s->recv_msgs, 16);
	s->send_buf = 16;
	nni_aio_list_init(&s->waq);
}

static void
hub0_sock_open(void *arg)
{
	NNI_ARG_UNUSED(arg);
}

static void
hub0_sock_close(void *arg)
{
	hub0_sock *s = arg;
	nni_aio   *aio;

	nni_mtx_lock(&s->mtx);

	while ((aio = nni_list_first(&s->waq)) != NULL) {
	  nni_aio_list_remove(aio);
	  nni_aio_finish_error(aio, NNG_ECLOSED);
	}

	while ((aio = nni_list_first(&s->recv_wait)) != NULL) {
		nni_list_remove(&s->recv_wait, aio);
		nni_aio_finish_error(aio, NNG_ECLOSED);
	}
	nni_mtx_unlock(&s->mtx);
}

static void
hub0_send_cancel(nng_aio *aio, void *arg, int rv)
{
	hub0_sock *s = arg;

	nni_mtx_lock(&s->mtx);
	if (nni_aio_list_active(aio)) {
		nni_aio_list_remove(aio);
		nni_aio_finish_error(aio, rv);
	}
	nni_mtx_unlock(&s->mtx);
}

static void
hub0_pipe_send(hub0_pipe *pipe, nni_msg *msg)
{
	if (!pipe->busy) {
		pipe->busy = true;
		nni_msg_clone(msg);
		nni_aio_set_msg(&pipe->aio_send, msg);
		nni_pipe_send(pipe->pipe, &pipe->aio_send);
	} else if (!nni_lmq_full(&pipe->send_queue)) {
		nni_msg_clone(msg);
		nni_lmq_put(&pipe->send_queue, msg);
	}
}

static bool
hub0_is_writable(hub0_sock *s)
{
	hub0_pipe       *pipe;

	NNI_LIST_FOREACH (&s->pipes, pipe) {
		//hub is writable if all pipes are writable
		if (nni_lmq_full(&pipe->send_queue)) {
			return false;
		}
	}
	return true;
}

static void
hub0_sched_send(hub0_sock *s)
{
	nni_aio         *aio;
	hub0_pipe       *pipe;
	int              rv;
	nni_msg         *msg;
	size_t           len;

	nni_mtx_lock(&s->mtx);

	if (!hub0_is_writable(s)){
		nni_mtx_unlock(&s->mtx);
		return;
	}

	while (!nni_list_empty(&s->waq)){
		if ((aio = nni_list_first(&s->waq)) != NULL) {
			nni_aio_list_remove(aio);

			if ((rv = nni_aio_schedule(aio, hub0_send_cancel, s)) != 0) {
				nni_aio_finish_error(aio, rv);
				continue;
			}

			msg = nni_aio_get_msg(aio);
			len = nni_msg_len(msg);
			nni_aio_set_msg(aio, NULL);

			NNI_LIST_FOREACH (&s->pipes, pipe) {
				hub0_pipe_send(pipe, msg);
			}

			nni_msg_free(msg);
			nni_aio_finish(aio, 0, len);
			break;
		}
	}

	if (hub0_is_writable(s)) {
		nni_pollable_raise(&s->can_send);
	} else {
		nni_pollable_clear(&s->can_send);
	}

	nni_mtx_unlock(&s->mtx);
}

static void
hub0_pipe_stop(void *arg)
{
	hub0_pipe *p = arg;
	hub0_sock *s = p->hub;

	nni_mtx_lock(&s->mtx);
	p->busy = true;

	if (p->read_ready) {
		nni_msg *m = nni_aio_get_msg(&p->aio_recv);
		nni_msg_free(m);
		p->read_ready = false;
	}

	nni_mtx_unlock(&s->mtx);

	nni_aio_stop(&p->aio_send);
	nni_aio_stop(&p->aio_recv);
}

static void
hub0_pipe_fini(void *arg)
{
	hub0_pipe *p = arg;

	nni_aio_fini(&p->aio_send);
	nni_aio_fini(&p->aio_recv);
	nni_lmq_fini(&p->send_queue);
}

static int
hub0_pipe_init(void *arg, nni_pipe *np, void *s)
{
	hub0_pipe *p = arg;

	p->pipe = np;
	p->hub  = s;
	NNI_LIST_NODE_INIT(&p->node);
	nni_aio_init(&p->aio_send, hub0_pipe_send_cb, p);
	nni_aio_init(&p->aio_recv, hub0_pipe_recv_cb, p);
	nni_lmq_init(&p->send_queue, p->hub->send_buf);

	return (0);
}

static int
hub0_pipe_start(void *arg)
{
	hub0_pipe *p = arg;
	hub0_sock *s = p->hub;

	if (nni_pipe_peer(p->pipe) != NNI_PROTO_HUB_V0) {
		return (NNG_EPROTO);
	}

	nni_mtx_lock(&s->mtx);
	nni_list_append(&s->pipes, p);
	p->busy = false;
	p->read_ready = false;
	nni_mtx_unlock(&s->mtx);

	hub0_sched_send(s);

	hub0_pipe_recv(p);

	return (0);
}

static void
hub0_pipe_close(void *arg)
{
	hub0_pipe *p = arg;
	hub0_sock *s = p->hub;

	nni_aio_close(&p->aio_send);
	nni_aio_close(&p->aio_recv);

	nni_mtx_lock(&s->mtx);
	nni_lmq_flush(&p->send_queue);
	if (nni_list_active(&s->pipes, p)) {
		nni_list_remove(&s->pipes, p);
	}
	nni_mtx_unlock(&s->mtx);
}

static void
hub0_pipe_send_cb(void *arg)
{
	hub0_pipe *p = arg;
	hub0_sock *s = p->hub;
	nni_msg   *msg;

	if (nni_aio_result(&p->aio_send) != 0) {
		// closed?
		nni_msg_free(nni_aio_get_msg(&p->aio_send));
		nni_aio_set_msg(&p->aio_send, NULL);
		nni_pipe_close(p->pipe);
		return;
	}

	nni_mtx_lock(&s->mtx);
	if (nni_lmq_get(&p->send_queue, &msg) == 0) {
		nni_aio_set_msg(&p->aio_send, msg);
		nni_pipe_send(p->pipe, &p->aio_send);
	} else {
		p->busy = false;
	}
	nni_mtx_unlock(&s->mtx);

  hub0_sched_send(s);
}

static void
hub0_pipe_recv_cb(void *arg)
{
	hub0_pipe *p = arg;
	hub0_sock *s = p->hub;
	nni_aio   *aio = NULL;
	nni_msg   *msg;

	if (nni_aio_result(&p->aio_recv) != 0) {
		nni_pipe_close(p->pipe);
		return;
	}

	msg = nni_aio_get_msg(&p->aio_recv);
	nni_msg_set_pipe(msg, nni_pipe_id(p->pipe));

	nni_mtx_lock(&s->mtx);

	if (!nni_list_empty(&s->recv_wait)) {
		aio = nni_list_first(&s->recv_wait);
		nni_aio_list_remove(aio);
		nni_aio_set_msg(aio, msg);
		nni_aio_set_msg(&p->aio_recv, NULL);
	} else if (nni_lmq_put(&s->recv_msgs, msg) == 0) {
		nni_aio_set_msg(&p->aio_recv, NULL);
		nni_pollable_raise(&s->can_recv);
	} else {
		p->read_ready = true;
		nni_pollable_raise(&s->can_recv);
	}

	if (!p->read_ready) {
		hub0_pipe_recv(p);
	}

	nni_mtx_unlock(&s->mtx);

	if (aio != NULL) {
		nni_aio_finish_sync(aio, 0, nni_msg_len(msg));
	}
}

static void
hub0_pipe_recv(hub0_pipe *p)
{
	nni_pipe_recv(p->pipe, &p->aio_recv);
}

static void
hub0_recv_activate(hub0_sock *s)
{
	nni_msg    *msg;
	hub0_pipe  *pipe;

	// Inform all pipes that we are ready to
	// receive messages
	NNI_LIST_FOREACH (&s->pipes, pipe) {
		if (pipe->read_ready) {
			msg = nni_aio_get_msg(&pipe->aio_recv);
			nni_msg_set_pipe(msg, nni_pipe_id(pipe->pipe));

			if (nni_lmq_put(&s->recv_msgs, msg) == 0) {
				pipe->read_ready = false;
				nni_aio_set_msg(&pipe->aio_recv, NULL);
				nni_pollable_raise(&s->can_recv);
				hub0_pipe_recv(pipe);
			} else {
				break;
			}
		}
	}
}

static void
hub0_sock_send(void *arg, nni_aio *aio)
{
	hub0_sock *s = arg;

	if (nni_aio_begin(aio) != 0) {
		return;
	}

	nni_mtx_lock(&s->mtx);
	nni_aio_list_append(&s->waq, aio);
	nni_mtx_unlock(&s->mtx);

	hub0_sched_send(s);
}

static void
hub0_recv_cancel(nng_aio *aio, void *arg, int rv)
{
	hub0_sock *s = arg;

	nni_mtx_lock(&s->mtx);
	if (nni_aio_list_active(aio)) {
		nni_aio_list_remove(aio);
		nni_aio_finish_error(aio, rv);
	}
	nni_mtx_unlock(&s->mtx);
}

static void
hub0_sock_recv(void *arg, nni_aio *aio)
{
	hub0_sock *s = arg;
	nni_msg   *msg;

	if (nni_aio_begin(aio) != 0) {
		return;
	}

	nni_mtx_lock(&s->mtx);
again:
	if (nni_lmq_empty(&s->recv_msgs)) {
		int rv;
		if ((rv = nni_aio_schedule(aio, hub0_recv_cancel, s)) != 0) {
			nni_mtx_unlock(&s->mtx);
			nni_aio_finish_error(aio, rv);
			return;
		}
		nni_list_append(&s->recv_wait, aio);
		nni_mtx_unlock(&s->mtx);
		return;
	}

	(void) nni_lmq_get(&s->recv_msgs, &msg);

	if (nni_lmq_empty(&s->recv_msgs)) {
		nni_pollable_clear(&s->can_recv);
	}
	if ((msg = nni_msg_unique(msg)) == NULL) {
		goto again;
	}
	nni_aio_set_msg(aio, msg);

	hub0_recv_activate(s);

	nni_mtx_unlock(&s->mtx);
	nni_aio_finish(aio, 0, nni_msg_len(msg));
}

static int
hub0_sock_get_send_fd(void *arg, void *buf, size_t *szp, nni_type t)
{
	hub0_sock *sock = arg;
	int        fd;
	int        rv;

	rv = nni_pollable_getfd(&sock->can_send, &fd);
	if (rv == 0) {
		rv = nni_copyout_int(fd, buf, szp, t);
	}
	return (rv);
}

static int
hub0_sock_get_recv_fd(void *arg, void *buf, size_t *szp, nni_opt_type t)
{
	hub0_sock *s = arg;
	int        rv;
	int        fd;

	if ((rv = nni_pollable_getfd(&s->can_recv, &fd)) == 0) {
		rv = nni_copyout_int(fd, buf, szp, t);
	}
	return (rv);
}

static int
hub0_sock_get_recv_buf_len(void *arg, void *buf, size_t *szp, nni_type t)
{
	hub0_sock *s = arg;
	int        val;

	nni_mtx_lock(&s->mtx);
	val = (int) nni_lmq_cap(&s->recv_msgs);
	nni_mtx_unlock(&s->mtx);

	return (nni_copyout_int(val, buf, szp, t));
}

static int
hub0_sock_get_send_buf_len(void *arg, void *buf, size_t *szp, nni_type t)
{
	hub0_sock *s = arg;
	int        val;

	nni_mtx_lock(&s->mtx);
	val = s->send_buf;
	nni_mtx_unlock(&s->mtx);
	return (nni_copyout_int(val, buf, szp, t));
}

static int
hub0_sock_set_recv_buf_len(void *arg, const void *buf, size_t sz, nni_type t)
{
	hub0_sock *s = arg;
	int        val;
	int        rv;

	if ((rv = nni_copyin_int(&val, buf, sz, 1, 8192, t)) != 0) {
		return (rv);
	}
	nni_mtx_lock(&s->mtx);
	if ((rv = nni_lmq_resize(&s->recv_msgs, (size_t) val)) != 0) {
		nni_mtx_unlock(&s->mtx);
		return (rv);
	}

	nni_mtx_unlock(&s->mtx);
	return (0);
}

static int
hub0_sock_set_send_buf_len(void *arg, const void *buf, size_t sz, nni_type t)
{
	hub0_sock *s = arg;
	hub0_pipe *p;
	int        val;
	int        rv;

	if ((rv = nni_copyin_int(&val, buf, sz, 1, 8192, t)) != 0) {
		return (rv);
	}

	nni_mtx_lock(&s->mtx);
	s->send_buf = val;
	NNI_LIST_FOREACH (&s->pipes, p) {
		if ((rv = nni_lmq_resize(&p->send_queue, (size_t) val)) != 0) {
			break;
		}
	}
	nni_mtx_unlock(&s->mtx);
	return (rv);
}

static nni_proto_pipe_ops hub0_pipe_ops = {
	.pipe_size  = sizeof(hub0_pipe),
	.pipe_init  = hub0_pipe_init,
	.pipe_fini  = hub0_pipe_fini,
	.pipe_start = hub0_pipe_start,
	.pipe_close = hub0_pipe_close,
	.pipe_stop  = hub0_pipe_stop,
};

static nni_option hub0_sock_options[] = {
	{
	    .o_name = NNG_OPT_SENDFD,
	    .o_get  = hub0_sock_get_send_fd,
	},
	{
	    .o_name = NNG_OPT_RECVFD,
	    .o_get  = hub0_sock_get_recv_fd,
	},
	{
	    .o_name = NNG_OPT_RECVBUF,
	    .o_get  = hub0_sock_get_recv_buf_len,
	    .o_set  = hub0_sock_set_recv_buf_len,
	},
	{
	    .o_name = NNG_OPT_SENDBUF,
	    .o_get  = hub0_sock_get_send_buf_len,
	    .o_set  = hub0_sock_set_send_buf_len,
	},
	// terminate list
	{
	    .o_name = NULL,
	},
};

static nni_proto_sock_ops hub0_sock_ops = {
	.sock_size    = sizeof(hub0_sock),
	.sock_init    = hub0_sock_init,
	.sock_fini    = hub0_sock_fini,
	.sock_open    = hub0_sock_open,
	.sock_close   = hub0_sock_close,
	.sock_send    = hub0_sock_send,
	.sock_recv    = hub0_sock_recv,
	.sock_options = hub0_sock_options,
};

static nni_proto hub0_proto = {
	.proto_version  = NNI_PROTOCOL_VERSION,
	.proto_self     = { NNI_PROTO_HUB_V0, "hub" },
	.proto_peer     = { NNI_PROTO_HUB_V0, "hub" },
	.proto_flags    = NNI_PROTO_FLAG_SNDRCV,
	.proto_sock_ops = &hub0_sock_ops,
	.proto_pipe_ops = &hub0_pipe_ops,
};

int
nng_hub0_open(nng_socket *id)
{
	return (nni_proto_open(id, &hub0_proto));
}
