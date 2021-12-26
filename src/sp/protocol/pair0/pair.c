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
#include "nng/protocol/pair0/pair.h"

// Pair protocol.  The PAIR protocol is a simple 1:1 messaging pattern.
// While a peer is connected to the server, all other peer connection
// attempts are discarded.

#ifndef NNI_PROTO_PAIR_V0
#define NNI_PROTO_PAIR_V0 NNI_PROTO(1, 0)
#endif

typedef struct pair0_pipe pair0_pipe;
typedef struct pair0_sock pair0_sock;

static void pair0_pipe_send_cb(void *);
static void pair0_pipe_recv_cb(void *);
static void pair0_pipe_fini(void *);
static void pair0_send_sched(pair0_sock *);
static void pair0_pipe_send(pair0_pipe *, nni_msg *);

// pair0_sock is our per-socket protocol private structure.
struct pair0_sock {
	pair0_pipe  *p;
	nni_mtx      mtx;
	nni_lmq      wmq;
	nni_list     waq;
	nni_lmq      rmq;
	nni_list     raq;
	nni_pollable readable;
	nni_pollable writable;
	bool         rd_ready; // pipe ready for read
	bool         wr_ready; // pipe ready for write
};

// A pair0_pipe is our per-pipe protocol private structure.  We keep
// one of these even though in theory we'd only have a single underlying
// pipe.  The separate data structure is more like other protocols that do
// manage multiple pipes.
struct pair0_pipe {
	nni_pipe   *pipe;
	pair0_sock *pair;
	nni_aio     aio_send;
	nni_aio     aio_recv;
};

static int
pair0_sock_init(void *arg, nni_sock *sock)
{
	pair0_sock *s = arg;
	NNI_ARG_UNUSED(sock);

	nni_mtx_init(&s->mtx);

	nni_lmq_init(&s->rmq, 0);
	nni_lmq_init(&s->wmq, 0);
	nni_aio_list_init(&s->raq);
	nni_aio_list_init(&s->waq);
	nni_pollable_init(&s->writable);
	nni_pollable_init(&s->readable);

	s->p = NULL;
	return (0);
}

static void
pair0_sock_fini(void *arg)
{
	pair0_sock *s = arg;

	nni_lmq_fini(&s->rmq);
	nni_lmq_fini(&s->wmq);
	nni_mtx_fini(&s->mtx);
}

static void
pair0_pipe_stop(void *arg)
{
	pair0_pipe *p = arg;
	pair0_sock *s = p->pair;

	nni_mtx_lock(&s->mtx);
	if (s->p == p) {
		s->p = NULL;
		if (s->rd_ready) {
			nni_msg *m = nni_aio_get_msg(&p->aio_recv);
			nni_msg_free(m);
			s->rd_ready = false;
		}
		if (s->wr_ready) {
			s->wr_ready = false;
			nni_pollable_clear(&s->writable);
		}
		if (nni_lmq_empty(&s->rmq)) {
			nni_pollable_clear(&s->readable);
		}
	}
	nni_mtx_unlock(&s->mtx);

	nni_aio_stop(&p->aio_send);
	nni_aio_stop(&p->aio_recv);
}

static void
pair0_pipe_fini(void *arg)
{
	pair0_pipe *p = arg;

	nni_aio_fini(&p->aio_send);
	nni_aio_fini(&p->aio_recv);
}

static int
pair0_pipe_init(void *arg, nni_pipe *pipe, void *pair)
{
	pair0_pipe *p = arg;

	nni_aio_init(&p->aio_send, pair0_pipe_send_cb, p);
	nni_aio_init(&p->aio_recv, pair0_pipe_recv_cb, p);

	p->pipe = pipe;
	p->pair = pair;

	return (0);
}

static void
pair0_cancel(nni_aio *aio, void *arg, int rv)
{
	pair0_sock *s = arg;

	nni_mtx_lock(&s->mtx);
	if (nni_aio_list_active(aio)) {
		nni_aio_list_remove(aio);
		nni_aio_finish_error(aio, rv);
	}
	nni_mtx_unlock(&s->mtx);
}

static int
pair0_pipe_start(void *arg)
{
	pair0_pipe *p = arg;
	pair0_sock *s = p->pair;

	if (nni_pipe_peer(p->pipe) != NNI_PROTO_PAIR_V0) {
		// Peer protocol mismatch.
		return (NNG_EPROTO);
	}

	nni_mtx_lock(&s->mtx);
	if (s->p != NULL) {
		nni_mtx_unlock(&s->mtx);
		return (NNG_EBUSY); // Already have a peer, denied.
	}
	s->p        = p;
	s->rd_ready = false;
	nni_mtx_unlock(&s->mtx);

	pair0_send_sched(s);

	// And the pipe read of course.
	nni_pipe_recv(p->pipe, &p->aio_recv);

	return (0);
}

static void
pair0_pipe_close(void *arg)
{
	pair0_pipe *p = arg;

	nni_aio_close(&p->aio_send);
	nni_aio_close(&p->aio_recv);
}

static void
pair0_pipe_recv_cb(void *arg)
{
	pair0_pipe *p = arg;
	pair0_sock *s = p->pair;
	nni_msg    *msg;
	nni_aio    *a;

	if (nni_aio_result(&p->aio_recv) != 0) {
		nni_pipe_close(p->pipe);
		return;
	}

	msg = nni_aio_get_msg(&p->aio_recv);
	// Store the pipe ID.
	nni_msg_set_pipe(msg, nni_pipe_id(p->pipe));

	nni_mtx_lock(&s->mtx);

	// if anyone is blocking, then the lmq will be empty, and
	// we should deliver it there.
	if ((a = nni_list_first(&s->raq)) != NULL) {
		nni_aio_list_remove(a);
		nni_aio_set_msg(a, msg);
		nni_pipe_recv(p->pipe, &p->aio_recv);
		nni_mtx_unlock(&s->mtx);
		nni_aio_finish_sync(a, 0, nni_msg_len(msg));
		return;
	}

	// maybe we have room in the rmq?
	if (!nni_lmq_full(&s->rmq)) {
		nni_lmq_put(&s->rmq, msg);
		nni_aio_set_msg(&p->aio_recv, NULL);
		nni_pipe_recv(p->pipe, &p->aio_recv);
	} else {
		s->rd_ready = true;
	}
	nni_pollable_raise(&s->readable);
	nni_mtx_unlock(&s->mtx);
}

static void
pair0_send_sched(pair0_sock *s)
{
	pair0_pipe *p;
	nni_msg    *m;
	nni_aio    *a = NULL;
	size_t      l = 0;

	nni_mtx_lock(&s->mtx);

	if ((p = s->p) == NULL) {
		nni_mtx_unlock(&s->mtx);
		return;
	}

	s->wr_ready = true;

	// if message waiting in buffered queue, then we prefer that.
	if (nni_lmq_get(&s->wmq, &m) == 0) {
		pair0_pipe_send(p, m);

		if ((a = nni_list_first(&s->waq)) != NULL) {
			nni_aio_list_remove(a);
			m = nni_aio_get_msg(a);
			l = nni_msg_len(m);
			nni_lmq_put(&s->wmq, m);
		}

	} else if ((a = nni_list_first(&s->waq)) != NULL) {
		// Looks like we had the unbuffered case, but
		// someone was waiting.
		nni_aio_list_remove(a);

		m = nni_aio_get_msg(a);
		l = nni_msg_len(m);
		pair0_pipe_send(p, m);
	}

	// if we were blocked before, but not now, update.
	if ((!nni_lmq_full(&s->wmq)) || s->wr_ready) {
		nni_pollable_raise(&s->writable);
	}

	nni_mtx_unlock(&s->mtx);

	if (a != NULL) {
		nni_aio_set_msg(a, NULL);
		nni_aio_finish_sync(a, 0, l);
	}
}

static void
pair0_pipe_send_cb(void *arg)
{
	pair0_pipe *p = arg;

	if (nni_aio_result(&p->aio_send) != 0) {
		nni_msg_free(nni_aio_get_msg(&p->aio_send));
		nni_aio_set_msg(&p->aio_send, NULL);
		nni_pipe_close(p->pipe);
		return;
	}

	pair0_send_sched(p->pair);
}

static void
pair0_sock_open(void *arg)
{
	NNI_ARG_UNUSED(arg);
}

static void
pair0_sock_close(void *arg)
{
	pair0_sock *s = arg;
	nni_aio    *a;
	nni_msg    *m;
	nni_mtx_lock(&s->mtx);
	while (((a = nni_list_first(&s->raq)) != NULL) ||
	    ((a = nni_list_first(&s->waq)) != NULL)) {
		nni_aio_list_remove(a);
		nni_aio_finish_error(a, NNG_ECLOSED);
	}
	while ((nni_lmq_get(&s->rmq, &m) == 0) ||
	    (nni_lmq_get(&s->wmq, &m) == 0)) {
		nni_msg_free(m);
	}
	nni_mtx_unlock(&s->mtx);
}

static void
pair0_pipe_send(pair0_pipe *p, nni_msg *m)
{
	pair0_sock *s = p->pair;
	// assumption: we have unique access to the message at this point.
	NNI_ASSERT(!nni_msg_shared(m));

	nni_aio_set_msg(&p->aio_send, m);
	nni_pipe_send(p->pipe, &p->aio_send);
	s->wr_ready = false;
}

static void
pair0_sock_send(void *arg, nni_aio *aio)
{
	pair0_sock *s = arg;
	nni_msg    *m;
	size_t      len;
	int         rv;

	if (nni_aio_begin(aio) != 0) {
		return;
	}

	m   = nni_aio_get_msg(aio);
	len = nni_msg_len(m);

	nni_mtx_lock(&s->mtx);
	if (s->wr_ready) {
		pair0_pipe *p = s->p;
		if (nni_lmq_full(&s->wmq)) {
			nni_pollable_clear(&s->writable);
		}
		nni_aio_set_msg(aio, NULL);
		nni_aio_finish(aio, 0, len);
		pair0_pipe_send(p, m);
		nni_mtx_unlock(&s->mtx);
		return;
	}

	// Can we maybe queue it.
	if (nni_lmq_put(&s->wmq, m) == 0) {
		// Yay, we can.  So we're done.
		nni_aio_set_msg(aio, NULL);
		nni_aio_finish(aio, 0, len);
		if (nni_lmq_full(&s->wmq)) {
			nni_pollable_clear(&s->writable);
		}
		nni_mtx_unlock(&s->mtx);
		return;
	}

	if ((rv = nni_aio_schedule(aio, pair0_cancel, s)) != 0) {
		nni_aio_finish_error(aio, rv);
		nni_mtx_unlock(&s->mtx);
		return;
	}
	nni_aio_list_append(&s->waq, aio);
	nni_mtx_unlock(&s->mtx);
}

static void
pair0_sock_recv(void *arg, nni_aio *aio)
{
	pair0_sock *s = arg;
	pair0_pipe *p;
	nni_msg    *m;
	int         rv;

	if (nni_aio_begin(aio) != 0) {
		return;
	}

	nni_mtx_lock(&s->mtx);
	p = s->p;

	// Buffered read.  If there is a message waiting for us, pick
	// it up.  We might need to post another read request as well.
	if (nni_lmq_get(&s->rmq, &m) == 0) {
		nni_aio_set_msg(aio, m);
		nni_aio_finish(aio, 0, nni_msg_len(m));
		if (s->rd_ready) {
			s->rd_ready = false;
			m           = nni_aio_get_msg(&p->aio_recv);
			nni_aio_set_msg(&p->aio_recv, NULL);
			nni_lmq_put(&s->rmq, m);
			nni_pipe_recv(p->pipe, &p->aio_recv);
		}
		if (nni_lmq_empty(&s->rmq)) {
			nni_pollable_clear(&s->readable);
		}
		nni_mtx_unlock(&s->mtx);
		return;
	}

	// Unbuffered -- but waiting.
	if (s->rd_ready) {
		s->rd_ready = false;
		m           = nni_aio_get_msg(&p->aio_recv);
		nni_aio_set_msg(&p->aio_recv, NULL);
		nni_aio_set_msg(aio, m);
		nni_aio_finish(aio, 0, nni_msg_len(m));
		nni_pipe_recv(p->pipe, &p->aio_recv);
		nni_pollable_clear(&s->readable);
		nni_mtx_unlock(&s->mtx);
		return;
	}

	if ((rv = nni_aio_schedule(aio, pair0_cancel, s)) != 0) {
		nni_aio_finish_error(aio, rv);
	} else {
		nni_aio_list_append(&s->raq, aio);
	}
	nni_mtx_unlock(&s->mtx);
}

static int
pair0_set_send_buf_len(void *arg, const void *buf, size_t sz, nni_type t)
{
	pair0_sock *s = arg;
	int         val;
	int         rv;

	if ((rv = nni_copyin_int(&val, buf, sz, 0, 8192, t)) != 0) {
		return (rv);
	}
	nni_mtx_lock(&s->mtx);
	rv = nni_lmq_resize(&s->wmq, (size_t) val);
	// Changing the size of the queue can affect our readiness.
	if (!nni_lmq_full(&s->wmq)) {
		nni_pollable_raise(&s->writable);
	} else if (!s->wr_ready) {
		nni_pollable_clear(&s->writable);
	}
	nni_mtx_unlock(&s->mtx);
	return (rv);
}

static int
pair0_get_send_buf_len(void *arg, void *buf, size_t *szp, nni_opt_type t)
{
	pair0_sock *s = arg;
	int         val;

	nni_mtx_lock(&s->mtx);
	val = (int) nni_lmq_cap(&s->wmq);
	nni_mtx_unlock(&s->mtx);

	return (nni_copyout_int(val, buf, szp, t));
}

static int
pair0_set_recv_buf_len(void *arg, const void *buf, size_t sz, nni_type t)
{
	pair0_sock *s = arg;
	int         val;
	int         rv;

	if ((rv = nni_copyin_int(&val, buf, sz, 0, 8192, t)) != 0) {
		return (rv);
	}
	nni_mtx_lock(&s->mtx);
	rv = nni_lmq_resize(&s->rmq, (size_t) val);
	// Changing the size of the queue can affect our readiness.
	if (!nni_lmq_empty(&s->rmq)) {
		nni_pollable_raise(&s->readable);
	} else if (!s->rd_ready) {
		nni_pollable_clear(&s->readable);
	}
	nni_mtx_unlock(&s->mtx);
	return (rv);
}

static int
pair0_get_recv_buf_len(void *arg, void *buf, size_t *szp, nni_opt_type t)
{
	pair0_sock *s = arg;
	int         val;

	nni_mtx_lock(&s->mtx);
	val = (int) nni_lmq_cap(&s->rmq);
	nni_mtx_unlock(&s->mtx);

	return (nni_copyout_int(val, buf, szp, t));
}

static int
pair0_sock_get_recv_fd(void *arg, void *buf, size_t *szp, nni_opt_type t)
{
	pair0_sock *s = arg;
	int         rv;
	int         fd;

	if ((rv = nni_pollable_getfd(&s->readable, &fd)) != 0) {
		return (rv);
	}
	return (nni_copyout_int(fd, buf, szp, t));
}

static int
pair0_sock_get_send_fd(void *arg, void *buf, size_t *szp, nni_opt_type t)
{
	pair0_sock *s = arg;
	int         rv;
	int         fd;

	if ((rv = nni_pollable_getfd(&s->writable, &fd)) != 0) {
		return (rv);
	}
	return (nni_copyout_int(fd, buf, szp, t));
}

static nni_option pair0_sock_options[] = {
	{
	    .o_name = NNG_OPT_RECVFD,
	    .o_get  = pair0_sock_get_recv_fd,
	},
	{
	    .o_name = NNG_OPT_SENDFD,
	    .o_get  = pair0_sock_get_send_fd,
	},
	{
	    .o_name = NNG_OPT_SENDBUF,
	    .o_get  = pair0_get_send_buf_len,
	    .o_set  = pair0_set_send_buf_len,
	},
	{
	    .o_name = NNG_OPT_RECVBUF,
	    .o_get  = pair0_get_recv_buf_len,
	    .o_set  = pair0_set_recv_buf_len,
	},
	// terminate list
	{
	    .o_name = NULL,
	},
};

static nni_proto_pipe_ops pair0_pipe_ops = {
	.pipe_size  = sizeof(pair0_pipe),
	.pipe_init  = pair0_pipe_init,
	.pipe_fini  = pair0_pipe_fini,
	.pipe_start = pair0_pipe_start,
	.pipe_close = pair0_pipe_close,
	.pipe_stop  = pair0_pipe_stop,
};

static nni_proto_sock_ops pair0_sock_ops = {
	.sock_size    = sizeof(pair0_sock),
	.sock_init    = pair0_sock_init,
	.sock_fini    = pair0_sock_fini,
	.sock_open    = pair0_sock_open,
	.sock_close   = pair0_sock_close,
	.sock_send    = pair0_sock_send,
	.sock_recv    = pair0_sock_recv,
	.sock_options = pair0_sock_options,
};

// Legacy protocol (v0)
static nni_proto pair0_proto = {
	.proto_version  = NNI_PROTOCOL_VERSION,
	.proto_self     = { NNI_PROTO_PAIR_V0, "pair" },
	.proto_peer     = { NNI_PROTO_PAIR_V0, "pair" },
	.proto_flags    = NNI_PROTO_FLAG_SNDRCV,
	.proto_sock_ops = &pair0_sock_ops,
	.proto_pipe_ops = &pair0_pipe_ops,
};

static nni_proto pair0_proto_raw = {
	.proto_version  = NNI_PROTOCOL_VERSION,
	.proto_self     = { NNI_PROTO_PAIR_V0, "pair" },
	.proto_peer     = { NNI_PROTO_PAIR_V0, "pair" },
	.proto_flags    = NNI_PROTO_FLAG_SNDRCV | NNI_PROTO_FLAG_RAW,
	.proto_sock_ops = &pair0_sock_ops,
	.proto_pipe_ops = &pair0_pipe_ops,
};

int
nng_pair0_open(nng_socket *sock)
{
	return (nni_proto_open(sock, &pair0_proto));
}

int
nng_pair0_open_raw(nng_socket *sock)
{
	return (nni_proto_open(sock, &pair0_proto_raw));
}
