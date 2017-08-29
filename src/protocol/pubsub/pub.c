//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
// Copyright 2017 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <stdlib.h>
#include <string.h>

#include "core/nng_impl.h"

// Publish protocol.  The PUB protocol simply sends messages out, as
// a broadcast.  It has nothing more sophisticated because it does not
// perform sender-side filtering.  Its best effort delivery, so anything
// that can't receive the message won't get one.

typedef struct pub_pipe pub_pipe;
typedef struct pub_sock pub_sock;

static void pub_pipe_recv_cb(void *);
static void pub_pipe_send_cb(void *);
static void pub_pipe_getq_cb(void *);
static void pub_sock_getq_cb(void *);
static void pub_sock_fini(void *);
static void pub_pipe_fini(void *);

// A pub_sock is our per-socket protocol private structure.
struct pub_sock {
	nni_sock *sock;
	nni_msgq *uwq;
	int       raw;
	nni_aio * aio_getq;
	nni_list  pipes;
	nni_mtx   mtx;
};

// A pub_pipe is our per-pipe protocol private structure.
struct pub_pipe {
	nni_pipe *    pipe;
	pub_sock *    pub;
	nni_msgq *    sendq;
	nni_aio *     aio_getq;
	nni_aio *     aio_send;
	nni_aio *     aio_recv;
	nni_list_node node;
};

static void
pub_sock_fini(void *arg)
{
	pub_sock *s = arg;

	nni_aio_stop(s->aio_getq);
	nni_aio_fini(s->aio_getq);
	nni_mtx_fini(&s->mtx);
	NNI_FREE_STRUCT(s);
}

static int
pub_sock_init(void **sp, nni_sock *sock)
{
	pub_sock *s;
	int       rv;

	if ((s = NNI_ALLOC_STRUCT(s)) == NULL) {
		return (NNG_ENOMEM);
	}
	nni_mtx_init(&s->mtx);
	if ((rv = nni_aio_init(&s->aio_getq, pub_sock_getq_cb, s)) != 0) {
		pub_sock_fini(s);
		return (rv);
	}

	s->sock = sock;
	s->raw  = 0;
	NNI_LIST_INIT(&s->pipes, pub_pipe, node);

	s->uwq = nni_sock_sendq(sock);

	*sp = s;
	nni_sock_recverr(sock, NNG_ENOTSUP);
	return (0);
}

static void
pub_sock_open(void *arg)
{
	pub_sock *s = arg;

	nni_msgq_aio_get(s->uwq, s->aio_getq);
}

static void
pub_sock_close(void *arg)
{
	pub_sock *s = arg;

	nni_aio_cancel(s->aio_getq, NNG_ECLOSED);
}

static void
pub_pipe_fini(void *arg)
{
	pub_pipe *p = arg;
	nni_aio_fini(p->aio_getq);
	nni_aio_fini(p->aio_send);
	nni_aio_fini(p->aio_recv);
	nni_msgq_fini(p->sendq);
	NNI_FREE_STRUCT(p);
}

static int
pub_pipe_init(void **pp, nni_pipe *pipe, void *s)
{
	pub_pipe *p;
	int       rv;

	if ((p = NNI_ALLOC_STRUCT(p)) == NULL) {
		return (NNG_ENOMEM);
	}

	// XXX: consider making this depth tunable
	if (((rv = nni_msgq_init(&p->sendq, 16)) != 0) ||
	    ((rv = nni_aio_init(&p->aio_getq, pub_pipe_getq_cb, p)) != 0) ||
	    ((rv = nni_aio_init(&p->aio_send, pub_pipe_send_cb, p)) != 0) ||
	    ((rv = nni_aio_init(&p->aio_recv, pub_pipe_recv_cb, p)) != 0)) {

		pub_pipe_fini(p);
		return (rv);
	}

	p->pipe = pipe;
	p->pub  = s;
	*pp     = p;
	return (0);
}

static int
pub_pipe_start(void *arg)
{
	pub_pipe *p = arg;
	pub_sock *s = p->pub;

	if (nni_pipe_peer(p->pipe) != NNG_PROTO_SUB) {
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
pub_pipe_stop(void *arg)
{
	pub_pipe *p = arg;
	pub_sock *s = p->pub;

	nni_aio_stop(p->aio_getq);
	nni_aio_stop(p->aio_send);
	nni_aio_stop(p->aio_recv);

	nni_msgq_close(p->sendq);

	nni_mtx_lock(&s->mtx);
	if (nni_list_active(&s->pipes, p)) {
		nni_list_remove(&s->pipes, p);
	}
	nni_mtx_unlock(&s->mtx);
}

static void
pub_sock_getq_cb(void *arg)
{
	pub_sock *s   = arg;
	nni_msgq *uwq = s->uwq;
	nni_msg * msg, *dup;

	pub_pipe *p;
	pub_pipe *last;
	int       rv;

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
pub_pipe_recv_cb(void *arg)
{
	pub_pipe *p = arg;

	if (nni_aio_result(p->aio_recv) != 0) {
		nni_pipe_stop(p->pipe);
		return;
	}

	nni_msg_free(nni_aio_get_msg(p->aio_recv));
	nni_aio_set_msg(p->aio_recv, NULL);
	nni_pipe_recv(p->pipe, p->aio_recv);
}

static void
pub_pipe_getq_cb(void *arg)
{
	pub_pipe *p = arg;

	if (nni_aio_result(p->aio_getq) != 0) {
		nni_pipe_stop(p->pipe);
		return;
	}

	nni_aio_set_msg(p->aio_send, nni_aio_get_msg(p->aio_getq));
	nni_aio_set_msg(p->aio_getq, NULL);

	nni_pipe_send(p->pipe, p->aio_send);
}

static void
pub_pipe_send_cb(void *arg)
{
	pub_pipe *p = arg;

	if (nni_aio_result(p->aio_send) != 0) {
		nni_msg_free(nni_aio_get_msg(p->aio_send));
		nni_aio_set_msg(p->aio_send, NULL);
		nni_pipe_stop(p->pipe);
		return;
	}

	nni_aio_set_msg(p->aio_send, NULL);
	nni_msgq_aio_get(p->sendq, p->aio_getq);
}

static int
pub_sock_setopt(void *arg, int opt, const void *buf, size_t sz)
{
	pub_sock *s  = arg;
	int       rv = NNG_ENOTSUP;

	if (opt == nng_optid_raw) {
		rv = nni_setopt_int(&s->raw, buf, sz, 0, 1);
	}
	return (rv);
}

static int
pub_sock_getopt(void *arg, int opt, void *buf, size_t *szp)
{
	pub_sock *s  = arg;
	int       rv = NNG_ENOTSUP;

	if (opt == nng_optid_raw) {
		rv = nni_getopt_int(s->raw, buf, szp);
	}
	return (rv);
}

static nni_proto_pipe_ops pub_pipe_ops = {
	.pipe_init  = pub_pipe_init,
	.pipe_fini  = pub_pipe_fini,
	.pipe_start = pub_pipe_start,
	.pipe_stop  = pub_pipe_stop,
};

static nni_proto_sock_ops pub_sock_ops = {
	.sock_init   = pub_sock_init,
	.sock_fini   = pub_sock_fini,
	.sock_open   = pub_sock_open,
	.sock_close  = pub_sock_close,
	.sock_setopt = pub_sock_setopt,
	.sock_getopt = pub_sock_getopt,
};

static nni_proto pub_proto = {
	.proto_version  = NNI_PROTOCOL_VERSION,
	.proto_self     = { NNG_PROTO_PUB_V0, "pub" },
	.proto_peer     = { NNG_PROTO_SUB_V0, "sub" },
	.proto_flags    = NNI_PROTO_FLAG_SND,
	.proto_sock_ops = &pub_sock_ops,
	.proto_pipe_ops = &pub_pipe_ops,
};

int
nng_pub0_open(nng_socket *sidp)
{
	return (nni_proto_open(sidp, &pub_proto));
}
