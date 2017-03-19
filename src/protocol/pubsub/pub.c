//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
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

typedef struct nni_pub_pipe	nni_pub_pipe;
typedef struct nni_pub_sock	nni_pub_sock;

static void nni_pub_pipe_recv_cb(void *);
static void nni_pub_pipe_send_cb(void *);
static void nni_pub_pipe_getq_cb(void *);
static void nni_pub_sock_getq_cb(void *);
static void nni_pub_sock_fini(void *);
static void nni_pub_pipe_fini(void *);

// An nni_pub_sock is our per-socket protocol private structure.
struct nni_pub_sock {
	nni_sock *	sock;
	nni_msgq *	uwq;
	int		raw;
	nni_aio		aio_getq;
	nni_list	pipes;
};

// An nni_pub_pipe is our per-pipe protocol private structure.
struct nni_pub_pipe {
	nni_pipe *	pipe;
	nni_pub_sock *	pub;
	nni_msgq *	sendq;
	nni_aio		aio_getq;
	nni_aio		aio_send;
	nni_aio		aio_recv;
	nni_list_node	node;
};

static int
nni_pub_sock_init(void **pubp, nni_sock *sock)
{
	nni_pub_sock *pub;
	int rv;

	if ((pub = NNI_ALLOC_STRUCT(pub)) == NULL) {
		return (NNG_ENOMEM);
	}
	rv = nni_aio_init(&pub->aio_getq, nni_pub_sock_getq_cb, pub);
	if (rv != 0) {
		nni_pub_sock_fini(pub);
		return (rv);
	}
	pub->sock = sock;
	pub->raw = 0;
	NNI_LIST_INIT(&pub->pipes, nni_pub_pipe, node);

	pub->uwq = nni_sock_sendq(sock);

	*pubp = pub;
	nni_sock_recverr(sock, NNG_ENOTSUP);
	return (0);
}


static void
nni_pub_sock_fini(void *arg)
{
	nni_pub_sock *pub = arg;

	if (pub != NULL) {
		nni_aio_fini(&pub->aio_getq);
		NNI_FREE_STRUCT(pub);
	}
}


static void
nni_pub_sock_open(void *arg)
{
	nni_pub_sock *pub = arg;

	nni_msgq_aio_get(pub->uwq, &pub->aio_getq);
}


static int
nni_pub_pipe_init(void **ppp, nni_pipe *pipe, void *psock)
{
	nni_pub_pipe *pp;
	int rv;

	if ((pp = NNI_ALLOC_STRUCT(pp)) == NULL) {
		return (NNG_ENOMEM);
	}
	// XXX: consider making this depth tunable
	if ((rv = nni_msgq_init(&pp->sendq, 16)) != 0) {
		nni_pub_pipe_fini(pp);
		return (rv);
	}

	rv = nni_aio_init(&pp->aio_getq, nni_pub_pipe_getq_cb, pp);
	if (rv != 0) {
		nni_pub_pipe_fini(pp);
		return (rv);
	}

	rv = nni_aio_init(&pp->aio_send, nni_pub_pipe_send_cb, pp);
	if (rv != 0) {
		nni_pub_pipe_fini(pp);
		return (rv);
	}

	rv = nni_aio_init(&pp->aio_recv, nni_pub_pipe_recv_cb, pp);
	if (rv != 0) {
		nni_pub_pipe_fini(pp);
		return (rv);
	}
	pp->pipe = pipe;
	pp->pub = psock;
	*ppp = pp;
	return (0);
}


static void
nni_pub_pipe_fini(void *arg)
{
	nni_pub_pipe *pp = arg;

	nni_msgq_fini(pp->sendq);
	nni_aio_fini(&pp->aio_getq);
	nni_aio_fini(&pp->aio_send);
	nni_aio_fini(&pp->aio_recv);
	NNI_FREE_STRUCT(pp);
}


static int
nni_pub_pipe_start(void *arg)
{
	nni_pub_pipe *pp = arg;
	nni_pub_sock *pub = pp->pub;

	if (nni_pipe_peer(pp->pipe) != NNG_PROTO_SUB) {
		return (NNG_EPROTO);
	}
	nni_list_append(&pub->pipes, pp);

	// Start the receiver and the queue reader.
	nni_pipe_incref(pp->pipe);
	nni_pipe_aio_recv(pp->pipe, &pp->aio_recv);
	nni_pipe_incref(pp->pipe);
	nni_msgq_aio_get(pp->sendq, &pp->aio_getq);

	return (0);
}


static void
nni_pub_pipe_stop(void *arg)
{
	nni_pub_pipe *pp = arg;
	nni_pub_sock *pub = pp->pub;

	if (nni_list_active(&pub->pipes, pp)) {
		nni_list_remove(&pub->pipes, pp);
		nni_msgq_close(pp->sendq);
	}
}


static void
nni_pub_sock_getq_cb(void *arg)
{
	nni_pub_sock *pub = arg;
	nni_msgq *uwq = pub->uwq;
	nni_msg *msg, *dup;
	nni_mtx *mx = nni_sock_mtx(pub->sock);

	nni_pub_pipe *pp;
	nni_pub_pipe *last;
	int rv;

	if (nni_aio_result(&pub->aio_getq) != 0) {
		return;
	}

	msg = pub->aio_getq.a_msg;
	pub->aio_getq.a_msg = NULL;

	nni_mtx_lock(mx);
	last = nni_list_last(&pub->pipes);
	NNI_LIST_FOREACH (&pub->pipes, pp) {
		if (pp != last) {
			rv = nni_msg_dup(&dup, msg);
			if (rv != 0) {
				continue;
			}
		} else {
			dup = msg;
		}
		if ((rv = nni_msgq_tryput(pp->sendq, dup)) != 0) {
			nni_msg_free(dup);
		}
	}
	nni_mtx_unlock(mx);

	if (last == NULL) {
		nni_msg_free(msg);
	}

	nni_msgq_aio_get(uwq, &pub->aio_getq);
}


static void
nni_pub_pipe_recv_cb(void *arg)
{
	nni_pub_pipe *pp = arg;

	if (nni_aio_result(&pp->aio_recv) != 0) {
		nni_pipe_close(pp->pipe);
		nni_pipe_decref(pp->pipe);
		return;
	}

	nni_msg_free(pp->aio_recv.a_msg);
	pp->aio_recv.a_msg = NULL;
	nni_pipe_aio_recv(pp->pipe, &pp->aio_recv);
}


static void
nni_pub_pipe_getq_cb(void *arg)
{
	nni_pub_pipe *pp = arg;

	if (nni_aio_result(&pp->aio_getq) != 0) {
		nni_pipe_close(pp->pipe);
		nni_pipe_decref(pp->pipe);
		return;
	}

	pp->aio_send.a_msg = pp->aio_getq.a_msg;
	pp->aio_getq.a_msg = NULL;

	nni_pipe_aio_send(pp->pipe, &pp->aio_send);
}


static void
nni_pub_pipe_send_cb(void *arg)
{
	nni_pub_pipe *pp = arg;

	if (nni_aio_result(&pp->aio_send) != 0) {
		nni_msg_free(pp->aio_send.a_msg);
		pp->aio_send.a_msg = NULL;
		nni_pipe_close(pp->pipe);
		nni_pipe_decref(pp->pipe);
		return;
	}

	pp->aio_send.a_msg = NULL;
	nni_msgq_aio_get(pp->sendq, &pp->aio_getq);
}


static int
nni_pub_sock_setopt(void *arg, int opt, const void *buf, size_t sz)
{
	nni_pub_sock *pub = arg;
	int rv;

	switch (opt) {
	case NNG_OPT_RAW:
		rv = nni_setopt_int(&pub->raw, buf, sz, 0, 1);
		break;
	default:
		rv = NNG_ENOTSUP;
	}
	return (rv);
}


static int
nni_pub_sock_getopt(void *arg, int opt, void *buf, size_t *szp)
{
	nni_pub_sock *pub = arg;
	int rv;

	switch (opt) {
	case NNG_OPT_RAW:
		rv = nni_getopt_int(&pub->raw, buf, szp);
		break;
	default:
		rv = NNG_ENOTSUP;
	}
	return (rv);
}


// This is the global protocol structure -- our linkage to the core.
// This should be the only global non-static symbol in this file.
static nni_proto_pipe_ops nni_pub_pipe_ops = {
	.pipe_init	= nni_pub_pipe_init,
	.pipe_fini	= nni_pub_pipe_fini,
	.pipe_start	= nni_pub_pipe_start,
	.pipe_stop	= nni_pub_pipe_stop,
};

nni_proto_sock_ops nni_pub_sock_ops = {
	.sock_init	= nni_pub_sock_init,
	.sock_fini	= nni_pub_sock_fini,
	.sock_open	= nni_pub_sock_open,
	.sock_setopt	= nni_pub_sock_setopt,
	.sock_getopt	= nni_pub_sock_getopt,
};

nni_proto nni_pub_proto = {
	.proto_self	= NNG_PROTO_PUB,
	.proto_peer	= NNG_PROTO_SUB,
	.proto_name	= "pub",
	.proto_flags	= NNI_PROTO_FLAG_SND,
	.proto_sock_ops = &nni_pub_sock_ops,
	.proto_pipe_ops = &nni_pub_pipe_ops,
};
